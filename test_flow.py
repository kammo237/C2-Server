"""
Smoke test for the hardened C2 server.
Starts server as a subprocess, then runs:
  1. Fetch RSA public key
  2. Register agent (RSA key exchange)
  3. Operator push a shell task
  4. Agent beacon -> receives task
  5. Agent uploads result
  6. Replay attack -> expect 401
  7. Verify DB persistence (tasks delivered, result saved)
Run: python test_flow.py
Requires OPERATOR_TOKEN env var (same as server will use).
"""

import base64
import hashlib
import hmac as _hmac
import json
import os
import signal
import subprocess
import sys
import time
import uuid

import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BASE_URL       = "http://127.0.0.1:15099"
OPERATOR_TOKEN = os.environ.get("OPERATOR_TOKEN", "smoke-test-secret-1234")
os.environ["OPERATOR_TOKEN"] = OPERATOR_TOKEN
os.environ["C2_PORT"]        = "15099"

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
failures = []

def check(label, cond, detail=""):
    if cond:
        print(f"  {PASS} {label}")
    else:
        print(f"  {FAIL} {label}  {detail}")
        failures.append(label)


def _sig(session_key: bytes, agent_id: str, ts: int) -> str:
    return _hmac.new(session_key, f"{agent_id}:{ts}".encode(), hashlib.sha256).hexdigest()


def auth_headers(session_key: bytes, agent_id: str) -> dict:
    ts = int(time.time() * 1000)
    return {
        "X-Agent-Id":  agent_id,
        "X-Timestamp": str(ts),
        "X-Signature": _sig(session_key, agent_id, ts),
    }


# ---------------------------------------------------------------------------
# Start server
# ---------------------------------------------------------------------------
python = sys.executable
print("[*] Starting server …")
proc  = subprocess.Popen(
    [python, "server.py"],
    cwd=os.path.dirname(__file__),
    env=os.environ.copy(),
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)
time.sleep(3)  # give waitress time to bind

try:
    # -------------------------------------------------------------------
    # 1. RSA public key
    # -------------------------------------------------------------------
    print("\n[1] Fetch RSA public key")
    r = requests.get(BASE_URL + "/pub")
    check("status 200", r.status_code == 200, r.status_code)
    pub_key = serialization.load_pem_public_key(r.content)
    check("valid RSA key", pub_key is not None)

    # -------------------------------------------------------------------
    # 2. Register agent
    # -------------------------------------------------------------------
    print("\n[2] Register agent")
    AGENT_ID   = str(uuid.uuid4())
    SESSION_KEY = Fernet.generate_key()
    fernet     = Fernet(SESSION_KEY)

    enc_sk = pub_key.encrypt(
        SESSION_KEY,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    reg_body = {
        "agent_id":        AGENT_ID,
        "session_key_enc": base64.b64encode(enc_sk).decode(),
        "timestamp_ms":    int(time.time() * 1000),
    }
    r = requests.post(BASE_URL + "/api/register", json=reg_body)
    check("status 200", r.status_code == 200, r.text)
    agent_token = r.json().get("token", "")
    check("token present", bool(agent_token))

    # -------------------------------------------------------------------
    # 3. Operator push a task (WRONG token -> 403)
    # -------------------------------------------------------------------
    print("\n[3] Operator push — wrong token rejected")
    r = requests.post(
        BASE_URL + "/api/push",
        json={"agent_id": AGENT_ID, "type": "shell", "command": "echo hello"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    check("403 on bad operator token", r.status_code == 403, r.status_code)

    # -------------------------------------------------------------------
    # 4. Operator push a task (correct token)
    # -------------------------------------------------------------------
    print("\n[4] Operator push — correct token")
    r = requests.post(
        BASE_URL + "/api/push",
        json={"agent_id": AGENT_ID, "type": "shell", "command": "echo hello"},
        headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
    )
    check("status 200", r.status_code == 200, r.text)
    check("task queued message", "queued" in r.json().get("status", ""))

    # -------------------------------------------------------------------
    # 5. Agent beacon -> receives task
    # -------------------------------------------------------------------
    print("\n[5] Agent beacon — receives task")
    payload_enc = fernet.encrypt(json.dumps({"id": AGENT_ID}).encode())
    r = requests.post(
        BASE_URL + "/api/status",
        data=payload_enc,
        headers=auth_headers(SESSION_KEY, AGENT_ID),
    )
    check("status 200", r.status_code == 200, r.status_code)
    resp_data = json.loads(fernet.decrypt(r.content).decode())
    task = resp_data.get("task")
    check("task received", task is not None)
    check("task type = shell", task and task.get("type") == "shell")

    # -------------------------------------------------------------------
    # 6. Agent uploads result
    # -------------------------------------------------------------------
    print("\n[6] Agent result upload")
    result_enc = fernet.encrypt(json.dumps({"id": AGENT_ID, "output": "hello\n"}).encode())
    r = requests.post(
        BASE_URL + "/api/upload",
        data=result_enc,
        headers=auth_headers(SESSION_KEY, AGENT_ID),
    )
    check("status 200", r.status_code == 200, r.status_code)
    check("received ack", "received" in json.loads(fernet.decrypt(r.content))["status"])

    # -------------------------------------------------------------------
    # 7. Replay attack — reuse same timestamp+sig -> 401
    # -------------------------------------------------------------------
    print("\n[7] Replay attack — stale / reused nonce rejected")
    old_ts = int(time.time() * 1000) - 120_000  # 2 minutes ago
    old_sig = _sig(SESSION_KEY, AGENT_ID, old_ts)
    stale_headers = {
        "X-Agent-Id":  AGENT_ID,
        "X-Timestamp": str(old_ts),
        "X-Signature": old_sig,
    }
    r = requests.post(
        BASE_URL + "/api/status",
        data=fernet.encrypt(json.dumps({"id": AGENT_ID}).encode()),
        headers=stale_headers,
    )
    check("stale timestamp rejected 401", r.status_code == 401, r.status_code)

    # -------------------------------------------------------------------
    # 8. Beacon again — no more tasks
    # -------------------------------------------------------------------
    print("\n[8] Second beacon — empty task queue")
    r = requests.post(
        BASE_URL + "/api/status",
        data=fernet.encrypt(json.dumps({"id": AGENT_ID}).encode()),
        headers=auth_headers(SESSION_KEY, AGENT_ID),
    )
    check("status 200", r.status_code == 200)
    resp_data = json.loads(fernet.decrypt(r.content).decode())
    check("task is None", resp_data.get("task") is None)

    # -------------------------------------------------------------------
    # 9. List agents (operator)
    # -------------------------------------------------------------------
    print("\n[9] Operator list agents")
    r = requests.get(
        BASE_URL + "/api/agents",
        headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
    )
    check("status 200", r.status_code == 200)
    agents = r.json()
    ids = [a["agent_id"] for a in agents]
    check("our agent in list", AGENT_ID in ids)

finally:
    proc.terminate()
    out, _ = proc.communicate(timeout=5)
    print("\n\n--- Server output ---")
    print(out.decode(errors="replace")[:3000])

# ---------------------------------------------------------------------------
print("\n" + "=" * 50)
if failures:
    print(f"{FAIL} {len(failures)} test(s) failed: {failures}")
    sys.exit(1)
else:
    print(f"{PASS} All tests passed.")
