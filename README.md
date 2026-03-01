# C2 Server — v0.2

A hardened, Python-based Command and Control (C2) framework featuring an advanced Agent/Server architecture with robust RSA+Fernet cryptography and an interactive operator console.

> [!WARNING]
> **Disclaimer:** This project is intended strictly for educational purposes, security research, and authorized auditing. Do not use this tool on systems where you do not have explicit permission. The author assumes no liability for the misuse of this educational framework.

## What's New in v0.2

- **Interactive Operator Console (`cli.py`):** Real-time management of agents with an interactive shell.
- **Asynchronous Tasking:** Use `!command` to queue tasks without blocking the console.
- **Enhanced Visibility:** Track tasks through `PENDING`, `DELIVERED`, and `COMPLETED` states.
- **Full Result History:** View complete command outputs via `history` and `cat <task_id>` inside the CLI.
- **Robust Decommissioning:** Agents now support explicit `shutdown` tasks and self-delete upon server-side session removal (401).
- **Hardened Monitoring:** Server logs are now private and do not leak command outputs.

## Features

- **End-to-End Encryption:** RSA-2048 for session key exchange and per-agent Fernet (AES-128-CBC) for all traffic.
- **HMAC Authentication:** Every request is authenticated with a per-request HMAC-SHA256 signature for replay protection.
- **Browser-Fingerprint Spoofing:** Agent uses `tls-client` to masquerade as a modern browser (Chrome).
- **Dynamic Sleep:** Jitter-based sleep ranges to evade behavioral analysis.
- **File Operations:** Support for downloading files to the target system.

## Project Structure

```text
├── agent/           # Client-side beacon
│   └── agent.py     
├── server/          # Hardened listener and task queue
│   ├── server.py    
│   └── c2.db        
├── operator/        # Operator console for interaction
│   └── cli.py       
├── tests/           # Integration tests
│   └── test_flow.py 
├── requirements.txt # Project dependencies
└── README.md        # Documentation
```

## Setup & Usage

### 1. Installation
Python 3.8+ is required. It is recommended to use a virtual environment.

```bash
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Start the Server
The server requires an `OPERATOR_TOKEN` for the CLI to authenticate. Run it from the `server` directory.

```bash
$env:OPERATOR_TOKEN="your_secret_here"
python server/server.py
```

### 3. Start the Agent
Run the agent from the root or the `agent` directory.

```bash
python agent/agent.py
```

### 4. Manage with CLI
Launch the interactive console to push tasks and view results.

```bash
python operator/cli.py
```

## License
MIT License - see the [LICENSE](LICENSE) file for details.
