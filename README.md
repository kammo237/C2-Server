# C2 Server

A Python-based demonstration Command and Control (C2) framework featuring an Agent and Server architecture with robust cryptography using RSA and Fernet algorithms. 

> [!WARNING]
> **Disclaimer:** This project is intended strictly for educational purposes, security research, and authorized auditing. Do not use this tool on systems where you do not have explicit permission. The author (`kammo237`) assumes no liability for the misuse of this educational framework.

## Features

- **End-to-End Encryption:** Utilizes RSA for secure public key exchange and Fernet (AES-128-CBC based HMAC-SHA256) for session key encryption. Every payload transmitted and received is encrypted.
- **Dynamic Sleep:** The agent employs a dynamic sleep range to evade analysis and behavioral detection.
- **Command Execution:** Run arbitrary shell commands on target mechanisms in an authenticated and secure loop.
- **REST API Server:** Built on top of Python's `Flask` framework managing endpoints for pubkey distribution, agent registration, beaconing, and result uploading.
- **File Exfiltration / Download:** Supports deploying files via server URLs dynamically to the target system.

## Project Structure

```text
├── agent.py         # The client-side beacon designed to run on the target
├── server.py        # The server-side listener handing requests and queues
├── test_flow.py     # Local integration tests to verify the crypto and API routing
├── requirements.txt # Project dependencies
└── README.md        # This documentation
```

## Prerequisites

Python 3.8+ is required.

Install the required Python modules using pip:

```bash
pip install -r requirements.txt
```

## Usage

### Starting the Server

The server serves as the command center for all agents.

```bash
python server.py
```
*Note: By default, the server runs on `0.0.0.0:5000`.*

### Running the Agent

On the target machine, execute the agent. It will automatically fetch the public key, register a session, and start beaconing for tasks.

```bash
python agent.py
```

### Running Tests

To verify that the server, agent, cryptography and routing are functioning correctly on your machine, you can run the integration flow:

```bash
python test_flow.py
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
