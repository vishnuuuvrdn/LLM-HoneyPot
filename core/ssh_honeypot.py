# ===============================
# PATH FIX (VERY IMPORTANT)
# ===============================
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

# ===============================
# IMPORTS
# ===============================
from ai.llm_engine import generate_response
from core.session import create_session
from detection.rules import detect_attack
from core.logger import log_attack

import socket
import threading
import paramiko

# ===============================
# SSH HOST KEY (PERSISTENT)
# ===============================
KEY_DIR = os.path.join(BASE_DIR, "keys")
KEY_PATH = os.path.join(KEY_DIR, "ssh_host_rsa.key")

os.makedirs(KEY_DIR, exist_ok=True)

if os.path.exists(KEY_PATH):
    HOST_KEY = paramiko.RSAKey(filename=KEY_PATH)
else:
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file(KEY_PATH)

# ===============================
# FAKE SSH SERVER
# ===============================
class FakeSSHServer(paramiko.ServerInterface):

    def check_auth_password(self, username, password):
        print(f"[+] Login attempt: {username}:{password}")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    # Prevent SSH PTY warnings
    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


# ===============================
# HANDLE ATTACKER CONNECTION
# ===============================
def handle_connection(client, addr):
    ip = addr[0]
    print(f"[+] Connection from {ip}")

    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)

    server = FakeSSHServer()
    transport.start_server(server=server)

    channel = transport.accept(20)
    if channel is None:
        return

    # Per-attacker session
    session = create_session(ip)

    # Fake banner
    channel.send(b"Welcome to Ubuntu 20.04 LTS\n")
    channel.send(b"admin@server:~$ ")

    buffer = ""  # 🔥 FIX: command buffering

    while True:
        try:
            data = channel.recv(1024)
            if not data:
                break

            buffer += data.decode("utf-8", errors="ignore")

            # Wait until ENTER is pressed
            if "\n" not in buffer:
                continue

            command, buffer = buffer.split("\n", 1)
            command = command.strip()

            if not command:
                channel.send(b"admin@server:~$ ")
                continue

            print(f"[{ip}] Command: {command}")
            session["commands"].append(command)

            # Exit handling
            if command.lower() in ("exit", "logout"):
                channel.send(b"logout\n")
                break

            # Detect attack
            detection = detect_attack(command)

            # Log attack
            log_attack(ip, command, detection)

            # SOC alert (medium/high)
            if detection["severity"].lower() != "low":
                print(
                    f"[!] Attack Detected | "
                    f"{detection['attack']} | "
                    f"Severity: {detection['severity']} | "
                    f"MITRE: {detection['mitre']}"
                )

            # AI response (fail-safe)
            try:
                response = generate_response(command, session)
            except Exception as e:
                print(f"[!] LLM error: {e}")
                response = "bash: internal error\n"

            if not response.endswith("\n"):
                response += "\n"

            channel.send(response.encode())
            channel.send(b"admin@server:~$ ")

        except EOFError:
            break
        except Exception as e:
            print(f"[!] Session error from {ip}: {e}")
            break

    channel.close()
    transport.close()
    print(f"[-] Connection closed for {ip}")


# ===============================
# START HONEYPOT SERVER
# ===============================
def start_honeypot(host="0.0.0.0", port=2222):
    print(f"[+] SSH Honeypot listening on port {port}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)

    try:
        while True:
            client, addr = sock.accept()
            threading.Thread(
                target=handle_connection,
                args=(client, addr),
                daemon=True
            ).start()

    except KeyboardInterrupt:
        print("\n[!] Honeypot stopped by user (Ctrl+C)")
    finally:
        sock.close()


# ===============================
# DIRECT RUN SUPPORT
# ===============================
if __name__ == "__main__":
    start_honeypot()
