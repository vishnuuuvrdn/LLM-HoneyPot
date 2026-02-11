import json
import os
from datetime import datetime

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "attacks.json")


def log_attack(ip, command, detection):
    """
    Store attacker activity in JSON format (DFIR-ready)
    """

    # Ensure logs directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "command": command,
        "attack": detection.get("attack", "").title(),
        "severity": detection.get("severity", "").title(),
        "mitre": detection.get("mitre", "").upper(),
    }

    # Create file if it does not exist
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f, indent=4)

    # Read → append → write
    with open(LOG_FILE, "r+") as f:
        data = json.load(f)
        data.append(entry)
        f.seek(0)
        json.dump(data, f, indent=4)
