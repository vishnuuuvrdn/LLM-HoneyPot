def detect_attack(command: str):
    cmd = command.lower()

    if "passwd" in cmd or "shadow" in cmd:
        return {
            "attack": "Credential Access",
            "severity": "High",
            "mitre": "T1003"
        }

    if cmd.startswith("sudo") or "su " in cmd:
        return {
            "attack": "Privilege Escalation",
            "severity": "High",
            "mitre": "T1068"
        }

    if "wget" in cmd or "curl" in cmd:
        return {
            "attack": "Malware Download",
            "severity": "High",
            "mitre": "T1105"
        }

    if "nmap" in cmd or "netstat" in cmd:
        return {
            "attack": "Network Reconnaissance",
            "severity": "Medium",
            "mitre": "T1046"
        }

    if "ls" in cmd or "pwd" in cmd or "whoami" in cmd:
        return {
            "attack": "Reconnaissance",
            "severity": "Low",
            "mitre": "T1082"
        }

    return {
        "attack": "Unknown",
        "severity": "Low",
        "mitre": "N/A"
    }
