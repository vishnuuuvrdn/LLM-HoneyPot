def generate_response(command, session):
    """
    Safe LLM-style response generator.
    Always returns a string.
    NEVER crashes the SSH session.
    """

    try:
        # Current working directory
        cwd = session.get("cwd", "/home/admin")

        # pwd
        if command == "pwd":
            return f"{cwd}\n"

        # ls
        if command == "ls":
            return "documents  downloads  backup.sh\n"

        # cd command
        if command.startswith("cd"):
            parts = command.split(maxsplit=1)

            if len(parts) == 2:
                target = parts[1]

                if target == "..":
                    session["cwd"] = "/home"
                elif target.startswith("/"):
                    session["cwd"] = target
                else:
                    session["cwd"] = f"{cwd}/{target}"

            # IMPORTANT: return newline so attacker sees prompt again
            return "\n"

        # whoami
        if command == "whoami":
            return "admin\n"

        # id
        if command == "id":
            return "uid=1000(admin) gid=1000(admin) groups=1000(admin)\n"

        # sensitive files
        if "passwd" in command or "shadow" in command:
            return "Permission denied\n"

        # sudo attempts
        if command.startswith("sudo"):
            return "admin is not in the sudoers file. This incident will be reported.\n"

        # fallback (unknown commands)
        return f"{command}: command not found\n"

    except Exception:
        # FAIL-SAFE: never break SSH session
        return "bash: unexpected internal error\n"
