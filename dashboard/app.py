import sys
import os
import json
import threading
from flask import Flask, render_template, jsonify, request, redirect, url_for, session

# Fix import path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from core.ssh_honeypot import start_honeypot

app = Flask(__name__)
app.secret_key = "llm-honeypot-secret-key"  # session security

LOG_FILE = os.path.join(BASE_DIR, "logs", "attacks.json")
honeypot_thread = None

# ----------------- AUTH CONFIG -----------------
USERNAME = "admin"
PASSWORD = "admin123"
# -----------------------------------------------


def load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return json.load(f)


def summarize_logs(logs):
    attack_types = {}
    severity_levels = {}

    for e in logs:
        attack_types[e["attack"]] = attack_types.get(e["attack"], 0) + 1
        severity_levels[e["severity"]] = severity_levels.get(e["severity"], 0) + 1

    return attack_types, severity_levels


def login_required():
    return "user" in session


# ----------------- ROUTES -----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username")
        pwd = request.form.get("password")

        if user == USERNAME and pwd == PASSWORD:
            session["user"] = user
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))

    logs = load_logs()
    attack_types, severity_levels = summarize_logs(logs)

    return render_template(
        "index.html",
        total=len(logs),
        attack_types=attack_types,
        severity_levels=severity_levels,
        logs=logs[-15:][::-1]
    )


@app.route("/logs")
def all_logs():
    if not login_required():
        return redirect(url_for("login"))
    return render_template("logs.html", logs=load_logs())


@app.route("/start")
def start_honeypot_web():
    if not login_required():
        return redirect(url_for("login"))

    global honeypot_thread
    if honeypot_thread is None or not honeypot_thread.is_alive():
        honeypot_thread = threading.Thread(
            target=start_honeypot,
            daemon=True
        )
        honeypot_thread.start()
        return jsonify({"status": "Honeypot started"})
    return jsonify({"status": "Already running"})


# ----------------- MAIN -----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
