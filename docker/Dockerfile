FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]

[Unit]
Description=LLM HoneyPot Dashboard Service
After=network.target

[Service]
Type=simple
User=honeypot
WorkingDirectory=/opt/llm-honeypot
Environment=PYTHONUNBUFFERED=1
Environment=DASHBOARD_SECRET_KEY=change-this-secret
Environment=DASHBOARD_USERNAME=admin
Environment=DASHBOARD_PASSWORD=change-this-password
ExecStart=/opt/llm-honeypot/.venv/bin/python dashboard/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
