# File: offensive_security/autopwn-framework/runner/autopwn-runner.py

import subprocess
import os
import requests

REPORT_OUTPUT = "/tmp/reports/last_report.json"

def generate_report_and_alert(session_id):
    print("[*] Запуск report_extractor.rb через msfconsole")
    subprocess.run([
        "msfconsole", "-q", "-x",
        f"resource metasploit/auxiliary_scripts/report_extractor.rb SESSION={session_id}"
    ])

    if os.path.exists(REPORT_OUTPUT):
        with open(REPORT_OUTPUT, "r") as f:
            report = f.read()

        send_alert_to_bot(report)

def send_alert_to_bot(report_text: str):
    print("[*] Отправка алерта через внутренний Telegram-бот")
    try:
        requests.post(
            "http://localhost:8000/bot/send_alert",  # Внутренний endpoint
            json={
                "text": f"⚠️ Новый отчёт постэксплуатации:\n\n{report_text[:1000]}",
                "priority": "high"
            },
            timeout=5
        )
    except Exception as e:
        print(f"[!] Ошибка при отправке алерта: {e}")
