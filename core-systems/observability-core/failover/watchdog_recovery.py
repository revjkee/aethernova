import os
import time
import logging
import subprocess
import requests
from typing import List, Tuple

# Настройка логгера
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [watchdog] %(levelname)s: %(message)s',
)

# Конфигурация из ENV
WATCHDOG_INTERVAL = int(os.getenv("WATCHDOG_INTERVAL", "30"))  # секунд
SERVICES_TO_MONITOR = os.getenv("SERVICES", "ai-core,agent-manager,rabbitmq,redis").split(",")
RECOVERY_COMMANDS = {
    "ai-core": ["systemctl", "restart", "ai-core"],
    "agent-manager": ["docker", "restart", "agent-manager"],
    "rabbitmq": ["systemctl", "restart", "rabbitmq-server"],
    "redis": ["systemctl", "restart", "redis-server"]
}
ALERT_URL = os.getenv("WATCHDOG_ALERT_WEBHOOK", "http://alertmanager:9093/api/v2/alerts")

def is_service_alive(service_name: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        return result.stdout.strip() == "active"
    except Exception as e:
        logging.error(f"Ошибка при проверке статуса сервиса {service_name}: {e}")
        return False

def restart_service(service_name: str) -> Tuple[bool, str]:
    cmd = RECOVERY_COMMANDS.get(service_name)
    if not cmd:
        return False, "Команда восстановления не определена"
    try:
        subprocess.run(cmd, check=True)
        logging.info(f"Сервис {service_name} был перезапущен.")
        return True, "Перезапущен"
    except subprocess.CalledProcessError as e:
        logging.error(f"Не удалось перезапустить {service_name}: {e}")
        return False, str(e)

def send_alert(service_name: str, error: str):
    alert_payload = [
        {
            "labels": {
                "alertname": "WatchdogRecoveryFailure",
                "service": service_name,
                "severity": "critical"
            },
            "annotations": {
                "summary": f"Сервис {service_name} не отвечает и не восстанавливается",
                "description": error
            },
            "startsAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    ]
    try:
        resp = requests.post(ALERT_URL, json=alert_payload, timeout=5)
        if resp.status_code == 200:
            logging.info(f"Алерт успешно отправлен для {service_name}")
        else:
            logging.warning(f"Ошибка при отправке алерта: {resp.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Не удалось отправить алерт: {e}")

def watchdog_cycle():
    for service in SERVICES_TO_MONITOR:
        logging.info(f"Проверка сервиса: {service}")
        if not is_service_alive(service):
            logging.warning(f"{service} не активен. Пытаемся восстановить...")
            success, msg = restart_service(service)
            if not success:
                send_alert(service, msg)

if __name__ == "__main__":
    logging.info("Watchdog recovery loop запущен.")
    while True:
        watchdog_cycle()
        time.sleep(WATCHDOG_INTERVAL)
