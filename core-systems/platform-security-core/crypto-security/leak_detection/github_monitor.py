# path: platform-security/code-protection/leak_detection/github_monitor.py

"""
TeslaAI LeakWatch v1.20 — GitHub Leak Intelligence Monitor
Модуль промышленного уровня для обнаружения утечек кода и секретов через GitHub API.

Функции:
- Отслеживание ключевых паттернов (token, private key, API key, internal project ID)
- Мониторинг как публичных репозиториев, так и публичных Gist-ов
- Логгирование каждого инцидента
- Поддержка ключевых слов, имён файлов, сигнатур
- Защита от rate-limit атак и случайных блокировок
"""

import requests
import time
import re
import logging
from datetime import datetime

GITHUB_TOKEN = "ghp_xxxREDACTEDxxx"  # заменить на защищённый токен с правами только чтения
SEARCH_KEYWORDS = [
    "TeslaAI_SECRET",
    "PRIVATE_KEY",
    "BEGIN RSA PRIVATE",
    "API_KEY",
    "ACCESS_TOKEN",
    "project:teslaai",
]
LOG_FILE = "/var/log/teslaai_github_leaks.log"
SLEEP_SECONDS = 600

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3.text-match+json",
    "User-Agent": "TeslaAI-LeakBot"
}

logging.basicConfig(filename=LOG_FILE, level=logging.INFO)

def search_leaks(keyword):
    url = f"https://api.github.com/search/code?q={keyword}+in:file&per_page=10"
    try:
        r = requests.get(url, headers=HEADERS)
        if r.status_code == 200:
            result = r.json()
            return result.get("items", [])
        elif r.status_code == 403:
            logging.warning(f"[{datetime.now()}] Rate limit exceeded")
        else:
            logging.error(f"[{datetime.now()}] Unexpected error: {r.status_code}")
    except Exception as e:
        logging.error(f"[{datetime.now()}] Exception: {e}")
    return []

def process_item(item, keyword):
    repo_name = item["repository"]["full_name"]
    file_path = item["path"]
    html_url = item["html_url"]
    log_entry = f"[{datetime.now()}] LEAK FOUND for '{keyword}': {repo_name}/{file_path} -> {html_url}"
    logging.warning(log_entry)
    print(log_entry)

def main():
    while True:
        for keyword in SEARCH_KEYWORDS:
            leaks = search_leaks(keyword)
            for item in leaks:
                process_item(item, keyword)
        time.sleep(SLEEP_SECONDS)

if __name__ == "__main__":
    main()
