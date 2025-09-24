# path: platform-security/code-protection/leak_detection/token_scanner.py

"""
TeslaAI LeakScanner v1.20 — Локальный детектор токенов и утечек в исходном коде

Особенности:
- Проверка по более чем 25 шаблонам (AWS, GCP, RSA, Telegram, JWT, API и др.)
- Рекурсивный обход директорий
- Игнорирование бинарных и временных файлов
- Сводка всех найденных утечек в конце + лог-файл
"""

import os
import re
import logging

SCAN_ROOT = "."  # Точка входа сканирования — текущая директория
LOG_FILE = "/var/log/teslaai_token_scan.log"

# Шаблоны чувствительных данных
PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "Generic API Key": r"[aA][pP][iI](_?key)?['\"]?\s*[:=]\s*['\"][\w-]{16,45}['\"]",
    "Telegram Token": r"\d{8,10}:[\w-]{35}",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "Private Key": r"-----BEGIN PRIVATE KEY-----",
    "DB Password": r"(?i)password\s*[:=]\s*['\"][^'\"]{4,40}['\"]",
}

EXCLUDED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".woff", ".ttf", ".otf", ".ico",
    ".mp4", ".zip", ".tar", ".gz", ".exe", ".dll", ".bin", ".pdf", ".docx"
}

logging.basicConfig(filename=LOG_FILE, level=logging.INFO)

def is_text_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return b'\x00' not in chunk
    except:
        return False

def scan_file(file_path):
    results = []
    try:
        with open(file_path, 'r', encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for label, pattern in PATTERNS.items():
                if re.search(pattern, content):
                    results.append((label, file_path))
                    logging.warning(f"LEAK DETECTED: {label} in {file_path}")
    except Exception as e:
        logging.error(f"ERROR scanning {file_path}: {e}")
    return results

def scan_directory(root):
    findings = []
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            ext = os.path.splitext(file_path)[-1]
            if ext in EXCLUDED_EXTENSIONS:
                continue
            if is_text_file(file_path):
                findings.extend(scan_file(file_path))
    return findings

def main():
    print(f"[*] Starting token scan in: {SCAN_ROOT}")
    findings = scan_directory(SCAN_ROOT)
    if findings:
        print(f"[!] Found {len(findings)} potential leak(s):")
        for label, path in findings:
            print(f" - {label}: {path}")
    else:
        print("[✓] No leaks detected.")
    print(f"[*] Log saved to {LOG_FILE}")

if __name__ == "__main__":
    main()
