"""
secrets_scanner.py

Инструмент для автоматического сканирования исходного кода на наличие секретов:
- API ключей
- Токенов
- Паролей и приватных ключей

Использует регулярные выражения, эвристики и базовые проверки формата.

"""

import re
import os
from typing import List, Tuple


# Основные паттерны секретов (можно расширять)
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
    "Private RSA Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Private EC Key": r"-----BEGIN EC PRIVATE KEY-----",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "Generic API Key": r"(?i)(api|token|secret)[\"'\s:=]{1,3}[A-Za-z0-9\-_]{16,40}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
}


def scan_file_for_secrets(filepath: str) -> List[Tuple[int, str, str]]:
    """
    Сканирует файл на наличие секретов.

    Возвращает список кортежей: (номер строки, тип секрета, найденный фрагмент)
    """
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                for secret_name, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, line)
                    if matches:
                        for match in matches:
                            findings.append((lineno, secret_name, match if isinstance(match, str) else match[0]))
    except Exception as e:
        print(f"Ошибка при сканировании файла {filepath}: {e}")
    return findings


def scan_directory(root_dir: str, extensions: List[str] = None) -> List[Tuple[str, int, str, str]]:
    """
    Рекурсивно сканирует директорию на секреты в файлах с указанными расширениями.

    Возвращает список кортежей: (путь к файлу, номер строки, тип секрета, найденный фрагмент)
    """
    if extensions is None:
        extensions = ['.py', '.js', '.ts', '.go', '.java', '.rb', '.sh', '.yaml', '.yml', '.json']

    all_findings = []

    for subdir, _, files in os.walk(root_dir):
        for filename in files:
            if any(filename.endswith(ext) for ext in extensions):
                filepath = os.path.join(subdir, filename)
                results = scan_file_for_secrets(filepath)
                for lineno, secret_type, fragment in results:
                    all_findings.append((filepath, lineno, secret_type, fragment))
    return all_findings


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Secrets Scanner for code repositories")
    parser.add_argument("path", help="Путь к директории или файлу для сканирования")
    args = parser.parse_args()

    if os.path.isfile(args.path):
        findings = scan_file_for_secrets(args.path)
        for lineno, secret_type, fragment in findings:
            print(f"[{args.path}:{lineno}] Найден секрет: {secret_type} => {fragment}")
    elif os.path.isdir(args.path):
        findings = scan_directory(args.path)
        for filepath, lineno, secret_type, fragment in findings:
            print(f"[{filepath}:{lineno}] Найден секрет: {secret_type} => {fragment}")
    else:
        print("Ошибка: указанный путь не существует.")


if __name__ == "__main__":
    main()
