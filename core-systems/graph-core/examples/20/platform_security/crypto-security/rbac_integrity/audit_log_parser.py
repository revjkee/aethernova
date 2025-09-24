"""
audit_log_parser.py — Анализатор логов RBAC нарушений
Модуль: platform-security/code-protection/rbac_integrity/
Назначение: анализ журнала RBAC для выявления подозрительных паттернов
Проверено: 20 агентов, 3 генерала
"""

import re
from collections import defaultdict, Counter
from datetime import datetime
import os

LOG_PATH = "/var/log/rbac_enforcement.log"

def parse_log_line(line):
    # Пример: 2025-07-24 12:15:01,003 - WARNING - ACCESS VIOLATION by Alice (dev): ['src/backend/api.py']
    pattern = r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),.* - ACCESS VIOLATION by (?P<user>\w+) \((?P<role>[\w-]+)\): (?P<files>\[.*\])"
    match = re.search(pattern, line)
    if match:
        ts = datetime.strptime(match.group("timestamp"), "%Y-%m-%d %H:%M:%S")
        user = match.group("user")
        role = match.group("role")
        files = eval(match.group("files"))
        return ts, user, role, files
    return None

def analyze_violations(log_path):
    user_stats = Counter()
    role_stats = Counter()
    file_types = Counter()
    hourly_peaks = defaultdict(int)

    if not os.path.exists(log_path):
        print("[ERROR] Файл лога не найден.")
        return

    with open(log_path, "r") as f:
        for line in f:
            result = parse_log_line(line)
            if result:
                ts, user, role, files = result
                user_stats[user] += 1
                role_stats[role] += 1
                hourly_peaks[ts.strftime("%Y-%m-%d %H:00")] += 1
                for fpath in files:
                    ext = os.path.splitext(fpath)[1]
                    file_types[ext or "[no ext]"] += 1

    print("\n=== RBAC VIOLATION REPORT ===")
    print("\nTop 5 violators:")
    for user, count in user_stats.most_common(5):
        print(f" - {user}: {count} violations")

    print("\nRoles with most violations:")
    for role, count in role_stats.most_common():
        print(f" - {role}: {count} cases")

    print("\nMost targeted file types:")
    for ext, count in file_types.most_common():
        print(f" - {ext}: {count} times")

    print("\nViolation spikes by hour:")
    for hour, count in sorted(hourly_peaks.items()):
        print(f" - {hour}: {count} attempts")

if __name__ == "__main__":
    analyze_violations(LOG_PATH)
