"""
enforce_rbac.py — RBAC валидатор доступа к коду
Модуль: platform-security/code-protection/rbac_integrity/
Назначение: проверка соблюдения access_matrix.yaml при коммитах/CI
Проверено: 20 агентов, 3 генерала
"""

import yaml
import os
import subprocess
import sys
import re
import logging

MATRIX_PATH = "platform-security/code-protection/rbac_integrity/access_matrix.yaml"
LOG_FILE = "/var/log/rbac_enforcement.log"

# === Логирование ===
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def load_access_matrix():
    with open(MATRIX_PATH, "r") as f:
        return yaml.safe_load(f)

def get_git_user():
    return os.environ.get("GIT_AUTHOR_NAME") or subprocess.getoutput("git config user.name")

def get_changed_files():
    diff_cmd = ["git", "diff", "--cached", "--name-only"]
    return subprocess.check_output(diff_cmd).decode().splitlines()

def check_permissions(role_id, matrix, changed_files):
    allowed = set()
    denied = []
    for res in matrix.get("resources", []):
        if role_id in res.get("access", []):
            allowed.add(res["id"].rstrip("/") + "/")

    for file_path in changed_files:
        if not any(file_path.startswith(a) for a in allowed):
            denied.append(file_path)
    return denied

def enforce():
    matrix = load_access_matrix()
    user = get_git_user()

    # Определяем роль (в промышленной системе: из CI или SSO)
    role = os.environ.get("GIT_USER_ROLE")
    if not role:
        print("[ERROR] Не задана роль пользователя (GIT_USER_ROLE)")
        sys.exit(1)

    changed = get_changed_files()
    denied = check_permissions(role, matrix, changed)

    if denied:
        logging.warning(f"ACCESS VIOLATION by {user} ({role}): {denied}")
        print(f"[BLOCKED] Нарушение RBAC. Файлы вне допустимых директорий для роли {role}:")
        for f in denied:
            print(" -", f)
        sys.exit(2)

    logging.info(f"RBAC PASS: {user} ({role}) — {len(changed)} file(s) validated")
    print(f"[OK] Проверка RBAC пройдена: {user} ({role})")

if __name__ == "__main__":
    enforce()
