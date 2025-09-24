#!/usr/bin/env python3

"""
TeslaAI Genesis — Integrity Verifier
Проверка хэшей, цифровых подписей и отклонений в критически важных компонентах
"""

import hashlib
import json
import os
import subprocess
from pathlib import Path

# Путь до файла со списком контрольных хэшей
MANIFEST_PATH = Path("launch/versioning/version_manifest.yaml")
CRITICAL_PATHS = [
    "volumes/backup/redis.rdb",
    "volumes/backup/postgres_dump.sql",
    "volumes/backup/graph.json",
    "volumes/backup/ai_state_log.json",
    "genius-core/graph-core/snapshot/graph.json",
]

SIGNATURE_FILES = [
    ("launch/approvals/launch_signatures/launch.sig", "launch/approvals/launch_signatures/launch.pub"),
]

def calculate_sha256(filepath: str) -> str:
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def load_manifest_hashes() -> dict:
    import yaml
    with open(MANIFEST_PATH, "r") as f:
        manifest = yaml.safe_load(f)
    return manifest.get("hashes", {})

def verify_hashes():
    expected = load_manifest_hashes()
    print("[*] Проверка SHA256-хэшей:")
    for path in CRITICAL_PATHS:
        if not os.path.exists(path):
            print(f"[!] ❌ Файл отсутствует: {path}")
            continue
        actual_hash = calculate_sha256(path)
        expected_hash = expected.get(path)
        if actual_hash == expected_hash:
            print(f"[+] ✅ OK: {path}")
        else:
            print(f"[!] ⚠️ MISMATCH: {path}")
            print(f"    Ожидалось: {expected_hash}")
            print(f"    Получено : {actual_hash}")

def verify_signatures():
    print("\n[*] Проверка цифровых подписей:")
    for sig_path, pubkey_path in SIGNATURE_FILES:
        if not os.path.exists(sig_path) or not os.path.exists(pubkey_path):
            print(f"[!] ❌ Отсутствует подпись или ключ: {sig_path} / {pubkey_path}")
            continue
        result = subprocess.run(
            ["gpg", "--verify", sig_path, "--keyring", pubkey_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        output = result.stdout.decode()
        if "Good signature" in output:
            print(f"[+] ✅ Подпись верна: {sig_path}")
        else:
            print(f"[!] ⚠️ Ошибка подписи: {sig_path}\n{output}")

if __name__ == "__main__":
    print("=== TeslaAI Integrity Verifier ===")
    verify_hashes()
    verify_signatures()
