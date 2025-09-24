# path: platform-security/code-protection/code_watermarking/fingerprint_inserter.py

import os
import hashlib
import random
import string
import datetime
import argparse

# Конфигурация по умолчанию
SUPPORTED_EXT = [".py", ".js", ".ts", ".go", ".rs"]
MARKER_PREFIX = "# TeslaAI-FP:"
FINGERPRINT_LENGTH = 24

def generate_fingerprint(salt=None):
    salt = salt or os.urandom(32)
    now = datetime.datetime.utcnow().isoformat()
    base = hashlib.sha256(salt + now.encode()).hexdigest()
    return base[:FINGERPRINT_LENGTH]

def insert_fingerprint(file_path, fingerprint):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Пропустить уже помеченные файлы
        if any(MARKER_PREFIX in line for line in lines[:5]):
            return False

        marker = f"{MARKER_PREFIX} {fingerprint} - DO NOT DELETE\n"
        lines.insert(0, marker)

        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        return True
    except Exception:
        return False

def scan_and_insert(base_dir):
    fingerprint = generate_fingerprint()
    inserted = 0
    for root, _, files in os.walk(base_dir):
        for fname in files:
            ext = os.path.splitext(fname)[1]
            if ext.lower() in SUPPORTED_EXT:
                fpath = os.path.join(root, fname)
                if insert_fingerprint(fpath, fingerprint):
                    inserted += 1
    return inserted

def main():
    parser = argparse.ArgumentParser(description="Insert TeslaAI fingerprint into source files")
    parser.add_argument("--path", type=str, required=True, help="Base path to scan")
    args = parser.parse_args()

    total = scan_and_insert(args.path)
    print(f"[+] Fingerprint inserted into {total} files.")

if __name__ == "__main__":
    main()
