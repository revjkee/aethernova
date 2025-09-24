# path: platform-security/code-protection/code_watermarking/watermark_validator.py

import os
import argparse
import re

# Конфигурация
MARKER_PREFIX = "# TeslaAI-FP:"
VALIDATION_DEPTH = 5
ALLOWED_LENGTH = 24
ALLOWED_CHARS = r"[a-f0-9]{24}"
MARKER_REGEX = re.compile(rf"{re.escape(MARKER_PREFIX)}\s({ALLOWED_CHARS})\s-\sDO\sNOT\sDELETE")

def extract_watermark(line):
    match = MARKER_REGEX.search(line)
    return match.group(1) if match else None

def validate_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = [next(f) for _ in range(VALIDATION_DEPTH)]
    except (FileNotFoundError, StopIteration, UnicodeDecodeError):
        return None

    for line in lines:
        fingerprint = extract_watermark(line)
        if fingerprint and len(fingerprint) == ALLOWED_LENGTH:
            return fingerprint
    return None

def scan_directory(base_path):
    validated = {}
    for root, _, files in os.walk(base_path):
        for fname in files:
            if not fname.endswith((".py", ".js", ".ts", ".go", ".rs")):
                continue
            fpath = os.path.join(root, fname)
            result = validate_file(fpath)
            if result:
                validated[fpath] = result
    return validated

def main():
    parser = argparse.ArgumentParser(description="Validate TeslaAI watermarks in source code")
    parser.add_argument("--path", type=str, required=True, help="Path to scan for fingerprint validation")
    args = parser.parse_args()

    results = scan_directory(args.path)
    print(f"[+] Found {len(results)} files with valid fingerprints.\n")
    for path, fp in results.items():
        print(f"✓ {path} → {fp}")

if __name__ == "__main__":
    main()
