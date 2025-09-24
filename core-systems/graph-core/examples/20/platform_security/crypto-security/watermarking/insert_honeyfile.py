# path: platform-security/code-protection/code_watermarking/insert_honeyfile.py

import os
import random
import string
import logging
import hashlib
import datetime

# Настройка логирования
log_path = "/var/log/teslaai_honeyfile_events.log"
logging.basicConfig(filename=log_path, level=logging.INFO, format="%(asctime)s %(message)s")

HONEYFILES_DIR = ".honeypots/"
TRIGGER_CONTENT = "# DO NOT DELETE - TeslaAI Internal Marker\n"
NUM_HONEYFILES = 5
FAKE_EXTENSIONS = [".py", ".md", ".txt", ".conf", ".sql"]

def generate_random_name(length=12):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_fake_file_content():
    fake_flag = hashlib.sha256(os.urandom(64)).hexdigest()[:24]
    content = f"{TRIGGER_CONTENT}\n# TeslaAI Honeyfile ID: {fake_flag}\n# Internal configuration file.\n"
    return content, fake_flag

def create_honeyfiles(base_path="."):
    os.makedirs(os.path.join(base_path, HONEYFILES_DIR), exist_ok=True)
    for _ in range(NUM_HONEYFILES):
        name = generate_random_name() + random.choice(FAKE_EXTENSIONS)
        content, flag = generate_fake_file_content()
        full_path = os.path.join(base_path, HONEYFILES_DIR, name)
        with open(full_path, "w") as f:
            f.write(content)
        os.chmod(full_path, 0o444)
        logging.info(f"Generated honeyfile {full_path} with flag {flag}")

def main():
    print("Injecting TeslaAI honeyfiles...")
    create_honeyfiles()
    print("Done. Honeyfiles placed.")

if __name__ == "__main__":
    main()
