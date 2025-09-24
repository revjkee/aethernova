#!/usr/bin/env python3

import os
import json
import subprocess
import hashlib
import logging
import socket
import importlib.util

HEALTH_DUMP = "launch/diagnostics/error_dump.log"
STATE_LOG = "launch/self_state/ai_state_log.json"
REQUIRED_PORTS = [5000, 6379, 5432, 5672]
REQUIRED_MODULES = ["torch", "transformers", "uvicorn", "alembic"]
CRITICAL_COMPONENTS = {
    "ai_platform_core.py": "2a1d340f3ef274e9a4d5eaa99716d192",
    "ai_defense_core.py": "b8822dd00ef10cd73b21a8f7c3e5d3be",
    "signature_verifier.py": "2756ec991be927b6f4fcac497cd9005a"
}

logging.basicConfig(filename=HEALTH_DUMP, level=logging.INFO)

def check_ports():
    for port in REQUIRED_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.settimeout(2)
                s.connect(("127.0.0.1", port))
                logging.info(f"[PORT] OK: {port}")
            except:
                logging.error(f"[PORT] ERROR: Port {port} is not listening")

def check_modules():
    for module in REQUIRED_MODULES:
        if importlib.util.find_spec(module) is None:
            logging.error(f"[MODULE] Missing: {module}")
        else:
            logging.info(f"[MODULE] Present: {module}")

def check_hashes():
    for file, expected_hash in CRITICAL_COMPONENTS.items():
        if not os.path.exists(file):
            logging.error(f"[HASH] File missing: {file}")
            continue
        with open(file, "rb") as f:
            file_hash = hashlib.md5(f.read()).hexdigest()
        if file_hash != expected_hash:
            logging.critical(f"[HASH] Tampered: {file} (Expected {expected_hash}, got {file_hash})")
        else:
            logging.info(f"[HASH] OK: {file}")

def check_ethics_lock():
    lock_flag = "launch/launch_flags/ethics_lock.flag"
    if not os.path.exists(lock_flag):
        logging.warning("[ETHICS] Ethics lock not confirmed (flag missing)")
        return False
    return True

def check_versions():
    try:
        result = subprocess.run(["python3", "--version"], capture_output=True, text=True)
        logging.info(f"[PYTHON] {result.stdout.strip()}")
    except:
        logging.error("[PYTHON] Failed to get Python version")

def dump_state_summary():
    state = {
        "ports_checked": REQUIRED_PORTS,
        "modules_required": REQUIRED_MODULES,
        "ethics_lock": os.path.exists("launch/launch_flags/ethics_lock.flag"),
        "components_verified": list(CRITICAL_COMPONENTS.keys())
    }
    os.makedirs(os.path.dirname(STATE_LOG), exist_ok=True)
    with open(STATE_LOG, "w") as f:
        json.dump(state, f, indent=2)

def run_healthcheck():
    logging.info("=== AI SYSTEM HEALTH CHECK INITIATED ===")
    check_ports()
    check_modules()
    check_hashes()
    check_ethics_lock()
    check_versions()
    dump_state_summary()
    logging.info("=== HEALTH CHECK COMPLETE ===")

if __name__ == "__main__":
    run_healthcheck()
