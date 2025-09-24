# path: backend/scripts/deploy_pipeline.py

import os
import sys
import json
import logging
import subprocess
from pathlib import Path
from datetime import datetime

from utils.rbac_guard import validate_deployment_rights
from utils.signature_check import verify_code_signature
from utils.alerting import notify_guard
from utils.env_loader import load_env

# === Настройки логирования ===
logging.basicConfig(
    filename='/var/log/teslaai/deploy_pipeline.log',
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s'
)

# === Основные переменные ===
DEPLOY_ENV = os.getenv('DEPLOY_ENV', 'staging')
ROOT_DIR = Path(__file__).resolve().parents[2]
PIPELINE_DEF_PATH = ROOT_DIR / 'infrastructure' / 'ci' / 'pipeline.yml'

def log_and_abort(message: str):
    logging.error(message)
    notify_guard(event_type="deploy_error", message=message, critical=True)
    sys.exit(1)

def check_permissions():
    user = os.getenv("DEPLOY_USER", "unknown")
    if not validate_deployment_rights(user):
        log_and_abort(f"Unauthorized deploy attempt by: {user}")
    logging.info(f"RBAC check passed for: {user}")

def verify_integrity():
    if not verify_code_signature(ROOT_DIR):
        log_and_abort("Signature verification failed")
    logging.info("Code signature verified successfully")

def run_pipeline():
    if not PIPELINE_DEF_PATH.exists():
        log_and_abort(f"Pipeline definition missing: {PIPELINE_DEF_PATH}")
    logging.info("Pipeline definition located")

    try:
        result = subprocess.run(
            ["bash", "launch/deploy.sh", DEPLOY_ENV],
            cwd=str(ROOT_DIR),
            check=True,
            capture_output=True,
            text=True
        )
        logging.info(f"Pipeline executed successfully:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        log_and_abort(f"Pipeline execution failed:\n{e.stderr}")

def main():
    logging.info(f"Starting deploy pipeline to: {DEPLOY_ENV}")
    load_env()
    check_permissions()
    verify_integrity()
    run_pipeline()
    logging.info("Deployment pipeline completed")

if __name__ == "__main__":
    main()
