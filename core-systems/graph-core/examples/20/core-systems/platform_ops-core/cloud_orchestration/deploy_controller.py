# path: backend/cloud-orchestration/deploy_controller.py

import os
import subprocess
import logging
import time
import json
from datetime import datetime
from security.gpg import verify_signature
from security.rbac import enforce_policy
from utils.alerting import notify_guard

# === Конфигурация ===
DEPLOYMENTS_PATH = "/opt/teslaai/deployments/"
LOG_FILE = "/var/log/teslaai/deploy_controller.log"
ALLOWED_ENVIRONMENTS = {"staging", "prod"}
KUBECTL_PATH = "/usr/local/bin/kubectl"
MANIFESTS_DIR = "/etc/teslaai/manifests/"

# === Логирование ===
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s'
)

def apply_k8s_manifest(manifest_file: str, environment: str):
    try:
        full_path = os.path.join(MANIFESTS_DIR, environment, manifest_file)

        # Проверка GPG-подписи
        if not verify_signature(full_path):
            raise PermissionError(f"GPG signature invalid: {full_path}")

        # Применение Kubernetes-манифеста
        result = subprocess.run([KUBECTL_PATH, "apply", "-f", full_path], capture_output=True, text=True)

        if result.returncode != 0:
            logging.error(f"[DEPLOY] ERROR applying {manifest_file}: {result.stderr}")
            notify_guard("deploy_failure", f"Failed to apply {manifest_file}", critical=True)
            return False

        logging.info(f"[DEPLOY] SUCCESS: {manifest_file} applied to {environment}")
        return True

    except Exception as e:
        logging.error(f"[DEPLOY] EXCEPTION: {e}")
        notify_guard("deploy_exception", str(e), critical=True)
        return False

def deploy_package(package_name: str, environment: str, user: str):
    try:
        if environment not in ALLOWED_ENVIRONMENTS:
            raise ValueError(f"Invalid environment: {environment}")

        if not enforce_policy(user, action="deploy", resource=package_name, env=environment):
            raise PermissionError(f"RBAC denied for user {user} to deploy {package_name}")

        deployment_dir = os.path.join(DEPLOYMENTS_PATH, environment, package_name)
        manifests = sorted(f for f in os.listdir(os.path.join(MANIFESTS_DIR, environment)) if f.endswith(".yaml"))

        logging.info(f"[DEPLOY] START | user={user} pkg={package_name} env={environment} files={manifests}")

        results = []
        for m in manifests:
            status = apply_k8s_manifest(m, environment)
            results.append((m, status))

        if all(r[1] for r in results):
            logging.info(f"[DEPLOY] COMPLETE | package={package_name} env={environment}")
            return True
        else:
            raise RuntimeError("Some manifests failed to apply")

    except Exception as ex:
        logging.error(f"[DEPLOY] FAILED | {ex}")
        notify_guard("deploy_error", str(ex), critical=True)
        return False

# === Основной интерфейс ===
if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser(description="TeslaAI Genesis: Secure Deployment Controller")
    parser.add_argument("--package", required=True, help="Name of package to deploy")
    parser.add_argument("--env", required=True, choices=ALLOWED_ENVIRONMENTS, help="Target environment")
    parser.add_argument("--user", required=True, help="Authenticated user triggering deploy")

    args = parser.parse_args()
    success = deploy_package(args.package, args.env, args.user)
    exit(0 if success else 1)
