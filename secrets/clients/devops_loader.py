# secrets/clients/devops_loader.py

import os
import json
import logging
from typing import Dict, Optional

from secrets.core.vault_connector import VaultConnector
from secrets.utils.signature_verifier import verify_signature
from secrets.utils.rbac_guard import enforce_rbac
from secrets.utils.audit_logger import log_secret_access

logger = logging.getLogger("DevOpsLoader")
logger.setLevel(logging.INFO)

class DevOpsSecretsLoader:
    def __init__(self, environment: str, role: str, vault_path: Optional[str] = None):
        self.environment = environment
        self.role = role
        self.vault_path = vault_path or f"secrets/{environment}/devops"
        self.vault = VaultConnector()
        self.context = {"env": environment, "role": role}

    def load(self) -> Dict[str, str]:
        """
        Загружает секреты DevOps-инфраструктуры с верификацией RBAC и подписи.
        """
        logger.info(f"[{self.environment}] Инициализация загрузки секретов DevOps для роли '{self.role}'")

        secrets_bundle = self.vault.read(path=self.vault_path)
        if not secrets_bundle:
            raise RuntimeError(f"Секреты не найдены по пути: {self.vault_path}")

        if not verify_signature(secrets_bundle):
            raise PermissionError("Подпись секретов недействительна или отсутствует")

        if not enforce_rbac(role=self.role, path=self.vault_path):
            raise PermissionError(f"Роль '{self.role}' не имеет доступа к {self.vault_path}")

        secrets = secrets_bundle.get("data", {})
        log_secret_access(user=self.role, path=self.vault_path, action="read", context=self.context)

        logger.info(f"[{self.environment}] Загрузка завершена. Ключей: {len(secrets)}")
        return secrets

    def get_secret(self, key: str) -> Optional[str]:
        """
        Получение одного секрета по ключу.
        """
        all_secrets = self.load()
        return all_secrets.get(key)


# Пример вызова через CI/CD или агентную шину:
# loader = DevOpsSecretsLoader(environment="production", role="ci-pipeline")
# docker_token = loader.get_secret("docker_registry_token")
