# keyvault/access/access_validator.py

import logging
import datetime
from typing import Dict, Optional

from keyvault.config.vault_config_loader import load_policy_matrix
from keyvault.core.crypto_engine import verify_signature
from keyvault.core.secret_manager import get_secret_metadata
from keyvault.rbac.rbac_evaluator import check_role_permission
from keyvault.utils.context_utils import get_current_context_hash, is_zone_allowed
from keyvault.utils.device_fingerprint import validate_device_fingerprint
from keyvault.utils.time_constraints import validate_access_window
from keyvault.zk.zk_proof_verifier import verify_zero_knowledge_proof
from keyvault.audit.access_logger import log_access_attempt

logger = logging.getLogger("access_validator")
logger.setLevel(logging.INFO)


class AccessDenied(Exception):
    pass


class AccessValidator:
    def __init__(self):
        self.policy_matrix = load_policy_matrix()

    def validate_access(self,
                        actor_id: str,
                        resource_id: str,
                        action: str,
                        metadata: Optional[Dict] = None) -> bool:
        """
        Основной метод проверки доступа к секрету
        """
        try:
            logger.debug(f"Валидация доступа: actor={actor_id}, resource={resource_id}, action={action}")

            # === 1. Загрузка метаданных ресурса ===
            secret_meta = get_secret_metadata(resource_id)
            if not secret_meta:
                raise AccessDenied("Ресурс не найден или удалён.")

            # === 2. RBAC / ABAC проверка ===
            if not check_role_permission(actor_id, action, secret_meta["classification"], self.policy_matrix):
                raise AccessDenied("Роль не разрешает это действие.")

            # === 3. Контекстная проверка ===
            if not self._validate_context(actor_id, metadata):
                raise AccessDenied("Контекст запроса недопустим.")

            # === 4. Проверка временного окна ===
            if not validate_access_window(actor_id):
                raise AccessDenied("Попытка доступа вне разрешённого времени.")

            # === 5. Проверка зоны доступа ===
            if not is_zone_allowed(actor_id, metadata.get("geo_zone", "")):
                raise AccessDenied("Геозона или зона доверия запрещена.")

            # === 6. Проверка устройства ===
            if not validate_device_fingerprint(actor_id, metadata.get("device_fingerprint", "")):
                raise AccessDenied("Недопустимое или неподтверждённое устройство.")

            # === 7. Проверка подписи запроса ===
            if not verify_signature(metadata.get("signature"), actor_id, metadata.get("timestamp")):
                raise AccessDenied("Подпись запроса недействительна или отсутствует.")

            # === 8. Проверка ZK-доказательства (Zero Knowledge Proof) ===
            if not verify_zero_knowledge_proof(actor_id, resource_id, metadata.get("zk_proof", {})):
                raise AccessDenied("ZK-доказательство не прошло верификацию.")

            log_access_attempt(actor_id, resource_id, action, success=True)
            return True

        except AccessDenied as e:
            logger.warning(f"Доступ отклонён: {e}")
            log_access_attempt(actor_id, resource_id, action, success=False, reason=str(e))
            return False

    def _validate_context(self, actor_id: str, metadata: Optional[Dict]) -> bool:
        """
        Проверка контекста сеанса — IP, fingerprint, версия клиента, session hash
        """
        if not metadata:
            return False
        context_hash = metadata.get("context_hash")
        expected_hash = get_current_context_hash(actor_id)
        return context_hash == expected_hash
