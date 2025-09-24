# zk-core/zk/zk_intent_verifier.py

import hashlib
import logging
from typing import Dict, Any, Optional

from zk.zk_utils import normalize_payload, hash_action_payload
from zk.zk_params.global_config import get_active_proof_scheme
from zk.zk_proof_verifier import ZKProofVerifier
from zk.zk_registry import IntentPolicyRegistry

logger = logging.getLogger("zk_intent_verifier")
logger.setLevel(logging.INFO)


class ZKIntentVerifier:
    def __init__(self):
        self.verifier = ZKProofVerifier()
        self.intent_registry = IntentPolicyRegistry()
        self.active_scheme = get_active_proof_scheme()

    def verify(self, user_id: str, action: str, zk_proof: Dict[str, Any], payload: Optional[Dict[str, Any]] = None) -> bool:
        """
        Основная функция верификации намерения действия AI/пользователя.
        """

        if not self.intent_registry.is_intent_allowed(user_id, action):
            logger.warning(f"Intent not allowed: user={user_id}, action={action}")
            return False

        # Хешируем намерение действия
        payload_hash = self._compute_intent_hash(user_id, action, payload)

        # Проверка по выбранной схеме ZK
        result = self.verifier.verify(
            proof=zk_proof,
            expected_hash=payload_hash,
            scheme=self.active_scheme
        )

        if not result:
            logger.error(f"ZK intent proof rejected: user={user_id}, action={action}")
        else:
            logger.info(f"ZK intent approved: user={user_id}, action={action}")
        return result

    def _compute_intent_hash(self, user_id: str, action: str, payload: Optional[Dict[str, Any]] = None) -> str:
        """
        Генерация нормализованного хэша намерения (для AI/человека).
        """
        payload = payload or {}
        norm_payload = normalize_payload(payload)
        data = f"{user_id}::{action}::{norm_payload}"
        return hashlib.sha256(data.encode()).hexdigest()

# Singleton instance
zk_intent_verifier = ZKIntentVerifier()


def verify_intent_proof(user_id: str, action: str, zk_proof: Dict[str, Any], payload: Optional[Dict[str, Any]] = None) -> bool:
    """
    Унифицированный вызов, совместимый с policy_enforcer.
    """
    return zk_intent_verifier.verify(user_id=user_id, action=action, zk_proof=zk_proof, payload=payload)

