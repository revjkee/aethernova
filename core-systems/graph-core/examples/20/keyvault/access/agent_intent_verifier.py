# keyvault/access/agent_intent_verifier.py

import logging
from typing import Dict, Any

from keyvault.config.rbac_rules_loader import load_intent_rules
from keyvault.core.intent_analysis import analyze_intent_nlp, detect_anomalous_intent
from keyvault.rbac.rbac_evaluator import check_role_permission
from keyvault.zk.zk_intent_verifier import verify_zk_intent_proof
from keyvault.audit.intent_logger import log_intent_check
from keyvault.utils.context_utils import get_current_context_hash
from keyvault.utils.threat_level import get_agent_risk_score

logger = logging.getLogger("agent_intent_verifier")
logger.setLevel(logging.INFO)


class IntentVerificationError(Exception):
    pass


class AgentIntentVerifier:
    def __init__(self):
        self.intent_matrix = load_intent_rules()

    def verify_intent(self, agent_id: str, requested_action: str, target_resource: str, metadata: Dict[str, Any]) -> bool:
        """
        Основной метод проверки намерения агента.
        """
        try:
            logger.debug(f"Проверка намерения агента {agent_id} → {requested_action} @ {target_resource}")

            # === 1. Проверка RBAC-доступа к действию ===
            if not check_role_permission(agent_id, requested_action, target_resource, self.intent_matrix):
                raise IntentVerificationError("RBAC запретил запрошенное действие.")

            # === 2. Анализ формулировки запроса на уровне намерения (NLP) ===
            intent_text = metadata.get("intent_text", "")
            if not analyze_intent_nlp(intent_text, agent_id):
                raise IntentVerificationError("Формулировка намерения отклонена (NLP анализ).")

            # === 3. Проверка ZK-доказательства (Zero Knowledge Proof of Intent) ===
            if not verify_zk_intent_proof(agent_id, requested_action, metadata.get("zk_proof", {})):
                raise IntentVerificationError("ZK-доказательство намерения не прошло проверку.")

            # === 4. Проверка рисков и аномалий в поведении агента ===
            if detect_anomalous_intent(agent_id, requested_action, metadata):
                raise IntentVerificationError("Намерение считается аномальным (поведенческий анализ).")

            # === 5. Проверка согласованности контекста запроса ===
            expected_context = get_current_context_hash(agent_id)
            if metadata.get("context_hash") != expected_context:
                raise IntentVerificationError("Контекст запроса не соответствует активной сессии.")

            # === 6. Проверка уровня доверия (динамический Zero Trust Trust Score) ===
            risk_score = get_agent_risk_score(agent_id)
            if risk_score >= 0.85:
                raise IntentVerificationError(f"Уровень риска агента критический: {risk_score:.2f}")

            log_intent_check(agent_id, requested_action, target_resource, success=True)
            return True

        except IntentVerificationError as e:
            logger.warning(f"[INTENT BLOCKED] {agent_id} → {requested_action} :: {e}")
            log_intent_check(agent_id, requested_action, target_resource, success=False, reason=str(e))
            return False
