# Главный исполнитель модулей политики
# covenant_engine.py
# Главный исполнитель модулей политики TeslaAI Genesis 2.0

from typing import Dict, Any
from .contract_parser import ContractParser
from .policy_executor import PolicyExecutor
from .signature_verifier import SignatureVerifier
from ..rbac.enforcer import RBACEnforcer
from ..utils.cryptography import decrypt_payload
from ..utils.validation import validate_policy_schema
import logging

logger = logging.getLogger("covenant_engine")
logger.setLevel(logging.INFO)

class CovenantEngine:
    def __init__(self, rbac_config: Dict[str, Any], public_keys: Dict[str, str]):
        self.contract_parser = ContractParser()
        self.policy_executor = PolicyExecutor()
        self.signature_verifier = SignatureVerifier(public_keys)
        self.rbac_enforcer = RBACEnforcer(rbac_config)

    def execute_contract(self, raw_contract: str, actor_id: str) -> Dict[str, Any]:
        logger.info(f"Запуск контракта от агента {actor_id}")
        try:
            # Расшифровка и парсинг контракта
            contract = decrypt_payload(raw_contract)
            parsed = self.contract_parser.parse(contract)

            logger.debug("Контракт успешно разобран")

            # Проверка подписи
            if not self.signature_verifier.verify(parsed["signature"], parsed["payload"], parsed["signer"]):
                logger.warning("Неверная цифровая подпись")
                return {"status": "failed", "reason": "invalid_signature"}

            # Проверка схемы
            if not validate_policy_schema(parsed["policy"]):
                logger.warning("Невалидная структура политики")
                return {"status": "failed", "reason": "invalid_policy_schema"}

            # RBAC-проверка
            if not self.rbac_enforcer.check_permission(actor_id, parsed["policy"]["action"]):
                logger.warning("Доступ запрещен согласно RBAC")
                return {"status": "denied", "reason": "unauthorized"}

            # Исполнение политики
            result = self.policy_executor.execute(parsed["policy"])
            logger.info(f"Политика успешно выполнена: {parsed['policy']['action']}")

            return {"status": "success", "result": result}

        except Exception as e:
            logger.exception("Ошибка при выполнении контракта")
            return {"status": "error", "reason": str(e)}
