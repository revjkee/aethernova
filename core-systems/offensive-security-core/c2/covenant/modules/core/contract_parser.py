# Парсер условий и ограничений
# contract_parser.py
# Парсер условий и ограничений для Covenant Engine

import json
import hashlib
import base64
from typing import Dict, Any
import logging

logger = logging.getLogger("contract_parser")
logger.setLevel(logging.INFO)


class ContractParser:
    def __init__(self):
        self.required_fields = {"payload", "signature", "signer"}

    def parse(self, raw_contract: str) -> Dict[str, Any]:
        """
        Парсит входящий контракт и проверяет наличие обязательных полей.
        Возвращает словарь: {payload, signature, signer, policy}
        """
        logger.debug("Начало парсинга контракта")

        try:
            decoded_data = self._decode_base64(raw_contract)
            contract_dict = json.loads(decoded_data)

            if not self.required_fields.issubset(set(contract_dict.keys())):
                missing = self.required_fields - set(contract_dict.keys())
                raise ValueError(f"Отсутствуют обязательные поля: {', '.join(missing)}")

            payload_data = self._validate_and_load_payload(contract_dict["payload"])
            contract_hash = self._compute_hash(contract_dict["payload"])

            logger.debug("Контракт успешно разобран и валиден")

            return {
                "payload": contract_dict["payload"],
                "signature": contract_dict["signature"],
                "signer": contract_dict["signer"],
                "policy": payload_data,
                "hash": contract_hash
            }

        except Exception as e:
            logger.exception("Ошибка парсинга контракта")
            raise ValueError(f"Ошибка парсинга контракта: {str(e)}")

    def _decode_base64(self, raw_data: str) -> str:
        """
        Декодирует строку base64 → str
        """
        try:
            return base64.b64decode(raw_data.encode()).decode()
        except Exception:
            raise ValueError("Некорректный base64-формат контракта")

    def _validate_and_load_payload(self, payload_str: str) -> Dict[str, Any]:
        """
        Загружает и валидирует JSON-политику из полезной нагрузки
        """
        try:
            data = json.loads(payload_str)
            if "action" not in data or "parameters" not in data:
                raise ValueError("Политика должна содержать поля: action, parameters")
            if not isinstance(data["parameters"], dict):
                raise ValueError("Поле parameters должно быть объектом")
            return data
        except json.JSONDecodeError:
            raise ValueError("Невалидный JSON в payload")

    def _compute_hash(self, payload_str: str) -> str:
        """
        Вычисляет SHA256 хеш от payload
        """
        return hashlib.sha256(payload_str.encode()).hexdigest()
