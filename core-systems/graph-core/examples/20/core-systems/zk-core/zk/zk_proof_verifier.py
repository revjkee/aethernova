# intel-core/zk/zk_proof_verifier.py

from typing import Dict, Any, Optional
import hashlib
import json
import logging

from intel_core.zk.schemas import ZKProofSchema
from intel_core.zk.utils import decode_hex_to_bytes, snark_verify, stark_verify

logger = logging.getLogger("zk_verifier")
logger.setLevel(logging.INFO)


class ZKProofVerifier:
    """
    Универсальный модуль верификации Zero-Knowledge доказательств.
    Поддерживает zk-SNARK и zk-STARK схемы.
    """

    def __init__(self, trusted_setup_params: Optional[Dict[str, Any]] = None):
        """
        Инициализация верификатора.
        :param trusted_setup_params: параметры доверенной установки (только для SNARK).
        """
        self.trusted_setup = trusted_setup_params or {}

    def verify(self, proof_data: Dict[str, Any]) -> bool:
        """
        Основной метод верификации.
        :param proof_data: словарь с полями схемы ZKProofSchema
        :return: True если доказательство корректно, иначе False
        """
        try:
            validated = ZKProofSchema(**proof_data)
            scheme = validated.scheme.lower()

            if scheme == "snark":
                return self._verify_snark(validated)
            elif scheme == "stark":
                return self._verify_stark(validated)
            else:
                logger.error(f"Неподдерживаемая схема доказательства: {scheme}")
                return False
        except Exception as e:
            logger.exception(f"Ошибка при верификации доказательства: {e}")
            return False

    def _verify_snark(self, proof: ZKProofSchema) -> bool:
        """
        Верификация zk-SNARK доказательства.
        :param proof: объект схемы ZKProofSchema
        :return: результат проверки
        """
        try:
            return snark_verify(
                vk=decode_hex_to_bytes(proof.verification_key),
                proof=decode_hex_to_bytes(proof.proof),
                public_inputs=proof.public_inputs,
                trusted_setup=self.trusted_setup,
            )
        except Exception as e:
            logger.exception(f"Ошибка верификации SNARK: {e}")
            return False

    def _verify_stark(self, proof: ZKProofSchema) -> bool:
        """
        Верификация zk-STARK доказательства.
        :param proof: объект схемы ZKProofSchema
        :return: результат проверки
        """
        try:
            return stark_verify(
                proof_data=decode_hex_to_bytes(proof.proof),
                public_inputs=proof.public_inputs
            )
        except Exception as e:
            logger.exception(f"Ошибка верификации STARK: {e}")
            return False

    @staticmethod
    def hash_inputs(inputs: Dict[str, Any]) -> str:
        """
        Генерация хэша публичных входов (например, для смарт-контрактов).
        :param inputs: словарь публичных входов
        :return: хэш строка
        """
        json_str = json.dumps(inputs, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()
