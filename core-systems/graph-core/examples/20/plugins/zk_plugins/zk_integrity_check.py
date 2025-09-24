import json
import hashlib
import logging
from typing import Dict, Any

from py_ecc.bls import G2ProofOfPossession as bls
from plugins.core.plugin_exceptions import PluginValidationError

logger = logging.getLogger("zk_integrity")


class ZKIntegrityVerifier:
    """
    ZKIntegrityVerifier реализует проверку целостности плагина
    с использованием схемы Zero-Knowledge подписи и hash-chain валидации.
    """

    def __init__(self, public_key: bytes, zk_registry: Dict[str, Any]):
        """
        :param public_key: общедоступный ключ валидатора (BLS-схема)
        :param zk_registry: словарь {plugin_id: {"hash": str, "signature": bytes}}
        """
        self.public_key = public_key
        self.zk_registry = zk_registry

    @staticmethod
    def compute_hash(plugin_bytes: bytes) -> str:
        """
        Возвращает SHA-256 hash содержимого плагина.
        """
        return hashlib.sha256(plugin_bytes).hexdigest()

    def verify_plugin(self, plugin_id: str, plugin_bytes: bytes) -> bool:
        """
        Проверяет подпись и целостность плагина по zk_registry.
        """
        if plugin_id not in self.zk_registry:
            raise PluginValidationError(plugin_id, "отсутствует в zk-реестре")

        expected_hash = self.zk_registry[plugin_id]["hash"]
        expected_signature = self.zk_registry[plugin_id]["signature"]

        actual_hash = self.compute_hash(plugin_bytes)
        if actual_hash != expected_hash:
            raise PluginValidationError(plugin_id, "не совпадает хеш содержимого")

        if not bls.Verify(self.public_key, actual_hash.encode(), expected_signature):
            raise PluginValidationError(plugin_id, "невалидная подпись")

        logger.info(f"[ZKIntegrity] Плагин '{plugin_id}' прошёл ZK-проверку")
        return True

    def load_registry(self, path: str):
        """
        Загружает zk-реестр из JSON-файла.
        """
        with open(path, "r") as f:
            self.zk_registry = json.load(f)
        logger.info(f"[ZKIntegrity] zk_registry обновлён из {path}")
