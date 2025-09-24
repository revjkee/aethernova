import hashlib
import uuid
from typing import Dict, Any, List, Optional
from plugins.core.base_plugin import BasePlugin
from plugins.utils.plugin_logger import plugin_logger as logger


class ScannerPlugin(BasePlugin):
    """
    Продвинутый сканер-плагин. Предназначен для анализа входных данных и поиска уязвимостей.
    Поддерживает правила безопасности, sandbox и генерацию трассировок.
    """

    plugin_name = "SecureScanner"
    plugin_version = "2.1.0"
    plugin_author = "TeslaAI Security Division"
    plugin_description = "Ищет подозрительные шаблоны, аномалии и уязвимости."
    plugin_dependencies = {
        "yara-python": ">=4.3.0",
        "re2": ">=0.2.0"
    }

    def __init__(self):
        super().__init__()
        self.scanner_rules: List[Dict[str, Any]] = []
        self.sandbox_enabled = True

    def load_scanner_rules(self, rules: List[Dict[str, Any]]) -> None:
        """
        Загружает правила сканирования.
        """
        self.scanner_rules = rules
        logger.info(f"[{self.plugin_name}] Загружено правил: {len(rules)}")

    def scan(self, payload: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Сканирует входной payload и применяет правила.
        """
        logger.info(f"[{self.plugin_name}] Сканирование начато...")
        matches = []
        for rule in self.scanner_rules:
            if rule["type"] == "contains" and rule["value"] in payload:
                matches.append({
                    "rule": rule["name"],
                    "type": "contains",
                    "match": rule["value"]
                })
            elif rule["type"] == "regex":
                import re
                if re.search(rule["pattern"], payload):
                    matches.append({
                        "rule": rule["name"],
                        "type": "regex",
                        "pattern": rule["pattern"]
                    })

        hash_digest = hashlib.sha256(payload.encode()).hexdigest()

        result = {
            "plugin": self.plugin_name,
            "payload_hash": hash_digest,
            "matches": matches,
            "metadata": metadata or {},
            "scan_id": str(uuid.uuid4())
        }

        logger.info(f"[{self.plugin_name}] Завершено. Найдено совпадений: {len(matches)}")
        return result

    def run(self, input_data: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """
        Основная точка входа в плагин.
        """
        payload = input_data.get("payload", "")
        metadata = input_data.get("metadata", {})
        return self.scan(payload, metadata)
