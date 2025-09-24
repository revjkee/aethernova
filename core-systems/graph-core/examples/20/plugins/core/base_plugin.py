import abc
import json
import inspect
import hashlib
from typing import Dict, Any, Optional, Union
from uuid import uuid4
from datetime import datetime
from plugins.utils.plugin_logger import plugin_logger as logger
from plugins.utils.plugin_signature import verify_signature, extract_signature_meta


class BasePlugin(abc.ABC):
    """
    Абстрактный базовый класс для всех плагинов TeslaAI.
    Поддерживает автоматическую мета-информацию, проверку подписи, аудит и runtime-валидацию.
    """

    plugin_id: str
    plugin_name: str
    plugin_version: str
    plugin_author: str
    plugin_description: str
    plugin_dependencies: Dict[str, str] = {}

    def __init__(self):
        self.plugin_id = f"{self.plugin_name}-{self.plugin_version}-{uuid4()}"
        self.init_timestamp = datetime.utcnow().isoformat()
        self._validate_metadata()
        logger.debug(f"[PluginInit] {self.plugin_name} initialized with ID {self.plugin_id}")

    def _validate_metadata(self):
        required_fields = [
            "plugin_name", "plugin_version", "plugin_author", "plugin_description"
        ]
        for field in required_fields:
            value = getattr(self, field, None)
            if not value:
                raise ValueError(f"Plugin metadata missing: {field}")
        if not isinstance(self.plugin_dependencies, dict):
            raise TypeError("plugin_dependencies must be a dict")
        logger.debug(f"[PluginMeta] Metadata validated for {self.plugin_name}")

    def get_info(self) -> Dict[str, Union[str, Dict[str, str]]]:
        return {
            "id": self.plugin_id,
            "name": self.plugin_name,
            "version": self.plugin_version,
            "author": self.plugin_author,
            "description": self.plugin_description,
            "dependencies": self.plugin_dependencies,
            "init_time": self.init_timestamp,
        }

    def verify_integrity(self) -> bool:
        """
        Проверка целостности кода плагина через подпись и checksum.
        """
        try:
            source = inspect.getsource(self.__class__)
            checksum = hashlib.sha256(source.encode()).hexdigest()
            sig_meta = extract_signature_meta(source)
            if not sig_meta:
                logger.warning(f"[PluginIntegrity] No signature found for {self.plugin_name}")
                return False
            valid = verify_signature(checksum, sig_meta["signature"], sig_meta["pubkey"])
            logger.debug(f"[PluginIntegrity] Verification result: {valid}")
            return valid
        except Exception as e:
            logger.error(f"[PluginIntegrity] Error verifying integrity: {e}")
            return False

    @abc.abstractmethod
    def run(self, input_data: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Абстрактный метод исполнения. Каждый плагин обязан реализовать его.
        """
        raise NotImplementedError("run() must be implemented by the plugin")
