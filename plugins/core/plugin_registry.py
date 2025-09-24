import threading
from typing import Dict, Optional, List
from plugins.core.base_plugin import BasePlugin
from plugins.core.plugin_exceptions import PluginRegistrationError
from plugins.utils.plugin_logger import plugin_logger as logger


class PluginMetadata:
    def __init__(self, plugin: BasePlugin):
        self.plugin_id = plugin.plugin_id
        self.name = plugin.plugin_name
        self.version = plugin.plugin_version
        self.interface = plugin.get_interface()
        self.module = plugin.__class__.__module__
        self.description = getattr(plugin, 'description', '')
        self.active = True

    def as_dict(self):
        return {
            "plugin_id": self.plugin_id,
            "name": self.name,
            "version": self.version,
            "interface": self.interface,
            "module": self.module,
            "description": self.description,
            "active": self.active,
        }


class PluginRegistry:
    """
    Централизованный реестр плагинов. Поддерживает регистрацию, кеширование, версионирование, выгрузку.
    Thread-safe.
    """
    _lock = threading.Lock()
    _instance = None

    def __init__(self):
        self._plugins: Dict[str, BasePlugin] = {}
        self._metadata: Dict[str, PluginMetadata] = {}

    def register_plugin(self, plugin: BasePlugin):
        with self._lock:
            plugin_id = plugin.plugin_id
            if plugin_id in self._plugins:
                raise PluginRegistrationError(f"Plugin with ID {plugin_id} already registered")

            self._plugins[plugin_id] = plugin
            self._metadata[plugin_id] = PluginMetadata(plugin)
            logger.info(f"[PluginRegistry] Registered plugin: {plugin.plugin_name} v{plugin.plugin_version}")

    def unregister_plugin(self, plugin_id: str):
        with self._lock:
            if plugin_id not in self._plugins:
                logger.warning(f"[PluginRegistry] Attempt to unregister non-existent plugin: {plugin_id}")
                return False
            del self._plugins[plugin_id]
            self._metadata[plugin_id].active = False
            logger.info(f"[PluginRegistry] Unregistered plugin: {plugin_id}")
            return True

    def get_plugin(self, plugin_id: str) -> Optional[BasePlugin]:
        return self._plugins.get(plugin_id)

    def get_metadata(self, plugin_id: str) -> Optional[Dict]:
        meta = self._metadata.get(plugin_id)
        return meta.as_dict() if meta else None

    def list_active_plugins(self) -> List[Dict]:
        return [meta.as_dict() for meta in self._metadata.values() if meta.active]

    def list_all_plugins(self) -> List[Dict]:
        return [meta.as_dict() for meta in self._metadata.values()]

    @classmethod
    def instance(cls) -> "PluginRegistry":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
                    logger.info("[PluginRegistry] Singleton instance created")
        return cls._instance
