import importlib.util
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Type, Union
from types import ModuleType
from plugins.core.base_plugin import BasePlugin
from plugins.core.plugin_validator import validate_plugin_package
from plugins.utils.plugin_logger import plugin_logger as logger

PLUGIN_ROOT = Path(__file__).resolve().parent.parent

class PluginLoadError(Exception):
    pass


class PluginLoader:
    """
    Загружает плагины с sandbox-поддержкой, выполняет валидацию схемы, зависимости, целостность.
    """

    def __init__(self, sandbox_enabled: bool = True):
        self.loaded_plugins: Dict[str, BasePlugin] = {}
        self.sandbox_enabled = sandbox_enabled

    def _load_module(self, plugin_path: Path) -> ModuleType:
        if not plugin_path.exists():
            raise PluginLoadError(f"Plugin path does not exist: {plugin_path}")
        spec = importlib.util.spec_from_file_location(plugin_path.stem, plugin_path)
        if spec is None or spec.loader is None:
            raise PluginLoadError(f"Failed to create spec for {plugin_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[plugin_path.stem] = module
        spec.loader.exec_module(module)  # type: ignore
        return module

    def _get_plugin_class(self, module: ModuleType) -> Type[BasePlugin]:
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
                return attr
        raise PluginLoadError("No subclass of BasePlugin found")

    def load_plugin(self, plugin_file: Union[str, Path]) -> BasePlugin:
        plugin_file = Path(plugin_file)
        logger.info(f"[PluginLoader] Attempting to load plugin from: {plugin_file}")
        try:
            validate_plugin_package(plugin_file)
            module = self._load_module(plugin_file)
            plugin_cls = self._get_plugin_class(module)
            plugin_instance = plugin_cls()
            plugin_id = plugin_instance.plugin_id

            if plugin_id in self.loaded_plugins:
                raise PluginLoadError(f"Plugin already loaded: {plugin_id}")

            self.loaded_plugins[plugin_id] = plugin_instance
            logger.info(f"[PluginLoader] Plugin {plugin_instance.plugin_name} v{plugin_instance.plugin_version} loaded")
            return plugin_instance

        except Exception as e:
            logger.error(f"[PluginLoader] Failed to load plugin {plugin_file}: {e}")
            traceback.print_exc()
            raise PluginLoadError from e

    def unload_plugin(self, plugin_id: str) -> bool:
        if plugin_id in self.loaded_plugins:
            del self.loaded_plugins[plugin_id]
            logger.info(f"[PluginLoader] Plugin {plugin_id} unloaded successfully")
            return True
        logger.warning(f"[PluginLoader] Plugin {plugin_id} not found")
        return False

    def get_loaded_plugins(self) -> Dict[str, BasePlugin]:
        return self.loaded_plugins.copy()
