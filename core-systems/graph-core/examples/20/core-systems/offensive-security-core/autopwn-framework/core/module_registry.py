# autopwn-framework/core/module_registry.py

import importlib
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class ModuleRegistry:
    def __init__(self):
        self._modules: Dict[str, Any] = {}

    def register_module(self, name: str, module: Any):
        if name in self._modules:
            logger.warning(f"Module '{name}' is already registered, overwriting.")
        self._modules[name] = module
        logger.info(f"Module '{name}' registered.")

    def unregister_module(self, name: str):
        if name in self._modules:
            del self._modules[name]
            logger.info(f"Module '{name}' unregistered.")
        else:
            logger.warning(f"Attempt to unregister non-existing module '{name}'.")

    def get_module(self, name: str) -> Optional[Any]:
        return self._modules.get(name)

    def load_module(self, module_path: str, module_name: str) -> Any:
        """
        Dynamically import a module by path and register it.
        module_path: Python import path e.g. 'plugins.exploit_scanner'
        module_name: unique identifier for the module in registry
        """
        try:
            module = importlib.import_module(module_path)
            self.register_module(module_name, module)
            logger.info(f"Module '{module_name}' loaded from '{module_path}'.")
            return module
        except ImportError as e:
            logger.error(f"Failed to import module '{module_path}': {e}")
            raise

    def list_modules(self):
        return list(self._modules.keys())

