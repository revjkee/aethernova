import importlib
import logging
from typing import Any, Dict, Optional, Callable

logger = logging.getLogger("calibration.adapters")

class AdapterLoadError(Exception):
    pass

class AdapterExecutionError(Exception):
    pass

class BaseAdapter:
    """
    Базовый интерфейс для всех внешних адаптеров.
    """
    def configure(self, config: Dict[str, Any]) -> None:
        raise NotImplementedError

    def execute(self, payload: Dict[str, Any]) -> Any:
        raise NotImplementedError

    def check_status(self) -> Dict[str, Any]:
        raise NotImplementedError


class AdapterManager:
    """
    Управление адаптерами для интеграции с внешними системами: 
    хаос-движки, телеметрия, агенты и CI-платформы.
    """

    def __init__(self):
        self.adapters: Dict[str, BaseAdapter] = {}

    def register_adapter(self, name: str, adapter_instance: BaseAdapter) -> None:
        if name in self.adapters:
            logger.warning(f"Adapter '{name}' already registered. Overwriting.")
        self.adapters[name] = adapter_instance
        logger.info(f"Adapter '{name}' registered.")

    def load_adapter_from_module(self, name: str, module_path: str, class_name: str,
                                 config: Optional[Dict[str, Any]] = None) -> None:
        try:
            module = importlib.import_module(module_path)
            adapter_class = getattr(module, class_name)
            if not issubclass(adapter_class, BaseAdapter):
                raise AdapterLoadError(f"{class_name} is not a valid BaseAdapter subclass")
            adapter = adapter_class()
            if config:
                adapter.configure(config)
            self.adapters[name] = adapter
            logger.info(f"Adapter '{name}' loaded from {module_path}.{class_name}")
        except Exception as e:
            logger.exception(f"Failed to load adapter '{name}': {str(e)}")
            raise AdapterLoadError from e

    def run_adapter(self, name: str, payload: Dict[str, Any]) -> Any:
        adapter = self.adapters.get(name)
        if not adapter:
            raise AdapterExecutionError(f"Adapter '{name}' not found")
        try:
            return adapter.execute(payload)
        except Exception as e:
            logger.exception(f"Execution failed for adapter '{name}': {str(e)}")
            raise AdapterExecutionError from e

    def health_check(self) -> Dict[str, Dict[str, Any]]:
        status = {}
        for name, adapter in self.adapters.items():
            try:
                result = adapter.check_status()
                status[name] = {"status": "healthy", "details": result}
            except Exception as e:
                status[name] = {"status": "error", "error": str(e)}
        return status
