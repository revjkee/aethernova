from typing import Any, Dict, Type, Optional, Callable
from threading import RLock

from plugins.core.plugin_exceptions import PluginContextError


class PluginContext:
    """
    Промышленный DI-контейнер для плагинов TeslaAI Genesis.
    Обеспечивает безопасную инъекцию зависимостей, lazy-loading и изоляцию по скоупу плагина.
    """

    _registry: Dict[str, Any] = {}
    _factories: Dict[str, Callable[[], Any]] = {}
    _lock = RLock()

    @classmethod
    def register(cls, name: str, instance: Any) -> None:
        with cls._lock:
            if name in cls._registry:
                raise PluginContextError(f"Dependency '{name}' already registered")
            cls._registry[name] = instance

    @classmethod
    def register_factory(cls, name: str, factory_fn: Callable[[], Any]) -> None:
        with cls._lock:
            if name in cls._factories:
                raise PluginContextError(f"Factory for '{name}' already registered")
            cls._factories[name] = factory_fn

    @classmethod
    def get(cls, name: str) -> Any:
        with cls._lock:
            if name in cls._registry:
                return cls._registry[name]

            if name in cls._factories:
                instance = cls._factories[name]()
                cls._registry[name] = instance
                return instance

            raise PluginContextError(f"Dependency '{name}' not found in context")

    @classmethod
    def clear(cls) -> None:
        with cls._lock:
            cls._registry.clear()
            cls._factories.clear()

    @classmethod
    def override(cls, name: str, instance: Any) -> None:
        with cls._lock:
            cls._registry[name] = instance

    @classmethod
    def unregister(cls, name: str) -> None:
        with cls._lock:
            cls._registry.pop(name, None)
            cls._factories.pop(name, None)
