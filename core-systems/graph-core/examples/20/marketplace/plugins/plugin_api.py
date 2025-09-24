from typing import Callable, Dict, Any, Optional

class PluginAPI:
    """
    Интерфейс для разработки и интеграции плагинов в маркетплейс TeslaAI.
    Обеспечивает регистрацию, вызов и управление плагинами с учетом безопасности.
    """

    def __init__(self):
        self._plugins: Dict[str, Callable[..., Any]] = {}

    def register_plugin(self, name: str, handler: Callable[..., Any]) -> None:
        """
        Зарегистрировать плагин с уникальным именем и обработчиком.
        :param name: Уникальное имя плагина.
        :param handler: Функция обработчика плагина.
        """
        if name in self._plugins:
            raise ValueError(f"Плагин с именем '{name}' уже зарегистрирован")
        self._plugins[name] = handler

    def unregister_plugin(self, name: str) -> None:
        """
        Удалить зарегистрированный плагин по имени.
        :param name: Имя плагина.
        """
        if name not in self._plugins:
            raise KeyError(f"Плагин с именем '{name}' не найден")
        del self._plugins[name]

    def call_plugin(self, name: str, *args, **kwargs) -> Optional[Any]:
        """
        Вызвать плагин с передачей аргументов.
        :param name: Имя плагина.
        :return: Результат вызова плагина.
        """
        if name not in self._plugins:
            raise KeyError(f"Плагин с именем '{name}' не зарегистрирован")
        handler = self._plugins[name]
        return handler(*args, **kwargs)

    def list_plugins(self) -> Dict[str, Callable[..., Any]]:
        """
        Вернуть словарь всех зарегистрированных плагинов.
        :return: Словарь имя -> обработчик.
        """
        return dict(self._plugins)
