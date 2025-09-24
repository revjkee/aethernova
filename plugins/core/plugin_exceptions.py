class PluginError(Exception):
    """
    Базовое исключение для всей инфраструктуры плагинов TeslaAI Genesis.
    Все остальные ошибки должны наследоваться от него.
    """
    def __init__(self, message: str):
        super().__init__(f"[PluginError] {message}")


class PluginLoadError(PluginError):
    """
    Ошибка загрузки плагина — например, при недопустимом импорте, сбое загрузчика или sandbox.
    """
    def __init__(self, plugin_name: str, details: str = ""):
        super().__init__(f"Ошибка загрузки плагина '{plugin_name}': {details}")


class PluginValidationError(PluginError):
    """
    Ошибка валидации плагина — неправильная подпись, структура, schema mismatch.
    """
    def __init__(self, plugin_name: str, reason: str):
        super().__init__(f"Плагин '{plugin_name}' не прошёл валидацию: {reason}")


class PluginExecutionError(PluginError):
    """
    Ошибка выполнения плагина — во время run-time логики.
    """
    def __init__(self, plugin_name: str, cause: str):
        super().__init__(f"Ошибка исполнения плагина '{plugin_name}': {cause}")


class PluginRegistryError(PluginError):
    """
    Ошибка в реестре плагинов — конфликт версий, не найден плагин и т.д.
    """
    def __init__(self, plugin_id: str, reason: str):
        super().__init__(f"Ошибка в PluginRegistry для '{plugin_id}': {reason}")


class PluginContextError(PluginError):
    """
    Ошибка DI-контекста — проблема с инъекцией или отсутствующей зависимостью.
    """
    def __init__(self, message: str):
        super().__init__(f"ContextError: {message}")


class PluginSignatureError(PluginError):
    """
    Ошибка подписи — hash mismatch, подпись невалидна, expired key и т.д.
    """
    def __init__(self, plugin_name: str, reason: str):
        super().__init__(f"Ошибка подписи плагина '{plugin_name}': {reason}")
