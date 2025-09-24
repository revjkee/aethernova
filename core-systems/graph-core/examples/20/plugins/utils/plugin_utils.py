import os
import sys
import importlib
import traceback
import json
import hashlib
import uuid
from typing import Any, Dict, Optional, Type


def generate_plugin_id(name: str, version: str) -> str:
    """
    Генерация уникального ID плагина на основе имени и версии
    """
    base = f"{name}:{version}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def load_module_from_path(module_name: str, file_path: str) -> Any:
    """
    Динамическая загрузка модуля из файла
    """
    try:
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load spec for {file_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        raise RuntimeError(f"[plugin_utils] Failed to load module from {file_path}: {e}")


def validate_plugin_metadata(metadata: Dict[str, Any], schema: Dict[str, Any]) -> bool:
    """
    Валидация метаинформации плагина по схеме (упрощённая, без jsonschema)
    """
    required_fields = schema.get("required", [])
    for field in required_fields:
        if field not in metadata:
            return False
    return True


def sanitize_plugin_env(plugin_env: Dict[str, Any]) -> Dict[str, Any]:
    """
    Удаляет небезопасные или запрещённые поля из окружения плагина
    """
    forbidden_keys = {"__class__", "__globals__", "__code__"}
    return {k: v for k, v in plugin_env.items() if k not in forbidden_keys}


def safe_serialize(obj: Any) -> str:
    """
    Безопасная сериализация объекта в JSON (с поддержкой fallback)
    """
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except Exception:
        return json.dumps({"error": "serialization_failed"})


def generate_plugin_signature(metadata: Dict[str, Any], secret_key: str) -> str:
    """
    Генерация подписи плагина на основе метаданных и ключа
    """
    serialized = safe_serialize(metadata)
    return hashlib.sha256((serialized + secret_key).encode("utf-8")).hexdigest()


def is_plugin_compatible(plugin_info: Dict[str, Any], system_version: str) -> bool:
    """
    Проверка совместимости плагина с текущей версией системы
    """
    min_ver = plugin_info.get("min_system_version", "0.0.0")
    max_ver = plugin_info.get("max_system_version", "999.999.999")
    return min_ver <= system_version <= max_ver


def print_plugin_error(e: Exception):
    """
    Отладочный вывод с трассировкой исключений
    """
    print(f"[plugin_utils] Error: {str(e)}", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)


def resolve_plugin_path(base_dir: str, plugin_name: str) -> Optional[str]:
    """
    Поиск пути к плагину по его названию
    """
    possible_path = os.path.join(base_dir, f"{plugin_name}.py")
    return possible_path if os.path.isfile(possible_path) else None


def secure_uuid() -> str:
    """
    Генерация безопасного UUID v4
    """
    return str(uuid.uuid4())
