# intel-core/correlation-engine/engines/utils.py

import datetime
from typing import Any, Dict, List, Optional

def parse_timestamp(timestamp_str: str) -> Optional[datetime.datetime]:
    """
    Парсит строку с временной меткой в объект datetime.
    Поддерживает несколько форматов, возвращает None при ошибке.

    :param timestamp_str: строка с датой/временем
    :return: datetime объект или None
    """
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.datetime.strptime(timestamp_str, fmt)
        except ValueError:
            continue
    return None

def merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Рекурсивно сливает два словаря, значения override имеют приоритет.

    :param base: базовый словарь
    :param override: словарь с переопределениями
    :return: новый словарь с результатом слияния
    """
    result = base.copy()
    for key, value in override.items():
        if (
            key in result 
            and isinstance(result[key], dict) 
            and isinstance(value, dict)
        ):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result

def flatten_list_of_dicts(list_of_dicts: List[Dict[str, Any]], key: str) -> List[Any]:
    """
    Извлекает значения из списка словарей по ключу, игнорирует отсутствующие.

    :param list_of_dicts: список словарей
    :param key: ключ для извлечения значения
    :return: список значений
    """
    return [d[key] for d in list_of_dicts if key in d]

def safe_get(d: Dict[str, Any], path: List[str], default: Any = None) -> Any:
    """
    Безопасно извлекает значение из вложенных словарей по пути.

    :param d: исходный словарь
    :param path: список ключей для доступа по уровню
    :param default: значение по умолчанию, если путь не найден
    :return: найденное значение или default
    """
    current = d
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
        if current is default:
            return default
    return current

