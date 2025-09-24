import json
from datetime import datetime, date, time
from decimal import Decimal
from typing import Any


class EnhancedJSONEncoder(json.JSONEncoder):
    """
    JSONEncoder с поддержкой datetime, date, time, Decimal и других нестандартных типов.
    Преобразует их в строковые представления для корректной сериализации.
    """

    def default(self, obj: Any) -> Any:
        if isinstance(obj, (datetime, date, time)):
            return obj.isoformat()
        if isinstance(obj, Decimal):
            return float(obj)
        # Можно расширить для других типов при необходимости
        return super().default(obj)


def dumps(obj: Any, **kwargs) -> str:
    """
    Сериализация объекта в JSON строку с использованием EnhancedJSONEncoder.
    Принимает любые аргументы, которые поддерживает json.dumps.
    """
    return json.dumps(obj, cls=EnhancedJSONEncoder, **kwargs)


def loads(s: str, **kwargs) -> Any:
    """
    Десериализация JSON строки в объект Python.
    Принимает любые аргументы, которые поддерживает json.loads.
    """
    return json.loads(s, **kwargs)
