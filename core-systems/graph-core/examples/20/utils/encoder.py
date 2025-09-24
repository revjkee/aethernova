# utils/encoder.py

import json
import datetime
import decimal
import uuid
from enum import Enum
from pathlib import Path
from typing import Any


class EnhancedJSONEncoder(json.JSONEncoder):
    """
    Промышленный сериализатор JSON для нестандартных типов:
    - Decimal
    - datetime
    - UUID
    - Enum
    - Path
    - bytes
    """
    def default(self, obj: Any) -> Any:
        if isinstance(obj, decimal.Decimal):
            return float(obj)
        elif isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        elif isinstance(obj, uuid.UUID):
            return str(obj)
        elif isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, Path):
            return str(obj)
        elif isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)


def safe_dumps(obj: Any, indent: int = None) -> str:
    """
    Надёжная сериализация объекта в строку JSON.

    Args:
        obj (Any): объект для сериализации
        indent (int): уровень отступа (по умолчанию None)

    Returns:
        str: сериализованный JSON
    """
    return json.dumps(obj, cls=EnhancedJSONEncoder, indent=indent, ensure_ascii=False)
