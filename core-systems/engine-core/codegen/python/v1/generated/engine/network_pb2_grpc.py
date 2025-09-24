# -*- coding: utf-8 -*-
"""
AUTO-FACADE for Aethernova Engine network.proto (gRPC stubs)
Этот модуль является фасадом над автогенерируемым _autogen/engine/network_pb2_grpc.py.

Назначение:
- Полагаться на соседний фасад `generated/engine/network_pb2.py` для:
  * идемпотентной генерации protobuf/gRPC кодов;
  * потокобезопасной файловой блокировки;
  * атомарного обновления артефактов;
  * добавления каталога `_autogen` в sys.path.
- После подготовки — импортировать реальный модуль `engine.network_pb2_grpc`
  из `_autogen` и ре-экспортировать все публичные символы.

Зависимости для генерации:
    pip install grpcio grpcio-tools protobuf
"""

from __future__ import annotations

import importlib
import sys
from typing import Any, Dict

CODEGEN_API_VERSION = "1.0.0"

class CodegenError(RuntimeError):
    """Ошибка подготовки/импорта автогенерированного gRPC-модуля."""

# 1) Импортируем соседний фасад, который гарантирует генерацию и sys.path к `_autogen`
try:
    # Локальный пакет: generated/engine/network_pb2.py
    from . import network_pb2 as _pb2_facade  # noqa: F401  (используется для побочных эффектов)
except Exception as e:
    raise CodegenError(
        f"Не удалось импортировать фасад network_pb2 для подготовки автогенерируемых файлов: {e}"
    ) from e

# 2) Импортируем реальный autogen-модуль gRPC стубов
try:
    _mod = importlib.import_module("engine.network_pb2_grpc")
except Exception as e:
    # Подсказка по сбою: вероятно, отсутствуют зависимости или ошибка генерации.
    hint = (
        "Проверьте, что установлены зависимости 'grpcio', 'grpcio-tools', 'protobuf' и "
        "что файл engine-core/schemas/proto/v1/engine/network.proto доступен."
    )
    raise CodegenError(
        f"Не удалось импортировать автогенерированный модуль engine.network_pb2_grpc: {e}\n{hint}"
    ) from e

# 3) Прозрачно ре-экспортируем публичные символы
def _export_public(module) -> Dict[str, Any]:
    if hasattr(module, "__all__"):
        names = list(module.__all__)  # type: ignore[attr-defined]
        return {name: getattr(module, name) for name in names}
    # Если __all__ отсутствует — экспортируем все неподчеркивающиеся атрибуты
    return {k: getattr(module, k) for k in dir(module) if not k.startswith("_")}

globals().update(_export_public(_mod))

# 4) Формируем __all__ для статического анализа и from-import
if hasattr(_mod, "__all__"):
    __all__ = list(_mod.__all__)  # type: ignore[attr-defined]
else:
    __all__ = [k for k in globals().keys() if not k.startswith("_")]

# 5) Метаданные для отладки
__codegen_api_version__ = CODEGEN_API_VERSION
__autogen_file__ = getattr(_mod, "__file__", None)
