# automation-core/src/automation_core/utils/typing_ext.py
# SPDX-License-Identifier: MIT
"""
Унифицированные расширения типизации для Python 3.8–3.12+.

Задачи:
- Единая точка импорта современных фич типизации (PEP 484/544/560/593/647/681/698),
  работающая как со встроенным `typing`, так и с `typing_extensions` (если доступно).
- Безопасные рантайм-хелперы для анализа аннотаций и сужения типов.
- Прикладные алиасы (JSONValue, PathLikeStr и пр.) для кода уровня приложения.

Примечания:
- Если конкретная конструкция недоступна в текущем окружении и пакет
  `typing_extensions` отсутствует, предоставляется безопасная "no-op" заглушка —
  это не влияет на выполнение (рантайм), но может ограничить поддержку статчекеров.
"""

from __future__ import annotations

import sys
import types as _types
import typing as _t

# -----------------------------------------------------------------------------
# Попытаться подтянуть typing_extensions, если нужно
# -----------------------------------------------------------------------------
try:  # pragma: no cover - простая ветка импорта
    import typing_extensions as _te  # type: ignore
except Exception:  # pragma: no cover
    _te = None  # type: ignore


def _pick(name: str):
    """
    Возвращает объект из stdlib typing, затем из typing_extensions,
    иначе — None (заглушка будет создана ниже).
    """
    obj = getattr(_t, name, None)
    if obj is not None:
        return obj
    if _te is not None:
        return getattr(_te, name, None)
    return None


# -----------------------------------------------------------------------------
# Базовые экспорты (с подстраховкой)
# -----------------------------------------------------------------------------
# Пытаемся взять из stdlib -> typing_extensions -> заглушка

# Аналогично поведению typing_extensions: заглушки — простые no-op реализация,
# достаточные для рантайма; статический анализ всё равно читает из типов.

# -- Специальные типы/алиасы
TypeAlias = _pick("TypeAlias") or str  # pragma: no cover (рантайм-алиас)
Never = _pick("Never") or _pick("NoReturn") or type(None)
NoReturn = _pick("NoReturn") or type(None)

# -- Контейнеры и утилиты
Annotated = _pick("Annotated") or (lambda tp, *meta: tp)
Literal = _pick("Literal") or (lambda *values: _t.Any)
Final = _pick("Final") or _t.Any
ClassVar = _pick("ClassVar") or _t.Any
Required = _pick("Required") or (lambda T: T)
NotRequired = _pick("NotRequired") or (lambda T: T)
Self = _pick("Self") or _t.TypeVar("Self")
# Параметры типов
ParamSpec = _pick("ParamSpec") or (lambda name: _t.TypeVar(name))  # упрощённо
TypeVarTuple = _pick("TypeVarTuple") or (lambda name: _t.TypeVar(name))  # упрощённо
Unpack = _pick("Unpack") or (lambda x: x)
TypeGuard = _pick("TypeGuard") or (lambda T: _t.Callable[[object], bool])

# -- Протоколы/интерфейсы
Protocol = _pick("Protocol") or type("Protocol", (), {})  # минимальная заглушка
runtime_checkable = _pick("runtime_checkable") or (lambda cls: cls)

# -- TypedDict
TypedDict = _pick("TypedDict")
if TypedDict is None:  # pragma: no cover
    class TypedDict(dict):  # type: ignore[no-redef]
        """Простейшая заглушка TypedDict для рантайма (без проверки ключей)."""
        pass

# -- Декораторы для статической типизации
override = _pick("override") or (lambda obj=None: (obj if obj is not None else (lambda x: x)))
dataclass_transform = _pick("dataclass_transform") or (
    # no-op декоратор согласно PEP 681 контракта (для рантайма)
    lambda *_, **__: (lambda x: x)
)

# -- Инспекция аннотаций
get_origin = _pick("get_origin") or (lambda tp: getattr(tp, "__origin__", None))
get_args = _pick("get_args") or (lambda tp: getattr(tp, "__args__", ()))

# -- Утверждения для исчерпывающих веток/типа
assert_never = _pick("assert_never") or (lambda value: (_raise(TypeError(f"Unhandled type: {type(value)!r}"))))
assert_type = _pick("assert_type") or (lambda value, *_: value)


def _raise(exc: BaseException):  # helper для лямбда выше
    raise exc


# -----------------------------------------------------------------------------
# Прикладные алиасы
# -----------------------------------------------------------------------------
# Строкоподобный путь
PathLikeStr = _t.Union[str, "_t os.PathLike[str]"]  # подсказка для IDE; динамически заменим ниже
try:
    import os as _os  # pragma: no cover
    PathLikeStr = _t.Union[str, _os.PathLike[str]]  # type: ignore[assignment]
except Exception:  # pragma: no cover
    pass

# JSON-типы (удобны для аннотаций API)
JSONScalar = _t.Union[str, int, float, bool, None]
JSONValue = _t.Union["JSONScalar", "_JSONArray", "_JSONObject"]  # forward
JSONArray = _t.List["JSONValue"]
JSONObject = _t.Dict[str, "JSONValue"]
# Для экспорта имён без подчёркивания:
_JSONScalar = JSONScalar
_JSONValue = JSONValue
_JSONArray = JSONArray
_JSONObject = JSONObject

# Часто используемые алиасы-утилиты
StrDict = _t.Dict[str, _t.Any]
StrMap = _t.Mapping[str, _t.Any]
BytesLike = _t.Union[bytes, bytearray, memoryview]


# -----------------------------------------------------------------------------
# Рантайм-утилиты для анализа и сужения типов
# -----------------------------------------------------------------------------
def type_name(tp: _t.Any) -> str:
    """Человекочитаемое имя типа/аннотации (для логов/ошибок)."""
    try:
        if hasattr(tp, "__qualname__"):
            return tp.__qualname__  # classes/functions
        if hasattr(tp, "__name__"):
            return tp.__name__
        return str(tp)
    except Exception:
        return repr(tp)


def is_optional(tp: _t.Any) -> bool:
    """
    True, если аннотация вида Optional[T] или Union[T, None].
    """
    origin = get_origin(tp)
    if origin is _t.Union:
        args = tuple(a for a in get_args(tp))
        return any(a is type(None) for a in args)  # noqa: E721
    return False


def optional_arg(tp: _t.Any) -> _t.Any:
    """
    Возвращает T из Optional[T]/Union[T, None], иначе — исходную аннотацию.
    """
    if not is_optional(tp):
        return tp
    return _t.Union[tuple(a for a in get_args(tp) if a is not type(None))]  # type: ignore[arg-type]


def safe_issubclass(cls: _t.Any, parent: _t.Any) -> bool:
    """
    issubclass с защитой от TypeError, возвращает False если вход не класс.
    """
    try:
        return issubclass(cls, parent)
    except Exception:
        return False


_T = _t.TypeVar("_T")


def narrow(value: _t.Any, predicate: _t.Callable[[_t.Any], bool]) -> _t.Optional[_T]:
    """
    Простое сужение: если предикат истинный — возвращаем значение (typed), иначе None.
    Полезно для пошаговой валидации без кастинга.
    """
    return value if predicate(value) else None  # type: ignore[return-value]


def ensure_type(value: _t.Any, typ: _t.Type[_T]) -> _T:
    """
    Гарантирует тип через isinstance или бросает TypeError с информативным сообщением.
    """
    if not isinstance(value, typ):
        raise TypeError(f"Expected {type_name(typ)}, got {type_name(type(value))}")
    return value


# -----------------------------------------------------------------------------
# Экспорт символов
# -----------------------------------------------------------------------------
__all__ = [
    # базовые алиасы / конструкции
    "TypeAlias",
    "Never",
    "NoReturn",
    "Annotated",
    "Literal",
    "Final",
    "ClassVar",
    "Required",
    "NotRequired",
    "Self",
    "ParamSpec",
    "TypeVarTuple",
    "Unpack",
    "TypeGuard",
    "Protocol",
    "runtime_checkable",
    "TypedDict",
    "override",
    "dataclass_transform",
    "get_origin",
    "get_args",
    "assert_never",
    "assert_type",
    # прикладные алиасы
    "PathLikeStr",
    "JSONScalar",
    "JSONValue",
    "JSONArray",
    "JSONObject",
    "StrDict",
    "StrMap",
    "BytesLike",
    # утилиты
    "type_name",
    "is_optional",
    "optional_arg",
    "safe_issubclass",
    "narrow",
    "ensure_type",
]

# -----------------------------------------------------------------------------
# Валидация модуля при импорте (минимальная самопроверка)
# -----------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    # Простые проверки без сторонних зависимостей
    assert isinstance(JSONScalar.__args__, tuple)  # type: ignore[attr-defined]
    assert type_name(int).endswith("int")
    assert is_optional(_t.Optional[int]) is True
    assert is_optional(int) is False
    assert optional_arg(_t.Optional[int]) is int
    assert safe_issubclass(int, object) is True
    assert narrow(10, lambda x: isinstance(x, int)) == 10
    try:
        ensure_type("x", int)  # должен упасть
    except TypeError:
        pass
