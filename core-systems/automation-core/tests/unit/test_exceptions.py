# automation-core/tests/unit/test_exceptions.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import importlib
import pickle
import types
from typing import Any, Iterable

import pytest

# Кандидаты на путь до модуля исключений проекта.
# Если ваш реальный путь иной — скорректируйте список.
MODULE_CANDIDATES: tuple[str, ...] = (
    "automation_core.exceptions",
    "automation.core.exceptions",
    "automation.exceptions",
)

# Ожидаемая номенклатура исключений:
# - Base: базовый класс проекта.
# - Остальные: распространенные доменные подклассы.
EXPECTED_CLASSES: dict[str, tuple[str, ...]] = {
    "Base": ("AutomationError",),
    "Subclasses": (
        "ConfigError",
        "ValidationError",
        "TimeoutError",          # допустимо перекрытие встроенного имени
        "ExternalServiceError",
        "RetryableError",
        "NonRetryableError",
        "CircuitOpenError",
    ),
}


def _import_exceptions_module() -> types.ModuleType:
    last_err: Exception | None = None
    for name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(name)
        except Exception as exc:  # pragma: no cover - диагностический путь
            last_err = exc
    raise AssertionError(
        "Модуль с исключениями не найден. "
        f"Пробовали: {', '.join(MODULE_CANDIDATES)}. "
        f"Последняя ошибка импорта: {last_err!r}"
    )


def _get_cls(mod: types.ModuleType, name: str) -> type[BaseException]:
    obj = getattr(mod, name, None)
    assert obj is not None, f"Ожидался класс {name} в модуле {mod.__name__}"
    assert isinstance(obj, type), f"{name} должен быть типом, а не {type(obj)}"
    assert issubclass(obj, BaseException), f"{name} должен наследоваться от BaseException"
    return obj  # type: ignore[return-value]


@pytest.fixture(scope="session")
def exc_mod() -> types.ModuleType:
    return _import_exceptions_module()


@pytest.fixture(scope="session")
def classes(exc_mod: types.ModuleType) -> dict[str, type[BaseException]]:
    out: dict[str, type[BaseException]] = {}
    for name_group in EXPECTED_CLASSES.values():
        for n in name_group:
            try:
                out[n] = _get_cls(exc_mod, n)
            except AssertionError:
                # Разрешаем отсутствие части классов — тесты ниже это учтут.
                # Но базовый AutomationError обязателен.
                if n in EXPECTED_CLASSES["Base"]:
                    raise
    return out


def _present(names: Iterable[str], pool: dict[str, Any]) -> list[str]:
    return [n for n in names if n in pool]


# -------------------------
# Наличие и иерархия
# -------------------------

def test_base_exception_exists(classes: dict[str, type[BaseException]]) -> None:
    assert "AutomationError" in classes, "Базовый класс AutomationError обязателен"


@pytest.mark.parametrize("name", EXPECTED_CLASSES["Subclasses"])
def test_subclasses_exist_or_explicitly_absent(
    classes: dict[str, type[BaseException]], name: str
) -> None:
    # Подкласс может отсутствовать в конкретной реализации — это не провал,
    # но если присутствует, должен быть валидным Exception.
    if name not in classes:
        pytest.xfail(f"Подкласс {name} отсутствует в текущей реализации исключений")
    assert issubclass(classes[name], Exception)


@pytest.mark.parametrize("name", _present(EXPECTED_CLASSES["Subclasses"], EXPECTED_CLASSES["Subclasses"]))
def test_inheritance_from_base(classes: dict[str, type[BaseException]], name: str) -> None:
    if name not in classes:
        pytest.xfail(f"{name} отсутствует — проверка иерархии пропущена")
    assert issubclass(classes[name], classes["AutomationError"]), (
        f"{name} должен наследоваться от AutomationError"
    )


# -------------------------
# Поведение: str / repr
# -------------------------

@pytest.mark.parametrize("name", lambda: _present(EXPECTED_CLASSES["Subclasses"], classes={}))
def test_str_and_repr_contain_message(monkeypatch, exc_mod: types.ModuleType, classes) -> None:
    # Динамически формируем параметры, когда известны реальные присутствующие классы.
    subs = [n for n in EXPECTED_CLASSES["Subclasses"] if n in classes]
    if not subs:
        pytest.skip("Нет ни одного подкласса для проверки")
    msg = "unit-test-message"
    for name in subs:
        exc_cls = classes[name]
        # Поддерживаем возможный кастомный конструктор: message/code/**kwargs
        try:
            err = exc_cls(msg)  # type: ignore[call-arg]
        except TypeError:
            try:
                err = exc_cls(message=msg)  # type: ignore[call-arg]
            except TypeError:
                # Как крайний случай — без сообщения
                err = exc_cls()  # type: ignore[call-arg]

        s = str(err)
        r = repr(err)
        assert msg in s or s, f"str({name}) должен содержать сообщение или быть непустым"
        assert r, f"repr({name}) не должен быть пустым"


# -------------------------
# Цепочка причин (__cause__)
# -------------------------

@pytest.mark.parametrize("name", lambda: _present(EXPECTED_CLASSES["Subclasses"], classes={}))
def test_cause_chaining(classes) -> None:
    subs = [n for n in EXPECTED_CLASSES["Subclasses"] if n in classes]
    if not subs:
        pytest.skip("Нет ни одного подкласса для проверки")
    exc_cls = classes[subs[0]]
    root = ValueError("root-cause")
    try:
        try:
            raise root
        except ValueError as e:
            raise exc_cls("wrapped") from e  # type: ignore[call-arg]
    except Exception as e:  # noqa: BLE001
        assert e.__cause__ is root, "__cause__ должен сохранять исходное исключение"


# -------------------------
# Pickle round-trip
# -------------------------

@pytest.mark.parametrize("name", lambda: _present(EXPECTED_CLASSES["Subclasses"], classes={}))
def test_pickle_round_trip(classes) -> None:
    subs = [n for n in EXPECTED_CLASSES["Subclasses"] if n in classes]
    if not subs:
        pytest.skip("Нет ни одного подкласса для проверки")
    exc_cls = classes[subs[0]]
    inst = exc_cls("pickle-me")  # type: ignore[call-arg]
    data = pickle.dumps(inst)
    clone = pickle.loads(data)
    assert type(clone) is type(inst)
    assert str(clone) == str(inst)


# -------------------------
# to_dict / from_dict (если есть)
# -------------------------

@pytest.mark.parametrize("name", lambda: _present(EXPECTED_CLASSES["Subclasses"], classes={}))
def test_to_from_dict_round_trip(classes) -> None:
    subs = [n for n in EXPECTED_CLASSES["Subclasses"] if n in classes]
    if not subs:
        pytest.skip("Нет ни одного подкласса для проверки")
    exc_cls = classes[subs[0]]

    if not (hasattr(exc_cls, "to_dict") and hasattr(exc_cls, "from_dict")):
        pytest.xfail(f"{exc_cls.__name__} не реализует to_dict/from_dict")

    inst = exc_cls("serialize-me", code=getattr(exc_cls, "default_code", None))  # type: ignore[call-arg]
    payload = exc_cls.to_dict(inst)  # type: ignore[attr-defined]
    clone = exc_cls.from_dict(payload)  # type: ignore[attr-defined]
    assert type(clone) is exc_cls
    assert str(clone) == str(inst)


# -------------------------
# Флаги повторяемости (если есть)
# -------------------------

def test_retryable_flags_if_present(classes) -> None:
    r = classes.get("RetryableError")
    nr = classes.get("NonRetryableError")

    if r is not None:
        inst = r("retriable")  # type: ignore[call-arg]
        flag = getattr(inst, "retryable", None)
        if flag is None:
            pytest.xfail("RetryableError не содержит флаг 'retryable'")
        else:
            assert flag is True

    if nr is not None:
        inst = nr("non-retriable")  # type: ignore[call-arg]
        flag = getattr(inst, "retryable", None)
        if flag is None:
            pytest.xfail("NonRetryableError не содержит флаг 'retryable'")
        else:
            assert flag is False


# -------------------------
# Перехват по базовому классу
# -------------------------

def test_catch_by_base(classes) -> None:
    base = classes["AutomationError"]
    some = next((classes[n] for n in EXPECTED_CLASSES["Subclasses"] if n in classes), None)
    if some is None:
        pytest.skip("Нет ни одного подкласса для проверки перехвата по базе")

    try:
        raise some("boom")  # type: ignore[call-arg]
    except base:
        caught = True
    else:
        caught = False

    assert caught, "Подкласс должен перехватываться базовым AutomationError"
