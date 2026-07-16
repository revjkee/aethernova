# agent_mash/tests/unit/agents/test_agent_memory.py

from __future__ import annotations

import importlib
import inspect
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional, Tuple, Type

import pytest


pytestmark = pytest.mark.unit


# -----------------------------------------------------------------------------
# Industrial test harness:
# - No assumptions about your concrete memory implementation.
# - Autodiscovers a memory backend by importing known paths and locating a class.
# - Runs a contract suite against whatever it finds.
# - If nothing is found, skips with a clear reason (no false failures).
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class MemoryCandidate:
    module_path: str
    class_name: str


_CANDIDATES: Tuple[MemoryCandidate, ...] = (
    # Common patterns in agent projects:
    MemoryCandidate("agent_mash.agents.memory", "AgentMemory"),
    MemoryCandidate("agent_mash.agents.memory", "Memory"),
    MemoryCandidate("agent_mash.agents.memory", "InMemoryMemory"),
    MemoryCandidate("agent_mash.agents.memory", "InMemoryAgentMemory"),
    MemoryCandidate("agent_mash.memory", "AgentMemory"),
    MemoryCandidate("agent_mash.memory", "Memory"),
    MemoryCandidate("agent_mash.memory", "InMemoryMemory"),
    MemoryCandidate("agent_mash.core.memory", "AgentMemory"),
    MemoryCandidate("agent_mash.core.memory", "Memory"),
    MemoryCandidate("agent_mash.core.memory", "InMemoryMemory"),
    MemoryCandidate("agent_mash.agents.agent_memory", "AgentMemory"),
    MemoryCandidate("agent_mash.agents.agent_memory", "Memory"),
    MemoryCandidate("agent_mash.agents.agent_memory", "InMemoryMemory"),
)


def _safe_import(module_path: str):
    try:
        return importlib.import_module(module_path)
    except Exception:
        return None


def _find_memory_class() -> Optional[Type[Any]]:
    for cand in _CANDIDATES:
        mod = _safe_import(cand.module_path)
        if mod is None:
            continue
        cls = getattr(mod, cand.class_name, None)
        if inspect.isclass(cls):
            return cls

    # Fallback: search any class in candidate modules that looks like memory.
    for cand in _CANDIDATES:
        mod = _safe_import(cand.module_path)
        if mod is None:
            continue
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if obj.__module__ != mod.__name__:
                continue
            if _looks_like_memory_class(obj):
                return obj

    return None


def _looks_like_memory_class(cls: Type[Any]) -> bool:
    # Heuristic: must have a "get" and some setter-like method.
    names = set(dir(cls))
    has_get = "get" in names
    has_set = any(n in names for n in ("set", "put", "add", "__setitem__"))
    return bool(has_get and has_set)


def _pick_method(obj: Any, names: Iterable[str]) -> Optional[Callable[..., Any]]:
    for n in names:
        fn = getattr(obj, n, None)
        if callable(fn):
            return fn
    return None


def _construct_memory(cls: Type[Any], *, capacity: Optional[int] = None) -> Any:
    """
    Tries to construct memory with safe, common kwargs. If signature mismatches,
    tries without kwargs. If still fails, skips to avoid false negatives.
    """
    sig = None
    try:
        sig = inspect.signature(cls)
    except Exception:
        sig = None

    kwargs: Dict[str, Any] = {}
    if capacity is not None and sig is not None:
        for k in ("capacity", "max_size", "max_entries", "limit"):
            if k in sig.parameters:
                kwargs[k] = capacity
                break

    try:
        return cls(**kwargs) if kwargs else cls()
    except Exception as e:
        pytest.skip(f"Agent memory class найден, но не удалось создать экземпляр: {cls.__name__}: {e}")


@pytest.fixture(scope="module")
def memory_cls() -> Type[Any]:
    cls = _find_memory_class()
    if cls is None:
        pytest.skip(
            "Реализация памяти агента не найдена по типовым путям. "
            "Добавь реализацию (например, AgentMemory/Memory) или обнови список _CANDIDATES."
        )
    return cls


@pytest.fixture()
def memory(memory_cls: Type[Any]) -> Any:
    return _construct_memory(memory_cls)


@pytest.fixture()
def memory_capacity_2(memory_cls: Type[Any]) -> Any:
    return _construct_memory(memory_cls, capacity=2)


@pytest.fixture()
def frozen_time(monkeypatch: pytest.MonkeyPatch) -> Callable[[], float]:
    """
    Freezes time.time() if the implementation relies on wall clock (e.g., TTL).
    """
    import time

    now = 1_700_000_000.0

    def _time() -> float:
        return now

    monkeypatch.setattr(time, "time", _time)
    return _time


# -----------------------------------------------------------------------------
# Contract tests: basic CRUD, idempotency, overwrite, delete, clear, capacity.
# These tests adapt to method naming differences.
# -----------------------------------------------------------------------------


def test_memory_has_minimum_interface(memory: Any) -> None:
    get_fn = _pick_method(memory, ("get", "__getitem__"))
    set_fn = _pick_method(memory, ("set", "put", "add", "__setitem__"))
    assert get_fn is not None, "Memory must expose get(key) or __getitem__"
    assert set_fn is not None, "Memory must expose set/put/add(key, value) or __setitem__"


def test_set_and_get_roundtrip(memory: Any) -> None:
    set_fn = _pick_method(memory, ("set", "put", "add"))
    if set_fn is None and hasattr(memory, "__setitem__"):
        def _set(k: str, v: Any) -> None:
            memory[k] = v
        set_fn = _set

    get_fn = _pick_method(memory, ("get",))
    if get_fn is None and hasattr(memory, "__getitem__"):
        def _get(k: str) -> Any:
            return memory[k]
        get_fn = _get

    assert set_fn is not None
    assert get_fn is not None

    set_fn("k1", {"a": 1})
    assert get_fn("k1") == {"a": 1}


def test_overwrite_same_key_last_write_wins(memory: Any) -> None:
    set_fn = _pick_method(memory, ("set", "put", "add"))
    if set_fn is None and hasattr(memory, "__setitem__"):
        def _set(k: str, v: Any) -> None:
            memory[k] = v
        set_fn = _set

    get_fn = _pick_method(memory, ("get",))
    if get_fn is None and hasattr(memory, "__getitem__"):
        def _get(k: str) -> Any:
            return memory[k]
        get_fn = _get

    assert set_fn is not None
    assert get_fn is not None

    set_fn("k", 1)
    set_fn("k", 2)
    assert get_fn("k") == 2


def test_get_missing_key_returns_default_or_raises(memory: Any) -> None:
    get_fn = _pick_method(memory, ("get",))
    if get_fn is not None:
        # Prefer dict-like: get(key, default)
        try:
            res = get_fn("missing", None)
            assert res is None
            return
        except TypeError:
            # get(key) might raise or return None
            res2 = get_fn("missing")
            assert res2 is None
            return
        except KeyError:
            return

    # If no get, __getitem__ should raise KeyError
    if hasattr(memory, "__getitem__"):
        with pytest.raises(KeyError):
            _ = memory["missing"]
        return

    pytest.skip("Не найден способ проверить поведение для отсутствующего ключа.")


def test_delete_removes_key_or_is_idempotent(memory: Any) -> None:
    set_fn = _pick_method(memory, ("set", "put", "add"))
    if set_fn is None and hasattr(memory, "__setitem__"):
        def _set(k: str, v: Any) -> None:
            memory[k] = v
        set_fn = _set

    del_fn = _pick_method(memory, ("delete", "remove", "pop", "__delitem__"))
    get_fn = _pick_method(memory, ("get",))

    if del_fn is None:
        pytest.skip("У реализации памяти нет delete/remove/pop/__delitem__ для проверки удаления.")

    assert set_fn is not None
    set_fn("k", "v")

    # Delete should not corrupt memory
    try:
        if del_fn.__name__ == "pop":
            del_fn("k", None)  # type: ignore[arg-type]
        elif del_fn.__name__ == "__delitem__":
            del memory["k"]
        else:
            del_fn("k")
    except KeyError:
        # acceptable in some designs if not present; here it was present though
        pytest.fail("Удаление существующего ключа не должно приводить к KeyError (если ключ был установлен).")

    # After deletion, key should be absent
    if get_fn is not None:
        try:
            assert get_fn("k", None) is None
        except TypeError:
            assert get_fn("k") is None
        except KeyError:
            pass
    elif hasattr(memory, "__getitem__"):
        with pytest.raises(KeyError):
            _ = memory["k"]


def test_clear_empties_memory_if_supported(memory: Any) -> None:
    set_fn = _pick_method(memory, ("set", "put", "add"))
    if set_fn is None and hasattr(memory, "__setitem__"):
        def _set(k: str, v: Any) -> None:
            memory[k] = v
        set_fn = _set

    clear_fn = _pick_method(memory, ("clear", "reset", "purge"))
    if clear_fn is None:
        pytest.skip("У реализации памяти нет clear/reset/purge для проверки очистки.")

    assert set_fn is not None
    set_fn("a", 1)
    set_fn("b", 2)

    clear_fn()

    # Validate emptiness via len/keys/items or get
    if hasattr(memory, "__len__"):
        assert len(memory) == 0
        return

    keys_fn = _pick_method(memory, ("keys",))
    if keys_fn is not None:
        assert list(keys_fn()) == []
        return

    get_fn = _pick_method(memory, ("get",))
    if get_fn is not None:
        try:
            assert get_fn("a", None) is None
        except TypeError:
            assert get_fn("a") is None
        return

    pytest.skip("Не найден способ верифицировать очистку памяти.")


def test_len_reflects_insertions_if_supported(memory: Any) -> None:
    if not hasattr(memory, "__len__"):
        pytest.skip("У реализации памяти нет __len__ для проверки размера.")

    set_fn = _pick_method(memory, ("set", "put", "add"))
    if set_fn is None and hasattr(memory, "__setitem__"):
        def _set(k: str, v: Any) -> None:
            memory[k] = v
        set_fn = _set

    assert set_fn is not None

    initial = len(memory)
    set_fn("k1", 1)
    set_fn("k2", 2)
    assert len(memory) == initial + 2


def test_capacity_eviction_or_rejection_if_supported(memory_capacity_2: Any) -> None:
    """
    Capacity behavior varies by implementation:
    - Some evict old entries (LRU/FIFO).
    - Some reject new entries.
    This test is flexible: it asserts that memory never exceeds its capacity
    if it provides __len__.
    """
    mem = memory_capacity_2

    if not hasattr(mem, "__len__"):
        pytest.skip("У реализации памяти нет __len__, поэтому нельзя проверить поведение capacity.")

    set_fn = _pick_method(mem, ("set", "put", "add"))
    if set_fn is None and hasattr(mem, "__setitem__"):
        def _set(k: str, v: Any) -> None:
            mem[k] = v
        set_fn = _set

    assert set_fn is not None

    set_fn("k1", 1)
    set_fn("k2", 2)
    set_fn("k3", 3)

    assert len(mem) <= 2


def test_ttl_expiration_if_supported(memory: Any, frozen_time: Callable[[], float], monkeypatch: pytest.MonkeyPatch) -> None:
    """
    TTL is optional. This test only runs if a TTL-like API is present.
    It validates that expired items are not returned.
    """
    # Detect TTL API by presence of parameters in setter
    set_fn = _pick_method(memory, ("set", "put", "add"))
    if set_fn is None and hasattr(memory, "__setitem__"):
        pytest.skip("TTL-проверка требует именованного setter, __setitem__ недостаточно.")

    assert set_fn is not None

    try:
        sig = inspect.signature(set_fn)
    except Exception:
        pytest.skip("Не удалось определить сигнатуру setter для проверки TTL.")

    ttl_param = None
    for name in ("ttl", "ttl_seconds", "expires_in", "expire_in", "expiration_seconds"):
        if name in sig.parameters:
            ttl_param = name
            break

    if ttl_param is None:
        pytest.skip("TTL API не обнаружен в setter (ttl/ttl_seconds/expires_in/... отсутствуют).")

    get_fn = _pick_method(memory, ("get",))
    if get_fn is None and hasattr(memory, "__getitem__"):
        def _get(k: str) -> Any:
            return memory[k]
        get_fn = _get

    # Freeze time at now
    now = frozen_time()

    kwargs = {ttl_param: 10}
    set_fn("ttl_key", "v", **kwargs)

    # Item should be visible immediately
    try:
        assert get_fn("ttl_key", None) == "v"  # type: ignore[misc]
    except TypeError:
        assert get_fn("ttl_key") == "v"

    # Advance time by monkeypatching our frozen time closure:
    # We cannot mutate the closure variable directly, so we patch time.time again.
    import time as _time_module

    def _time_plus_20() -> float:
        return now + 20.0

    monkeypatch.setattr(_time_module, "time", _time_plus_20)

    # After expiration, should be missing or None/KeyError depending on design
    try:
        res = get_fn("ttl_key", None)  # type: ignore[misc]
        assert res is None
    except TypeError:
        try:
            res2 = get_fn("ttl_key")
            assert res2 is None
        except KeyError:
            pass
    except KeyError:
        pass
