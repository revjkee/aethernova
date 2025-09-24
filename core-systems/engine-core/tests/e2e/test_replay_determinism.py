# -*- coding: utf-8 -*-
"""
E2E: Replay Determinism

Запуск (одна реализация):
  REPLAY_TARGET="engine.ingest:ingest" pytest -q engine/e2e/test_replay_determinism.py

Differential‑replay (сравнение A vs B):
  REPLAY_TARGET_A="engine.v1:ingest" \
  REPLAY_TARGET_B="engine.v2:ingest" \
  pytest -q engine/e2e/test_replay_determinism.py::test_replay_equivalence_across_targets

Параметры (ENV):
  REPLAY_TARGET          — "module.sub:callable" целевой обработчик (dict -> dict)
  REPLAY_TARGET_A / _B   — для дифф‑сравнения.
  REPLAY_CASES=200       — количество событий в сценарии.
  REPLAY_SEED=1337       — базовый сид.
  IGNORE_FIELDS=id,ts    — CSV полей для маскирования при хэшировании.
  STABLE_TIME_BASE=1700000000  — опорное «время» (сек) для стабилизации.
  TRACE_COMPRESSION=0    — 0|1: сжимать jsonl.gz (по умолчанию 0).
  STRICT_JSON=1          — 1: гарантировать json‑совместимость, исключая NaN/Inf (по умолчанию 1).

Интерфейс цели:
  callable(event: dict) -> dict
"""

from __future__ import annotations

import dataclasses
import gzip
import hashlib
import importlib
import io
import json
import os
import random
import re
import time
import types
import uuid
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import pytest


# ------------------------------------------------------------------------------
# Утилиты env
# ------------------------------------------------------------------------------

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip() in ("1", "true", "True", "yes")

def _env_csv(name: str, default: str) -> Tuple[str, ...]:
    raw = os.getenv(name, default)
    return tuple([x.strip() for x in raw.split(",") if x.strip()])

# ------------------------------------------------------------------------------
# Загрузка целей
# ------------------------------------------------------------------------------

def _load_callable(path: str) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    mod, _, obj = path.partition(":")
    if not mod or not obj:
        raise RuntimeError(f"Invalid callable path: {path!r}")
    m = importlib.import_module(mod)
    fn = getattr(m, obj)
    if not callable(fn):
        raise RuntimeError(f"Loaded object is not callable: {path!r}")
    return fn

def _target_single() -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    path = os.getenv("REPLAY_TARGET")
    if not path:
        return _reference_handler
    return _load_callable(path)

def _targets_pair() -> Tuple[Callable[[Dict[str, Any]], Dict[str, Any]], Callable[[Dict[str, Any]], Dict[str, Any]]]:
    a, b = os.getenv("REPLAY_TARGET_A"), os.getenv("REPLAY_TARGET_B")
    if not (a and b):
        pytest.skip("REPLAY_TARGET_A/REPLAY_TARGET_B not set")
    return _load_callable(a), _load_callable(b)

# ------------------------------------------------------------------------------
# Дет‑слой: монкипатч источников недетерминизма
# ------------------------------------------------------------------------------

@dataclasses.dataclass
class DeterministicContext:
    seed: int
    base_time: int
    _rng: random.Random = dataclasses.field(init=False)

    def __post_init__(self):
        self._rng = random.Random(self.seed)

    # детерминированные источники
    def randbytes(self, n: int) -> bytes:
        # Python 3.9+: Random.randbytes; на старших имитируем
        buf = bytearray()
        for _ in range(n):
            buf.append(self._rng.randrange(0, 256))
        return bytes(buf)

    def uuid4(self) -> uuid.UUID:
        # Строим uuid4 из randbytes
        b = bytearray(self.randbytes(16))
        # Версия 4/вариант RFC 4122
        b[6] = (b[6] & 0x0F) | 0x40
        b[8] = (b[8] & 0x3F) | 0x80
        return uuid.UUID(bytes=bytes(b))

    def now(self) -> float:
        # «Тикаем» со случайной, но сидируемой дельтой 0..3мс
        return float(self.base_time) + self._rng.random() * 0.003

class _Patched:
    def __init__(self):
        self._orig = {}

    def apply(self, det: DeterministicContext):
        import builtins, os as _os, time as _time, uuid as _uuid, random as _random
        # Сохраняем оригиналы
        self._orig["time.time"] = _time.time
        self._orig["os.urandom"] = _os.urandom
        self._orig["uuid.uuid4"] = _uuid.uuid4
        self._orig["random.random"] = _random.random
        self._orig["random.randrange"] = _random.randrange
        self._orig["random.getrandbits"] = _random.getrandbits

        _time.time = lambda: det.now()  # type: ignore
        _os.urandom = lambda n: det.randbytes(n)  # type: ignore
        _uuid.uuid4 = lambda: det.uuid4()  # type: ignore
        _random.random = lambda: det._rng.random()  # type: ignore
        _random.randrange = lambda *a, **kw: det._rng.randrange(*a, **kw)  # type: ignore
        _random.getrandbits = lambda k: det._rng.getrandbits(k)  # type: ignore

    def restore(self):
        import os as _os, time as _time, uuid as _uuid, random as _random
        for k, v in self._orig.items():
            mod, name = k.split(".")
            if k == "time.time":
                _time.time = v  # type: ignore
            elif k == "os.urandom":
                _os.urandom = v  # type: ignore
            elif k == "uuid.uuid4":
                _uuid.uuid4 = v  # type: ignore
            elif k == "random.random":
                _random.random = v  # type: ignore
            elif k == "random.randrange":
                _random.randrange = v  # type: ignore
            elif k == "random.getrandbits":
                _random.getrandbits = v  # type: ignore
        self._orig.clear()

# ------------------------------------------------------------------------------
# Нормализация/хэширование результата
# ------------------------------------------------------------------------------

_IGNORE_FIELDS = _env_csv("IGNORE_FIELDS", "id,ts")
_STRICT_JSON = _env_bool("STRICT_JSON", True)

def _sanitize_json_compat(obj: Any) -> Any:
    # Удаляем NaN/Inf, приводим к JSON‑совместимому виду
    if isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            return 0.0
        return obj
    if isinstance(obj, dict):
        return {str(k): _sanitize_json_compat(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_json_compat(v) for v in obj]
    return obj

def _mask_volatile(d: Dict[str, Any], ignore: Iterable[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if k in ignore:
            out[k] = "<masked>"
        elif isinstance(v, dict):
            out[k] = _mask_volatile(v, ignore)
        elif isinstance(v, list):
            out[k] = [(_mask_volatile(x, ignore) if isinstance(x, dict) else x) for x in v]
        else:
            out[k] = v
    return out

def _stable_dumps(d: Dict[str, Any]) -> bytes:
    obj = _mask_volatile(d, _IGNORE_FIELDS)
    if _STRICT_JSON:
        obj = _sanitize_json_compat(obj)
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _hash_dict(d: Dict[str, Any]) -> str:
    return hashlib.sha256(_stable_dumps(d)).hexdigest()

# ------------------------------------------------------------------------------
# Трасса: запись/чтение
# ------------------------------------------------------------------------------

@dataclasses.dataclass
class TraceEntry:
    step: int
    seed: int
    event: Dict[str, Any]
    result_hash: str

def _open_trace(path: str, write: bool, compress: bool) -> io.TextIOBase:
    if compress:
        if write:
            return io.TextIOWrapper(gzip.GzipFile(filename=path, mode="wb"), encoding="utf-8")
        return io.TextIOWrapper(gzip.GzipFile(filename=path, mode="rb"), encoding="utf-8")
    return open(path, "wt" if write else "rt", encoding="utf-8")

def write_trace(path: str, entries: Iterable[TraceEntry], compress: bool = False) -> None:
    with _open_trace(path, True, compress) as f:
        for e in entries:
            f.write(json.dumps(dataclasses.asdict(e), ensure_ascii=False) + "\n")

def read_trace(path: str) -> List[TraceEntry]:
    compress = path.endswith(".gz")
    out: List[TraceEntry] = []
    with _open_trace(path, False, compress) as f:
        for line in f:
            j = json.loads(line)
            out.append(TraceEntry(**j))
    return out

# ------------------------------------------------------------------------------
# Генератор событий сценария
# ------------------------------------------------------------------------------

def _synth_event(rng: random.Random, idx: int) -> Dict[str, Any]:
    # Небольшой реалистичный синтетический ивент
    size = rng.randint(0, 3)
    payload = {f"k{j}": rng.randint(0, 10_000) for j in range(size)}
    return {
        "id": str(uuid.uuid4()),
        "ts": int(time.time() * 1000),
        "source": f"e2e-replay",
        "type": "test",
        "payload": payload,
        "attrs": {"idx": idx, "rnd": rng.random()},
    }

# ------------------------------------------------------------------------------
# Референс‑цель (если REPLAY_TARGET не задан)
# ------------------------------------------------------------------------------

def _reference_handler(event: Dict[str, Any]) -> Dict[str, Any]:
    # Мини‑нормализатор: сортировка ключей, трим строк, гарантии типов
    out = dict(event)
    out["source"] = str(out.get("source", "")).strip()[:64] or "unknown"
    out["type"] = str(out.get("type", "")).strip()[:64] or "unknown"
    for k in ("payload", "attrs"):
        v = out.get(k, {})
        out[k] = v if isinstance(v, dict) else {}
    # Пример детерминированной агрегации
    s = 0
    for v in out["payload"].values():
        try:
            s += int(v)
        except Exception:
            pass
    out["attrs"]["sum_payload"] = s
    return out

# ------------------------------------------------------------------------------
# Основные тесты
# ------------------------------------------------------------------------------

@pytest.mark.e2e
def test_replay_is_bitwise_deterministic(tmp_path, monkeypatch):
    cases = _env_int("REPLAY_CASES", 200)
    seed = _env_int("REPLAY_SEED", 1337)
    base_time = _env_int("STABLE_TIME_BASE", 1_700_000_000)
    compress = _env_bool("TRACE_COMPRESSION", False)

    det = DeterministicContext(seed=seed, base_time=base_time)
    patch = _Patched()
    patch.apply(det)
    try:
        target = _target_single()
        rng = random.Random(seed)

        entries: List[TraceEntry] = []
        for i in range(cases):
            ev = _synth_event(rng, i)
            res = target(ev)
            h = _hash_dict(res)
            entries.append(TraceEntry(step=i, seed=seed, event=ev, result_hash=h))

        # пишем трассу
        trace_path = tmp_path / ("replay_trace.jsonl" + (".gz" if compress else ""))
        write_trace(str(trace_path), entries, compress=compress)

        # «портим» глобальные источники недетерминизма (проверка устойчивости воспроизведения)
        import os as _os, time as _time, uuid as _uuid, random as _random
        _os.urandom = lambda n: b"\x00" * n  # type: ignore
        _time.time = lambda: 0.0  # type: ignore
        _uuid.uuid4 = lambda: uuid.UUID(int=0)  # type: ignore
        _random.random = lambda: 0.5  # type: ignore

        # повторный прогон по трассе
        replay = read_trace(str(trace_path))
        for e in replay:
            out = target(e.event)
            assert _hash_dict(out) == e.result_hash, f"Mismatch at step={e.step}"
    finally:
        patch.restore()


@pytest.mark.e2e
def test_same_seed_same_output_without_trace(monkeypatch):
    # Проверяем, что два независимых запуска с одинаковым сидом дают один и тот же набор хэшей.
    cases = _env_int("REPLAY_CASES", 200)
    seed = _env_int("REPLAY_SEED", 1337)
    base_time = _env_int("STABLE_TIME_BASE", 1_700_000_000)

    def run_once() -> List[str]:
        det = DeterministicContext(seed=seed, base_time=base_time)
        patch = _Patched()
        patch.apply(det)
        try:
            t = _target_single()
            rng = random.Random(seed)
            return [_hash_dict(t(_synth_event(rng, i))) for i in range(cases)]
        finally:
            patch.restore()

    h1 = run_once()
    h2 = run_once()
    assert h1 == h2, "Determinism broken for same seed runs"


@pytest.mark.e2e
def test_replay_equivalence_across_targets(tmp_path):
    # Differential‑replay: A и B обязаны выдавать детерминированные, но допускаем слабую эквивалентность
    # по маскированному хэшу (после IGNORE_FIELDS) для каждого шага.
    a, b = _targets_pair()

    cases = _env_int("REPLAY_CASES", 200)
    seed = _env_int("REPLAY_SEED", 1337)
    base_time = _env_int("STABLE_TIME_BASE", 1_700_000_000)

    det = DeterministicContext(seed=seed, base_time=base_time)
    patch = _Patched()
    patch.apply(det)
    try:
        rng = random.Random(seed)
        for i in range(cases):
            ev = _synth_event(rng, i)
            ha = _hash_dict(a(ev))
            hb = _hash_dict(b(ev))
            assert ha == hb, f"Equivalence broken at step={i}"
    finally:
        patch.restore()

# ------------------------------------------------------------------------------
# Отладочная печать при падении (включается опционально)
# ------------------------------------------------------------------------------

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # При фейле — выводим профиль окружения для быстрой диагностики
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "call" and rep.failed:
        cfg = {
            "REPLAY_TARGET": os.getenv("REPLAY_TARGET", ""),
            "REPLAY_TARGET_A": os.getenv("REPLAY_TARGET_A", ""),
            "REPLAY_TARGET_B": os.getenv("REPLAY_TARGET_B", ""),
            "REPLAY_CASES": os.getenv("REPLAY_CASES", ""),
            "REPLAY_SEED": os.getenv("REPLAY_SEED", ""),
            "IGNORE_FIELDS": os.getenv("IGNORE_FIELDS", ""),
            "STRICT_JSON": os.getenv("STRICT_JSON", ""),
            "STABLE_TIME_BASE": os.getenv("STABLE_TIME_BASE", ""),
        }
        print("\n[replay-determinism] ENV:", json.dumps(cfg, ensure_ascii=False))
