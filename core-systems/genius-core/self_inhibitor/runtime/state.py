# core-systems/genius_core/security/self_inhibitor/runtime/state.py
from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Deque, Dict, Iterable, Optional, Tuple, Protocol, runtime_checkable

LOG = logging.getLogger("genius_core.security.self_inhibitor.runtime.state")
if not LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    LOG.addHandler(_h)
LOG.setLevel(logging.INFO)


Clock = Callable[[], float]  # epoch seconds


# =========================
# Нормализация ключей
# =========================

def normalize_key(*parts: str, namespace: str = "si") -> str:
    """
    Детерминированная нормализация ключа состояния.
    Пример: normalize_key("user:42", "post-message", namespace="cooldown") -> "cooldown|user:42|post-message"
    """
    cleaned = [str(p).strip() for p in parts if str(p).strip()]
    if not cleaned:
        raise ValueError("At least one non-empty part is required for key")
    return f"{namespace}|" + "|".join(cleaned)


# =========================
# События и исходы
# =========================

class Outcome(str, Enum):
    OK = "ok"               # успешная операция
    VIOLATION = "violation" # нарушение (триггер для страйков/кулдауна)
    ERROR = "error"         # техническая ошибка (может учитываться отдельно)


@dataclass(slots=True)
class Event:
    ts: float
    outcome: Outcome
    weight: float = 1.0
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"ts": self.ts, "outcome": self.outcome.value, "weight": self.weight, "note": self.note}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> Event:
        return Event(ts=float(d["ts"]), outcome=Outcome(str(d["outcome"])), weight=float(d.get("weight", 1.0)), note=str(d.get("note", "")))


# =========================
# Rolling-окно метрик
# =========================

@dataclass(slots=True)
class RollingWindow:
    """
    Счётчики в скользящем окне времени с дискретизацией по бакетам.
    Операции add()/stats() потокобезопасны при внешней синхронизации.
    """
    window_s: int = 60
    bucket_s: int = 5
    clock: Clock = time.time
    # buckets: start_ts -> (ok_sum, viol_sum, err_sum)
    buckets: Dict[int, Tuple[float, float, float]] = field(default_factory=dict)

    def _bucket_of(self, ts: Optional[float] = None) -> int:
        t = int(self.clock() if ts is None else ts)
        return (t // self.bucket_s) * self.bucket_s

    def _gc(self) -> None:
        cutoff = int(self.clock()) - self.window_s
        for b in list(self.buckets.keys()):
            if b < cutoff:
                self.buckets.pop(b, None)

    def add(self, outcome: Outcome, weight: float = 1.0, *, ts: Optional[float] = None) -> None:
        self._gc()
        b = self._bucket_of(ts)
        ok, viol, err = self.buckets.get(b, (0.0, 0.0, 0.0))
        if outcome == Outcome.OK:
            ok += weight
        elif outcome == Outcome.VIOLATION:
            viol += weight
        else:
            err += weight
        self.buckets[b] = (ok, viol, err)

    def stats(self) -> Dict[str, float]:
        self._gc()
        ok = viol = err = 0.0
        for o, v, e in self.buckets.values():
            ok += o; viol += v; err += e
        total = ok + viol + err
        return {
            "ok": ok,
            "violation": viol,
            "error": err,
            "total": total,
            "fail_ratio": (viol / total) if total > 0 else 0.0,
            "rate_per_sec": total / float(self.window_s) if self.window_s > 0 else 0.0,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_s": self.window_s,
            "bucket_s": self.bucket_s,
            "buckets": {str(k): list(v) for k, v in self.buckets.items()},
        }

    @staticmethod
    def from_dict(d: Dict[str, Any], clock: Clock = time.time) -> RollingWindow:
        rw = RollingWindow(window_s=int(d.get("window_s", 60)), bucket_s=int(d.get("bucket_s", 5)), clock=clock)
        buckets = {}
        for k, v in (d.get("buckets") or {}).items():
            b = int(k)
            ok, viol, err = v
            buckets[b] = (float(ok), float(viol), float(err))
        rw.buckets = buckets
        return rw


# =========================
# Кольцевой журнал событий
# =========================

@dataclass(slots=True)
class RingLog:
    """
    Лёгкий журнал последних N событий для отладки/аудита.
    """
    capacity: int = 64
    _q: Deque[Event] = field(default_factory=lambda: deque(maxlen=64))

    def append(self, e: Event) -> None:
        if self._q.maxlen != self.capacity:
            self._q = deque(self._q, maxlen=self.capacity)
        self._q.append(e)

    def tail(self, n: int = 10) -> Iterable[Event]:
        n = max(0, n)
        return list(self._q)[-n:]

    def to_list(self) -> list[Dict[str, Any]]:
        return [e.to_dict() for e in self._q]

    @staticmethod
    def from_list(items: Iterable[Dict[str, Any]], capacity: int = 64) -> RingLog:
        rl = RingLog(capacity=capacity)
        rl._q = deque((Event.from_dict(d) for d in items), maxlen=capacity)
        return rl


# =========================
# Модель состояния Self-Inhibitor
# =========================

@dataclass(slots=True)
class BreakerView:
    state: str = "closed"   # closed|open|half_open
    fails: int = 0
    open_until_ts: float = 0.0


@dataclass(slots=True)
class RuntimeState:
    """
    Единое состояние для self-inhibitor (поддерживает стратегии кулдауна, circuit breaker и метрики).
    """
    key: str
    version: int = 0                  # для CAS
    fencing_token: int = 0            # для «наиболее нового писателя»
    last_update_ts: float = field(default_factory=time.time)
    strikes: float = 0.0
    cooldown_until_ts: float = 0.0
    totals_ok: float = 0.0
    totals_violation: float = 0.0
    totals_error: float = 0.0
    rolling: RollingWindow = field(default_factory=RollingWindow)
    recent: RingLog = field(default_factory=lambda: RingLog(capacity=64))
    breaker: BreakerView = field(default_factory=BreakerView)
    # произвольные метаданные для конкретной стратегии
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ----- вычислимые представления -----
    def allowed_now(self, clock: Clock = time.time) -> bool:
        return max(0.0, self.cooldown_until_ts - float(clock())) <= 0.0 and self.breaker.state != "open"

    def retry_after_s(self, clock: Clock = time.time) -> float:
        return max(0.0, self.cooldown_until_ts - float(clock()))

    def to_snapshot(self) -> Dict[str, Any]:
        """
        Стабильное сериализуемое представление (например, для HTTP/JSON).
        """
        return {
            "key": self.key,
            "version": self.version,
            "fencing_token": self.fencing_token,
            "last_update_ts": self.last_update_ts,
            "strikes": self.strikes,
            "cooldown_until_ts": self.cooldown_until_ts,
            "totals": {
                "ok": self.totals_ok,
                "violation": self.totals_violation,
                "error": self.totals_error,
            },
            "rolling": self.rolling.to_dict(),
            "recent": self.recent.to_list(),
            "breaker": asdict(self.breaker),
            "metadata": self.metadata,
            "allowed_now": self.allowed_now(),
            "retry_after_s": self.retry_after_s(),
        }

    @staticmethod
    def from_dict(d: Dict[str, Any], clock: Clock = time.time) -> RuntimeState:
        rs = RuntimeState(
            key=str(d["key"]),
            version=int(d.get("version", 0)),
            fencing_token=int(d.get("fencing_token", 0)),
            last_update_ts=float(d.get("last_update_ts", clock())),
            strikes=float(d.get("strikes", 0.0)),
            cooldown_until_ts=float(d.get("cooldown_until_ts", 0.0)),
            totals_ok=float((d.get("totals") or {}).get("ok", 0.0)),
            totals_violation=float((d.get("totals") or {}).get("violation", 0.0)),
            totals_error=float((d.get("totals") or {}).get("error", 0.0)),
            rolling=RollingWindow.from_dict(d.get("rolling") or {}, clock=clock),
            recent=RingLog.from_list(d.get("recent") or [], capacity=64),
            breaker=BreakerView(**(d.get("breaker") or {})),
            metadata=dict(d.get("metadata") or {}),
        )
        return rs


# =========================
# Контракт хранилища
# =========================

@runtime_checkable
class StateStore(Protocol):
    """
    Абстракция хранилища состояния с CAS и TTL.
    """

    def get(self, key: str) -> Optional[RuntimeState]:
        ...

    def put(self, state: RuntimeState, *, ttl_s: float) -> None:
        """
        Безусловная запись (создание или замена). Версия и fencing_token обновляются внутри хранилища.
        """
        ...

    def cas(self, state: RuntimeState, *, prev_version: int, ttl_s: float) -> bool:
        """
        Compare-And-Set: применить, если текущая версия == prev_version. При успехе версия+token увеличиваются.
        """
        ...

    def update(self, key: str, mutator: Callable[[RuntimeState], RuntimeState], *, ttl_s: float) -> RuntimeState:
        """
        Универсальный атомарный апдейт: get -> mutate -> cas (с ретраями).
        """
        ...

    def delete(self, key: str) -> None:
        ...

    def now(self) -> float:
        ...


# =========================
# In-memory реализация
# =========================

class InMemoryStateStore(StateStore):
    """
    Потокобезопасное in-memory хранилище с TTL, версионированием и fencing-token.
    """

    def __init__(self, *, clock: Clock = time.time) -> None:
        self._data: Dict[str, Tuple[RuntimeState, float]] = {}
        self._lock = threading.RLock()
        self._clock = clock

    def _gc(self) -> None:
        now = self._clock()
        for k, (_, exp) in list(self._data.items()):
            if exp <= now:
                self._data.pop(k, None)

    def get(self, key: str) -> Optional[RuntimeState]:
        with self._lock:
            self._gc()
            item = self._data.get(key)
            if not item:
                return None
            state, exp = item
            if exp <= self._clock():
                self._data.pop(key, None)
                return None
            # возвращаем копию (сериализация/десериализация гарантирует немутируемость оригинала)
            return RuntimeState.from_dict(state.to_snapshot(), clock=self._clock)

    def put(self, state: RuntimeState, *, ttl_s: float) -> None:
        ttl_s = max(0.0, float(ttl_s))
        with self._lock:
            self._gc()
            cur = self._data.get(state.key)
            version = (cur[0].version + 1) if cur else 1
            token = (cur[0].fencing_token + 1) if cur else 1
            s = RuntimeState.from_dict(state.to_snapshot(), clock=self._clock)
            s.version = version
            s.fencing_token = token
            s.last_update_ts = self._clock()
            self._data[state.key] = (s, self._clock() + ttl_s)

    def cas(self, state: RuntimeState, *, prev_version: int, ttl_s: float) -> bool:
        ttl_s = max(0.0, float(ttl_s))
        with self._lock:
            self._gc()
            cur = self._data.get(state.key)
            if cur is None:
                # допускаем создание «с нуля» только если prev_version == 0
                if prev_version != 0:
                    return False
                new_state = RuntimeState.from_dict(state.to_snapshot(), clock=self._clock)
                new_state.version = 1
                new_state.fencing_token = 1
                new_state.last_update_ts = self._clock()
                self._data[state.key] = (new_state, self._clock() + ttl_s)
                return True

            cur_state, _ = cur
            if cur_state.version != prev_version:
                return False

            new_state = RuntimeState.from_dict(state.to_snapshot(), clock=self._clock)
            new_state.version = cur_state.version + 1
            new_state.fencing_token = cur_state.fencing_token + 1
            new_state.last_update_ts = self._clock()
            self._data[state.key] = (new_state, self._clock() + ttl_s)
            return True

    def update(self, key: str, mutator: Callable[[RuntimeState], RuntimeState], *, ttl_s: float) -> RuntimeState:
        attempts = 0
        while True:
            attempts += 1
            cur = self.get(key)
            if cur is None:
                # создаём пустое состояние и пытаемся применить
                cur = RuntimeState(key=key)
                mutated = mutator(RuntimeState.from_dict(cur.to_snapshot(), clock=self._clock))
                ok = self.cas(mutated, prev_version=0, ttl_s=ttl_s)
                if ok:
                    return self.get(key)  # type: ignore[return-value]
                continue

            prev_version = cur.version
            mutated = mutator(RuntimeState.from_dict(cur.to_snapshot(), clock=self._clock))
            if self.cas(mutated, prev_version=prev_version, ttl_s=ttl_s):
                return self.get(key)  # type: ignore[return-value]
            if attempts >= 10:
                raise RuntimeError("Too many CAS retries in InMemoryStateStore.update")

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def now(self) -> float:
        return float(self._clock())


# =========================
# Асинхронная обёртка
# =========================

class AsyncStateStore:
    """
    Простая асинхронная обёртка для совместимости с asyncio-кодом.
    """
    def __init__(self, store: StateStore) -> None:
        self._store = store

    async def get(self, key: str) -> Optional[RuntimeState]:
        return self._store.get(key)

    async def put(self, state: RuntimeState, *, ttl_s: float) -> None:
        self._store.put(state, ttl_s=ttl_s)

    async def cas(self, state: RuntimeState, *, prev_version: int, ttl_s: float) -> bool:
        return self._store.cas(state, prev_version=prev_version, ttl_s=ttl_s)

    async def update(self, key: str, mutator: Callable[[RuntimeState], RuntimeState], *, ttl_s: float) -> RuntimeState:
        return self._store.update(key, mutator, ttl_s=ttl_s)

    async def delete(self, key: str) -> None:
        self._store.delete(key)

    async def now(self) -> float:
        return self._store.now()


# =========================
# Хелперы обновления состояния
# =========================

def apply_event(state: RuntimeState, event: Event, *, cooldown_until_ts: Optional[float] = None) -> RuntimeState:
    """
    Обновляет агрегаты состояния с учётом события.
    Внешняя стратегия (например, CooldownStrategy) может задать новое окно кулдауна.
    """
    s = RuntimeState.from_dict(state.to_snapshot())
    # totals
    if event.outcome == Outcome.OK:
        s.totals_ok += event.weight
    elif event.outcome == Outcome.VIOLATION:
        s.totals_violation += event.weight
    else:
        s.totals_error += event.weight
    # rolling и журнал
    s.rolling.add(event.outcome, weight=event.weight, ts=event.ts)
    s.recent.append(event)
    # опционально — скорректировать strikes/cooldown (если стратегия уже посчитала)
    if cooldown_until_ts is not None:
        s.cooldown_until_ts = float(cooldown_until_ts)
    s.last_update_ts = event.ts
    return s


def set_strikes(state: RuntimeState, *, strikes: float, cooldown_until_ts: Optional[float] = None) -> RuntimeState:
    """
    Удобный helper для стратегий: массово обновить strikes/окно кулдауна.
    """
    s = RuntimeState.from_dict(state.to_snapshot())
    s.strikes = max(0.0, float(strikes))
    if cooldown_until_ts is not None:
        s.cooldown_until_ts = float(cooldown_until_ts)
    s.last_update_ts = time.time()
    return s


# =========================
# Пример локального запуска
# =========================

if __name__ == "__main__":
    store = InMemoryStateStore()
    key = normalize_key("user:42", "post-message", namespace="cooldown")

    # Инициализация
    base = RuntimeState(key=key)
    store.put(base, ttl_s=30)

    # Применим нарушение
    st1 = store.update(
        key,
        lambda s: apply_event(
            set_strikes(s, strikes=s.strikes + 1.0, cooldown_until_ts=store.now() + 2.0),
            Event(ts=store.now(), outcome=Outcome.VIOLATION, note="rate-limit"),
        ),
        ttl_s=30,
    )
    print("After violation:", json.dumps(st1.to_snapshot(), ensure_ascii=False, indent=2))

    # Применим успех
    st2 = store.update(
        key,
        lambda s: apply_event(
            set_strikes(s, strikes=max(0.0, s.strikes - 0.5)),  # мягкий спад
            Event(ts=store.now(), outcome=Outcome.OK, note="ok"),
        ),
        ttl_s=30,
    )
    print("After ok:", json.dumps(st2.to_snapshot(), ensure_ascii=False, indent=2))
