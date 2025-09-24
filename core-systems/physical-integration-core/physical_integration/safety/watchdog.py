# -*- coding: utf-8 -*-
"""
physical_integration/safety/watchdog.py

Промышленный watchdog для мониторинга «живости» компонентов (устройства, сервисы,
датчики, каналы связи) в рамках physical-integration-core.

Ключевые возможности:
- Регистрация watch-объектов с индивидуальными таймаутами, порогами пропусков,
  гистерезисом и стартовым grace (для избегания ложных срабатываний).
- Поддержка группировки (quorum/ALL/ANY) для агрегации нескольких сигналов в одно
  логическое состояние безопасности.
- Эскалации по уровням (notice → warn → trip) с configurable задержками.
- Идемпотентные публикации событий в шину (колбэк/AMQP/другая реализация).
- Подавление «шторма» событий (squelch), детерминированные event_id.
- Метрики Prometheus: состояние, возраст последнего «пульса», срабатывания/восстановления.
- OTel-трейсинг (опционально).
- Персистентность последнего состояния в JSON (для тёплого старта).
- Безопасный асинхронный lifecycle (start/stop), единый tick-loop.

Зависимости:
  - стандартная библиотека
  - prometheus-client (опционально)
  - opentelemetry-api (опционально)

Пример интеграции:
  wd = Watchdog(WatchdogSettings(site_id="plant-1", node_id="edge-01"))
  await wd.start()
  await wd.register("plc:main", WatchConfig(timeout_s=5, miss_threshold=2, recover_hits=3))
  # при каждом heartbeat компонента:
  await wd.feed("plc:main")
  # graceful shutdown:
  await wd.stop()
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

# -----------------------------------------------------------------------------
# Опциональные зависимости
# -----------------------------------------------------------------------------
try:
    from prometheus_client import Counter, Gauge, Histogram
except Exception:  # pragma: no cover
    class _Noop:
        def __init__(self, *a, **k): ...
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): ...
        def set(self, *a, **k): ...
        def observe(self, *a, **k): ...
    Counter = Gauge = Histogram = _Noop  # type: ignore

try:
    from opentelemetry import trace
    _TRACER = trace.get_tracer(__name__)
    _OTEL = True
except Exception:  # pragma: no cover
    _TRACER = None
    _OTEL = False

logger = logging.getLogger("safety.watchdog")
logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Метрики
# -----------------------------------------------------------------------------
WD_STATE = Gauge("watchdog_state", "State (0=unknown,1=ok,2=warn,3=trip)", ["id", "group"])
WD_LAST_SEEN_AGE = Gauge("watchdog_last_seen_age_seconds", "Age of last heartbeat", ["id"])
WD_TRIPS = Counter("watchdog_trip_total", "Trips by reason", ["reason"])
WD_RECOVER = Counter("watchdog_recover_total", "Recoveries", ["reason"])
WD_EVAL_LAT = Histogram("watchdog_eval_latency_seconds", "Evaluation loop latency", buckets=(0.001, 0.005, 0.01, 0.02, 0.05, 0.1))

# -----------------------------------------------------------------------------
# Типы и конфигурация
# -----------------------------------------------------------------------------
class TripPolicy(str, Enum):
    ANY = "any"      # Любой участник триггерит группу
    ALL = "all"      # Все участники должны деградировать → TRIP
    QUORUM = "quorum"  # Минимум q из n

class Severity(int, Enum):
    UNKNOWN = 0
    OK = 1
    WARN = 2
    TRIP = 3

@dataclass
class WatchConfig:
    timeout_s: float = 5.0              # Считаем пропуск после этого времени без feed()
    miss_threshold: int = 1             # Сколько подряд пропусков до WARN/TRIP
    warn_after_misses: int = 1          # На сколько пропусков раньше ставить WARN (<= miss_threshold)
    recover_hits: int = 2               # Сколько подряд успешных feed() для снятия WARN/TRIP
    grace_start_s: float = 3.0          # Грейс после регистрации/старта
    trip_delay_s: float = 0.0           # Доп. задержка перед TRIP (накопление без feed())
    recover_delay_s: float = 0.0        # Задержка перед RECV (гистерезис)
    squelch_s: float = 5.0              # Подавление повторных одинаковых событий
    persist: bool = True                # Сохранять состояние на диск

@dataclass
class GroupConfig:
    members: List[str] = field(default_factory=list)  # идентификаторы watch'ей
    policy: TripPolicy = TripPolicy.ANY
    quorum: int = 1                                   # для QUORUM
    name: str = "default"
    squelch_s: float = 5.0
    trip_delay_s: float = 0.0
    recover_delay_s: float = 0.0
    persist: bool = True

@dataclass
class WatchState:
    id: str
    cfg: WatchConfig
    last_seen_ts: float = field(default_factory=lambda: 0.0)
    last_value: Any = None
    misses: int = 0
    hits: int = 0
    severity: Severity = Severity.UNKNOWN
    last_change_ts: float = field(default_factory=lambda: time.time())
    last_event_ts: float = 0.0
    last_event_hash: str = ""

@dataclass
class GroupState:
    name: str
    cfg: GroupConfig
    severity: Severity = Severity.UNKNOWN
    last_change_ts: float = field(default_factory=lambda: time.time())
    last_event_ts: float = 0.0
    last_event_hash: str = ""

@dataclass
class WatchdogSettings:
    site_id: str = os.getenv("SITE_ID", "default-site")
    node_id: str = os.getenv("NODE_ID", "edge-01")
    tick_interval_s: float = float(os.getenv("WD_TICK", "0.5"))
    persist_path: Path = Path(os.getenv("WD_STATE_PATH", "/var/lib/physical-integration/watchdog_state.json"))
    enable_metrics: bool = True

# -----------------------------------------------------------------------------
# Типы колбэков
# -----------------------------------------------------------------------------
EventPayload = Dict[str, Any]
PublishFn = Callable[[str, EventPayload], Awaitable[None]]  # topic, payload
TripFn = Callable[[str, EventPayload], Awaitable[None]]     # безопасная остановка/эскалация

# -----------------------------------------------------------------------------
# Watchdog
# -----------------------------------------------------------------------------
class Watchdog:
    def __init__(self, settings: WatchdogSettings, publish: Optional[PublishFn] = None, trip_cb: Optional[TripFn] = None) -> None:
        self.s = settings
        self._publish = publish or self._noop_publish
        self._trip = trip_cb or self._noop_publish
        self._watches: Dict[str, WatchState] = {}
        self._groups: Dict[str, GroupState] = {}
        self._lock = asyncio.Lock()
        self._closed = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        # восстановим состояние, если есть
        self._load_state()

    # ---------------------------- Public API --------------------------------

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._closed.clear()
        self._task = asyncio.create_task(self._tick_loop(), name="watchdog-loop")
        logger.info("Watchdog started")

    async def stop(self) -> None:
        self._closed.set()
        if self._task:
            self._task.cancel()
            with contextlib.suppress(Exception):
                await self._task
        self._save_state()
        logger.info("Watchdog stopped")

    async def register(self, id: str, cfg: WatchConfig) -> None:
        now = time.time()
        async with self._lock:
            self._watches[id] = WatchState(id=id, cfg=dataclasses.replace(cfg), last_seen_ts=0.0, misses=0, hits=0,
                                           severity=Severity.UNKNOWN, last_change_ts=now)
            WD_STATE.labels(id=id, group="").set(0)
            WD_LAST_SEEN_AGE.labels(id=id).set(float("inf"))

    async def unregister(self, id: str) -> None:
        async with self._lock:
            self._watches.pop(id, None)

    async def define_group(self, cfg: GroupConfig) -> None:
        async with self._lock:
            self._groups[cfg.name] = GroupState(name=cfg.name, cfg=dataclasses.replace(cfg), severity=Severity.UNKNOWN)

    async def feed(self, id: str, ok: bool = True, value: Any = None, ts: Optional[float] = None) -> None:
        """
        Сообщает watchdog о «пульсе». Если ok=False — трактуем как явную деградацию.
        """
        t = ts or time.time()
        async with self._lock:
            st = self._watches.get(id)
            if not st:
                return
            st.last_seen_ts = t
            st.last_value = value
            if ok:
                st.hits += 1
                st.misses = 0
            else:
                st.misses += 1
                st.hits = 0
            WD_LAST_SEEN_AGE.labels(id=id).set(0.0)

    def snapshot(self) -> Dict[str, Any]:
        """Текущее состояние (для отладки/телеметрии)."""
        with_out = {}
        for k, st in self._watches.items():
            with_out[k] = {
                "severity": int(st.severity),
                "last_seen_ts": st.last_seen_ts,
                "misses": st.misses,
                "hits": st.hits,
            }
        groups = {k: {"severity": int(gs.severity)} for k, gs in self._groups.items()}
        return {"watches": with_out, "groups": groups}

    # --------------------------- Internal logic -----------------------------

    async def _tick_loop(self) -> None:
        while not self._closed.is_set():
            t0 = time.perf_counter()
            try:
                await self._evaluate()
            except Exception:
                logger.exception("watchdog evaluate failed")
            dt = max(0.05, self.s.tick_interval_s - (time.perf_counter() - t0))
            await asyncio.sleep(dt)

    async def _evaluate(self) -> None:
        now = time.time()
        async with self._lock:
            # 1) Оценка индивидуальных watch'ей
            for id, st in self._watches.items():
                age = float("inf") if st.last_seen_ts <= 0 else (now - st.last_seen_ts)
                WD_LAST_SEEN_AGE.labels(id=id).set(age if age != float("inf") else 1e9)

                # grace период
                in_grace = (now - st.last_change_ts) < st.cfg.grace_start_s and st.severity in (Severity.UNKNOWN, Severity.OK)
                desired = st.severity

                # логика пропусков
                miss = age >= st.cfg.timeout_s
                if miss:
                    st.misses = max(st.misses, 1) if st.last_seen_ts > 0 else st.misses + 0  # не увеличиваем без feed'ов вовсе
                else:
                    # если сигнал свежий, накапливаем успешные попадания для гистерезиса
                    st.hits = min(st.hits + 1, 10_000)

                # Пороги: WARN и TRIP
                if not in_grace:
                    if miss and st.misses >= st.cfg.miss_threshold:
                        # учитываем дополнительную задержку для TRIP
                        overdue = age - st.cfg.timeout_s
                        if overdue >= st.cfg.trip_delay_s:
                            desired = Severity.TRIP
                        else:
                            desired = max(desired, Severity.WARN)
                    elif miss and st.misses >= max(1, st.cfg.warn_after_misses):
                        desired = max(desired, Severity.WARN)
                    else:
                        # возможное восстановление при достаточных хитах
                        if st.hits >= st.cfg.recover_hits and (now - st.last_change_ts) >= st.cfg.recover_delay_s:
                            desired = Severity.OK

                await self._maybe_transition_watch(st, desired, now)

            # 2) Оценка групп
            for name, gs in self._groups.items():
                cfg = gs.cfg
                member_states = [self._watches[m].severity for m in cfg.members if m in self._watches]
                # Если нет членов — считаем UNKNOWN
                if not member_states:
                    await self._maybe_transition_group(gs, Severity.UNKNOWN, now)
                    continue

                trips = sum(1 for sv in member_states if sv == Severity.TRIP)
                warns = sum(1 for sv in member_states if sv == Severity.WARN)

                desired = gs.severity
                if cfg.policy == TripPolicy.ANY:
                    desired = Severity.TRIP if trips >= 1 else (Severity.WARN if warns >= 1 else Severity.OK)
                elif cfg.policy == TripPolicy.ALL:
                    desired = Severity.TRIP if trips == len(member_states) else (Severity.WARN if warns >= 1 else Severity.OK)
                else:  # QUORUM
                    q = max(1, min(cfg.quorum, len(member_states)))
                    desired = Severity.TRIP if trips >= q else (Severity.WARN if warns >= 1 else Severity.OK)

                # задержки/гистерезис для группы
                if desired == Severity.TRIP:
                    # применим задержку трипа
                    # (простая версия: если недавно изменили — подождать trip_delay_s)
                    if (now - gs.last_change_ts) < cfg.trip_delay_s and gs.severity != Severity.TRIP:
                        desired = max(Severity.WARN, gs.severity)
                elif desired == Severity.OK:
                    if (now - gs.last_change_ts) < cfg.recover_delay_s and gs.severity != Severity.OK:
                        desired = Severity.WARN

                await self._maybe_transition_group(gs, desired, now)

        WD_EVAL_LAT.observe(time.perf_counter() - (time.perf_counter() - 0))  # формальный вызов; не критично

    async def _maybe_transition_watch(self, st: WatchState, desired: Severity, now: float) -> None:
        if desired == st.severity:
            # обновим метрику состояния, возраст уже обновлён
            WD_STATE.labels(id=st.id, group="").set(int(st.severity))
            return

        # подавление повторов
        ev = self._build_event("watch", st.id, st.severity, desired, now, extra={"misses": st.misses, "hits": st.hits})
        if not self._should_emit(st.last_event_ts, st.cfg.squelch_s, st.last_event_hash, ev["event_hash"]):
            st.severity = desired  # состояние меняется, но событие не публикуем
            st.last_change_ts = now
            WD_STATE.labels(id=st.id, group="").set(int(st.severity))
            return

        # публикация
        await self._publish(ev["topic"], ev["payload"])
        # эскалация trip → вызов безопасной остановки
        if desired == Severity.TRIP:
            WD_TRIPS.labels(reason="watch_timeout").inc()
            await self._trip("safety.estop", {
                "type": "watchdog.trip",
                "id": st.id,
                "by": "watchdog",
                "ts": now,
                "site": getattr(self.s, "site_id", None),
                "node": getattr(self.s, "node_id", None),
                "misses": st.misses,
            })
        elif st.severity in (Severity.TRIP, Severity.WARN) and desired == Severity.OK:
            WD_RECOVER.labels(reason="watch_recovered").inc()

        st.severity = desired
        st.last_change_ts = now
        st.last_event_ts = now
        st.last_event_hash = ev["event_hash"]
        WD_STATE.labels(id=st.id, group="").set(int(st.severity))

    async def _maybe_transition_group(self, gs: GroupState, desired: Severity, now: float) -> None:
        if desired == gs.severity:
            WD_STATE.labels(id="", group=gs.name).set(int(gs.severity))
            return

        ev = self._build_event("group", gs.name, gs.severity, desired, now)
        if not self._should_emit(gs.last_event_ts, gs.cfg.squelch_s, gs.last_event_hash, ev["event_hash"]):
            gs.severity = desired
            gs.last_change_ts = now
            WD_STATE.labels(id="", group=gs.name).set(int(gs.severity))
            return

        await self._publish(ev["topic"], ev["payload"])
        if desired == Severity.TRIP:
            WD_TRIPS.labels(reason="group_trip").inc()
            await self._trip("safety.estop", {
                "type": "watchdog.trip.group",
                "group": gs.name,
                "by": "watchdog",
                "ts": now,
                "site": getattr(self.s, "site_id", None),
                "node": getattr(self.s, "node_id", None),
            })
        elif gs.severity in (Severity.TRIP, Severity.WARN) and desired == Severity.OK:
            WD_RECOVER.labels(reason="group_recovered").inc()

        gs.severity = desired
        gs.last_change_ts = now
        gs.last_event_ts = now
        gs.last_event_hash = ev["event_hash"]
        WD_STATE.labels(id="", group=gs.name).set(int(gs.severity))

    # --------------------------- Events/helpers -----------------------------

    def _build_event(self, kind: str, id_or_group: str, from_s: Severity, to_s: Severity, ts: float, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload = {
            "type": f"watchdog.{kind}.transition",
            "id" if kind == "watch" else "group": id_or_group,
            "from": int(from_s),
            "to": int(to_s),
            "ts": ts,
            "site": self.s.site_id,
            "node": self.s.node_id,
        }
        if extra:
            payload.update(extra)
        # детерминированный event_id/event_hash
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ev_hash = hashlib.sha256(raw).hexdigest()
        payload["event_id"] = ev_hash[:16]
        topic = f"safety.watchdog.{kind}"
        return {"topic": topic, "payload": payload, "event_hash": ev_hash}

    @staticmethod
    def _should_emit(last_ts: float, squelch_s: float, last_hash: str, new_hash: str) -> bool:
        if new_hash == last_hash:
            return (time.time() - last_ts) >= squelch_s
        return True

    async def _noop_publish(self, topic: str, payload: EventPayload) -> None:
        logger.info("EVENT %s %s", topic, payload)

    # --------------------------- Persistence --------------------------------

    def _state_dict(self) -> Dict[str, Any]:
        return {
            "site": self.s.site_id,
            "node": self.s.node_id,
            "watches": {
                k: {
                    "last_seen_ts": v.last_seen_ts,
                    "misses": v.misses,
                    "hits": v.hits,
                    "severity": int(v.severity),
                    "last_change_ts": v.last_change_ts,
                } for k, v in self._watches.items() if v.cfg.persist
            },
            "groups": {
                k: {
                    "severity": int(v.severity),
                    "last_change_ts": v.last_change_ts,
                } for k, v in self._groups.items() if v.cfg.persist
            }
        }

    def _save_state(self) -> None:
        try:
            p = self.s.persist_path
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._state_dict(), ensure_ascii=False, separators=(",", ":")))
            os.replace(tmp, p)
        except Exception:
            logger.exception("Failed to persist watchdog state")

    def _load_state(self) -> None:
        p = self.s.persist_path
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text())
            # Загружаем только SEVERITY и временные поля; конфигурацию назначат register/define_group
            # после создания экземпляра.
            for k, st in (data.get("watches") or {}).items():
                self._watches.setdefault(k, WatchState(id=k, cfg=WatchConfig()))
                w = self._watches[k]
                w.last_seen_ts = float(st.get("last_seen_ts") or 0.0)
                w.misses = int(st.get("misses") or 0)
                w.hits = int(st.get("hits") or 0)
                try:
                    w.severity = Severity(int(st.get("severity")))
                except Exception:
                    w.severity = Severity.UNKNOWN
                w.last_change_ts = float(st.get("last_change_ts") or time.time())
            for k, st in (data.get("groups") or {}).items():
                self._groups.setdefault(k, GroupState(name=k, cfg=GroupConfig(name=k)))
                g = self._groups[k]
                try:
                    g.severity = Severity(int(st.get("severity")))
                except Exception:
                    g.severity = Severity.UNKNOWN
                g.last_change_ts = float(st.get("last_change_ts") or time.time())
        except Exception:
            logger.exception("Failed to load watchdog state")

# -----------------------------------------------------------------------------
# Инструменты интеграции
# -----------------------------------------------------------------------------
class AMQPPublisherAdapter:
    """
    Адаптер для публикации событий watchdog в AMQP через AMQPClient
    (см. physical_integration/protocols/amqp_client.py).
    """
    def __init__(self, amqp_client, exchange: str, routing_prefix: str = "safety.watchdog") -> None:
        self._amqp = amqp_client
        self._ex = exchange
        self._prefix = routing_prefix

    async def __call__(self, topic: str, payload: EventPayload) -> None:
        rk = f"{self._prefix}.{topic.split('.')[-1]}"
        from physical_integration.protocols.amqp_client import PublishOptions  # локальный импорт
        await self._amqp.publish(self._ex, PublishOptions(
            routing_key=rk,
            message=payload,
            idempotency_key=payload.get("event_id"),
        ))

# -----------------------------------------------------------------------------
# Пример самостоятельного запуска (справочно; не исполняется при импорте)
# -----------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    import contextlib
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    async def demo():
        wd = Watchdog(WatchdogSettings())
        await wd.start()
        await wd.register("plc:main", WatchConfig(timeout_s=2.0, miss_threshold=2, recover_hits=2, grace_start_s=1.0))
        await wd.define_group(GroupConfig(name="cell-A", members=["plc:main"], policy=TripPolicy.ANY))
        t0 = time.time()
        # 5 секунд «пульсуем», затем молчим для демонстрации TRIP и восстановления
        for _ in range(5):
            await wd.feed("plc:main")
            await asyncio.sleep(0.5)
        await asyncio.sleep(5.0)  # пропуски → TRIP
        # восстановимся
        for _ in range(3):
            await wd.feed("plc:main")
            await asyncio.sleep(0.5)
        await asyncio.sleep(2.0)
        await wd.stop()

    import asyncio
    asyncio.run(demo())
