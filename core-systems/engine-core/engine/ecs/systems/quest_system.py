from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field, asdict, is_dataclass
from enum import IntEnum, Enum
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Callable

# Зависимости от ECS-ядра
from engine.ecs.world import World, System, CommandBuffer, Query, QueryBuilder

# ====== Опциональные метрики Prometheus ======
import os
_PROM_ENABLED = os.getenv("QUEST_PROMETHEUS", "true").lower() == "true"
_prom = None
if _PROM_ENABLED:
    try:
        from prometheus_client import Counter, Histogram, Gauge  # type: ignore

        class _Prom:
            def __init__(self):
                self.events = Counter("quest_events_total", "Quest events processed", ["type"])
                self.transitions = Counter("quest_state_transitions_total", "Quest FSM transitions", ["from", "to", "reason"])
                self.errors = Counter("quest_errors_total", "Quest errors", ["type"])
                self.tick_seconds = Histogram("quest_tick_seconds", "Quest system tick duration (s)", buckets=[0.0005, 0.001, 0.002, 0.005, 0.01, 0.02])
                self.active_quests = Gauge("quest_active_total", "Active quests in world", ["world"])
                self.objectives_left = Gauge("quest_objectives_left", "Remaining objectives per quest", ["world"])
        _prom = _Prom()
    except Exception:
        _prom = None


# ======================
# Компоненты квестов
# ======================

class QuestState(IntEnum):
    LOCKED = 0
    AVAILABLE = 10
    ACTIVE = 20
    COOLDOWN = 25
    COMPLETED = 30
    FAILED = 40
    EXPIRED = 45
    REWARDED = 50

class ObjectiveType(Enum):
    ACTION = "action"          # произвольное событие действия
    ITEM = "item"              # сбор/передача предметов
    LOCATION = "location"      # достижение координаты/зоны
    TIMER = "timer"            # ожидание/таймер
    CUSTOM = "custom"          # пользовательский предикат

@dataclass
class Objective:
    id: str
    type: ObjectiveType
    target: str                       # ключ/идентификатор цели (имя действия, item_id, zone_id и т.д.)
    required: int = 1                 # сколько требуется (например, 5 предметов)
    current: int = 0                  # прогресс
    extra: Dict[str, Any] = field(default_factory=dict)   # параметры: радиус, координаты, сравнения
    optional: bool = False            # если True — цель не блокирует завершение

    def is_done(self) -> bool:
        return self.current >= self.required

@dataclass
class Reward:
    type: str                         # "xp", "item", "currency", "flag", "unlock"
    amount: int = 0
    payload: Dict[str, Any] = field(default_factory=dict)

@dataclass
class QuestConfig:
    id: str
    name: str
    description: str = ""
    auto_accept: bool = True
    auto_complete: bool = True
    prerequisites: Set[str] = field(default_factory=set)      # id квестов-зависимостей
    mutually_exclusive: Set[str] = field(default_factory=set) # id несовместимых квестов
    expires_at_ts: Optional[float] = None                    # абсолютный дедлайн
    ttl_sec: Optional[float] = None                          # время на выполнение после активации
    cooldown_sec: float = 0.0                                # кулдаун после завершения/провала
    objectives: List[Objective] = field(default_factory=list)
    rewards: List[Reward] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)   # для UI/аналитики/баланса

@dataclass
class QuestStatus:
    state: QuestState = QuestState.LOCKED
    activated_ts: Optional[float] = None
    updated_ts: float = field(default_factory=lambda: time.time())
    expire_ts: Optional[float] = None
    cooldown_until_ts: Optional[float] = None

@dataclass
class QuestComponent:
    """
    Вешается на сущность-носителя (например, игрока/агента).
    catalog: неизменяемый каталог всех квестов (по id).
    log: журнал экземпляров квестов для этого носителя.
    """
    catalog: Dict[str, QuestConfig] = field(default_factory=dict)
    log: Dict[str, QuestStatus] = field(default_factory=dict)

    def ensure(self, qid: str) -> QuestStatus:
        st = self.log.get(qid)
        if not st:
            st = QuestStatus(state=QuestState.AVAILABLE if self._available_initial(qid) else QuestState.LOCKED)
            self.log[qid] = st
        return st

    def _available_initial(self, qid: str) -> bool:
        qc = self.catalog.get(qid)
        return bool(qc and qc.auto_accept)

@dataclass
class QuestTagComponent:
    """
    Допполезные флаги/теги сущности для условий квестов (уровень, фракция и т.д.)
    """
    tags: Dict[str, Any] = field(default_factory=dict)


# ======================
# События квестов
# ======================

@dataclass
class EvAction:
    actor_eid: int
    action: str
    amount: int = 1
    payload: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EvItem:
    actor_eid: int
    item_id: str
    amount: int = 1
    payload: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EvLocation:
    actor_eid: int
    zone_id: str
    pos: Tuple[float, float, float] | None = None
    payload: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EvTimer:
    actor_eid: int
    timer_id: str
    payload: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EvCustom:
    actor_eid: int
    key: str
    payload: Dict[str, Any] = field(default_factory=dict)


# ======================
# Утилиты сериализации
# ======================

def _to_jsonable(obj: Any) -> Any:
    from pydantic import BaseModel as _BM  # lazy import if present
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, _BM):  # type: ignore[misc]
        return obj.model_dump()
    if hasattr(obj, "__dict__"):
        return dict(obj.__dict__)
    return obj

# ======================
# Кастомные предикаты целей (hook API)
# ======================

ObjectivePredicate = Callable[[Objective, Dict[str, Any]], bool]
_CUSTOM_PREDICATES: Dict[str, ObjectivePredicate] = {}

def register_objective_predicate(name: str, fn: ObjectivePredicate) -> None:
    """Регистрация пользовательского предиката для ObjectiveType.CUSTOM (extra['predicate']=name)."""
    _CUSTOM_PREDICATES[name] = fn


# ======================
# Система квестов
# ======================

class QuestSystem(System):
    """
    Поток: события -> накопление прогресса -> валидация зависимостей -> переходы FSM -> награды/кулдауны.
    """
    def __init__(
        self,
        name: str = "QuestSystem",
        phase: str = "update",
        priority: int = 0,
        max_events_per_tick: int = 2048,
    ) -> None:
        self.name = name
        self.phase = phase
        self.priority = priority
        self._q_cache: Optional[Query] = None
        self._max_events = int(max_events_per_tick)

    # -------- Основной цикл --------
    async def run(self, world: World, dt: float) -> None:
        t0 = time.perf_counter()
        q = self._q_cache or world.query(QuestComponent)
        self._q_cache = q

        # 1) Обработка событий ограниченной пачкой (защита от штормов)
        events = self._drain_events(world, self._max_events)

        cb = world.command_buffer()

        # 2) Для каждого актора с QuestComponent — применить события
        for eid in world.view(q):
            qc: QuestComponent = world.get(eid, QuestComponent)
            tags: Optional[QuestTagComponent] = world.try_get(eid, QuestTagComponent)

            # 2.1 Просрочки/кулдауны/разблокировки по зависимостям
            self._update_timeouts(qc)
            self._unlock_by_dependencies(qc)

            # 2.2 Применить события к прогрессу
            for ev in events.get(eid, []):
                try:
                    self._apply_event(qc, ev, tags)
                except Exception:
                    if _prom:
                        _prom.errors.labels("apply_event").inc()
                    # проглатываем — квесты не должны падать игру/симуляцию

            # 2.3 FSM переходы: завершение, провал, выдача наград
            self._advance_fsm(world, eid, qc, cb)

            # 2.4 Сбор метрик
            if _prom:
                try:
                    active = sum(1 for st in qc.log.values() if st.state in (QuestState.ACTIVE, QuestState.AVAILABLE))
                    _prom.active_quests.labels(world.name).set(active)
                    remain = 0
                    for qid, st in qc.log.items():
                        if st.state == QuestState.ACTIVE:
                            conf = qc.catalog.get(qid)
                            if conf:
                                remain += sum(1 for o in conf.objectives if not o.optional and not o.is_done())
                    _prom.objectives_left.labels(world.name).set(remain)
                except Exception:
                    pass

        cb.apply()

        if _prom:
            try:
                _prom.tick_seconds.observe(max(0.0, time.perf_counter() - t0))
            except Exception:
                pass

    # -------- Событийный вход --------

    def _drain_events(self, world: World, budget: int) -> Dict[int, List[Any]]:
        events_by_actor: Dict[int, List[Any]] = {}

        def _pull(etype):
            batch = world.events.consume(etype)
            if _prom and batch:
                _prom.events.labels(etype.__name__).inc(len(batch))
            return batch

        # Порядок не важен, но бюджет ограничивает суммарное число
        all_batches: List[List[Any]] = [
            _pull(EvAction),
            _pull(EvItem),
            _pull(EvLocation),
            _pull(EvTimer),
            _pull(EvCustom),
        ]
        count = 0
        for batch in all_batches:
            for ev in batch:
                if count >= budget:
                    return events_by_actor
                events_by_actor.setdefault(ev.actor_eid, []).append(ev)
                count += 1
        return events_by_actor

    # -------- Тайминги, зависимости, кулдауны --------

    def _update_timeouts(self, qc: QuestComponent) -> None:
        now = time.time()
        for qid, st in qc.log.items():
            conf = qc.catalog.get(qid)
            if not conf:
                continue
            # общий дедлайн конфигурации
            if conf.expires_at_ts and st.state in (QuestState.AVAILABLE, QuestState.ACTIVE) and now >= conf.expires_at_ts:
                self._transition(st, QuestState.EXPIRED, reason="expires_at")
                continue
            # TTL после активации
            if conf.ttl_sec and st.state == QuestState.ACTIVE and st.activated_ts is not None:
                if now >= (st.activated_ts + conf.ttl_sec):
                    self._transition(st, QuestState.FAILED, reason="ttl")
                    # включим кулдаун если задан
                    self._apply_cooldown(st, conf, now)
            # окончание кулдауна
            if st.state == QuestState.COOLDOWN and st.cooldown_until_ts and now >= st.cooldown_until_ts:
                self._transition(st, QuestState.AVAILABLE, reason="cooldown_end")

    def _unlock_by_dependencies(self, qc: QuestComponent) -> None:
        # Если все prerequisites выполнены — делаем AVAILABLE
        for qid, conf in qc.catalog.items():
            st = qc.log.get(qid)
            if not st:
                continue
            if st.state in (QuestState.LOCKED,):
                if all((qc.log.get(pid) and qc.log[pid].state in (QuestState.COMPLETED, QuestState.REWARDED)) for pid in conf.prerequisites):
                    self._transition(st, QuestState.AVAILABLE, reason="deps_satisfied")

    # -------- Применение событий к прогрессу --------

    def _apply_event(self, qc: QuestComponent, ev: Any, tags: Optional[QuestTagComponent]) -> None:
        # Прогресс применяем только к ACTIVE квестам
        for qid, st in qc.log.items():
            if st.state != QuestState.ACTIVE:
                continue
            conf = qc.catalog.get(qid)
            if not conf:
                continue
            for obj in conf.objectives:
                if obj.is_done():
                    continue
                if self._obj_matches_event(obj, ev, tags):
                    amount = self._event_amount(ev)
                    obj.current = min(obj.required, obj.current + amount)
                    st.updated_ts = time.time()

    def _event_amount(self, ev: Any) -> int:
        if isinstance(ev, (EvAction, EvItem)):
            return max(1, int(ev.amount))
        return 1

    def _obj_matches_event(self, obj: Objective, ev: Any, tags: Optional[QuestTagComponent]) -> bool:
        if obj.type == ObjectiveType.ACTION and isinstance(ev, EvAction):
            return ev.action == obj.target and self._extra_match(obj, ev.payload, tags)
        if obj.type == ObjectiveType.ITEM and isinstance(ev, EvItem):
            return ev.item_id == obj.target and self._extra_match(obj, ev.payload, tags)
        if obj.type == ObjectiveType.LOCATION and isinstance(ev, EvLocation):
            return ev.zone_id == obj.target and self._extra_match(obj, {"pos": ev.pos, **ev.payload}, tags)
        if obj.type == ObjectiveType.TIMER and isinstance(ev, EvTimer):
            return ev.timer_id == obj.target and self._extra_match(obj, ev.payload, tags)
        if obj.type == ObjectiveType.CUSTOM and isinstance(ev, EvCustom):
            # extra.predicate — имя зарегистрированного предиката
            pred = obj.extra.get("predicate")
            fn = _CUSTOM_PREDICATES.get(pred)
            if fn:
                try:
                    return fn(obj, {"event": ev, "tags": tags.tags if tags else {}, **ev.payload})
                except Exception:
                    return False
        return False

    def _extra_match(self, obj: Objective, payload: Dict[str, Any], tags: Optional[QuestTagComponent]) -> bool:
        """
        Простые условия: equals, min/max, within_radius, require_tag, tag_equals, payload_equals.
        """
        ex = obj.extra or {}
        # Требуемый тег сущности
        req_tag = ex.get("require_tag")
        if req_tag and not (tags and req_tag in tags.tags):
            return False
        # Сравнение тегов
        tag_eq = ex.get("tag_equals")
        if tag_eq and tags:
            for k, v in (tag_eq or {}).items():
                if tags.tags.get(k) != v:
                    return False
        # Сравнение payload
        pay_eq = ex.get("payload_equals")
        if pay_eq:
            for k, v in (pay_eq or {}).items():
                if payload.get(k) != v:
                    return False
        # Числовые условия
        min_v = ex.get("min")
        if min_v is not None and payload.get("value", 0) < min_v:
            return False
        max_v = ex.get("max")
        if max_v is not None and payload.get("value", 0) > max_v:
            return False
        # Георадиус (если pos=(x,y,z) есть)
        if "within_radius" in ex:
            pos = payload.get("pos")
            center = ex.get("center")
            radius = float(ex.get("within_radius") or 0.0)
            if pos and center and radius > 0:
                try:
                    dx = float(pos[0]) - float(center[0])
                    dy = float(pos[1]) - float(center[1])
                    dz = float(pos[2]) - float(center[2])
                    if (dx*dx + dy*dy + dz*dz) > (radius * radius):
                        return False
                except Exception:
                    return False
            else:
                return False
        return True

    # -------- Машина состояний и награды --------

    def _advance_fsm(self, world: World, eid: int, qc: QuestComponent, cb: CommandBuffer) -> None:
        now = time.time()
        for qid, st in qc.log.items():
            conf = qc.catalog.get(qid)
            if not conf:
                continue

            # Авто-активация
            if st.state == QuestState.AVAILABLE and conf.auto_accept:
                self._activate(st, conf, reason="auto_accept")

            # Проверка несовместимости
            if st.state in (QuestState.AVAILABLE, QuestState.ACTIVE) and conf.mutually_exclusive:
                if any(qc.log.get(mid) and qc.log[mid].state in (QuestState.ACTIVE,) for mid in conf.mutually_exclusive):
                    # Блокируем этот квест как LOCKED, чтобы не нарушить эксклюзивность
                    self._transition(st, QuestState.LOCKED, reason="mutually_exclusive")
                    continue

            # Завершение
            if st.state == QuestState.ACTIVE:
                if self._all_required_done(conf):
                    if conf.auto_complete:
                        self._transition(st, QuestState.COMPLETED, reason="objectives_done")
                        self._apply_cooldown(st, conf, now)  # кулдаун будет после REWARDED, но фиксируем время
                        self._dispatch_rewards(world, eid, conf, cb)
                        self._transition(st, QuestState.REWARDED, reason="rewards_dispatched")
                    else:
                        self._transition(st, QuestState.COMPLETED, reason="objectives_done")
                else:
                    # проверка истечения TTL обрабатывается в _update_timeouts
                    pass

            # Состояния FINAL: COMPLETED/FAILED/EXPIRED -> COOLDOWN при наличии
            if st.state in (QuestState.FAILED, QuestState.EXPIRED) and conf.cooldown_sec > 0:
                self._apply_cooldown(st, conf, now)

    def _all_required_done(self, conf: QuestConfig) -> bool:
        for o in conf.objectives:
            if not o.optional and not o.is_done():
                return False
        return True

    def _activate(self, st: QuestStatus, conf: QuestConfig, reason: str) -> None:
        if st.state in (QuestState.AVAILABLE, QuestState.LOCKED):
            st.activated_ts = time.time()
            st.updated_ts = st.activated_ts
            st.state = QuestState.ACTIVE
            if conf.ttl_sec:
                st.expire_ts = st.activated_ts + conf.ttl_sec
            if _prom:
                _prom.transitions.labels("AVAILABLE", "ACTIVE", reason).inc()

    def _apply_cooldown(self, st: QuestStatus, conf: QuestConfig, now: float) -> None:
        if conf.cooldown_sec > 0:
            st.cooldown_until_ts = now + conf.cooldown_sec
            st.state = QuestState.COOLDOWN
            st.updated_ts = now
            if _prom:
                _prom.transitions.labels("ANY", "COOLDOWN", "cooldown_start").inc()

    def _transition(self, st: QuestStatus, new_state: QuestState, reason: str) -> None:
        old = st.state
        if old == new_state:
            return
        st.state = new_state
        st.updated_ts = time.time()
        if _prom:
            try:
                _prom.transitions.labels(old.name, new_state.name, reason).inc()
            except Exception:
                pass

    def _dispatch_rewards(self, world: World, eid: int, conf: QuestConfig, cb: CommandBuffer) -> None:
        """
        Вознаграждения отправляются событиями, чтобы остальной мир принял решение (начисление, права, локи).
        Можно интегрировать с системой инвентаря/валют/пермишенов.
        """
        for rw in conf.rewards:
            ev = {
                "type": "reward",
                "quest_id": conf.id,
                "reward": {
                    "type": rw.type,
                    "amount": rw.amount,
                    "payload": rw.payload,
                }
            }
            # Пример: публикуем в локальную шину мира через CommandBuffer.emit
            # Создадим специальный тип события как dict, либо определите строго типизированный класс EvReward.
            cb.emit(dict, {"actor_eid": eid, **ev})

    # ======================
    # API высокого уровня
    # ======================

    @staticmethod
    def grant(world: World, actor_eid: int, quest: QuestConfig) -> None:
        """
        Инициализировать/обновить каталог квестов для актора. Идемпотентно.
        """
        cb = world.command_buffer()
        qc = world.try_get(actor_eid, QuestComponent)
        if not qc:
            qc = QuestComponent(catalog={quest.id: quest}, log={})
            cb.set(actor_eid, qc)
        else:
            qc.catalog[quest.id] = quest
        cb.apply()

    @staticmethod
    def set_state(world: World, actor_eid: int, quest_id: str, new_state: QuestState) -> bool:
        qc = world.try_get(actor_eid, QuestComponent)
        if not qc or quest_id not in qc.log:
            return False
        st = qc.log[quest_id]
        st.state = new_state
        st.updated_ts = time.time()
        return True

    @staticmethod
    def snapshot(world: World, actor_eid: int) -> Dict[str, Any]:
        qc = world.try_get(actor_eid, QuestComponent)
        if not qc:
            return {"catalog": {}, "log": {}}
        def _ser(obj: Any) -> Any:
            return _to_jsonable(obj)
        return {
            "catalog": {qid: _ser(conf) for qid, conf in qc.catalog.items()},
            "log": {qid: _ser(st) for qid, st in qc.log.items()},
        }


# ======================
# Утилиты создания квестов
# ======================

def make_objective(
    id: str,
    type: ObjectiveType,
    target: str,
    *,
    required: int = 1,
    optional: bool = False,
    **extra: Any
) -> Objective:
    return Objective(id=id, type=type, target=target, required=required, optional=optional, extra=dict(extra))


def make_quest(
    id: str,
    name: str,
    *,
    description: str = "",
    objectives: Iterable[Objective],
    rewards: Iterable[Reward] = (),
    auto_accept: bool = True,
    auto_complete: bool = True,
    prerequisites: Iterable[str] = (),
    mutually_exclusive: Iterable[str] = (),
    ttl_sec: float | None = None,
    cooldown_sec: float = 0.0,
    expires_at_ts: float | None = None,
    metadata: Dict[str, Any] | None = None,
) -> QuestConfig:
    return QuestConfig(
        id=id,
        name=name,
        description=description,
        objectives=list(objectives),
        rewards=list(rewards),
        auto_accept=auto_accept,
        auto_complete=auto_complete,
        prerequisites=set(prerequisites),
        mutually_exclusive=set(mutually_exclusive),
        ttl_sec=ttl_sec,
        cooldown_sec=cooldown_sec,
        expires_at_ts=expires_at_ts,
        metadata=metadata or {},
    )


def reward(type: str, amount: int = 0, **payload: Any) -> Reward:
    return Reward(type=type, amount=amount, payload=payload)


__all__ = [
    "QuestSystem",
    "QuestState",
    "ObjectiveType",
    "Objective",
    "Reward",
    "QuestConfig",
    "QuestStatus",
    "QuestComponent",
    "QuestTagComponent",
    "EvAction",
    "EvItem",
    "EvLocation",
    "EvTimer",
    "EvCustom",
    "register_objective_predicate",
    "make_objective",
    "make_quest",
    "reward",
]
