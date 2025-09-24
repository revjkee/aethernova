# -*- coding: utf-8 -*-
"""
Industrial-grade Effects System

Назначение:
- Управление кратковременными и постоянными эффектами на сущностях (бафы/дебафы/ауры/DoT/HoT/шоки/щиты и т.п.).
- Детерминированный порядок применения, кросс-платформенная воспроизводимость.
- Богатая политика стекинга, приоритеты, эксклюзивность и иммунитеты по тегам.
- Модификаторы статов: add / mul / override / clamp(min,max).
- Периодические тики (N раз в секунду) и единичные триггеры on_apply/on_remove.
- Кулдауны, условия (predicate), резисты/иммунитеты.
- Полная сериализация/восстановление состояния.

Зависимости: стандартная библиотека.
"""

from __future__ import annotations

import enum
import math
import time
import threading
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple, Set

# =============================================================================
# Детерминированный RNG (PCG-подобный, 64-bit state)
# =============================================================================

class DeterministicRNG:
    __slots__ = ("_state", "_inc")

    def __init__(self, seed: int, seq: int = 1442695040888963407):
        self._state = (seed & 0xFFFFFFFFFFFFFFFF) or 0x853C49E6748FEA9B
        self._inc = ((seq << 1) | 1) & 0xFFFFFFFFFFFFFFFF

    def _step(self) -> int:
        # LCG 64 -> xorshift
        old = self._state
        self._state = (old * 6364136223846793005 + self._inc) & 0xFFFFFFFFFFFFFFFF
        xorshifted = (((old >> 18) ^ old) >> 27) & 0xFFFFFFFF
        rot = (old >> 59) & 0x1F
        return ((xorshifted >> rot) | (xorshifted << ((-rot) & 31))) & 0xFFFFFFFF

    def rand_u32(self) -> int:
        return self._step()

    def rand_float01(self) -> float:
        return (self.rand_u32() & 0xFFFFFF) / float(1 << 24)

    def choice(self, n: int) -> int:
        if n <= 0:
            return 0
        # rejection-free for power of two; otherwise rejection loop
        while True:
            v = self.rand_u32()
            r = v % n
            if v - r <= 0xFFFFFFFF - (0xFFFFFFFF % n):
                return r

    def jump(self, steps: int) -> None:
        for _ in range(max(0, steps)):
            self._step()

    def snapshot(self) -> Dict[str, int]:
        return {"state": self._state, "inc": self._inc}

    def restore(self, data: Dict[str, int]) -> None:
        self._state = int(data["state"]) & 0xFFFFFFFFFFFFFFFF
        self._inc = int(data["inc"]) & 0xFFFFFFFFFFFFFFFF

# =============================================================================
# Модификаторы статов
# =============================================================================

class ModOp(enum.Enum):
    ADD = "add"
    MUL = "mul"            # умножение (после add)
    OVERRIDE = "override"  # жёсткая подмена итогового значения
    CLAMP = "clamp"        # ограничение min/max (на финале)

@dataclass(frozen=True)
class StatModifier:
    stat: str
    op: ModOp
    value: float | Tuple[float, float]  # для clamp -> (min,max)
    priority: int = 0                   # порядок внутри стадии
    source_effect: str = ""             # effect_id для трассировки
    tags: Set[str] = field(default_factory=set)

@dataclass
class StatBlock:
    """
    Хранит базовые значения и применяет модификаторы в стабильном порядке:
    1) ADD по возрастанию priority
    2) MUL по возрастанию priority
    3) OVERRIDE по убыванию priority (последний выигрывает)
    4) CLAMP по возрастанию priority
    """
    base: Dict[str, float] = field(default_factory=dict)

    def evaluate(self, mods: List[StatModifier]) -> Dict[str, float]:
        out = dict(self.base)
        by_stat: Dict[str, List[StatModifier]] = {}
        for m in mods:
            by_stat.setdefault(m.stat, []).append(m)

        for stat, arr in by_stat.items():
            v = out.get(stat, 0.0)
            adds = sorted((m for m in arr if m.op is ModOp.ADD), key=lambda x: x.priority)
            muls = sorted((m for m in arr if m.op is ModOp.MUL), key=lambda x: x.priority)
            ovs = sorted((m for m in arr if m.op is ModOp.OVERRIDE), key=lambda x: -x.priority)
            cls = sorted((m for m in arr if m.op is ModOp.CLAMP), key=lambda x: x.priority)

            for m in adds:
                v += float(m.value)  # type: ignore[arg-type]
            for m in muls:
                v *= float(m.value)  # type: ignore[arg-type]
            if ovs:
                v = float(ovs[0].value)  # самый приоритетный override
            for m in cls:
                mn, mx = m.value  # type: ignore[misc]
                v = max(float(mn), min(float(mx), v))
            out[stat] = v
        return out

# =============================================================================
# Эффекты: описания и инстансы
# =============================================================================

class StackPolicy(enum.Enum):
    NONE = "none"                # повторное применение игнорируется
    STACK = "stack"              # +1 стак (меняет силу/модификаторы)
    REFRESH = "refresh"          # обновить длительность, стак не меняется
    EXTEND = "extend"            # увеличить оставшееся время (+duration)
    LIMITED = "limited"          # стек с верхним пределом max_stacks

@dataclass(frozen=True)
class EffectSpec:
    effect_id: str                     # неизменный идентификатор типа эффекта
    name: str
    tags: Set[str] = field(default_factory=set)
    priority: int = 0                  # выше — применится позже (перекроет менее приоритетные override)
    exclusive_group: Optional[str] = None  # взаимное исключение внутри группы (оставляем более приоритетный)
    stack_policy: StackPolicy = StackPolicy.NONE
    max_stacks: int = 1
    duration_s: float = 0.0            # 0 => бесконечный
    tick_rate_hz: float = 0.0          # 0 => без тиков
    modifiers_factory: Optional[Callable[[int], List[StatModifier]]] = None  # по числу стаков
    on_apply: Optional[Callable[["EffectContext"], None]] = None
    on_tick: Optional[Callable[["EffectContext"], None]] = None
    on_remove: Optional[Callable[["EffectContext"], None]] = None
    conditions: Optional[Callable[["EffectContext"], bool]] = None  # условие допуска
    cooldown_s: float = 0.0

@dataclass
class EffectContext:
    entity_id: str
    time_now: float
    rng: DeterministicRNG
    stacks: int
    data: Dict[str, Any]
    engine: "EffectEngine"
    spec: EffectSpec

@dataclass
class EffectInstance:
    spec: EffectSpec
    source_id: str                       # от кого пришёл эффект (для логики дружеский/вражеский)
    started_at: float
    duration_s: float
    stacks: int = 1
    next_tick_at: float = 0.0
    data: Dict[str, Any] = field(default_factory=dict)
    immutable_id: str = ""               # уникальный id инстанса (для трекинга/сериализации)

    def remaining(self, now: float) -> float:
        if self.duration_s <= 0.0:
            return float("inf")
        end = self.started_at + self.duration_s
        return max(0.0, end - now)

    def expired(self, now: float) -> bool:
        return self.duration_s > 0.0 and (self.started_at + self.duration_s) <= now

# =============================================================================
# Политика иммунитетов/резистов
# =============================================================================

@dataclass
class ResistConfig:
    immune_tags: Set[str] = field(default_factory=set)   # полностью блокируем эффекты с этими тегами
    resist_scalar: Dict[str, float] = field(default_factory=dict)  # tag -> 0..1 множитель длительности/силы

    def is_immune(self, spec: EffectSpec) -> bool:
        return bool(self.immune_tags & spec.tags)

    def scale_for(self, spec: EffectSpec) -> float:
        # берём минимальный множитель по пересечению тегов; если пусто — 1.0
        scalars = [self.resist_scalar[t] for t in (self.resist_scalar.keys() & spec.tags)]
        return min(scalars) if scalars else 1.0

# =============================================================================
# Событийные хуки аудита/метрик (заглушки)
# =============================================================================

class Audit:
    @staticmethod
    def emit(event: str, payload: Dict[str, Any]) -> None:
        # В проде: вывод в трассировку/шину
        pass

class Metrics:
    @staticmethod
    def inc(name: str, **labels) -> None:
        pass

# =============================================================================
# Движок эффектов
# =============================================================================

@dataclass
class EntityState:
    stats: StatBlock = field(default_factory=StatBlock)
    resist: ResistConfig = field(default_factory=ResistConfig)
    active: Dict[str, EffectInstance] = field(default_factory=dict)  # key = immutable_id
    # индексы:
    by_spec: Dict[str, List[str]] = field(default_factory=dict)      # effect_id -> [immutable_id]
    cooldowns: Dict[str, float] = field(default_factory=dict)         # effect_id -> next_allowed_time

class EffectEngine:
    """
    Детализация:
    - Время — float сек, подается через update(now) для детерминизма.
    - Все операции идемпотентны по immutable_id (если указан).
    - Стек/эксклюзивность/иммунитеты применяются строго в порядке (см. apply()).
    """
    def __init__(self, seed: int = 1):
        self._entities: Dict[str, EntityState] = {}
        self._rng_base = seed & 0xFFFFFFFF
        self._lock = threading.RLock()

    # ------------- Entity lifecycle ------------- #

    def ensure(self, entity_id: str) -> EntityState:
        with self._lock:
            es = self._entities.get(entity_id)
            if es is None:
                es = EntityState()
                self._entities[entity_id] = es
            return es

    # ------------- Apply/Remove/Update ------------- #

    def _rng_for(self, entity_id: str, spec_id: str, salt: str = "") -> DeterministicRNG:
        h = (hash(entity_id) ^ (hash(spec_id) << 1) ^ (hash(salt) << 7) ^ self._rng_base) & 0xFFFFFFFFFFFFFFFF
        return DeterministicRNG(h, seq=0x5851F42D4C957F2D)

    def can_apply(self, entity_id: str, spec: EffectSpec, now: float) -> Tuple[bool, str]:
        es = self.ensure(entity_id)
        if es.cooldowns.get(spec.effect_id, 0.0) > now:
            return False, "cooldown"
        if es.resist.is_immune(spec):
            return False, "immune"
        return True, ""

    def apply(
        self,
        entity_id: str,
        spec: EffectSpec,
        *,
        now: float,
        source_id: str = "",
        immutable_id: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Возвращает immutable_id созданного/обновленного инстанса или None, если отклонено.
        """
        ok, reason = self.can_apply(entity_id, spec, now)
        if not ok:
            Audit.emit("effect_rejected", {"entity": entity_id, "spec": spec.effect_id, "reason": reason})
            return None

        es = self.ensure(entity_id)
        iid = immutable_id or f"{spec.effect_id}#{len(es.active)+1}@{int(now*1000)}"
        if iid in es.active:
            # повторная попытка с тем же id — идемпотентность
            return iid

        # эксклюзивность: выбросим менее приоритетные эффекты в группе
        if spec.exclusive_group:
            victims: List[str] = []
            for eid in list(es.by_spec.keys()):
                for existing_id in es.by_spec[eid]:
                    inst = es.active[existing_id]
                    if inst.spec.exclusive_group == spec.exclusive_group:
                        if inst.spec.priority <= spec.priority:
                            victims.append(existing_id)
            for vid in victims:
                self._remove_instance(entity_id, vid, now, reason="exclusive_preempt")

        # стек/продление
        current_ids = list(es.by_spec.get(spec.effect_id, []))
        if current_ids:
            # работаем с самым "молодым" по started_at
            current_ids.sort(key=lambda x: es.active[x].started_at, reverse=True)
            cur = es.active[current_ids[0]]
            if spec.stack_policy is StackPolicy.NONE:
                return current_ids[0]
            elif spec.stack_policy is StackPolicy.REFRESH:
                cur.started_at = now
                cur.duration_s = spec.duration_s * self.ensure(entity_id).resist.scale_for(spec)
                self._fire_on_apply(entity_id, cur, now, is_refresh=True)
                return current_ids[0]
            elif spec.stack_policy is StackPolicy.EXTEND:
                cur.duration_s += spec.duration_s * self.ensure(entity_id).resist.scale_for(spec)
                return current_ids[0]
            else:
                # STACK / LIMITED
                if spec.stack_policy is StackPolicy.LIMITED:
                    cur.stacks = min(spec.max_stacks, cur.stacks + 1)
                else:
                    cur.stacks += 1
                # обновим модификаторы через on_apply (если нужно) и длительность — обычно НЕ сбрасываем
                self._fire_on_apply(entity_id, cur, now, is_refresh=False)
                return current_ids[0]

        # новый инстанс
        scaled = spec.duration_s * es.resist.scale_for(spec)
        inst = EffectInstance(
            spec=spec,
            source_id=source_id,
            started_at=now,
            duration_s=scaled,
            stacks=1,
            next_tick_at=(now + (1.0 / spec.tick_rate_hz) if spec.tick_rate_hz > 0 else float("inf")),
            data=data or {},
            immutable_id=iid,
        )

        # проверим условие допуска
        if spec.conditions:
            ctx = self._mk_ctx(entity_id, inst, now)
            if not spec.conditions(ctx):
                Audit.emit("effect_rejected", {"entity": entity_id, "spec": spec.effect_id, "reason": "conditions"})
                return None

        es.active[iid] = inst
        es.by_spec.setdefault(spec.effect_id, []).append(iid)

        # кулдаун
        if spec.cooldown_s > 0:
            es.cooldowns[spec.effect_id] = now + spec.cooldown_s

        self._fire_on_apply(entity_id, inst, now, is_refresh=False)
        return iid

    def _mk_ctx(self, entity_id: str, inst: EffectInstance, now: float) -> EffectContext:
        rng = self._rng_for(entity_id, inst.spec.effect_id, inst.immutable_id)
        return EffectContext(
            entity_id=entity_id,
            time_now=now,
            rng=rng,
            stacks=inst.stacks,
            data=inst.data,
            engine=self,
            spec=inst.spec,
        )

    def _fire_on_apply(self, entity_id: str, inst: EffectInstance, now: float, *, is_refresh: bool) -> None:
        ctx = self._mk_ctx(entity_id, inst, now)
        if inst.spec.on_apply:
            inst.spec.on_apply(ctx)
        Metrics.inc("effect_apply", effect=inst.spec.effect_id, entity=entity_id, refresh=is_refresh)
        Audit.emit("effect_apply", {"entity": entity_id, "effect": inst.spec.effect_id, "iid": inst.immutable_id, "stacks": inst.stacks})

    def _remove_instance(self, entity_id: str, iid: str, now: float, reason: str = "expired") -> None:
        es = self.ensure(entity_id)
        inst = es.active.pop(iid, None)
        if not inst:
            return
        arr = es.by_spec.get(inst.spec.effect_id)
        if arr:
            try:
                arr.remove(iid)
                if not arr:
                    es.by_spec.pop(inst.spec.effect_id, None)
            except ValueError:
                pass
        if inst.spec.on_remove:
            inst.spec.on_remove(self._mk_ctx(entity_id, inst, now))
        Metrics.inc("effect_remove", effect=inst.spec.effect_id, entity=entity_id, reason=reason)
        Audit.emit("effect_remove", {"entity": entity_id, "effect": inst.spec.effect_id, "iid": iid, "reason": reason})

    def dispel_by_tag(self, entity_id: str, tag: str, now: float) -> int:
        es = self.ensure(entity_id)
        rm: List[str] = [iid for iid, inst in es.active.items() if tag in inst.spec.tags]
        for iid in rm:
            self._remove_instance(entity_id, iid, now, reason="dispel_tag")
        return len(rm)

    def update(self, now: float, *, tick_budget_per_entity: int = 64) -> None:
        """
        Продвигает таймеры и выполняет тики.
        tick_budget_per_entity — хард‑лимит на количество тиков за вызов (против штормов).
        """
        with self._lock:
            for entity_id, es in self._entities.items():
                # удаление истёкших (сначала — чтобы не тикать мёртвых)
                expired: List[str] = [iid for iid, inst in es.active.items() if inst.expired(now)]
                for iid in expired:
                    self._remove_instance(entity_id, iid, now, reason="expired")

                # тики
                ticked = 0
                # стабильный порядок: по priority, затем по started_at, затем по immutable_id
                live = list(es.active.values())
                live.sort(key=lambda i: (i.spec.priority, i.started_at, i.immutable_id))
                for inst in live:
                    if ticked >= tick_budget_per_entity:
                        break
                    if inst.spec.tick_rate_hz <= 0:
                        continue
                    while inst.next_tick_at <= now and ticked < tick_budget_per_entity:
                        if inst.spec.on_tick:
                            inst.spec.on_tick(self._mk_ctx(entity_id, inst, inst.next_tick_at))
                        ticked += 1
                        inst.next_tick_at += 1.0 / inst.spec.tick_rate_hz
                        # чтобы не копился дрейф при больших пропусках кадров:
                        if now - inst.next_tick_at > (5.0 / inst.spec.tick_rate_hz):
                            inst.next_tick_at = now + (1.0 / inst.spec.tick_rate_hz)

    # ------------- Вычисление итоговых модов/статов ------------- #

    def collect_modifiers(self, entity_id: str) -> List[StatModifier]:
        es = self.ensure(entity_id)
        mods: List[StatModifier] = []
        for iid, inst in es.active.items():
            if inst.spec.modifiers_factory:
                cur = inst.spec.modifiers_factory(inst.stacks) or []
                # проставим метаданные источника
                cur = [StatModifier(m.stat, m.op, m.value, m.priority, inst.spec.effect_id, set(m.tags)) for m in cur]
                mods.extend(cur)
        # конфликт в exclusive_group уже снят при apply(), но дополнительно выровняем по приоритету
        mods.sort(key=lambda m: (m.priority, m.stat, m.source_effect))
        return mods

    def evaluate_stats(self, entity_id: str) -> Dict[str, float]:
        es = self.ensure(entity_id)
        mods = self.collect_modifiers(entity_id)
        # для стабильности: сначала сгруппированы моды, затем StatBlock применяет в фиксированном порядке
        return es.stats.evaluate(mods)

    # ------------- Снапшоты ------------- #

    def snapshot(self, entity_id: Optional[str] = None) -> Dict[str, Any]:
        if entity_id:
            return {entity_id: self._snapshot_entity(self.ensure(entity_id))}
        return {eid: self._snapshot_entity(es) for eid, es in self._entities.items()}

    def _snapshot_entity(self, es: EntityState) -> Dict[str, Any]:
        return {
            "stats": dict(es.stats.base),
            "resist": {
                "immune_tags": list(es.resist.immune_tags),
                "resist_scalar": dict(es.resist.resist_scalar),
            },
            "cooldowns": dict(es.cooldowns),
            "active": {
                iid: {
                    "spec": self._spec_to_dict(inst.spec),
                    "source_id": inst.source_id,
                    "started_at": inst.started_at,
                    "duration_s": inst.duration_s,
                    "stacks": inst.stacks,
                    "next_tick_at": inst.next_tick_at,
                    "data": dict(inst.data),
                }
                for iid, inst in es.active.items()
            },
            "by_spec": {k: list(v) for k, v in es.by_spec.items()},
        }

    @staticmethod
    def _spec_to_dict(spec: EffectSpec) -> Dict[str, Any]:
        return {
            "effect_id": spec.effect_id,
            "name": spec.name,
            "tags": list(spec.tags),
            "priority": spec.priority,
            "exclusive_group": spec.exclusive_group,
            "stack_policy": spec.stack_policy.value,
            "max_stacks": spec.max_stacks,
            "duration_s": spec.duration_s,
            "tick_rate_hz": spec.tick_rate_hz,
            "cooldown_s": spec.cooldown_s,
            # функции не сериализуем; рабочий паттерн — ре-регистрация по effect_id при restore()
        }

    def restore(self, data: Dict[str, Any], *, specs: Dict[str, EffectSpec]) -> None:
        """
        Восстановление состояния. Требуется словарь зарегистрированных EffectSpec по effect_id
        для реконструкции ссылок и колбеков.
        """
        with self._lock:
            self._entities.clear()
            for eid, snap in data.items():
                es = EntityState()
                es.stats.base = dict(snap.get("stats") or {})
                r = snap.get("resist") or {}
                es.resist.immune_tags = set(r.get("immune_tags") or [])
                es.resist.resist_scalar = dict(r.get("resist_scalar") or {})
                es.cooldowns = dict(snap.get("cooldowns") or {})
                # active
                for iid, inst in (snap.get("active") or {}).items():
                    spec_id = inst["spec"]["effect_id"]
                    sp = specs.get(spec_id)
                    if not sp:
                        # если нет регистрации — пропускаем такой инстанс
                        continue
                    e = EffectInstance(
                        spec=sp,
                        source_id=inst["source_id"],
                        started_at=float(inst["started_at"]),
                        duration_s=float(inst["duration_s"]),
                        stacks=int(inst["stacks"]),
                        next_tick_at=float(inst["next_tick_at"]),
                        data=dict(inst.get("data") or {}),
                        immutable_id=iid,
                    )
                    es.active[iid] = e
                    es.by_spec.setdefault(sp.effect_id, []).append(iid)
                self._entities[eid] = es

# =============================================================================
# Примеры преднастроенных эффектов и использование
# =============================================================================

# Модификаторы урона/здоровья как демонстрация
def mod_add(stat: str, v: float, prio: int = 0, tags: Optional[Set[str]] = None) -> StatModifier:
    return StatModifier(stat=stat, op=ModOp.ADD, value=v, priority=prio, tags=tags or set())

def mod_mul(stat: str, v: float, prio: int = 0, tags: Optional[Set[str]] = None) -> StatModifier:
    return StatModifier(stat=stat, op=ModOp.MUL, value=v, priority=prio, tags=tags or set())

def mod_ovr(stat: str, v: float, prio: int = 0, tags: Optional[Set[str]] = None) -> StatModifier:
    return StatModifier(stat=stat, op=ModOp.OVERRIDE, value=v, priority=prio, tags=tags or set())

def mod_clamp(stat: str, minn: float, maxx: float, prio: int = 0, tags: Optional[Set[str]] = None) -> StatModifier:
    return StatModifier(stat=stat, op=ModOp.CLAMP, value=(minn, maxx), priority=prio, tags=tags or set())

# Библиотека спецификаций (обычно регистрируется в DI/каталоге)
def spec_regeneration() -> EffectSpec:
    def _mods(stacks: int) -> List[StatModifier]:
        # +2 HP/s за стак, применяется как add к "regen_hp"
        return [mod_add("regen_hp", 2.0 * stacks, prio=10, tags={"healing", "hot"})]
    def _tick(ctx: EffectContext) -> None:
        # можно использовать ctx.engine для записи в состояние сущности
        # здесь — просто аудит тика
        Audit.emit("tick_regen", {"entity": ctx.entity_id, "stacks": ctx.stacks, "time": ctx.time_now})
    return EffectSpec(
        effect_id="regen",
        name="Regeneration",
        tags={"buff", "healing"},
        priority=10,
        stack_policy=StackPolicy.LIMITED,
        max_stacks=5,
        duration_s=10.0,
        tick_rate_hz=2.0,
        modifiers_factory=_mods,
        on_tick=_tick,
        cooldown_s=0.5,
    )

def spec_bleed() -> EffectSpec:
    def _mods(stacks: int) -> List[StatModifier]:
        # отрицательная регенерация как урон в секунду
        return [mod_add("regen_hp", -1.5 * stacks, prio=20, tags={"dot", "bleed"})]
    return EffectSpec(
        effect_id="bleed",
        name="Bleeding",
        tags={"debuff", "dot", "physical"},
        priority=20,
        stack_policy=StackPolicy.STACK,
        max_stacks=999,
        duration_s=6.0,
        tick_rate_hz=3.0,
        modifiers_factory=_mods,
    )

def spec_shield() -> EffectSpec:
    def _mods(stacks: int) -> List[StatModifier]:
        # override ставит минимальное значение урона в ноль (пример clamp/override)
        return [mod_add("shield_points", 50.0 * stacks, prio=100, tags={"shield"})]
    return EffectSpec(
        effect_id="shield",
        name="Barrier",
        tags={"buff", "shield", "magical"},
        priority=100,
        exclusive_group="barrier",
        stack_policy=StackPolicy.REFRESH,
        duration_s=8.0,
        modifiers_factory=_mods,
        cooldown_s=2.0,
    )

# =============================================================================
# Демонстрация (локальный smoke)
# =============================================================================

if __name__ == "__main__":
    eng = EffectEngine(seed=1234)
    p = "player-1"

    # Базовые статы
    es = eng.ensure(p)
    es.stats.base = {"hp": 100.0, "regen_hp": 0.0, "shield_points": 0.0}

    # Иммунитет к bleed
    es.resist.immune_tags.add("poison")  # не влияет на bleed
    es.resist.resist_scalar["dot"] = 0.8 # все dot короче на 20%

    now = 0.0
    regen = spec_regeneration()
    bleed = spec_bleed()
    shield = spec_shield()

    # Применяем эффекты
    eng.apply(p, regen, now=now)
    eng.apply(p, bleed, now=now)         # срезается по resist_scalar(dot)
    eng.apply(p, shield, now=now)

    # Обновляем время и считаем статы
    for step in range(0, 30):
        now = step * 0.5
        eng.update(now)
        vals = eng.evaluate_stats(p)
        print(f"t={now:4.1f}s  regen_hp={vals.get('regen_hp',0):.2f}  shield={vals.get('shield_points',0):.1f}  effects={len(eng.ensure(p).active)}")

    # Снапшот/восстановление
    snap = eng.snapshot()
    eng2 = EffectEngine(seed=1234)
    # регистрируем доступные спецификации
    registry = {s.effect_id: s for s in [regen, bleed, shield]}
    eng2.restore(snap, specs=registry)
    print("restored mods:", len(eng2.collect_modifiers(p)))
