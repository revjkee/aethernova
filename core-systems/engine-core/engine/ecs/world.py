from __future__ import annotations

import asyncio
import json
import time
from dataclasses import asdict, is_dataclass
from typing import Any, Callable, Coroutine, Dict, Generic, Iterable, List, Optional, Protocol, Set, Tuple, Type, TypeVar

# ========== Опциональные метрики Prometheus ==========
import os

_PROM_ENABLED = os.getenv("ECS_PROMETHEUS", "true").lower() == "true"
_prom = None
if _PROM_ENABLED:
    try:
        from prometheus_client import Counter, Gauge, Histogram  # type: ignore

        class _Prom:
            def __init__(self):
                self.entities = Gauge("ecs_entities", "Number of alive entities", ["world"])
                self.components = Gauge("ecs_components_total", "Total components attached", ["world"])
                self.tick_seconds = Histogram(
                    "ecs_tick_seconds", "World update tick duration", ["world", "phase"],
                    buckets=[0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1]
                )
                self.events_pending = Gauge("ecs_events_pending", "Pending events in bus", ["world", "etype"])
                self.cmd_buffer_ops = Counter("ecs_cmd_buffer_ops_total", "Command buffer operations", ["world", "op"])
                self.systems = Gauge("ecs_systems_total", "Registered systems", ["world", "phase"])

        _prom = _Prom()
    except Exception:
        _prom = None


# ========== Базовые типы ==========
EID = int
C = TypeVar("C")  # Component type
T = TypeVar("T")

class Component(Protocol):
    """Маркёрный протокол для компонентов."""


class System(Protocol):
    """Протокол систем ECS (async)."""
    name: str
    phase: str  # "startup" | "update" | "fixed" | "shutdown"
    priority: int  # чем выше — тем раньше

    async def run(self, world: "World", dt: float) -> None:  # pragma: no cover - интерфейс
        ...


# ========== Исключения ==========
class ECSException(Exception): ...
class EntityNotFound(ECSException): ...
class ComponentNotRegistered(ECSException): ...
class ComponentNotFound(ECSException): ...
class WorldClosed(ECSException): ...


# ========== Утилиты битовых масок ==========
class BitSet(int):
    __slots__ = ()
    def has_all(self, mask: "BitSet") -> bool:
        return (self & mask) == mask
    def has_any(self, mask: "BitSet") -> bool:
        return (self & mask) != 0


# ========== Реестр компонентов ==========
class ComponentRegistry:
    def __init__(self) -> None:
        self._type_to_bit: Dict[Type[Any], BitSet] = {}
        self._bit_to_type: Dict[BitSet, Type[Any]] = {}
        self._next_bit: int = 0

    def register(self, ctype: Type[C]) -> BitSet:
        if ctype in self._type_to_bit:
            return self._type_to_bit[ctype]
        if self._next_bit >= 63:
            # при желании поменять на big-int битсеты (Python int и так безразмерный),
            # здесь лишь логический барьер для контроля количества типов
            pass
        bit = BitSet(1 << self._next_bit)
        self._next_bit += 1
        self._type_to_bit[ctype] = bit
        self._bit_to_type[bit] = ctype
        return bit

    def bit(self, ctype: Type[C]) -> BitSet:
        if ctype not in self._type_to_bit:
            raise ComponentNotRegistered(f"Component {ctype.__name__} is not registered")
        return self._type_to_bit[ctype]

    def types(self) -> Iterable[Type[Any]]:
        return self._type_to_bit.keys()


# ========== Управление сущностями ==========
class EntityStore:
    def __init__(self) -> None:
        self._alive: Set[EID] = set()
        self._versions: Dict[EID, int] = {}
        self._free: List[EID] = []
        self._next_id: EID = 1

    def create(self) -> Tuple[EID, int]:
        if self._free:
            eid = self._free.pop()
            ver = self._versions[eid] = (self._versions.get(eid, 0) + 1) & 0xFFFFFFFF
        else:
            eid = self._next_id
            self._next_id += 1
            ver = self._versions[eid] = 1
        self._alive.add(eid)
        return eid, ver

    def destroy(self, eid: EID) -> None:
        if eid not in self._alive:
            raise EntityNotFound(f"Entity {eid} not found")
        self._alive.remove(eid)
        self._free.append(eid)

    def is_alive(self, eid: EID) -> bool:
        return eid in self._alive

    def version(self, eid: EID) -> int:
        if eid not in self._versions:
            raise EntityNotFound(f"Entity {eid} not found")
        return self._versions[eid]

    def all(self) -> Iterable[EID]:
        return iter(self._alive)

    def count(self) -> int:
        return len(self._alive)


# ========== Хранилище компонентов ==========
class ComponentStore:
    def __init__(self, registry: ComponentRegistry) -> None:
        self._registry = registry
        self._by_type: Dict[Type[Any], Dict[EID, Any]] = {}
        self._signature: Dict[EID, BitSet] = {}
        self._count: int = 0

    def signature(self, eid: EID) -> BitSet:
        return self._signature.get(eid, BitSet(0))

    def add(self, eid: EID, comp: Any) -> None:
        ctype = type(comp)
        bit = self._registry.register(ctype)
        bucket = self._by_type.setdefault(ctype, {})
        replaced = eid in bucket
        bucket[eid] = comp
        prev = self._signature.get(eid, BitSet(0))
        self._signature[eid] = BitSet(prev | bit)
        if not replaced:
            self._count += 1

    def get(self, eid: EID, ctype: Type[C]) -> C:
        bucket = self._by_type.get(ctype)
        if not bucket or eid not in bucket:
            raise ComponentNotFound(f"Entity {eid} has no {ctype.__name__}")
        return bucket[eid]  # type: ignore[return-value]

    def try_get(self, eid: EID, ctype: Type[C]) -> Optional[C]:
        bucket = self._by_type.get(ctype)
        if not bucket:
            return None
        return bucket.get(eid)  # type: ignore[return-value]

    def remove(self, eid: EID, ctype: Type[C]) -> bool:
        bucket = self._by_type.get(ctype)
        if not bucket or eid not in bucket:
            return False
        del bucket[eid]
        bit = self._registry.bit(ctype)
        prev = self._signature.get(eid, BitSet(0))
        self._signature[eid] = BitSet(prev & ~bit)
        self._count -= 1
        return True

    def remove_entity(self, eid: EID) -> None:
        sig = self._signature.pop(eid, BitSet(0))
        # быстро обойти все типы в сигнатуре
        for ctype, bucket in self._by_type.items():
            if eid in bucket:
                del bucket[eid]
                self._count -= 1

    def has(self, eid: EID, ctype: Type[C]) -> bool:
        return eid in self._by_type.get(ctype, {})

    def count(self) -> int:
        return self._count

    def iterate(self, ctype: Type[C]) -> Iterable[Tuple[EID, C]]:
        bucket = self._by_type.get(ctype, {})
        for eid, comp in bucket.items():
            yield eid, comp  # type: ignore[misc]


# ========== Запросы ==========
class Query:
    __slots__ = ("include", "exclude", "_cache_version", "_cache", "_compiled")

    def __init__(self, include: BitSet, exclude: BitSet) -> None:
        self.include = include
        self.exclude = exclude
        self._cache_version = -1
        self._cache: List[EID] = []
        self._compiled = (include, exclude)

    def match(self, sig: BitSet) -> bool:
        inc, exc = self._compiled
        return sig.has_all(inc) and not sig.has_any(exc)

    def compile(self) -> Tuple[BitSet, BitSet]:
        return self._compiled


class QueryBuilder:
    def __init__(self, reg: ComponentRegistry) -> None:
        self._reg = reg
        self._inc: BitSet = BitSet(0)
        self._exc: BitSet = BitSet(0)

    def include(self, *ctypes: Type[Any]) -> "QueryBuilder":
        for ct in ctypes:
            self._inc |= self._reg.register(ct)
        return self

    def exclude(self, *ctypes: Type[Any]) -> "QueryBuilder":
        for ct in ctypes:
            self._exc |= self._reg.register(ct)
        return self

    def build(self) -> Query:
        return Query(self._inc, self._exc)


# ========== Шина событий ==========
class EventBus:
    def __init__(self, world_name: str) -> None:
        self._queues: Dict[Type[Any], List[Any]] = {}
        self._world_name = world_name

    def emit(self, etype: Type[T], event: T) -> None:
        q = self._queues.setdefault(etype, [])
        q.append(event)
        if _prom:
            try:
                _prom.events_pending.labels(self._world_name, etype.__name__).set(len(q))
            except Exception:
                pass

    def consume(self, etype: Type[T]) -> List[T]:
        q = self._queues.get(etype, [])
        self._queues[etype] = []
        if _prom:
            try:
                _prom.events_pending.labels(self._world_name, etype.__name__).set(0)
            except Exception:
                pass
        return q  # type: ignore[return-value]

    def clear_all(self) -> None:
        for et, q in self._queues.items():
            q.clear()
            if _prom:
                try:
                    _prom.events_pending.labels(self._world_name, et.__name__).set(0)
                except Exception:
                    pass


# ========== Буфер команд ==========
class CommandBuffer:
    def __init__(self, world: "World") -> None:
        self._w = world
        self._ops: List[Tuple[str, Tuple[Any, ...]]] = []

    def create(self) -> None:
        self._ops.append(("create", tuple()))
        if _prom:
            try: _prom.cmd_buffer_ops.labels(self._w.name, "create").inc()
            except Exception: pass

    def destroy(self, eid: EID) -> None:
        self._ops.append(("destroy", (eid,)))
        if _prom:
            try: _prom.cmd_buffer_ops.labels(self._w.name, "destroy").inc()
            except Exception: pass

    def add(self, eid: EID, comp: Any) -> None:
        self._ops.append(("add", (eid, comp)))
        if _prom:
            try: _prom.cmd_buffer_ops.labels(self._w.name, "add").inc()
            except Exception: pass

    def set(self, eid: EID, comp: Any) -> None:
        self._ops.append(("set", (eid, comp)))
        if _prom:
            try: _prom.cmd_buffer_ops.labels(self._w.name, "set").inc()
            except Exception: pass

    def remove(self, eid: EID, ctype: Type[Any]) -> None:
        self._ops.append(("remove", (eid, ctype)))
        if _prom:
            try: _prom.cmd_buffer_ops.labels(self._w.name, "remove").inc()
            except Exception: pass

    def emit(self, etype: Type[T], event: T) -> None:
        self._ops.append(("emit", (etype, event)))
        if _prom:
            try: _prom.cmd_buffer_ops.labels(self._w.name, "emit").inc()
            except Exception: pass

    def apply(self) -> None:
        w = self._w
        for op, args in self._ops:
            if op == "create":
                w._create_entity()
            elif op == "destroy":
                w._destroy_entity(args[0])  # type: ignore[index]
            elif op == "add":
                w._add_component(args[0], args[1])  # type: ignore[index]
            elif op == "set":
                w._set_component(args[0], args[1])  # type: ignore[index]
            elif op == "remove":
                w._remove_component(args[0], args[1])  # type: ignore[index]
            elif op == "emit":
                w.events.emit(args[0], args[1])  # type: ignore[index]
        self._ops.clear()


# ========== Планировщик систем ==========
class _SystemEntry:
    __slots__ = ("system", "priority")
    def __init__(self, system: System) -> None:
        self.system = system
        self.priority = system.priority


# ========== Мир ==========
class World:
    """
    Высокопроизводительный ECS‑мир с системами, запросами и событийной шиной.
    Потокобезопасность обеспечивается через asyncio‑lock для публичных мутаций.
    """
    def __init__(self, name: str = "world", fixed_dt: float = 0.0166667) -> None:
        self.name = name
        self.registry = ComponentRegistry()
        self.entities = EntityStore()
        self.comps = ComponentStore(self.registry)
        self.events = EventBus(self.name)
        self._lock = asyncio.Lock()
        self._closed = False

        # системы по фазам
        self._systems: Dict[str, List[_SystemEntry]] = {
            "startup": [], "update": [], "fixed": [], "shutdown": []
        }
        self._fixed_dt = float(fixed_dt)
        self._accum = 0.0

        if _prom:
            try:
                _prom.entities.labels(self.name).set(0)
                _prom.components.labels(self.name).set(0)
                for phase in self._systems.keys():
                    _prom.systems.labels(self.name, phase).set(0)
            except Exception:
                pass

    # ---------- Регистрация систем ----------
    def add_system(self, system: System) -> None:
        phase = system.phase
        if phase not in self._systems:
            raise ECSException(f"Unknown phase: {phase}")
        self._systems[phase].append(_SystemEntry(system))
        self._systems[phase].sort(key=lambda e: e.priority, reverse=True)
        if _prom:
            try: _prom.systems.labels(self.name, phase).set(len(self._systems[phase]))
            except Exception: pass

    # ---------- Командный буфер ----------
    def command_buffer(self) -> CommandBuffer:
        return CommandBuffer(self)

    # ---------- Публичные мутации (деферринг рекомендован) ----------
    async def create(self) -> EID:
        async with self._lock:
            return self._create_entity()

    async def destroy(self, eid: EID) -> None:
        async with self._lock:
            self._destroy_entity(eid)

    async def add(self, eid: EID, comp: Any) -> None:
        async with self._lock:
            self._add_component(eid, comp)

    async def set(self, eid: EID, comp: Any) -> None:
        async with self._lock:
            self._set_component(eid, comp)

    async def remove(self, eid: EID, ctype: Type[Any]) -> None:
        async with self._lock:
            self._remove_component(eid, ctype)

    # ---------- Низкоуровневые операции (используются буфером команд) ----------
    def _create_entity(self) -> EID:
        eid, _ = self.entities.create()
        if _prom:
            try: _prom.entities.labels(self.name).set(self.entities.count())
            except Exception: pass
        return eid

    def _destroy_entity(self, eid: EID) -> None:
        if not self.entities.is_alive(eid):
            raise EntityNotFound(f"Entity {eid} not found")
        self.comps.remove_entity(eid)
        self.entities.destroy(eid)
        if _prom:
            try:
                _prom.entities.labels(self.name).set(self.entities.count())
                _prom.components.labels(self.name).set(self.comps.count())
            except Exception:
                pass

    def _add_component(self, eid: EID, comp: Any) -> None:
        if not self.entities.is_alive(eid):
            raise EntityNotFound(f"Entity {eid} not found")
        self.comps.add(eid, comp)
        if _prom:
            try: _prom.components.labels(self.name).set(self.comps.count())
            except Exception: pass

    def _set_component(self, eid: EID, comp: Any) -> None:
        # set = add с заменой экземпляра
        self._add_component(eid, comp)

    def _remove_component(self, eid: EID, ctype: Type[Any]) -> None:
        if not self.entities.is_alive(eid):
            raise EntityNotFound(f"Entity {eid} not found")
        if not self.comps.remove(eid, ctype):
            raise ComponentNotFound(f"Entity {eid} has no {ctype.__name__}")
        if _prom:
            try: _prom.components.labels(self.name).set(self.comps.count())
            except Exception: pass

    # ---------- Доступ к компонентам ----------
    def get(self, eid: EID, ctype: Type[C]) -> C:
        return self.comps.get(eid, ctype)

    def try_get(self, eid: EID, ctype: Type[C]) -> Optional[C]:
        return self.comps.try_get(eid, ctype)

    def has(self, eid: EID, ctype: Type[C]) -> bool:
        return self.comps.has(eid, ctype)

    # ---------- Запросы ----------
    def query(self, *include: Type[Any], exclude: Tuple[Type[Any], ...] = tuple()) -> Query:
        qb = QueryBuilder(self.registry).include(*include).exclude(*exclude)
        return qb.build()

    def view(self, q: Query) -> Iterable[EID]:
        # простой и быстрый проход по всем сущностям, матч по сигнатуре
        inc, exc = q.compile()
        for eid in self.entities.all():
            sig = self.comps.signature(eid)
            if sig.has_all(inc) and not sig.has_any(exc):
                yield eid

    # ---------- Цикл исполнения ----------
    async def _run_phase(self, phase: str, dt: float) -> None:
        if self._closed:
            raise WorldClosed("world is closed")
        systems = self._systems.get(phase, [])
        if not systems:
            return
        t0 = time.perf_counter()
        for entry in systems:
            await entry.system.run(self, dt)
        if _prom:
            try: _prom.tick_seconds.labels(self.name, phase).observe(max(0.0, time.perf_counter() - t0))
            except Exception: pass

    async def startup(self) -> None:
        await self._run_phase("startup", 0.0)

    async def shutdown(self) -> None:
        await self._run_phase("shutdown", 0.0)
        self._closed = True

    async def tick(self, dt: float) -> None:
        """Один кадр мира с фиксированной фазой."""
        # update
        await self._run_phase("update", dt)
        # fixed (аккумулятор)
        self._accum += dt
        while self._accum >= self._fixed_dt:
            await self._run_phase("fixed", self._fixed_dt)
            self._accum -= self._fixed_dt

    async def run(self, timestep: float = 0.0166667) -> None:
        """Простой цикл съсонным `sleep` (можно заменить сторонним лупом)."""
        await self.startup()
        prev = time.perf_counter()
        try:
            while not self._closed:
                now = time.perf_counter()
                dt = max(0.0, now - prev)
                prev = now
                await self.tick(dt)
                await asyncio.sleep(max(0.0, timestep))
        finally:
            await self.shutdown()

    # ---------- Сериализация/снепшоты ----------
    def snapshot(self) -> Dict[str, Any]:
        """Снимок всего мира (компоненты должны быть dataclass/Pydantic/JSON‑сериализуемы)."""
        data: Dict[str, Any] = {
            "name": self.name,
            "entities": list(self.entities.all()),
            "components": {},
        }
        for ctype in self.registry.types():
            bucket = self.comps._by_type.get(ctype, {})
            if not bucket:
                continue
            # сериализация компонентов
            items = []
            for eid, comp in bucket.items():
                items.append({"eid": eid, "data": _to_jsonable(comp)})
            data["components"][ctype.__module__ + ":" + ctype.__name__] = items
        return data

    def restore(self, data: Dict[str, Any], resolve: Callable[[str], Type[Any]]) -> None:
        """Восстановление из снимка. `resolve` должен вернуть тип компонента по строковому ключу."""
        for eid in list(self.entities.all()):
            self._destroy_entity(eid)
        for _ in data.get("entities", []):
            self._create_entity()
        for key, items in data.get("components", {}).items():
            ctype = resolve(key)
            for rec in items:
                eid = int(rec["eid"])
                comp = _from_jsonable(rec["data"], ctype)
                self._add_component(eid, comp)


# ========== Вспомогательные сериализация ==========
def _to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    try:
        from pydantic import BaseModel  # type: ignore
        if isinstance(obj, BaseModel):
            return obj.model_dump()
    except Exception:
        pass
    if hasattr(obj, "__dict__"):
        # последний шанс
        return dict(obj.__dict__)
    return obj


def _from_jsonable(data: Any, ctype: Type[T]) -> T:
    try:
        # dataclass
        return ctype(**data)  # type: ignore[arg-type]
    except Exception:
        try:
            from pydantic import BaseModel  # type: ignore
            if issubclass(ctype, BaseModel):
                return ctype.model_validate(data)  # type: ignore[return-value]
        except Exception:
            pass
        # как есть
        return data  # type: ignore[return-value]


# ========== Пример минимальной системы (для справки в коде) ==========
class IntervalSystem:
    """Пример системы, срабатывающей раз в N секунд (по накопителю)."""
    def __init__(self, name: str, phase: str, priority: int, interval: float, fn: Callable[[World], Coroutine[Any, Any, None]]) -> None:
        self.name = name
        self.phase = phase
        self.priority = priority
        self._interval = float(interval)
        self._accum = 0.0
        self._fn = fn

    async def run(self, world: World, dt: float) -> None:
        self._accum += dt
        if self._accum >= self._interval:
            self._accum -= self._interval
            await self._fn(world)


__all__ = [
    "World",
    "System",
    "Component",
    "Query",
    "QueryBuilder",
    "EventBus",
    "CommandBuffer",
    "EntityNotFound",
    "ComponentNotFound",
    "ComponentNotRegistered",
    "WorldClosed",
    "IntervalSystem",
]
