# -*- coding: utf-8 -*-
"""
Mythos Core — Quest State Machine (industrial)
Чистая доменная FSM для квестов: события/команды, прогресс, дедлайны, пауза, идемпотентность и оптимистические блокировки.

Python: 3.11+
Внешние зависимости: нет (только стандартная библиотека)

Интеграция:
  - Реализуйте Protocol-хранилище и событийну шину (EventSink), затем вызывайте process_command(...)
  - Снимки (QuestSnapshot) храните как JSON/ORM-объекты, версии — для optimistic locking
"""

from __future__ import annotations

import abc
import dataclasses
import enum
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, runtime_checkable


__all__ = [
    # доменная модель
    "QuestState",
    "ObjectiveStatus",
    "Objective",
    "QuestSnapshot",
    # команды и события
    "Command",
    "AcceptQuest",
    "StartQuest",
    "RecordProgress",
    "CompleteQuest",
    "FailQuest",
    "CancelQuest",
    "PauseQuest",
    "ResumeQuest",
    "ExpireQuest",
    "SetVar",
    "AddTag",
    "Event",
    "QuestAccepted",
    "QuestStarted",
    "ProgressRecorded",
    "ObjectiveCompleted",
    "QuestCompleted",
    "QuestFailed",
    "QuestCancelled",
    "QuestPaused",
    "QuestResumed",
    "QuestExpired",
    "VariableChanged",
    "TagAdded",
    # ошибки
    "DomainError",
    "ConflictError",
    "GuardError",
    "IdempotencyError",
    # FSM
    "QuestStateMachine",
    # порты/интерфейсы
    "QuestStore",
    "EventSink",
    "IdempotencyStore",
    # сервис
    "process_command",
]


# =========================
# Errors
# =========================

class DomainError(RuntimeError):
    pass


class ConflictError(DomainError):
    """Оптимистический конфликт версий."""
    pass


class GuardError(DomainError):
    """Нарушение guard-условий/перехода."""
    pass


class IdempotencyError(DomainError):
    """Команда с таким command_id уже обработана и стратегия запретила повтор."""
    pass


# =========================
# Enums & DTO
# =========================

class QuestState(str, enum.Enum):
    DRAFT = "DRAFT"
    AVAILABLE = "AVAILABLE"
    ACCEPTED = "ACCEPTED"
    IN_PROGRESS = "IN_PROGRESS"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"  # напр., пока не выполнены пререквизиты


class ObjectiveStatus(str, enum.Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class Objective:
    """
    Базовая цель квеста.
    kind: семантика цели (e.g. "collect", "kill", "reach", "talk")
    target: объект/ссылка/идентификатор цели
    required: требуемая величина/счётчик (для булевых целей = 1)
    current: текущий прогресс
    """
    id: str
    kind: str
    target: str
    required: int = 1
    current: int = 0
    status: ObjectiveStatus = ObjectiveStatus.PENDING
    meta: Dict[str, Any] = field(default_factory=dict)

    def with_progress(self, delta: int) -> "Objective":
        if self.status in (ObjectiveStatus.COMPLETED, ObjectiveStatus.FAILED):
            return self
        new_current = max(0, self.current + max(0, int(delta)))
        if new_current >= self.required:
            return dataclasses.replace(self, current=self.required, status=ObjectiveStatus.COMPLETED)
        st = ObjectiveStatus.IN_PROGRESS if new_current > 0 else self.status
        return dataclasses.replace(self, current=new_current, status=st)


@dataclass(frozen=True)
class QuestSnapshot:
    """
    Текущий снимок квеста (агрегат).
    """
    quest_id: str
    player_id: str
    title: str
    state: QuestState
    objectives: Tuple[Objective, ...]
    vars: Dict[str, Any] = field(default_factory=dict)
    tags: Tuple[str, ...] = tuple()
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    available_at: Optional[datetime] = None
    accepted_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    failed_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None
    paused_at: Optional[datetime] = None
    resumed_at: Optional[datetime] = None
    expired_at: Optional[datetime] = None
    deadline_at: Optional[datetime] = None  # если задан дедлайн
    blocked_reason: Optional[str] = None
    version: int = 0  # optimistic locking version

    # Утилиты
    def is_terminal(self) -> bool:
        return self.state in {QuestState.COMPLETED, QuestState.FAILED, QuestState.CANCELLED, QuestState.EXPIRED}

    def all_objectives_completed(self) -> bool:
        return all(o.status == ObjectiveStatus.COMPLETED for o in self.objectives)

    def bump_version(self) -> "QuestSnapshot":
        return dataclasses.replace(self, version=self.version + 1)


# =========================
# Commands / Events
# =========================

@dataclass(frozen=True)
class Command:
    command_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


@dataclass(frozen=True)
class AcceptQuest(Command):
    pass


@dataclass(frozen=True)
class StartQuest(Command):
    pass


@dataclass(frozen=True)
class RecordProgress(Command):
    objective_id: str = ""
    delta: int = 0


@dataclass(frozen=True)
class CompleteQuest(Command):
    pass


@dataclass(frozen=True)
class FailQuest(Command):
    reason: str = ""


@dataclass(frozen=True)
class CancelQuest(Command):
    reason: str = ""


@dataclass(frozen=True)
class PauseQuest(Command):
    reason: str = ""


@dataclass(frozen=True)
class ResumeQuest(Command):
    pass


@dataclass(frozen=True)
class ExpireQuest(Command):
    pass


@dataclass(frozen=True)
class SetVar(Command):
    key: str = ""
    value: Any = None


@dataclass(frozen=True)
class AddTag(Command):
    tag: str = ""


@dataclass(frozen=True)
class Event:
    event_id: str
    at: datetime


@dataclass(frozen=True)
class QuestAccepted(Event):
    pass


@dataclass(frozen=True)
class QuestStarted(Event):
    pass


@dataclass(frozen=True)
class ProgressRecorded(Event):
    objective_id: str
    delta: int
    new_value: int
    completed: bool


@dataclass(frozen=True)
class ObjectiveCompleted(Event):
    objective_id: str


@dataclass(frozen=True)
class QuestCompleted(Event):
    pass


@dataclass(frozen=True)
class QuestFailed(Event):
    reason: str


@dataclass(frozen=True)
class QuestCancelled(Event):
    reason: str


@dataclass(frozen=True)
class QuestPaused(Event):
    reason: str


@dataclass(frozen=True)
class QuestResumed(Event):
    pass


@dataclass(frozen=True)
class QuestExpired(Event):
    pass


@dataclass(frozen=True)
class VariableChanged(Event):
    key: str
    value: Any


@dataclass(frozen=True)
class TagAdded(Event):
    tag: str


# =========================
# Guards / Transition map
# =========================

_ALLOWED_TRANSITIONS: Mapping[Tuple[QuestState, str], QuestState] = {
    # публикация и блокировка вне рамок (предполагаются в другой миграции/сервисе)
    (QuestState.AVAILABLE, "AcceptQuest"): QuestState.ACCEPTED,
    (QuestState.ACCEPTED, "StartQuest"): QuestState.IN_PROGRESS,
    (QuestState.ACCEPTED, "CancelQuest"): QuestState.CANCELLED,
    (QuestState.ACCEPTED, "ExpireQuest"): QuestState.EXPIRED,

    (QuestState.IN_PROGRESS, "CompleteQuest"): QuestState.COMPLETED,
    (QuestState.IN_PROGRESS, "FailQuest"): QuestState.FAILED,
    (QuestState.IN_PROGRESS, "CancelQuest"): QuestState.CANCELLED,
    (QuestState.IN_PROGRESS, "PauseQuest"): QuestState.PAUSED,
    (QuestState.IN_PROGRESS, "ExpireQuest"): QuestState.EXPIRED,

    (QuestState.PAUSED, "ResumeQuest"): QuestState.IN_PROGRESS,
    (QuestState.PAUSED, "CancelQuest"): QuestState.CANCELLED,
    (QuestState.PAUSED, "ExpireQuest"): QuestState.EXPIRED,
}

_TERMINAL: set[QuestState] = {QuestState.COMPLETED, QuestState.CANCELLED, QuestState.FAILED, QuestState.EXPIRED}


def _ensure_allowed_transition(state: QuestState, cmd: Command) -> None:
    cname = type(cmd).__name__
    if state in _TERMINAL:
        raise GuardError(f"Quest is terminal ({state}), command {cname} is not allowed")
    if isinstance(cmd, (RecordProgress, SetVar, AddTag)):
        return  # обработка отдельно
    if (state, cname) not in _ALLOWED_TRANSITIONS:
        raise GuardError(f"Transition ({state} -> {cname}) is not allowed")


# =========================
# FSM (decide/apply)
# =========================

class QuestStateMachine:
    """
    Чистая доменная машина состояний.
    - decide(snapshot, command) -> list[Event]
    - apply(snapshot, event)    -> new snapshot
    """

    # -------- DECIDE --------

    @staticmethod
    def decide(s: QuestSnapshot, cmd: Command) -> List[Event]:
        _ensure_allowed_transition(s.state, cmd)
        at = cmd.at

        # дедлайн → автопревращение в ExpireQuest (если просрочен) допустимо на любом mutating cmd
        if s.deadline_at and at > s.deadline_at and s.state not in _TERMINAL:
            return [QuestExpired(event_id=uuid.uuid4().hex, at=at)]

        if isinstance(cmd, AcceptQuest):
            if s.state != QuestState.AVAILABLE:
                raise GuardError("Quest can be accepted only from AVAILABLE")
            return [QuestAccepted(event_id=cmd.command_id, at=at)]

        if isinstance(cmd, StartQuest):
            if s.state != QuestState.ACCEPTED:
                raise GuardError("Quest can be started only from ACCEPTED")
            return [QuestStarted(event_id=cmd.command_id, at=at)]

        if isinstance(cmd, RecordProgress):
            if s.state not in {QuestState.IN_PROGRESS, QuestState.ACCEPTED, QuestState.PAUSED}:
                raise GuardError("Progress can be recorded only in ACCEPTED/IN_PROGRESS/PAUSED")
            if s.state == QuestState.PAUSED:
                raise GuardError("Progress cannot be recorded while PAUSED")
            obj = _find_objective(s, cmd.objective_id)
            if obj.status in (ObjectiveStatus.COMPLETED, ObjectiveStatus.FAILED):
                return []
            new_obj = obj.with_progress(cmd.delta)
            events: List[Event] = [
                ProgressRecorded(
                    event_id=cmd.command_id,
                    at=at,
                    objective_id=obj.id,
                    delta=cmd.delta,
                    new_value=new_obj.current,
                    completed=new_obj.status == ObjectiveStatus.COMPLETED,
                )
            ]
            if new_obj.status == ObjectiveStatus.COMPLETED:
                events.append(ObjectiveCompleted(event_id=uuid.uuid4().hex, at=at, objective_id=obj.id))
                # Автозавершение квеста, если все цели достигнуты и квест уже в IN_PROGRESS/ACCEPTED
                if s.state in {QuestState.IN_PROGRESS, QuestState.ACCEPTED} and _all_completed_after(s, obj.id, new_obj):
                    events.append(QuestCompleted(event_id=uuid.uuid4().hex, at=at))
            return events

        if isinstance(cmd, CompleteQuest):
            if s.state not in {QuestState.IN_PROGRESS, QuestState.ACCEPTED}:
                raise GuardError("Complete is allowed only from IN_PROGRESS/ACCEPTED")
            return [QuestCompleted(event_id=cmd.command_id, at=at)]

        if isinstance(cmd, FailQuest):
            if s.state not in {QuestState.IN_PROGRESS, QuestState.ACCEPTED, QuestState.PAUSED}:
                raise GuardError("Fail is allowed only from IN_PROGRESS/ACCEPTED/PAUSED")
            return [QuestFailed(event_id=cmd.command_id, at=at, reason=cmd.reason)]

        if isinstance(cmd, CancelQuest):
            return [QuestCancelled(event_id=cmd.command_id, at=at, reason=cmd.reason)]

        if isinstance(cmd, PauseQuest):
            if s.state != QuestState.IN_PROGRESS:
                raise GuardError("Pause is allowed only from IN_PROGRESS")
            return [QuestPaused(event_id=cmd.command_id, at=at, reason=cmd.reason)]

        if isinstance(cmd, ResumeQuest):
            if s.state != QuestState.PAUSED:
                raise GuardError("Resume is allowed only from PAUSED")
            return [QuestResumed(event_id=cmd.command_id, at=at)]

        if isinstance(cmd, ExpireQuest):
            return [QuestExpired(event_id=cmd.command_id, at=at)]

        if isinstance(cmd, SetVar):
            return [VariableChanged(event_id=cmd.command_id, at=at, key=cmd.key, value=cmd.value)]

        if isinstance(cmd, AddTag):
            if cmd.tag and cmd.tag not in s.tags:
                return [TagAdded(event_id=cmd.command_id, at=at, tag=cmd.tag)]
            return []

        raise DomainError(f"Unsupported command: {type(cmd).__name__}")

    # -------- APPLY --------

    @staticmethod
    def apply(s: QuestSnapshot, e: Event) -> QuestSnapshot:
        now = e.at
        if isinstance(e, QuestAccepted):
            return dataclasses.replace(s, state=QuestState.ACCEPTED, accepted_at=now, updated_at=now)
        if isinstance(e, QuestStarted):
            return dataclasses.replace(s, state=QuestState.IN_PROGRESS, started_at=now, updated_at=now)
        if isinstance(e, ProgressRecorded):
            new_objs = []
            for obj in s.objectives:
                if obj.id == e.objective_id:
                    st = ObjectiveStatus.COMPLETED if e.completed else (ObjectiveStatus.IN_PROGRESS if e.new_value > 0 else obj.status)
                    new_objs.append(dataclasses.replace(obj, current=e.new_value, status=st))
                else:
                    new_objs.append(obj)
            return dataclasses.replace(s, objectives=tuple(new_objs), updated_at=now)
        if isinstance(e, ObjectiveCompleted):
            # уже помечено в ProgressRecorded; здесь можно добавить побочные эффекты через vars/tags при желании
            return dataclasses.replace(s, updated_at=now)
        if isinstance(e, QuestCompleted):
            return dataclasses.replace(s, state=QuestState.COMPLETED, completed_at=now, updated_at=now)
        if isinstance(e, QuestFailed):
            return dataclasses.replace(s, state=QuestState.FAILED, failed_at=now, updated_at=now)
        if isinstance(e, QuestCancelled):
            return dataclasses.replace(s, state=QuestState.CANCELLED, cancelled_at=now, updated_at=now)
        if isinstance(e, QuestPaused):
            return dataclasses.replace(s, state=QuestState.PAUSED, paused_at=now, updated_at=now)
        if isinstance(e, QuestResumed):
            return dataclasses.replace(s, state=QuestState.IN_PROGRESS, resumed_at=now, updated_at=now)
        if isinstance(e, QuestExpired):
            return dataclasses.replace(s, state=QuestState.EXPIRED, expired_at=now, updated_at=now)
        if isinstance(e, VariableChanged):
            new_vars = dict(s.vars)
            new_vars[e.key] = e.value
            return dataclasses.replace(s, vars=new_vars, updated_at=now)
        if isinstance(e, TagAdded):
            return dataclasses.replace(s, tags=tuple(list(s.tags) + [e.tag]), updated_at=now)
        raise DomainError(f"Unsupported event: {type(e).__name__}")


def _find_objective(s: QuestSnapshot, objective_id: str) -> Objective:
    for o in s.objectives:
        if o.id == objective_id:
            return o
    raise GuardError(f"Objective {objective_id} not found")


def _all_completed_after(s: QuestSnapshot, changed_id: str, new_obj: Objective) -> bool:
    for o in s.objectives:
        if o.id == changed_id:
            oeff = new_obj
        else:
            oeff = o
        if oeff.status != ObjectiveStatus.COMPLETED:
            return False
    return True


# =========================
# Ports / Adapters Protocols
# =========================

@runtime_checkable
class QuestStore(Protocol):
    """
    Порт хранилища снимков квестов + журнал событий по квесту (опционально).
    Должно обеспечивать оптимистическую блокировку по version.
    """
    async def load(self, quest_id: str, player_id: str) -> QuestSnapshot: ...
    async def save(self, snapshot: QuestSnapshot, expected_version: int) -> None: ...
    async def append_events(self, quest_id: str, player_id: str, events: Sequence[Event]) -> None: ...


@runtime_checkable
class EventSink(Protocol):
    """
    Внешняя шина событий для публикации доменных событий наружу (Kafka/NATS/etc).
    """
    async def publish(self, events: Sequence[Event]) -> None: ...


@runtime_checkable
class IdempotencyStore(Protocol):
    """
    Хранилище идемпотентности команд по command_id (TTL зависит от SLA).
    True → впервые видим этот command_id и помечаем; False → уже обработан.
    """
    async def register(self, command_id: str) -> bool: ...


# =========================
# Application Service
# =========================

async def process_command(
    store: QuestStore,
    *,
    quest_id: str,
    player_id: str,
    command: Command,
    event_sink: Optional[EventSink] = None,
    idempotency: Optional[IdempotencyStore] = None,
    allow_duplicate: bool = True,
) -> Tuple[QuestSnapshot, Tuple[Event, ...]]:
    """
    Транзакционная обработка команды:
      1) (опционально) регистрация идемпотентности
      2) загрузка снимка
      3) decide -> events
      4) apply events -> new snapshot
      5) append events, save(snapshot, expected_version)
      6) publish events

    allow_duplicate=False → если команда уже была — бросает IdempotencyError
    """
    # идемпотентность
    if idempotency is not None:
        first = await idempotency.register(command.command_id)
        if not first and not allow_duplicate:
            raise IdempotencyError(f"Command {command.command_id} already processed")

    # снимок и версия
    snapshot = await store.load(quest_id=quest_id, player_id=player_id)
    expected_version = snapshot.version

    # доменная логика
    events = QuestStateMachine.decide(snapshot, command)

    # короткий путь: нет событий
    if not events:
        return snapshot, tuple()

    # применяем локально
    new_snapshot = snapshot
    for ev in events:
        new_snapshot = QuestStateMachine.apply(new_snapshot, ev)

    # bump версии
    new_snapshot = new_snapshot.bump_version()

    # персист
    await store.append_events(quest_id=quest_id, player_id=player_id, events=events)
    try:
        await store.save(new_snapshot, expected_version=expected_version)
    except ConflictError:
        # прокинем выше — вызывающий может ретраить
        raise

    # паблиш
    if event_sink:
        await event_sink.publish(events)

    return new_snapshot, tuple(events)


# =========================
# Builders / Defaults
# =========================

def new_available(
    *,
    quest_id: str,
    player_id: str,
    title: str,
    objectives: Iterable[Objective],
    available_at: Optional[datetime] = None,
    deadline_at: Optional[datetime] = None,
    blocked_reason: Optional[str] = None,
    tags: Iterable[str] = (),
    vars: Optional[Mapping[str, Any]] = None,
) -> QuestSnapshot:
    """
    Фабрика нового квеста в AVAILABLE или BLOCKED.
    """
    state = QuestState.BLOCKED if blocked_reason else QuestState.AVAILABLE
    if available_at is None:
        available_at = datetime.now(tz=timezone.utc)
    return QuestSnapshot(
        quest_id=quest_id,
        player_id=player_id,
        title=title,
        state=state,
        objectives=tuple(objectives),
        vars=dict(vars or {}),
        tags=tuple(tags or ()),
        available_at=available_at,
        deadline_at=deadline_at,
        blocked_reason=blocked_reason,
        version=0,
    )


# =========================
# Debug / JSON helpers (optional)
# =========================

def snapshot_to_json(s: QuestSnapshot) -> str:
    def _default(o: Any) -> Any:
        if isinstance(o, enum.Enum):
            return o.value
        if isinstance(o, datetime):
            return o.isoformat()
        if dataclasses.is_dataclass(o):
            return asdict(o)
        return str(o)
    return json.dumps(asdict(s), ensure_ascii=False, sort_keys=True, default=_default, indent=2)


# =========================
# Example (manual run)
# =========================

if __name__ == "__main__":  # локальная проверка без хранилища
    # Создаём квест
    q = new_available(
        quest_id="q1",
        player_id="p1",
        title="Войди в архив и найди свиток",
        objectives=[
            Objective(id="enter", kind="reach", target="archive_door", required=1),
            Objective(id="scroll", kind="collect", target="ancient_scroll", required=1),
        ],
        deadline_at=datetime.now(tz=timezone.utc) + timedelta(hours=2),
    )

    # Простая симуляция decide/apply без персиста
    def run(cmd: Command):
        nonlocal q
        evs = QuestStateMachine.decide(q, cmd)
        for ev in evs:
            q = QuestStateMachine.apply(q, ev)
        q = q.bump_version()
        print(f"\n> {type(cmd).__name__}")
        for ev in evs:
            print("  -", ev)
        print("state:", q.state, "version:", q.version)
        print(snapshot_to_json(q))

    run(AcceptQuest())
    run(StartQuest())
    run(RecordProgress(objective_id="enter", delta=1))
    run(RecordProgress(objective_id="scroll", delta=1))
    # Автозавершение при выполнении всех целей
