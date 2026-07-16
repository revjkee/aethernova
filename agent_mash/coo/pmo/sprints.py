# agent_mash/pmo/sprints.py
from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence, Tuple


class SprintError(Exception):
    pass


class SprintState(str, enum.Enum):
    DRAFT = "draft"
    PLANNED = "planned"
    ACTIVE = "active"
    FROZEN = "frozen"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class SprintItemState(str, enum.Enum):
    BACKLOG = "backlog"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    DONE = "done"
    DROPPED = "dropped"


@dataclass(frozen=True)
class CapacityModel:
    """
    Модель capacity для workforce или отдельного агента.
    Все значения детерминированы и проверяемы.
    """
    max_points: int
    hard_limit: bool = True

    def validate(self, planned_points: int) -> None:
        if planned_points > self.max_points:
            if self.hard_limit:
                raise SprintError("capacity_exceeded")
            return


@dataclass(frozen=True)
class SprintItem:
    """
    Единица работы в спринте.
    """
    item_id: str
    title: str
    points: int
    state: SprintItemState = SprintItemState.BACKLOG
    assignee: Optional[str] = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def with_state(
        self,
        *,
        state: SprintItemState,
        assignee: Optional[str] = None,
    ) -> "SprintItem":
        return SprintItem(
            item_id=self.item_id,
            title=self.title,
            points=self.points,
            state=state,
            assignee=assignee if assignee is not None else self.assignee,
            metadata=dict(self.metadata),
        )


@dataclass(frozen=True)
class SprintAuditEvent:
    at_epoch_s: int
    sprint_id: str
    actor: str
    action: str
    details: Mapping[str, str] = field(default_factory=dict)


@dataclass
class Sprint:
    """
    Sprint как управляемый объект PMO.
    """
    sprint_id: str
    tenant_id: str
    name: str
    goal: str
    state: SprintState = SprintState.DRAFT
    start_epoch_s: Optional[int] = None
    end_epoch_s: Optional[int] = None
    capacity: Optional[CapacityModel] = None
    items: Dict[str, SprintItem] = field(default_factory=dict)
    audit_log: List[SprintAuditEvent] = field(default_factory=list)

    def _audit(self, actor: str, action: str, details: Optional[Mapping[str, str]] = None) -> None:
        self.audit_log.append(
            SprintAuditEvent(
                at_epoch_s=int(time.time()),
                sprint_id=self.sprint_id,
                actor=actor,
                action=action,
                details=dict(details or {}),
            )
        )

    def _ensure_state(self, allowed: Sequence[SprintState]) -> None:
        if self.state not in allowed:
            raise SprintError(f"invalid_state_transition:{self.state}")

    def plan(
        self,
        *,
        actor: str,
        start_epoch_s: int,
        end_epoch_s: int,
        capacity: CapacityModel,
    ) -> None:
        self._ensure_state([SprintState.DRAFT])
        if end_epoch_s <= start_epoch_s:
            raise SprintError("invalid_time_window")

        self.start_epoch_s = start_epoch_s
        self.end_epoch_s = end_epoch_s
        self.capacity = capacity
        self.state = SprintState.PLANNED

        self._audit(actor, "plan_sprint")

    def activate(self, *, actor: str) -> None:
        self._ensure_state([SprintState.PLANNED])
        self._validate_capacity()
        self.state = SprintState.ACTIVE
        self._audit(actor, "activate_sprint")

    def freeze(self, *, actor: str) -> None:
        self._ensure_state([SprintState.ACTIVE])
        self.state = SprintState.FROZEN
        self._audit(actor, "freeze_sprint")

    def complete(self, *, actor: str) -> None:
        self._ensure_state([SprintState.ACTIVE, SprintState.FROZEN])
        self.state = SprintState.COMPLETED
        self._audit(actor, "complete_sprint")

    def archive(self, *, actor: str) -> None:
        self._ensure_state([SprintState.COMPLETED])
        self.state = SprintState.ARCHIVED
        self._audit(actor, "archive_sprint")

    def add_item(self, *, actor: str, item: SprintItem) -> None:
        self._ensure_state([SprintState.DRAFT, SprintState.PLANNED])
        if item.item_id in self.items:
            raise SprintError("duplicate_item")
        self.items[item.item_id] = item
        self._audit(actor, "add_item", {"item_id": item.item_id})

    def assign_item(self, *, actor: str, item_id: str, assignee: str) -> None:
        self._ensure_state([SprintState.ACTIVE])
        item = self._get_item(item_id)
        if item.state not in [SprintItemState.BACKLOG, SprintItemState.ASSIGNED]:
            raise SprintError("invalid_item_state")
        self.items[item_id] = item.with_state(
            state=SprintItemState.ASSIGNED,
            assignee=assignee,
        )
        self._audit(actor, "assign_item", {"item_id": item_id, "assignee": assignee})

    def start_item(self, *, actor: str, item_id: str) -> None:
        self._ensure_state([SprintState.ACTIVE])
        item = self._get_item(item_id)
        if item.state != SprintItemState.ASSIGNED:
            raise SprintError("invalid_item_state")
        self.items[item_id] = item.with_state(state=SprintItemState.IN_PROGRESS)
        self._audit(actor, "start_item", {"item_id": item_id})

    def complete_item(self, *, actor: str, item_id: str) -> None:
        self._ensure_state([SprintState.ACTIVE])
        item = self._get_item(item_id)
        if item.state != SprintItemState.IN_PROGRESS:
            raise SprintError("invalid_item_state")
        self.items[item_id] = item.with_state(state=SprintItemState.DONE)
        self._audit(actor, "complete_item", {"item_id": item_id})

    def drop_item(self, *, actor: str, item_id: str, reason: str) -> None:
        self._ensure_state([SprintState.ACTIVE, SprintState.FROZEN])
        item = self._get_item(item_id)
        self.items[item_id] = item.with_state(state=SprintItemState.DROPPED)
        self._audit(actor, "drop_item", {"item_id": item_id, "reason": reason})

    def _get_item(self, item_id: str) -> SprintItem:
        try:
            return self.items[item_id]
        except KeyError:
            raise SprintError("item_not_found")

    def _validate_capacity(self) -> None:
        if self.capacity is None:
            return
        total_points = sum(
            item.points
            for item in self.items.values()
            if item.state not in [SprintItemState.DROPPED]
        )
        self.capacity.validate(total_points)


def create_sprint(
    *,
    tenant_id: str,
    name: str,
    goal: str,
) -> Sprint:
    if not tenant_id or not name:
        raise SprintError("invalid_sprint_definition")

    return Sprint(
        sprint_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        name=name,
        goal=goal,
    )
