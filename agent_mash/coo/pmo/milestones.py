# agent_mash/pmo/milestones.py
from __future__ import annotations

import dataclasses
import datetime as _dt
import enum
import re
import typing as t
import uuid

__all__ = [
    "MilestoneError",
    "MilestoneValidationError",
    "MilestoneStatus",
    "Milestone",
    "MilestoneGraph",
    "utc_now",
]


# =========================
# Errors
# =========================

class MilestoneError(RuntimeError):
    """Base PMO milestone error."""


class MilestoneValidationError(MilestoneError):
    """Raised when milestone validation fails."""


# =========================
# Time helpers
# =========================

def utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _ensure_utc(dt: _dt.datetime) -> None:
    if dt.tzinfo is None or dt.utcoffset() != _dt.timedelta(0):
        raise MilestoneValidationError("datetime must be UTC timezone-aware")


# =========================
# ID helpers
# =========================

_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-:.]{7,127}$")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _validate_id(value: str, field: str) -> None:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise MilestoneValidationError(f"{field} has invalid format: {value}")


# =========================
# Status enum
# =========================

class MilestoneStatus(str, enum.Enum):
    PLANNED = "planned"
    READY = "ready"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


# =========================
# Milestone
# =========================

@dataclasses.dataclass(frozen=True, slots=True)
class Milestone:
    """
    Single PMO milestone.

    A milestone is immutable. Any update produces a new instance.
    """
    milestone_id: str
    title: str
    status: MilestoneStatus
    owner: str
    created_at: _dt.datetime
    due_at: t.Optional[_dt.datetime] = None
    completed_at: t.Optional[_dt.datetime] = None
    progress: int = 0
    dependencies: t.Tuple[str, ...] = ()
    metadata: t.Dict[str, str] = dataclasses.field(default_factory=dict)

    # ---------------------

    def validate(self) -> None:
        _validate_id(self.milestone_id, "milestone_id")

        if not isinstance(self.title, str) or not self.title:
            raise MilestoneValidationError("title must be non-empty string")

        if not isinstance(self.owner, str) or not self.owner:
            raise MilestoneValidationError("owner must be non-empty string")

        if not isinstance(self.status, MilestoneStatus):
            raise MilestoneValidationError("invalid milestone status")

        _ensure_utc(self.created_at)

        if self.due_at is not None:
            _ensure_utc(self.due_at)
            if self.due_at < self.created_at:
                raise MilestoneValidationError("due_at cannot be earlier than created_at")

        if self.completed_at is not None:
            _ensure_utc(self.completed_at)
            if self.completed_at < self.created_at:
                raise MilestoneValidationError("completed_at cannot be earlier than created_at")

        if not isinstance(self.progress, int) or not (0 <= self.progress <= 100):
            raise MilestoneValidationError("progress must be int between 0 and 100")

        if self.status == MilestoneStatus.COMPLETED:
            if self.progress != 100 or self.completed_at is None:
                raise MilestoneValidationError(
                    "completed milestone must have progress=100 and completed_at set"
                )

        for dep in self.dependencies:
            _validate_id(dep, "dependency_id")

        for k, v in self.metadata.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise MilestoneValidationError("metadata keys and values must be strings")

    # ---------------------

    def to_dict(self) -> dict:
        self.validate()
        return {
            "milestone_id": self.milestone_id,
            "title": self.title,
            "status": self.status.value,
            "owner": self.owner,
            "created_at": self.created_at.isoformat(),
            "due_at": self.due_at.isoformat() if self.due_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "progress": self.progress,
            "dependencies": list(self.dependencies),
            "metadata": dict(self.metadata),
        }

    # ---------------------

    @staticmethod
    def new(
        *,
        title: str,
        owner: str,
        due_at: t.Optional[_dt.datetime] = None,
        dependencies: t.Iterable[str] = (),
        metadata: t.Optional[t.Dict[str, str]] = None,
    ) -> "Milestone":
        milestone = Milestone(
            milestone_id=_new_id("ms"),
            title=title,
            status=MilestoneStatus.PLANNED,
            owner=owner,
            created_at=utc_now(),
            due_at=due_at,
            completed_at=None,
            progress=0,
            dependencies=tuple(dependencies),
            metadata=metadata or {},
        )
        milestone.validate()
        return milestone


# =========================
# Milestone Graph
# =========================

class MilestoneGraph:
    """
    Manages milestone dependency graph and PMO rules.
    """

    def __init__(self) -> None:
        self._milestones: dict[str, Milestone] = {}

    # ---------------------

    def add(self, milestone: Milestone) -> None:
        milestone.validate()
        if milestone.milestone_id in self._milestones:
            raise MilestoneError("milestone already exists")
        self._milestones[milestone.milestone_id] = milestone

    # ---------------------

    def get(self, milestone_id: str) -> Milestone:
        try:
            return self._milestones[milestone_id]
        except KeyError:
            raise MilestoneError(f"milestone not found: {milestone_id}")

    # ---------------------

    def all(self) -> t.Tuple[Milestone, ...]:
        return tuple(self._milestones.values())

    # ---------------------

    def dependencies_satisfied(self, milestone_id: str) -> bool:
        milestone = self.get(milestone_id)
        for dep_id in milestone.dependencies:
            dep = self.get(dep_id)
            if dep.status != MilestoneStatus.COMPLETED:
                return False
        return True

    # ---------------------

    def update_status(
        self,
        milestone_id: str,
        *,
        status: MilestoneStatus,
        progress: t.Optional[int] = None,
    ) -> Milestone:
        milestone = self.get(milestone_id)

        if status == MilestoneStatus.IN_PROGRESS:
            if not self.dependencies_satisfied(milestone_id):
                raise MilestoneError("cannot start milestone with incomplete dependencies")

        completed_at = milestone.completed_at
        new_progress = milestone.progress if progress is None else progress

        if status == MilestoneStatus.COMPLETED:
            new_progress = 100
            completed_at = utc_now()

        updated = dataclasses.replace(
            milestone,
            status=status,
            progress=new_progress,
            completed_at=completed_at,
        )
        updated.validate()
        self._milestones[milestone_id] = updated
        return updated

    # ---------------------

    def overall_progress(self) -> int:
        if not self._milestones:
            return 0
        return sum(m.progress for m in self._milestones.values()) // len(self._milestones)

    # ---------------------

    def blocked_milestones(self) -> t.Tuple[Milestone, ...]:
        blocked: list[Milestone] = []
        for m in self._milestones.values():
            if m.status in (MilestoneStatus.PLANNED, MilestoneStatus.READY):
                if not self.dependencies_satisfied(m.milestone_id):
                    blocked.append(m)
        return tuple(blocked)
