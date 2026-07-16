# agent_mash/pmo/risks.py
from __future__ import annotations

import dataclasses
import datetime as dt
import enum
import hashlib
import json
import os
import re
import threading
import uuid
from collections.abc import Iterable, Mapping
from typing import Any, Optional


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskStatus(str, enum.Enum):
    OPEN = "open"
    MITIGATING = "mitigating"
    ACCEPTED = "accepted"
    TRANSFERRED = "transferred"
    CLOSED = "closed"


class RiskCategory(str, enum.Enum):
    SCOPE = "scope"
    SCHEDULE = "schedule"
    COST = "cost"
    QUALITY = "quality"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    OPERATIONS = "operations"
    VENDOR = "vendor"
    PEOPLE = "people"
    TECHNICAL = "technical"
    PRODUCT = "product"
    REPUTATION = "reputation"
    OTHER = "other"


class MitigationType(str, enum.Enum):
    AVOID = "avoid"
    REDUCE = "reduce"
    TRANSFER = "transfer"
    ACCEPT = "accept"


class EventType(str, enum.Enum):
    CREATED = "created"
    UPDATED = "updated"
    STATUS_CHANGED = "status_changed"
    MITIGATION_ADDED = "mitigation_added"
    MITIGATION_UPDATED = "mitigation_updated"
    MITIGATION_REMOVED = "mitigation_removed"
    COMMENT = "comment"
    EVIDENCE_ADDED = "evidence_added"
    EVIDENCE_REMOVED = "evidence_removed"
    LINKED = "linked"
    UNLINKED = "unlinked"


@dataclasses.dataclass(frozen=True)
class RiskScoringModel:
    """
    1) Probability (P): 1..5
    2) Impact (I): 1..5
    3) Score = P * I : 1..25

    Thresholds are configurable but conservative by default:
      - 1..5    -> LOW
      - 6..10   -> MEDIUM
      - 11..16  -> HIGH
      - 17..25  -> CRITICAL
    """
    low_max: int = 5
    medium_max: int = 10
    high_max: int = 16
    critical_max: int = 25

    def level_for_score(self, score: int) -> RiskLevel:
        s = int(score)
        if s <= self.low_max:
            return RiskLevel.LOW
        if s <= self.medium_max:
            return RiskLevel.MEDIUM
        if s <= self.high_max:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL


@dataclasses.dataclass(frozen=True)
class RiskOwner:
    id: str
    name: str
    role: str = ""
    contact: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "role": self.role, "contact": self.contact}


@dataclasses.dataclass(frozen=True)
class RiskTrigger:
    """
    Trigger is a condition or observable signal that indicates risk activation.
    """
    id: str
    title: str
    description: str = ""
    severity_hint: str = ""
    source: str = ""  # e.g. monitoring, incident, audit, user_report

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity_hint": self.severity_hint,
            "source": self.source,
        }


@dataclasses.dataclass(frozen=True)
class RiskMitigation:
    id: str
    type: MitigationType
    title: str
    description: str = ""
    owner: Optional[RiskOwner] = None
    due_date: Optional[dt.date] = None
    status: str = "planned"  # planned/in_progress/done/blocked
    effectiveness: Optional[int] = None  # 0..100
    created_at: dt.datetime = dataclasses.field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    updated_at: dt.datetime = dataclasses.field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "title": self.title,
            "description": self.description,
            "owner": self.owner.to_dict() if self.owner else None,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "status": self.status,
            "effectiveness": self.effectiveness,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclasses.dataclass(frozen=True)
class RiskEvidence:
    """
    Evidence is a link/reference that supports the existence/assessment of a risk.
    No raw secrets: store references only (URLs, ticket ids, doc ids).
    """
    id: str
    ref: str
    kind: str = "link"  # link/ticket/doc/log/metric/screenshot
    note: str = ""
    added_at: dt.datetime = dataclasses.field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "ref": self.ref, "kind": self.kind, "note": self.note, "added_at": self.added_at.isoformat()}


@dataclasses.dataclass(frozen=True)
class RiskEvent:
    id: str
    ts: dt.datetime
    type: EventType
    actor: str
    message: str
    patch: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts.isoformat(),
            "type": self.type.value,
            "actor": self.actor,
            "message": self.message,
            "patch": self.patch,
        }


@dataclasses.dataclass(frozen=True)
class RiskItem:
    """
    PMO Risk Register item with:
      - scoring (probability/impact/score/level)
      - status lifecycle
      - ownership
      - triggers, mitigations, evidence
      - SLA: review cadence and next review date
      - links to incidents/epics/tasks
    """
    id: str
    title: str
    description: str
    category: RiskCategory
    status: RiskStatus
    probability: int  # 1..5
    impact: int       # 1..5
    created_at: dt.datetime
    updated_at: dt.datetime

    owner: Optional[RiskOwner] = None
    tags: tuple[str, ...] = ()
    triggers: tuple[RiskTrigger, ...] = ()
    mitigations: tuple[RiskMitigation, ...] = ()
    evidence: tuple[RiskEvidence, ...] = ()
    links: tuple[str, ...] = ()  # e.g. "JIRA-123", "INC-77", "EPIC-42"

    review_interval_days: int = 14
    next_review_date: Optional[dt.date] = None
    last_reviewed_at: Optional[dt.datetime] = None

    def score(self) -> int:
        return int(self.probability) * int(self.impact)

    def to_dict(self, *, scoring: Optional[RiskScoringModel] = None) -> dict[str, Any]:
        sc = scoring or RiskScoringModel()
        score = self.score()
        level = sc.level_for_score(score).value
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "category": self.category.value,
            "status": self.status.value,
            "probability": int(self.probability),
            "impact": int(self.impact),
            "score": score,
            "level": level,
            "owner": self.owner.to_dict() if self.owner else None,
            "tags": list(self.tags),
            "triggers": [t.to_dict() for t in self.triggers],
            "mitigations": [m.to_dict() for m in self.mitigations],
            "evidence": [e.to_dict() for e in self.evidence],
            "links": list(self.links),
            "review_interval_days": int(self.review_interval_days),
            "next_review_date": self.next_review_date.isoformat() if self.next_review_date else None,
            "last_reviewed_at": self.last_reviewed_at.isoformat() if self.last_reviewed_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class RiskRegistry:
    """
    Industrial PMO risk register:
      - in-memory registry with thread-safety
      - deterministic IDs
      - deduplication helpers
      - audit event log per risk
      - export to JSON/CSV (no external deps)
      - filtering and sorting
    """

    def __init__(
        self,
        *,
        service: str = "agent_mash_pmo",
        scoring: Optional[RiskScoringModel] = None,
        now_fn: Optional[callable] = None,
    ) -> None:
        self._service = str(service)
        self._scoring = scoring or RiskScoringModel()
        self._now_fn = now_fn or (lambda: dt.datetime.now(dt.timezone.utc))
        self._lock = threading.RLock()
        self._items: dict[str, RiskItem] = {}
        self._events: dict[str, list[RiskEvent]] = {}

    @property
    def service(self) -> str:
        return self._service

    @property
    def scoring(self) -> RiskScoringModel:
        return self._scoring

    def list_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._items.keys()))

    def get(self, risk_id: str) -> Optional[RiskItem]:
        with self._lock:
            return self._items.get(risk_id)

    def events(self, risk_id: str) -> tuple[RiskEvent, ...]:
        with self._lock:
            return tuple(self._events.get(risk_id, []))

    def add(
        self,
        *,
        title: str,
        description: str,
        category: RiskCategory,
        probability: int,
        impact: int,
        owner: Optional[RiskOwner] = None,
        tags: Iterable[str] = (),
        triggers: Iterable[RiskTrigger] = (),
        links: Iterable[str] = (),
        review_interval_days: int = 14,
        actor: str = "system",
        risk_id: Optional[str] = None,
    ) -> RiskItem:
        t = _norm_title(title)
        d = _norm_text(description)
        p = _clamp_1_5(probability)
        i = _clamp_1_5(impact)
        rid = risk_id or _new_risk_id(t, category.value, p, i)

        now = self._now_fn()
        next_review = _calc_next_review(now, review_interval_days)

        item = RiskItem(
            id=rid,
            title=t,
            description=d,
            category=category,
            status=RiskStatus.OPEN,
            probability=p,
            impact=i,
            created_at=now,
            updated_at=now,
            owner=owner,
            tags=_norm_tags(tags),
            triggers=tuple(triggers),
            mitigations=(),
            evidence=(),
            links=_norm_links(links),
            review_interval_days=int(max(1, review_interval_days)),
            next_review_date=next_review,
            last_reviewed_at=None,
        )

        with self._lock:
            if rid in self._items:
                raise ValueError(f"risk already exists: {rid}")
            self._items[rid] = item
            self._events[rid] = []
            self._append_event(
                rid,
                EventType.CREATED,
                actor,
                f"Risk created: {item.title}",
                patch={"risk": item.to_dict(scoring=self._scoring)},
            )
        return item

    def update(
        self,
        risk_id: str,
        *,
        title: Optional[str] = None,
        description: Optional[str] = None,
        category: Optional[RiskCategory] = None,
        probability: Optional[int] = None,
        impact: Optional[int] = None,
        owner: Optional[RiskOwner] = None,
        tags: Optional[Iterable[str]] = None,
        triggers: Optional[Iterable[RiskTrigger]] = None,
        links: Optional[Iterable[str]] = None,
        review_interval_days: Optional[int] = None,
        actor: str = "system",
    ) -> RiskItem:
        with self._lock:
            item = self._require(risk_id)
            patch: dict[str, Any] = {}

            new_title = item.title if title is None else _norm_title(title)
            new_desc = item.description if description is None else _norm_text(description)
            new_cat = item.category if category is None else category
            new_p = item.probability if probability is None else _clamp_1_5(probability)
            new_i = item.impact if impact is None else _clamp_1_5(impact)
            new_owner = item.owner if owner is None else owner
            new_tags = item.tags if tags is None else _norm_tags(tags)
            new_triggers = item.triggers if triggers is None else tuple(triggers)
            new_links = item.links if links is None else _norm_links(links)
            new_review_interval = item.review_interval_days if review_interval_days is None else int(max(1, review_interval_days))

            now = self._now_fn()
            # Recalculate next review if cadence changed or missing.
            next_review = item.next_review_date
            if review_interval_days is not None or next_review is None:
                next_review = _calc_next_review(now, new_review_interval)

            updated = dataclasses.replace(
                item,
                title=new_title,
                description=new_desc,
                category=new_cat,
                probability=new_p,
                impact=new_i,
                owner=new_owner,
                tags=new_tags,
                triggers=new_triggers,
                links=new_links,
                review_interval_days=new_review_interval,
                next_review_date=next_review,
                updated_at=now,
            )

            if updated.to_dict(scoring=self._scoring) != item.to_dict(scoring=self._scoring):
                patch = _diff_item(item, updated, scoring=self._scoring)
                self._items[risk_id] = updated
                self._append_event(risk_id, EventType.UPDATED, actor, "Risk updated", patch=patch)

            return updated

    def set_status(self, risk_id: str, status: RiskStatus, *, actor: str = "system", note: str = "") -> RiskItem:
        with self._lock:
            item = self._require(risk_id)
            now = self._now_fn()
            if item.status == status:
                return item
            updated = dataclasses.replace(item, status=status, updated_at=now)
            self._items[risk_id] = updated
            self._append_event(
                risk_id,
                EventType.STATUS_CHANGED,
                actor,
                f"Status changed: {item.status.value} -> {status.value}",
                patch={"from": item.status.value, "to": status.value, "note": str(note or "")},
            )
            return updated

    def review(self, risk_id: str, *, actor: str = "system", note: str = "") -> RiskItem:
        with self._lock:
            item = self._require(risk_id)
            now = self._now_fn()
            next_review = _calc_next_review(now, item.review_interval_days)
            updated = dataclasses.replace(item, last_reviewed_at=now, next_review_date=next_review, updated_at=now)
            self._items[risk_id] = updated
            self._append_event(
                risk_id,
                EventType.COMMENT,
                actor,
                "Risk reviewed",
                patch={"note": str(note or ""), "next_review_date": next_review.isoformat() if next_review else None},
            )
            return updated

    def add_mitigation(self, risk_id: str, mitigation: RiskMitigation, *, actor: str = "system") -> RiskItem:
        with self._lock:
            item = self._require(risk_id)
            now = self._now_fn()
            updated = dataclasses.replace(item, mitigations=tuple(item.mitigations) + (mitigation,), updated_at=now)
            self._items[risk_id] = updated
            self._append_event(
                risk_id,
                EventType.MITIGATION_ADDED,
                actor,
                f"Mitigation added: {mitigation.title}",
                patch={"mitigation": mitigation.to_dict()},
            )
            return updated

    def update_mitigation(self, risk_id: str, mitigation_id: str, *, patch: Mapping[str, Any], actor: str = "system") -> RiskItem:
        with self._lock:
            item = self._require(risk_id)
            now = self._now_fn()
            mitigations = list(item.mitigations)
            idx = _find_by_id(mitigations, mitigation_id)
            if idx is None:
                raise KeyError(f"mitigation not found: {mitigation_id}")

            m = mitigations[idx]
            updated_m = _patch_mitigation(m, patch, now=now)
            mitigations[idx] = updated_m

            updated_item = dataclasses.replace(item, mitigations=tuple(mitigations), updated_at=now)
            self._items[risk_id] = updated_item
            self._append_event(
                risk_id,
                EventType.MITIGATION_UPDATED,
                actor,
                f"Mitigation updated: {m.title}",
                patch={"mitigation_id": mitigation_id, "patch": dict(patch)},
            )
            return updated_item

    def remove_mitigation(self, risk_id: str, mitigation_id: str, *, actor: str = "system") -> RiskItem:
        with self._lock:
            item = self._require(risk_id)
            mitigations = [m for m in item.mitigations if m.id != mitigation_id]
            if len(mitigations) == len(item.mitigations):
                return item
            now = self._now_fn()
            updated = dataclasses.replace(item, mitigations=tuple(mitigations), updated_at=now)
            self._items[risk_id] = updated
            self._append_event(
                risk_id,
                EventType.MITIGATION_REMOVED,
                actor,
                f"Mitigation removed: {mitigation_id}",
                patch={"mitigation_id": mitigation_id},
            )
            return updated

    def add_evidence(self, risk_id: str, evidence: RiskEvidence, *, actor: str = "system") -> RiskItem:
        with self._lock:
            item = self._require(risk_id)
            now = self._now_fn()
            updated = dataclasses.replace(item, evidence=tuple(item.evidence) + (evidence,), updated_at=now)
            self._items[risk_id] = updated
            self._append_event(
                risk_id,
                EventType.EVIDENCE_ADDED,
                actor,
                f"Evidence added: {evidence.kind}",
                patch={"evidence": evidence.to_dict()},
            )
            return updated

    def remove_evidence(self, risk_id: str, evidence_id: str, *, actor: str = "system") -> RiskItem:
        with self._lock:
            item = self._require(risk_id)
            evidence = [e for e in item.evidence if e.id != evidence_id]
            if len(evidence) == len(item.evidence):
                return item
            now = self._now_fn()
            updated = dataclasses.replace(item, evidence=tuple(evidence), updated_at=now)
            self._items[risk_id] = updated
            self._append_event(
                risk_id,
                EventType.EVIDENCE_REMOVED,
                actor,
                f"Evidence removed: {evidence_id}",
                patch={"evidence_id": evidence_id},
            )
            return updated

    def link(self, risk_id: str, ref: str, *, actor: str = "system") -> RiskItem:
        with self._lock:
            item = self._require(risk_id)
            ref_n = _norm_link(ref)
            if ref_n in item.links:
                return item
            now = self._now_fn()
            updated = dataclasses.replace(item, links=tuple(item.links) + (ref_n,), updated_at=now)
            self._items[risk_id] = updated
            self._append_event(risk_id, EventType.LINKED, actor, f"Linked: {ref_n}", patch={"ref": ref_n})
            return updated

    def unlink(self, risk_id: str, ref: str, *, actor: str = "system") -> RiskItem:
        with self._lock:
            item = self._require(risk_id)
            ref_n = _norm_link(ref)
            links = tuple(x for x in item.links if x != ref_n)
            if links == item.links:
                return item
            now = self._now_fn()
            updated = dataclasses.replace(item, links=links, updated_at=now)
            self._items[risk_id] = updated
            self._append_event(risk_id, EventType.UNLINKED, actor, f"Unlinked: {ref_n}", patch={"ref": ref_n})
            return updated

    def comment(self, risk_id: str, message: str, *, actor: str = "system") -> None:
        with self._lock:
            self._require(risk_id)
            self._append_event(risk_id, EventType.COMMENT, actor, _norm_text(message), patch={})

    def query(
        self,
        *,
        statuses: Optional[Iterable[RiskStatus]] = None,
        categories: Optional[Iterable[RiskCategory]] = None,
        owners: Optional[Iterable[str]] = None,
        min_level: Optional[RiskLevel] = None,
        tags_any: Optional[Iterable[str]] = None,
        overdue_only: bool = False,
        text: str = "",
        sort_by: str = "level_desc",
        limit: Optional[int] = None,
    ) -> tuple[RiskItem, ...]:
        with self._lock:
            items = list(self._items.values())

        now_date = dt.datetime.now(dt.timezone.utc).date()

        statuses_s = set(s.value for s in (statuses or []))
        categories_s = set(c.value for c in (categories or []))
        owners_s = set(str(o) for o in (owners or []))
        tags_s = set(_norm_tag(t) for t in (tags_any or []))
        needle = _norm_text(text).lower()

        def level(item: RiskItem) -> RiskLevel:
            return self._scoring.level_for_score(item.score())

        def matches(item: RiskItem) -> bool:
            if statuses_s and item.status.value not in statuses_s:
                return False
            if categories_s and item.category.value not in categories_s:
                return False
            if owners_s:
                if not item.owner or item.owner.id not in owners_s:
                    return False
            if min_level is not None:
                if _level_rank(level(item)) < _level_rank(min_level):
                    return False
            if tags_s:
                if not set(item.tags).intersection(tags_s):
                    return False
            if overdue_only:
                if not item.next_review_date or item.next_review_date >= now_date:
                    return False
            if needle:
                hay = (item.title + " " + item.description + " " + " ".join(item.tags)).lower()
                if needle not in hay:
                    return False
            return True

        out = [i for i in items if matches(i)]
        out.sort(key=_sort_key(sort_by, level_fn=level))
        if limit is not None:
            out = out[: int(max(0, limit))]
        return tuple(out)

    def export_json(self) -> str:
        with self._lock:
            payload = {
                "service": self._service,
                "exported_at": self._now_fn().isoformat(),
                "scoring": dataclasses.asdict(self._scoring),
                "risks": [r.to_dict(scoring=self._scoring) for r in sorted(self._items.values(), key=lambda x: x.id)],
                "events": {rid: [e.to_dict() for e in self._events.get(rid, [])] for rid in sorted(self._items.keys())},
            }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=False)

    def export_csv(self) -> str:
        """
        CSV for spreadsheets. Escapes with quotes. No external deps.
        """
        with self._lock:
            rows = []
            for r in sorted(self._items.values(), key=lambda x: x.id):
                d = r.to_dict(scoring=self._scoring)
                rows.append(
                    {
                        "id": d["id"],
                        "title": d["title"],
                        "category": d["category"],
                        "status": d["status"],
                        "probability": d["probability"],
                        "impact": d["impact"],
                        "score": d["score"],
                        "level": d["level"],
                        "owner_id": (d["owner"]["id"] if d["owner"] else ""),
                        "owner_name": (d["owner"]["name"] if d["owner"] else ""),
                        "tags": ",".join(d["tags"] or []),
                        "links": ",".join(d["links"] or []),
                        "next_review_date": d["next_review_date"] or "",
                        "updated_at": d["updated_at"],
                    }
                )

        headers = [
            "id",
            "title",
            "category",
            "status",
            "probability",
            "impact",
            "score",
            "level",
            "owner_id",
            "owner_name",
            "tags",
            "links",
            "next_review_date",
            "updated_at",
        ]

        def esc(s: Any) -> str:
            x = "" if s is None else str(s)
            x = x.replace('"', '""')
            return f'"{x}"'

        lines = [",".join(esc(h) for h in headers)]
        for row in rows:
            lines.append(",".join(esc(row.get(h, "")) for h in headers))
        return "\n".join(lines)

    def dedupe_key(self, title: str, category: RiskCategory) -> str:
        """
        Stable dedupe key for external systems: title+category, normalized.
        """
        base = f"{_norm_title(title)}|{category.value}"
        return hashlib.sha256(base.encode("utf-8")).hexdigest()

    def find_by_dedupe(self, *, title: str, category: RiskCategory) -> Optional[RiskItem]:
        key = self.dedupe_key(title, category)
        with self._lock:
            for r in self._items.values():
                if self.dedupe_key(r.title, r.category) == key:
                    return r
        return None

    def _require(self, risk_id: str) -> RiskItem:
        item = self._items.get(risk_id)
        if item is None:
            raise KeyError(f"risk not found: {risk_id}")
        return item

    def _append_event(self, risk_id: str, et: EventType, actor: str, message: str, patch: Mapping[str, Any]) -> None:
        ev = RiskEvent(
            id=_new_event_id(),
            ts=self._now_fn(),
            type=et,
            actor=str(actor or "system"),
            message=_norm_text(message),
            patch=dict(patch or {}),
        )
        self._events.setdefault(risk_id, []).append(ev)


def _new_event_id() -> str:
    return uuid.uuid4().hex


def _new_risk_id(title: str, category: str, p: int, i: int) -> str:
    # Deterministic-ish id based on content + randomness to avoid collisions in same title.
    # Prefix for readability.
    salt = uuid.uuid4().hex[:8]
    base = f"{title}|{category}|{p}|{i}|{salt}"
    digest = hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]
    return f"RISK-{digest}".upper()


def _norm_text(s: str) -> str:
    x = "" if s is None else str(s)
    x = x.strip()
    x = re.sub(r"\s+", " ", x)
    return x


def _norm_title(s: str) -> str:
    x = _norm_text(s)
    if not x:
        raise ValueError("title must be non-empty")
    if len(x) > 200:
        x = x[:200].rstrip()
    return x


def _norm_tag(tag: str) -> str:
    t = _norm_text(tag).lower()
    t = re.sub(r"[^a-z0-9_\-.:/]+", "_", t)
    t = t.strip("_")
    if not t:
        return ""
    if len(t) > 48:
        t = t[:48]
    return t


def _norm_tags(tags: Iterable[str]) -> tuple[str, ...]:
    out = []
    seen = set()
    for t in tags or ():
        nt = _norm_tag(t)
        if not nt or nt in seen:
            continue
        seen.add(nt)
        out.append(nt)
    return tuple(out)


def _norm_link(ref: str) -> str:
    x = _norm_text(ref)
    if not x:
        raise ValueError("link ref must be non-empty")
    if len(x) > 200:
        x = x[:200].rstrip()
    return x


def _norm_links(links: Iterable[str]) -> tuple[str, ...]:
    out = []
    seen = set()
    for r in links or ():
        nr = _norm_link(r)
        if nr in seen:
            continue
        seen.add(nr)
        out.append(nr)
    return tuple(out)


def _clamp_1_5(x: Any) -> int:
    try:
        v = int(x)
    except Exception as e:
        raise ValueError(f"probability/impact must be int 1..5: {x}") from e
    if v < 1:
        return 1
    if v > 5:
        return 5
    return v


def _calc_next_review(now: dt.datetime, interval_days: int) -> dt.date:
    days = int(max(1, interval_days))
    return (now.date() + dt.timedelta(days=days))


def _level_rank(level: RiskLevel) -> int:
    return {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }[level]


def _sort_key(sort_by: str, *, level_fn):
    s = (sort_by or "").strip().lower()

    if s == "updated_desc":
        return lambda r: (r.updated_at, r.id),  # type: ignore[misc]
    if s == "updated_asc":
        return lambda r: (r.updated_at, r.id)  # type: ignore[misc]
    if s == "score_desc":
        return lambda r: (r.score(), r.updated_at, r.id)  # type: ignore[misc]
    if s == "score_asc":
        return lambda r: (r.score(), r.updated_at, r.id)  # type: ignore[misc]
    if s == "level_asc":
        return lambda r: (_level_rank(level_fn(r)), r.score(), r.updated_at, r.id)  # type: ignore[misc]
    # default: level_desc
    return lambda r: (-_level_rank(level_fn(r)), -r.score(), r.updated_at, r.id)  # type: ignore[misc]


def _diff_item(before: RiskItem, after: RiskItem, *, scoring: RiskScoringModel) -> dict[str, Any]:
    b = before.to_dict(scoring=scoring)
    a = after.to_dict(scoring=scoring)
    patch: dict[str, Any] = {}
    for k in a.keys():
        if a.get(k) != b.get(k):
            patch[k] = {"from": b.get(k), "to": a.get(k)}
    return patch


def _find_by_id(items: list[Any], item_id: str) -> Optional[int]:
    for idx, it in enumerate(items):
        if getattr(it, "id", None) == item_id:
            return idx
    return None


def _patch_mitigation(m: RiskMitigation, patch: Mapping[str, Any], *, now: dt.datetime) -> RiskMitigation:
    data = dict(patch or {})
    title = m.title if "title" not in data else _norm_title(str(data["title"]))
    description = m.description if "description" not in data else _norm_text(str(data["description"]))
    status = m.status if "status" not in data else _norm_text(str(data["status"]))
    effectiveness = m.effectiveness
    if "effectiveness" in data:
        eff = data["effectiveness"]
        if eff is None:
            effectiveness = None
        else:
            try:
                v = int(eff)
            except Exception as e:
                raise ValueError("effectiveness must be int 0..100") from e
            if v < 0:
                v = 0
            if v > 100:
                v = 100
            effectiveness = v

    due_date = m.due_date
    if "due_date" in data:
        v = data["due_date"]
        if v is None or v == "":
            due_date = None
        elif isinstance(v, dt.date):
            due_date = v
        else:
            # ISO date string
            due_date = dt.date.fromisoformat(str(v))

    owner = m.owner
    if "owner" in data:
        ov = data["owner"]
        if ov is None:
            owner = None
        elif isinstance(ov, RiskOwner):
            owner = ov
        elif isinstance(ov, Mapping):
            owner = RiskOwner(
                id=str(ov.get("id", "")),
                name=str(ov.get("name", "")),
                role=str(ov.get("role", "")),
                contact=str(ov.get("contact", "")),
            )
        else:
            raise ValueError("owner must be RiskOwner|mapping|None")

    mtype = m.type
    if "type" in data:
        tv = str(data["type"])
        try:
            mtype = MitigationType(tv)
        except Exception as e:
            raise ValueError(f"invalid mitigation type: {tv}") from e

    return dataclasses.replace(
        m,
        type=mtype,
        title=title,
        description=description,
        owner=owner,
        due_date=due_date,
        status=status,
        effectiveness=effectiveness,
        updated_at=now,
    )
