# agent_mash/pmo/roadmap.py
# -*- coding: utf-8 -*-
"""
PMO Roadmap core for agent_mash.

Industrial goals:
- Strong domain model for roadmap items (initiative, epic, task, milestone)
- Deterministic IDs, validation, and dependency graph integrity checks
- Topological ordering, cycle detection
- Critical path estimation on DAG with durations and optional dates
- Progress computation (weighted) with status rules
- Export/import JSON (and minimal YAML-like text output without external deps)
- CLI utility for linting, stats, ordering, and exporting

No external dependencies. Standard library only.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import logging
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)


class RoadmapError(Exception):
    pass


class ValidationError(RoadmapError):
    pass


class GraphError(RoadmapError):
    pass


class ItemType(str, Enum):
    INITIATIVE = "initiative"
    EPIC = "epic"
    TASK = "task"
    MILESTONE = "milestone"


class Status(str, Enum):
    TODO = "todo"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    DONE = "done"
    CANCELED = "canceled"


def _utc_today() -> _dt.date:
    return _dt.datetime.utcnow().date()


def _parse_date(value: Optional[str]) -> Optional[_dt.date]:
    if value is None:
        return None
    if isinstance(value, str) and value.strip() == "":
        return None
    try:
        return _dt.date.fromisoformat(value)
    except Exception as e:
        raise ValidationError(f"Invalid ISO date: {value}") from e


def _date_to_str(d: Optional[_dt.date]) -> Optional[str]:
    return d.isoformat() if d else None


def _stable_id(value: str) -> str:
    v = (value or "").strip()
    if not v:
        raise ValidationError("Empty id is not allowed")
    return v


@dataclass(frozen=True)
class Dependency:
    """
    A dependency edge: this item depends on `depends_on`.
    """
    depends_on: str


@dataclass
class RoadmapItem:
    """
    A single unit in the roadmap. All scheduling is optional; if dates are absent,
    critical path uses durations and assumes day-based units.

    Key fields:
    - id: unique identifier
    - type: initiative/epic/task/milestone
    - status: todo/in_progress/blocked/done/canceled
    - owner: accountable person or team
    - duration_days: planned effort duration for critical-path calculations
    - start_date, due_date: optional explicit dates (ISO)
    - dependencies: list of Dependency edges
    - children: logical hierarchy (initiative -> epics -> tasks)
    """
    id: str
    title: str
    type: ItemType = ItemType.TASK
    status: Status = Status.TODO
    owner: str = "unassigned"
    domain: str = "general"

    priority: int = 3  # 1 highest, 5 lowest
    weight: float = 1.0  # for progress weighting
    duration_days: int = 1

    start_date: Optional[_dt.date] = None
    due_date: Optional[_dt.date] = None

    dependencies: List[Dependency] = field(default_factory=list)
    children: List[str] = field(default_factory=list)

    description: str = ""
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.id = _stable_id(self.id)
        self.title = (self.title or "").strip()
        if not self.title:
            raise ValidationError(f"Item {self.id}: title is required")

        if not isinstance(self.type, ItemType):
            self.type = ItemType(str(self.type))

        if not isinstance(self.status, Status):
            self.status = Status(str(self.status))

        if not isinstance(self.priority, int) or self.priority < 1 or self.priority > 5:
            raise ValidationError(f"Item {self.id}: priority must be int in [1..5]")

        if not isinstance(self.weight, (int, float)) or float(self.weight) <= 0:
            raise ValidationError(f"Item {self.id}: weight must be > 0")

        if not isinstance(self.duration_days, int) or self.duration_days < 0:
            raise ValidationError(f"Item {self.id}: duration_days must be >= 0")

        if self.start_date and not isinstance(self.start_date, _dt.date):
            raise ValidationError(f"Item {self.id}: start_date must be date")
        if self.due_date and not isinstance(self.due_date, _dt.date):
            raise ValidationError(f"Item {self.id}: due_date must be date")

        if self.start_date and self.due_date and self.start_date > self.due_date:
            raise ValidationError(f"Item {self.id}: start_date must be <= due_date")

        # Normalize deps and children ids
        deps: List[Dependency] = []
        for d in self.dependencies:
            if isinstance(d, Dependency):
                deps.append(d)
            else:
                deps.append(Dependency(depends_on=_stable_id(str(d))))
        self.dependencies = deps

        self.children = [_stable_id(str(c)) for c in self.children]

        # Normalize tags
        self.tags = [t.strip() for t in (self.tags or []) if str(t).strip()]

        # Normalize owner/domain
        self.owner = (self.owner or "").strip() or "unassigned"
        self.domain = (self.domain or "").strip() or "general"

    def is_active(self) -> bool:
        return self.status not in (Status.DONE, Status.CANCELED)

    def progress_value(self) -> float:
        """
        Converts status into numeric progress.
        """
        if self.status == Status.DONE:
            return 1.0
        if self.status == Status.CANCELED:
            return 1.0
        if self.status == Status.IN_PROGRESS:
            return 0.5
        if self.status == Status.BLOCKED:
            return 0.25
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "type": self.type.value,
            "status": self.status.value,
            "owner": self.owner,
            "domain": self.domain,
            "priority": self.priority,
            "weight": float(self.weight),
            "duration_days": int(self.duration_days),
            "start_date": _date_to_str(self.start_date),
            "due_date": _date_to_str(self.due_date),
            "dependencies": [d.depends_on for d in self.dependencies],
            "children": list(self.children),
            "description": self.description,
            "tags": list(self.tags),
            "meta": dict(self.meta),
        }

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "RoadmapItem":
        return RoadmapItem(
            id=str(data.get("id", "")).strip(),
            title=str(data.get("title", "")).strip(),
            type=ItemType(str(data.get("type", ItemType.TASK.value))),
            status=Status(str(data.get("status", Status.TODO.value))),
            owner=str(data.get("owner", "unassigned")),
            domain=str(data.get("domain", "general")),
            priority=int(data.get("priority", 3)),
            weight=float(data.get("weight", 1.0)),
            duration_days=int(data.get("duration_days", 1)),
            start_date=_parse_date(data.get("start_date")),
            due_date=_parse_date(data.get("due_date")),
            dependencies=[Dependency(depends_on=str(x)) for x in (data.get("dependencies") or [])],
            children=[str(x) for x in (data.get("children") or [])],
            description=str(data.get("description", "")),
            tags=[str(x) for x in (data.get("tags") or [])],
            meta=dict(data.get("meta") or {}),
        )


@dataclass(frozen=True)
class CriticalPathNode:
    item_id: str
    duration_days: int
    earliest_start_day: int
    earliest_finish_day: int


@dataclass(frozen=True)
class RoadmapStats:
    total_items: int
    active_items: int
    done_items: int
    blocked_items: int
    progress_percent: float
    critical_path_days: int
    critical_path: Tuple[str, ...]


class Roadmap:
    """
    Roadmap container with graph logic.
    """

    def __init__(self, name: str = "roadmap", created_on: Optional[_dt.date] = None) -> None:
        self.name = (name or "roadmap").strip()
        self.created_on = created_on or _utc_today()
        self._items: Dict[str, RoadmapItem] = {}

    def add(self, item: RoadmapItem) -> None:
        if item.id in self._items:
            raise ValidationError(f"Duplicate item id: {item.id}")
        self._items[item.id] = item

    def upsert(self, item: RoadmapItem) -> None:
        self._items[item.id] = item

    def get(self, item_id: str) -> RoadmapItem:
        try:
            return self._items[item_id]
        except KeyError as e:
            raise ValidationError(f"Unknown item id: {item_id}") from e

    def items(self) -> List[RoadmapItem]:
        return list(self._items.values())

    def ids(self) -> List[str]:
        return list(self._items.keys())

    def validate(self) -> None:
        """
        Validates:
        - referenced dependencies exist
        - children exist
        - no self-dependency
        - DAG has no cycles
        """
        for it in self._items.values():
            for dep in it.dependencies:
                if dep.depends_on == it.id:
                    raise GraphError(f"Self-dependency detected: {it.id} depends on itself")
                if dep.depends_on not in self._items:
                    raise GraphError(f"Missing dependency item: {it.id} depends on {dep.depends_on}")
            for ch in it.children:
                if ch not in self._items:
                    raise GraphError(f"Missing child item: {it.id} has child {ch}")

        _ = self.topological_order()  # will raise on cycles

    def _build_graph(self) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        """
        Returns:
        - forward adjacency: node -> set of successors
        - reverse adjacency: node -> set of predecessors
        Edge direction: dep -> item (dep must be done before item).
        """
        succ: Dict[str, Set[str]] = {k: set() for k in self._items}
        pred: Dict[str, Set[str]] = {k: set() for k in self._items}
        for it in self._items.values():
            for dep in it.dependencies:
                succ[dep.depends_on].add(it.id)
                pred[it.id].add(dep.depends_on)
        return succ, pred

    def topological_order(self) -> Tuple[str, ...]:
        """
        Kahn's algorithm.
        """
        succ, pred = self._build_graph()
        indeg: Dict[str, int] = {k: len(pred[k]) for k in pred}
        queue: List[str] = [k for k, d in indeg.items() if d == 0]
        queue.sort()
        out: List[str] = []

        while queue:
            n = queue.pop(0)
            out.append(n)
            for m in sorted(succ[n]):
                indeg[m] -= 1
                if indeg[m] == 0:
                    queue.append(m)

        if len(out) != len(self._items):
            # cycle exists: find a simple witness set
            remaining = [k for k in self._items if k not in out]
            raise GraphError(f"Dependency cycle detected. Remaining nodes: {remaining[:20]}")
        return tuple(out)

    def compute_progress(self) -> float:
        """
        Weighted average progress across items.
        """
        if not self._items:
            return 0.0
        total_w = 0.0
        total_p = 0.0
        for it in self._items.values():
            w = float(it.weight)
            total_w += w
            total_p += w * float(it.progress_value())
        if total_w <= 0:
            return 0.0
        return max(0.0, min(1.0, total_p / total_w))

    def critical_path(self, include_canceled: bool = False) -> Tuple[int, Tuple[str, ...], Tuple[CriticalPathNode, ...]]:
        """
        Returns:
        - total duration days on critical path
        - path as tuple of item ids (in order)
        - per-node schedule for the path (earliest start/finish in day units)

        Model:
        - DAG longest path on durations using dynamic programming in topological order.
        - If include_canceled is False, canceled items have duration 0 and do not block.
        """
        if not self._items:
            return 0, (), ()

        succ, pred = self._build_graph()
        topo = self.topological_order()

        duration: Dict[str, int] = {}
        for k in topo:
            it = self._items[k]
            if it.status == Status.CANCELED and not include_canceled:
                duration[k] = 0
            else:
                duration[k] = max(0, int(it.duration_days))

        # earliest finish times
        es: Dict[str, int] = {k: 0 for k in topo}  # earliest start
        ef: Dict[str, int] = {k: 0 for k in topo}  # earliest finish
        parent: Dict[str, Optional[str]] = {k: None for k in topo}

        for n in topo:
            best_pre = None
            best_finish = 0
            if pred[n]:
                # pick predecessor that maximizes earliest finish
                for p in pred[n]:
                    if ef[p] >= best_finish:
                        best_finish = ef[p]
                        best_pre = p
            es[n] = best_finish
            ef[n] = es[n] + duration[n]
            parent[n] = best_pre

        # find sink with maximal ef
        end = max(topo, key=lambda x: ef[x])
        total_days = int(ef[end])

        # reconstruct path
        path: List[str] = []
        cur: Optional[str] = end
        while cur is not None:
            path.append(cur)
            cur = parent[cur]
        path.reverse()

        nodes: List[CriticalPathNode] = [
            CriticalPathNode(
                item_id=i,
                duration_days=duration[i],
                earliest_start_day=int(es[i]),
                earliest_finish_day=int(ef[i]),
            )
            for i in path
        ]

        return total_days, tuple(path), tuple(nodes)

    def stats(self) -> RoadmapStats:
        total = len(self._items)
        done = sum(1 for x in self._items.values() if x.status == Status.DONE)
        blocked = sum(1 for x in self._items.values() if x.status == Status.BLOCKED)
        active = sum(1 for x in self._items.values() if x.is_active())
        progress = self.compute_progress()
        cp_days, cp_path, _ = self.critical_path(include_canceled=False)
        return RoadmapStats(
            total_items=total,
            active_items=active,
            done_items=done,
            blocked_items=blocked,
            progress_percent=round(progress * 100.0, 2),
            critical_path_days=int(cp_days),
            critical_path=cp_path,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "created_on": self.created_on.isoformat(),
            "items": [it.to_dict() for it in sorted(self._items.values(), key=lambda x: x.id)],
        }

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "Roadmap":
        name = str(data.get("name", "roadmap"))
        created_on = _parse_date(data.get("created_on")) or _utc_today()
        rm = Roadmap(name=name, created_on=created_on)
        for it_data in data.get("items") or []:
            rm.add(RoadmapItem.from_dict(it_data))
        return rm

    def to_json(self, pretty: bool = True) -> str:
        obj = self.to_dict()
        if pretty:
            return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def from_json(text: str) -> "Roadmap":
        try:
            data = json.loads(text)
        except Exception as e:
            raise ValidationError("Invalid JSON roadmap") from e
        if not isinstance(data, dict):
            raise ValidationError("Roadmap JSON root must be an object")
        return Roadmap.from_dict(data)

    def to_minimal_yaml(self) -> str:
        """
        Minimal YAML-like output without a YAML library.
        It is intended for human reading, not strict YAML parsing.
        """
        lines: List[str] = []
        lines.append(f"name: {self.name}")
        lines.append(f"created_on: {self.created_on.isoformat()}")
        lines.append("items:")
        for it in sorted(self._items.values(), key=lambda x: x.id):
            lines.append(f"  - id: {it.id}")
            lines.append(f"    title: {it.title}")
            lines.append(f"    type: {it.type.value}")
            lines.append(f"    status: {it.status.value}")
            lines.append(f"    owner: {it.owner}")
            lines.append(f"    domain: {it.domain}")
            lines.append(f"    priority: {it.priority}")
            lines.append(f"    weight: {float(it.weight)}")
            lines.append(f"    duration_days: {int(it.duration_days)}")
            if it.start_date:
                lines.append(f"    start_date: {it.start_date.isoformat()}")
            if it.due_date:
                lines.append(f"    due_date: {it.due_date.isoformat()}")
            if it.dependencies:
                lines.append("    dependencies:")
                for d in it.dependencies:
                    lines.append(f"      - {d.depends_on}")
            if it.children:
                lines.append("    children:")
                for c in it.children:
                    lines.append(f"      - {c}")
            if it.tags:
                lines.append("    tags:")
                for t in it.tags:
                    lines.append(f"      - {t}")
            if it.description:
                desc = it.description.replace("\n", "\\n")
                lines.append(f"    description: {desc}")
            if it.meta:
                lines.append("    meta:")
                for k, v in sorted(it.meta.items(), key=lambda kv: str(kv[0])):
                    vv = str(v).replace("\n", "\\n")
                    lines.append(f"      {k}: {vv}")
        return "\n".join(lines)

    def render_markdown(self, include_critical_path: bool = True) -> str:
        """
        Human-readable markdown report.
        """
        st = self.stats()
        lines: List[str] = []
        lines.append(f"# {self.name}")
        lines.append("")
        lines.append(f"Created on: {self.created_on.isoformat()}")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- Total items: {st.total_items}")
        lines.append(f"- Active items: {st.active_items}")
        lines.append(f"- Done items: {st.done_items}")
        lines.append(f"- Blocked items: {st.blocked_items}")
        lines.append(f"- Progress: {st.progress_percent}%")
        lines.append(f"- Critical path: {st.critical_path_days} days")
        lines.append("")
        if include_critical_path and st.critical_path:
            lines.append("## Critical path")
            lines.append("")
            for idx, item_id in enumerate(st.critical_path, start=1):
                it = self._items[item_id]
                lines.append(f"{idx}. {it.id} {it.title} ({it.status.value})")
            lines.append("")
        lines.append("## Items")
        lines.append("")
        for it in sorted(self._items.values(), key=lambda x: (x.type.value, x.priority, x.id)):
            deps = [d.depends_on for d in it.dependencies]
            lines.append(f"- {it.id} [{it.type.value}] [{it.status.value}] p{it.priority} {it.title}")
            lines.append(f"  owner: {it.owner} domain: {it.domain} duration_days: {it.duration_days} weight: {it.weight}")
            if it.start_date or it.due_date:
                lines.append(f"  dates: {(_date_to_str(it.start_date) or '-') } -> {(_date_to_str(it.due_date) or '-')}")
            if deps:
                lines.append(f"  depends_on: {', '.join(deps)}")
            if it.children:
                lines.append(f"  children: {', '.join(it.children)}")
            if it.tags:
                lines.append(f"  tags: {', '.join(it.tags)}")
        lines.append("")
        return "\n".join(lines)


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError as e:
        raise ValidationError(f"File not found: {path}") from e
    except Exception as e:
        raise ValidationError(f"Cannot read file: {path}") from e


def _write_text(path: str, text: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    except Exception as e:
        raise ValidationError(f"Cannot write file: {path}") from e


def load_roadmap(path: str) -> Roadmap:
    text = _read_text(path)
    return Roadmap.from_json(text)


def save_roadmap(path: str, roadmap: Roadmap, pretty: bool = True) -> None:
    _write_text(path, roadmap.to_json(pretty=pretty))


def _cmd_lint(args: argparse.Namespace) -> int:
    rm = load_roadmap(args.path)
    rm.validate()
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    rm = load_roadmap(args.path)
    rm.validate()
    st = rm.stats()
    out = {
        "total_items": st.total_items,
        "active_items": st.active_items,
        "done_items": st.done_items,
        "blocked_items": st.blocked_items,
        "progress_percent": st.progress_percent,
        "critical_path_days": st.critical_path_days,
        "critical_path": list(st.critical_path),
    }
    sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return 0


def _cmd_order(args: argparse.Namespace) -> int:
    rm = load_roadmap(args.path)
    rm.validate()
    order = rm.topological_order()
    sys.stdout.write("\n".join(order) + "\n")
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    rm = load_roadmap(args.path)
    rm.validate()
    if args.format == "json":
        sys.stdout.write(rm.to_json(pretty=True) + "\n")
        return 0
    if args.format == "yaml":
        sys.stdout.write(rm.to_minimal_yaml() + "\n")
        return 0
    if args.format == "md":
        sys.stdout.write(rm.render_markdown(include_critical_path=True) + "\n")
        return 0
    raise ValidationError(f"Unknown export format: {args.format}")


def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent_mash.pmo.roadmap", add_help=True)
    p.add_argument("--log-level", default="WARNING", help="DEBUG, INFO, WARNING, ERROR")
    sub = p.add_subparsers(dest="cmd", required=True)

    lint = sub.add_parser("lint", help="Validate roadmap JSON (graph, refs, cycles)")
    lint.add_argument("path", help="Path to roadmap JSON file")
    lint.set_defaults(func=_cmd_lint)

    stats = sub.add_parser("stats", help="Print roadmap statistics as JSON")
    stats.add_argument("path", help="Path to roadmap JSON file")
    stats.set_defaults(func=_cmd_stats)

    order = sub.add_parser("order", help="Print topological order of items")
    order.add_argument("path", help="Path to roadmap JSON file")
    order.set_defaults(func=_cmd_order)

    exp = sub.add_parser("export", help="Export roadmap to json, yaml-like, or markdown")
    exp.add_argument("path", help="Path to roadmap JSON file")
    exp.add_argument("--format", choices=["json", "yaml", "md"], default="md")
    exp.set_defaults(func=_cmd_export)

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(argv) if argv is not None else sys.argv[1:]
    parser = build_cli()
    args = parser.parse_args(argv)

    level_name = str(getattr(args, "log_level", "WARNING")).upper().strip()
    level = getattr(logging, level_name, logging.WARNING)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    try:
        return int(args.func(args))
    except (ValidationError, GraphError) as e:
        sys.stderr.write(f"ERROR: {e}\n")
        return 2
    except Exception as e:
        logger.exception("Unexpected error")
        sys.stderr.write(f"ERROR: {type(e).__name__}: {e}\n")
        return 3


__all__ = [
    "Roadmap",
    "RoadmapItem",
    "Dependency",
    "ItemType",
    "Status",
    "RoadmapStats",
    "CriticalPathNode",
    "load_roadmap",
    "save_roadmap",
    "main",
]

if __name__ == "__main__":
    raise SystemExit(main())
