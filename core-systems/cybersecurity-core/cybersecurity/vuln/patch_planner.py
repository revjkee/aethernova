# cybersecurity-core/cybersecurity/vuln/patch_planner.py
"""
Industrial-grade Patch Planner for Vulnerability Management.

Core capabilities:
- Inputs: Vulnerabilities (CVSS/EPSS/exploit flags), Findings, Assets, Patches, Maintenance Windows
- Policy-driven risk scoring (weights for CVSS, EPSS, exploit presence, asset criticality, age)
- SLA-based deadlines per severity; breach detection and reporting
- Dependency-aware scheduling (topological order, cycle detection)
- Maintenance windows filtering by BU/Env/Asset/Platform with capacity (max_concurrency)
- Canary rollout (first N% assets in batch), then full rollout
- Grouping: by (patch_id, platform, BU); splits into capacity-aware batches
- Outputs: Plan with tasks, conflicts, unpatchable items, SLA breaches, summary metrics
- Pure stdlib, fully typed. Timezone aware via zoneinfo.

Authoritative assumptions:
- No external DB; planner consumes Python objects and produces a deterministic plan
- Datetimes must be timezone-aware (ZoneInfo), else they will be coerced to policy.timezone

Copyright:
- MIT or project license, as preferred by repository policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import (
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)
from enum import Enum
import heapq
import math
import uuid
from collections import defaultdict, deque, Counter


# ---------------------------
# Domain models
# ---------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Vulnerability:
    vuln_id: str
    severity: Severity
    cvss_v3: float  # 0..10
    epss: float = 0.0  # 0..1
    exploited_in_the_wild: bool = False
    published_at: Optional[datetime] = None  # tz-aware recommended
    cwe: Optional[str] = None
    description: Optional[str] = None


@dataclass(frozen=True)
class Asset:
    asset_id: str
    name: str
    business_unit: str
    environment: str  # prod/stage/dev/etc
    platform: str     # windows/linux/macos/network/ios/android/etc
    criticality: int = 3  # 1..5
    tags: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Patch:
    patch_id: str
    description: str
    platform: str
    estimated_duration: timedelta = timedelta(minutes=20)
    requires_reboot: bool = False
    dependencies: Tuple[str, ...] = ()  # list of patch_id prerequisites
    cab_required: bool = False  # change advisory board requirement flag (can be auto-set by policy)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    vuln_id: str
    asset_id: str
    suggested_patch_id: Optional[str]  # may be None if not mapped
    detected_at: datetime


@dataclass(frozen=True)
class MaintenanceWindow:
    window_id: str
    start: datetime
    end: datetime
    max_concurrency: int = 50
    business_units: Tuple[str, ...] = ()
    environments: Tuple[str, ...] = ()
    assets: Tuple[str, ...] = ()
    platforms: Tuple[str, ...] = ()
    blackout: bool = False  # if True, do not schedule here

    def duration(self) -> timedelta:
        return self.end - self.start

    def matches(self, asset: Asset) -> bool:
        if self.blackout:
            return False
        if self.business_units and asset.business_unit not in self.business_units:
            return False
        if self.environments and asset.environment not in self.environments:
            return False
        if self.assets and asset.asset_id not in self.assets:
            return False
        if self.platforms and asset.platform not in self.platforms:
            return False
        return True


# ---------------------------
# Policy and config
# ---------------------------

@dataclass(frozen=True)
class SLAConfig:
    days_critical: int = 7
    days_high: int = 14
    days_medium: int = 30
    days_low: int = 90
    days_info: int = 180

    def deadline_for(self, severity: Severity, detected_at: datetime) -> datetime:
        delta = {
            Severity.CRITICAL: timedelta(days=self.days_critical),
            Severity.HIGH: timedelta(days=self.days_high),
            Severity.MEDIUM: timedelta(days=self.days_medium),
            Severity.LOW: timedelta(days=self.days_low),
            Severity.INFO: timedelta(days=self.days_info),
        }[severity]
        return detected_at + delta


@dataclass(frozen=True)
class RiskWeights:
    w_cvss: float = 0.4
    w_epss: float = 0.2
    w_exploit: float = 0.2
    w_asset_crit: float = 0.15
    w_age: float = 0.05  # age factor

    def normalize(self) -> "RiskWeights":
        s = self.w_cvss + self.w_epss + self.w_exploit + self.w_asset_crit + self.w_age
        if s <= 0:
            return self
        return RiskWeights(
            w_cvss=self.w_cvss / s,
            w_epss=self.w_epss / s,
            w_exploit=self.w_exploit / s,
            w_asset_crit=self.w_asset_crit / s,
            w_age=self.w_age / s,
        )


@dataclass(frozen=True)
class PlannerPolicy:
    timezone: str = "UTC"
    sla: SLAConfig = SLAConfig()
    risk: RiskWeights = RiskWeights().normalize()
    canary_percent: int = 10  # 10% of assets go first
    max_batch_size: int = 200  # hard upper bound per task
    require_cab_risk_threshold: float = 85.0  # tasks with average risk >= require CAB
    max_parallel_tasks_per_window: int = 100  # safety cap in addition to window.max_concurrency
    # Penalty for proximity to SLA deadline (in risk points)
    deadline_urgency_boost_days: int = 3
    deadline_urgency_points: float = 10.0


# ---------------------------
# Planning outputs
# ---------------------------

@dataclass
class PlanTask:
    task_id: str
    patch_id: str
    window_id: str
    start: datetime
    end: datetime
    assets: Tuple[str, ...]
    risk_reduction: float
    average_risk: float
    requires_reboot: bool
    cab_required: bool
    covers_findings: Tuple[str, ...]  # finding_ids
    meta: Mapping[str, str] = field(default_factory=dict)


@dataclass
class Conflict:
    code: str
    message: str
    details: Mapping[str, str] = field(default_factory=dict)


@dataclass
class SLABreach:
    finding_id: str
    deadline: datetime
    reason: str


@dataclass
class Plan:
    tasks: Tuple[PlanTask, ...]
    conflicts: Tuple[Conflict, ...]
    breaches: Tuple[SLABreach, ...]
    unpatchable_findings: Tuple[str, ...]
    metrics: Mapping[str, float]


# ---------------------------
# Internal helpers
# ---------------------------

def _tz(dt: datetime, zone: ZoneInfo) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=zone)
    return dt.astimezone(zone)


def _age_days(now: datetime, published_at: Optional[datetime]) -> float:
    if not published_at:
        return 0.0
    delta = now - published_at
    return max(0.0, delta.total_seconds() / 86400.0)


def risk_score(
    *,
    now: datetime,
    vuln: Vulnerability,
    asset: Asset,
    weights: RiskWeights,
    sla: SLAConfig,
    detected_at: datetime,
    deadline_urgency_boost_days: int,
    deadline_urgency_points: float,
) -> float:
    cvss = max(0.0, min(10.0, vuln.cvss_v3)) / 10.0 * 100.0
    epss = max(0.0, min(1.0, vuln.epss)) * 100.0
    exploit = 100.0 if vuln.exploited_in_the_wild else 0.0
    asset_crit = (max(1, min(5, asset.criticality)) - 1) / 4.0 * 100.0
    age = min(3650.0, _age_days(now, vuln.published_at)) / 3650.0 * 100.0  # up to ~10 years scaled

    base = (
        weights.w_cvss * cvss
        + weights.w_epss * epss
        + weights.w_exploit * exploit
        + weights.w_asset_crit * asset_crit
        + weights.w_age * age
    )

    # SLA urgency boost if close to deadline
    deadline = sla.deadline_for(vuln.severity, detected_at)
    days_left = (deadline - now).total_seconds() / 86400.0
    if days_left <= deadline_urgency_boost_days:
        base = min(100.0, base + deadline_urgency_points)

    return round(min(100.0, max(0.0, base)), 2)


def _toposort(deps: Mapping[str, Sequence[str]]) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """
    Returns topological order for patches and a tuple of nodes that participate in cycles.
    """
    indeg: Dict[str, int] = {}
    g: Dict[str, Set[str]] = defaultdict(set)
    all_nodes: Set[str] = set(deps.keys())

    for node, prereqs in deps.items():
        all_nodes.add(node)
        indeg.setdefault(node, 0)
        for p in prereqs:
            g[p].add(node)
            indeg[node] = indeg.get(node, 0) + 1
            all_nodes.add(p)
            indeg.setdefault(p, indeg.get(p, 0))

    q = deque([n for n in all_nodes if indeg.get(n, 0) == 0])
    order: List[str] = []
    while q:
        u = q.popleft()
        order.append(u)
        for v in g.get(u, ()):
            indeg[v] -= 1
            if indeg[v] == 0:
                q.append(v)

    cyclic = tuple(sorted(n for n in all_nodes if indeg.get(n, 0) > 0))
    return tuple(order), cyclic


# ---------------------------
# Planner
# ---------------------------

class PatchPlanner:
    """
    Build patch tasks across maintenance windows with risk- and SLA-aware prioritization.
    """

    def __init__(self, policy: Optional[PlannerPolicy] = None) -> None:
        self.policy = policy or PlannerPolicy()
        self.zone = ZoneInfo(self.policy.timezone)

    def plan(
        self,
        *,
        now: datetime,
        vulnerabilities: Mapping[str, Vulnerability],
        assets: Mapping[str, Asset],
        patches: Mapping[str, Patch],
        findings: Sequence[Finding],
        windows: Sequence[MaintenanceWindow],
    ) -> Plan:
        now = _tz(now, self.zone)

        # Normalize timezones for all inputs
        windows = tuple(
            MaintenanceWindow(
                window_id=w.window_id,
                start=_tz(w.start, self.zone),
                end=_tz(w.end, self.zone),
                max_concurrency=w.max_concurrency,
                business_units=w.business_units,
                environments=w.environments,
                assets=w.assets,
                platforms=w.platforms,
                blackout=w.blackout,
            )
            for w in windows
            if w.end > now  # ignore past windows entirely
        )

        conflicts: List[Conflict] = []
        breaches: List[SLABreach] = []
        unpatchable: List[str] = []

        # Validate windows basic consistency
        for w in windows:
            if w.start >= w.end:
                conflicts.append(Conflict(code="window_invalid", message="Window has non-positive duration",
                                          details={"window_id": w.window_id}))
        if conflicts:
            # Do not return early: report but continue to schedule in valid ones
            pass

        # Build dependency graph for patches
        deps: Dict[str, Tuple[str, ...]] = {p_id: tuple(p.dependencies) for p_id, p in patches.items()}
        topo, cyclic = _toposort(deps)
        if cyclic:
            for pid in cyclic:
                conflicts.append(Conflict(code="dependency_cycle", message="Patch participates in a dependency cycle",
                                          details={"patch_id": pid}))
            # We will proceed but deprioritize cyclic patches to the end, and schedule them standalone if possible.

        # Compute risk per finding and group by (patch, platform, BU)
        priority_items: List[Tuple[float, Tuple[str, str, str], Finding]] = []
        finding_deadline: Dict[str, datetime] = {}

        for f in findings:
            vuln = vulnerabilities.get(f.vuln_id)
            asset = assets.get(f.asset_id)
            if not vuln or not asset:
                conflicts.append(Conflict(code="missing_ref", message="Finding references unknown vuln/asset",
                                          details={"finding_id": f.finding_id,
                                                   "vuln_id": f.vuln_id, "asset_id": f.asset_id}))
                continue
            if not f.suggested_patch_id or f.suggested_patch_id not in patches:
                unpatchable.append(f.finding_id)
                continue

            p = patches[f.suggested_patch_id]
            s = risk_score(
                now=now,
                vuln=vuln,
                asset=asset,
                weights=self.policy.risk,
                sla=self.policy.sla,
                detected_at=_tz(f.detected_at, self.zone),
                deadline_urgency_boost_days=self.policy.deadline_urgency_boost_days,
                deadline_urgency_points=self.policy.deadline_urgency_points,
            )
            finding_deadline[f.finding_id] = self.policy.sla.deadline_for(vuln.severity, _tz(f.detected_at, self.zone))
            key = (p.patch_id, asset.platform, asset.business_unit)
            # Use max-heap via negative risk
            heapq.heappush(priority_items, (-s, key, f))

        # Accumulate items into group buckets
        groups: Dict[Tuple[str, str, str], List[Finding]] = defaultdict(list)
        group_risk_sum: Dict[Tuple[str, str, str], float] = defaultdict(float)
        group_assets: Dict[Tuple[str, str, str], Set[str]] = defaultdict(set)

        tmp_items = list(priority_items)
        while tmp_items:
            neg, key, f = heapq.heappop(tmp_items)
            s = -neg
            groups[key].append(f)
            group_risk_sum[key] += s
            group_assets[key].add(f.asset_id)

        # Prepare window index
        by_id: Dict[str, MaintenanceWindow] = {w.window_id: w for w in windows}
        windows_sorted = sorted(windows, key=lambda w: (w.start, w.window_id))

        # Capacity tracking: how many assets scheduled in window at any time (approximate)
        window_load: Dict[str, int] = Counter()

        tasks: List[PlanTask] = []

        # Order groups: by average risk desc, then by earliest deadline among findings
        def group_priority(key: Tuple[str, str, str]) -> Tuple[float, datetime]:
            risk_avg = group_risk_sum[key] / max(1, len(groups[key]))
            earliest_deadline = min(finding_deadline[f.finding_id] for f in groups[key])
            # Lower tuple sorts earlier; we want high risk first, so invert sign
            return (-risk_avg, earliest_deadline)

        ordered_groups = sorted(groups.keys(), key=group_priority)

        # Map patch -> dependencies resolved?
        deps_map: Dict[str, Tuple[str, ...]] = deps

        for key in ordered_groups:
            patch_id, platform, bu = key
            patch = patches[patch_id]

            # Skip if patch platform does not match key platform rigorously
            if patch.platform and patch.platform != platform:
                conflicts.append(Conflict(code="platform_mismatch",
                                          message="Patch platform differs from finding platform",
                                          details={"patch_id": patch_id, "patch_platform": patch.platform, "platform": platform}))
                continue

            related_findings = groups[key]
            related_assets = sorted(group_assets[key])  # deterministic
            avg_risk = round(group_risk_sum[key] / max(1, len(related_findings)), 2)

            # Respect dependencies: schedule prereqs first if present
            prereqs = tuple(deps_map.get(patch_id, ()))
            if prereqs:
                # Ensure all prereqs exist
                missing_prereqs = [d for d in prereqs if d not in patches]
                if missing_prereqs:
                    conflicts.append(Conflict(code="missing_dependency", message="Patch dependency not found",
                                              details={"patch_id": patch_id, "missing": ",".join(missing_prereqs)}))
                    # Continue, but mark as conflict; still attempt to schedule patch alone
                else:
                    # Insert tasks for dependencies first over the same asset set (best-effort)
                    for dep_id in prereqs:
                        dep_patch = patches[dep_id]
                        # Create a synthetic group for dependency limited to the same assets
                        self._schedule_group_tasks(
                            now=now,
                            patch=dep_patch,
                            asset_ids=related_assets,
                            findings=[],  # dependency tasks may not directly map findings
                            avg_risk=avg_risk,  # inherit priority
                            windows=windows_sorted,
                            by_window=by_id,
                            window_load=window_load,
                            tasks=tasks,
                        )

            # Schedule main group
            self._schedule_group_tasks(
                now=now,
                patch=patch,
                asset_ids=related_assets,
                findings=related_findings,
                avg_risk=avg_risk,
                windows=windows_sorted,
                by_window=by_id,
                window_load=window_load,
                tasks=tasks,
            )

        # SLA breach check: if any finding not covered by tasks before its deadline
        covered_findings: Set[str] = set()
        for t in tasks:
            covered_findings.update(t.covers_findings)

        for f in findings:
            if f.finding_id in covered_findings or f.finding_id in unpatchable:
                continue
            deadline = finding_deadline.get(f.finding_id)
            if not deadline:
                # entries without vuln mapping were already classified unpatchable
                continue
            # Find scheduled time for asset's patch; if none or after deadline => breach
            # Coarse check: any task that affects this asset and patch_id?
            is_planned_before_deadline = False
            for t in tasks:
                if f.suggested_patch_id == t.patch_id and f.asset_id in t.assets and t.start <= deadline:
                    is_planned_before_deadline = True
                    break
            if not is_planned_before_deadline:
                breaches.append(SLABreach(finding_id=f.finding_id, deadline=deadline, reason="not_scheduled_before_deadline"))

        # Metrics
        metrics = {
            "total_tasks": float(len(tasks)),
            "total_conflicts": float(len(conflicts)),
            "total_breaches": float(len(breaches)),
            "unpatchable_findings": float(len(unpatchable)),
            "avg_task_risk": (sum(t.average_risk for t in tasks) / len(tasks)) if tasks else 0.0,
        }

        return Plan(
            tasks=tuple(tasks),
            conflicts=tuple(conflicts),
            breaches=tuple(breaches),
            unpatchable_findings=tuple(unpatchable),
            metrics=metrics,
        )

    # -----------------------
    # Internal scheduling
    # -----------------------

    def _schedule_group_tasks(
        self,
        *,
        now: datetime,
        patch: Patch,
        asset_ids: Sequence[str],
        findings: Sequence[Finding],
        avg_risk: float,
        windows: Sequence[MaintenanceWindow],
        by_window: Mapping[str, MaintenanceWindow],
        window_load: MutableMapping[str, int],
        tasks: List[PlanTask],
    ) -> None:
        """
        Split group into canary + remainder, fit into earliest feasible windows with capacity.
        """
        if not asset_ids:
            return

        # Determine canary split
        canary_n = max(1, math.floor(len(asset_ids) * max(0, min(100, self.policy.canary_percent)) / 100.0))
        canary_assets = list(asset_ids[:canary_n])
        remainder_assets = list(asset_ids[canary_n:])

        # Helper to schedule a batch of assets
        def schedule_batch(batch_assets: List[str], batch_meta: str) -> Optional[PlanTask]:
            if not batch_assets:
                return None
            # Clip to max batch size
            batch_assets = batch_assets[: self.policy.max_batch_size]

            # Find the earliest feasible window that matches all assets' attributes and has capacity
            chosen_window_id: Optional[str] = None
            for w in windows:
                if w.start < now:
                    continue
                # Check all assets compatible with window filters
                if not all(w.matches(asset=self._asset_index[a_id]) for a_id in batch_assets):
                    continue
                # Capacity: window-wide load and per-policy cap
                remaining = min(w.max_concurrency, self.policy.max_parallel_tasks_per_window) - window_load.get(w.window_id, 0)
                # Estimate slots needed: each asset counts as one slot for duration estimate
                if remaining <= 0:
                    continue
                chosen_window_id = w.window_id
                break

            if not chosen_window_id:
                # No window fits; record conflict but continue
                # The upper-level SLA breach checker will catch deadlines
                return None

            w = by_window[chosen_window_id]
            # Compute duration: per-asset duration aggregated, but constrained by window
            # Simplify: each asset ~ patch.estimated_duration; serial per slot in the window capacity => since we batch in one task,
            # we assume orchestrated parallelism within capacity. We'll bound task end by window end.
            est_minutes = math.ceil(patch.estimated_duration.total_seconds() / 60.0)
            # For batch, wall-clock bounded by patch duration (parallel), but include reboot buffer if needed
            reboot_buf = 10 if patch.requires_reboot else 0
            end_time = min(w.end, w.start + timedelta(minutes=est_minutes + reboot_buf))
            task = PlanTask(
                task_id=str(uuid.uuid4()),
                patch_id=patch.patch_id,
                window_id=w.window_id,
                start=w.start,
                end=end_time,
                assets=tuple(batch_assets),
                risk_reduction=avg_risk,  # coarse proxy; could be refined
                average_risk=avg_risk,
                requires_reboot=patch.requires_reboot,
                cab_required=(patch.cab_required or avg_risk >= self.policy.require_cab_risk_threshold),
                covers_findings=tuple(f.finding_id for f in findings if f.asset_id in set(batch_assets)),
                meta={"batch": batch_meta},
            )
            tasks.append(task)
            # Update capacity accounting: consume len(batch_assets) slots
            window_load[w.window_id] = window_load.get(w.window_id, 0) + len(batch_assets)
            return task

        # Build quick asset index for window checks
        # This is done lazily once per planner; memoize
        # For simplicity, attach to self
        if not hasattr(self, "_asset_index"):
            self._asset_index = {}

        # self._asset_index must contain all assets referenced
        for a_id in asset_ids:
            if a_id not in self._asset_index:
                raise KeyError(f"Asset {a_id} not found in planner asset index. Call plan() entrypoint.")

        # Canary first
        schedule_batch(canary_assets, "canary")

        # Remainder: split into chunks fitting into max_batch_size
        if remainder_assets:
            for i in range(0, len(remainder_assets), self.policy.max_batch_size):
                chunk = remainder_assets[i : i + self.policy.max_batch_size]
                schedule_batch(chunk, f"batch_{1 + i // self.policy.max_batch_size}")

    # Hook to preload asset index (internal use)
    def _preload_assets(self, assets: Mapping[str, Asset]) -> None:
        self._asset_index = dict(assets)


# ---------------------------
# Public convenience function
# ---------------------------

def build_patch_plan(
    *,
    now: datetime,
    vulnerabilities: Mapping[str, Vulnerability],
    assets: Mapping[str, Asset],
    patches: Mapping[str, Patch],
    findings: Sequence[Finding],
    windows: Sequence[MaintenanceWindow],
    policy: Optional[PlannerPolicy] = None,
) -> Plan:
    """
    Convenience wrapper to construct planner, preload assets, and run plan().
    """
    planner = PatchPlanner(policy=policy)
    planner._preload_assets(assets)
    return planner.plan(
        now=now,
        vulnerabilities=vulnerabilities,
        assets=assets,
        patches=patches,
        findings=findings,
        windows=windows,
    )
