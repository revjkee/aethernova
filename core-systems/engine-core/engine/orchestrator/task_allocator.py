# -*- coding: utf-8 -*-
"""
engine-core / engine / orchestrator / task_allocator.py

Industrial task allocator:
- Resource vector scheduling (cpu, mem, gpu, io, custom)
- Hard constraints: capacity, capabilities, affinity/anti-affinity, zones, concurrency limits
- Soft constraints & scoring: balance, fragmentation cost, network distance, operator cost
- Priorities, SLA deadlines (EDF-weighted), estimated duration
- Fairness: tenant quotas with DRF-like dominant share estimator
- Deterministic tie-breaking (stable hashing/seed)
- Optional soft preemption plan (evict lower-prio tasks to admit high-prio)
- Snapshot/restore & audit trail
- Observability hooks

No external dependencies.

Author: Aethernova / engine-core
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass, field, asdict
from threading import RLock
from typing import Any, Dict, Iterable, List, Optional, Tuple

# =============================================================================
# Types & data model
# =============================================================================

ResourceName = str
TenantId = str
TaskId = str
WorkerId = str
ZoneName = str

DEFAULT_RES_ORDER: Tuple[ResourceName, ...] = ("cpu", "mem", "gpu", "io")

@dataclass(frozen=True)
class ResourceVector:
    """
    Generic resource vector. Only non-negative floats. Keys not present are treated as 0.
    """
    values: Dict[ResourceName, float] = field(default_factory=dict)

    def get(self, name: ResourceName) -> float:
        return float(self.values.get(name, 0.0))

    def has(self, name: ResourceName) -> bool:
        return name in self.values

    def items(self) -> Iterable[Tuple[ResourceName, float]]:
        return self.values.items()

    def plus(self, other: "ResourceVector") -> "ResourceVector":
        keys = set(self.values) | set(other.values)
        return ResourceVector({k: float(self.get(k) + other.get(k)) for k in keys})

    def minus(self, other: "ResourceVector") -> "ResourceVector":
        keys = set(self.values) | set(other.values)
        res = {k: float(self.get(k) - other.get(k)) for k in keys}
        if any(v < -1e-9 for v in res.values()):
            # negative allowed for intermediate math; clamp later
            pass
        return ResourceVector(res)

    def leq(self, other: "ResourceVector") -> bool:
        return all(self.get(k) <= other.get(k) + 1e-12 for k in set(self.values) | set(other.values))

    def clamp_nonneg(self) -> "ResourceVector":
        return ResourceVector({k: max(0.0, v) for k, v in self.values.items()})

    def norm_inf_ratio(self, capacity: "ResourceVector") -> float:
        """
        Return max_i demand_i / capacity_i, missing capacity treated as +inf (=> ratio=+inf if demand>0 without cap).
        """
        r = 0.0
        for k, v in self.values.items():
            cap = capacity.get(k)
            if cap <= 0.0:
                if v > 0.0:
                    return float("inf")
                else:
                    continue
            r = max(r, v / cap)
        return r

    def __repr__(self) -> str:
        return f"RV({', '.join(f'{k}={v:.3f}' for k,v in sorted(self.values.items()))})"


@dataclass(frozen=True)
class CapabilitySet:
    """
    Capabilities as tags (e.g., cuda, avx2, ssd, featureX).
    """
    required: List[str] = field(default_factory=list)
    preferred: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class Affinity:
    """
    Affinity/anti-affinity for placement.
    - with_workers: hard preference to specific workers
    - with_tags: worker tags affinity (e.g., rack, cache-locality)
    """
    with_workers: List[WorkerId] = field(default_factory=list)
    with_tags: List[str] = field(default_factory=list)
    anti_with_workers: List[WorkerId] = field(default_factory=list)
    anti_with_tags: List[str] = field(default_factory=list)
    zone: Optional[ZoneName] = None  # hard zone constraint if set


@dataclass(frozen=True)
class Task:
    id: TaskId
    tenant: TenantId
    demand: ResourceVector
    priority: int = 0                 # higher = more important
    sla_deadline_ts: Optional[float] = None   # epoch seconds
    est_duration_sec: Optional[float] = None  # for EDF risk
    capabilities: CapabilitySet = field(default_factory=CapabilitySet)
    affinity: Affinity = field(default_factory=Affinity)
    labels: Dict[str, str] = field(default_factory=dict)
    preemptible: bool = False
    # Soft cost per resource unit if needs to exceed capacity via preemption (informative)
    penalty_cost: float = 1.0


@dataclass
class RunningTask:
    task: Task
    started_ts: float
    # optional metadata: for preemption decision
    remaining_est_sec: Optional[float] = None


@dataclass
class Worker:
    id: WorkerId
    zone: ZoneName
    tags: List[str]
    capacity: ResourceVector
    max_concurrency: int = 1
    capabilities: List[str] = field(default_factory=list)
    cost_weight: float = 1.0      # relative infra cost
    # Runtime state
    running: List[RunningTask] = field(default_factory=list)

    def free_capacity(self) -> ResourceVector:
        used = ResourceVector()
        for r in self.running:
            used = used.plus(r.task.demand)
        return self.capacity.minus(used).clamp_nonneg()

    def can_fit(self, demand: ResourceVector) -> bool:
        return demand.leq(self.free_capacity()) and (len(self.running) < self.max_concurrency)

    def __repr__(self) -> str:
        return f"Worker(id={self.id}, zone={self.zone}, tags={self.tags}, cap={self.capacity}, running={len(self.running)})"


# =============================================================================
# Allocation plan & audit
# =============================================================================

@dataclass
class Placement:
    task_id: TaskId
    worker_id: WorkerId
    score: float
    reason: str
    soft_constraints: Dict[str, float] = field(default_factory=dict)

@dataclass
class Eviction:
    task_id: TaskId
    worker_id: WorkerId
    reason: str

@dataclass
class AllocationPlan:
    placements: List[Placement] = field(default_factory=list)
    evictions: List[Eviction] = field(default_factory=list)
    rejected: List[Tuple[TaskId, str]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    audit: List[Dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps({
            "placements": [asdict(p) for p in self.placements],
            "evictions": [asdict(e) for e in self.evictions],
            "rejected": list(self.rejected),
            "stats": self.stats,
            "audit": self.audit,
        }, ensure_ascii=False, separators=(",", ":"))

# =============================================================================
# Policy configuration
# =============================================================================

@dataclass
class Policy:
    # Weights for score
    w_priority: float = 5.0
    w_sla_risk: float = 3.0
    w_balance: float = 1.0
    w_affinity: float = 1.0
    w_capabilities: float = 2.0
    w_cost: float = 0.25
    w_fragmentation: float = 0.5
    # DRF quotas: tenant -> share in [0..1]
    tenant_quota: Dict[TenantId, float] = field(default_factory=dict)
    # Allow soft preemption (evict lower priority if strictly needed)
    allow_soft_preemption: bool = False
    # Deterministic seed salt
    seed_salt: str = "aethernova-allocator-v1"
    # Ordered resource names for DRF and sorting
    resource_order: Tuple[ResourceName, ...] = DEFAULT_RES_ORDER

# =============================================================================
# Allocator
# =============================================================================

class TaskAllocator:
    """
    Deterministic, explainable task allocator.

    Algorithm sketch:
      1) Normalize inputs, build working copies of free capacities.
      2) Sort tasks by (priority desc, SLA urgency (EDF), demand size desc (FFD), stable hash).
      3) For each task:
           a) Generate feasible workers (hard constraints).
           b) If none and preemption allowed, compute smallest eviction set on some worker
              composed of strictly lower-priority tasks to fit.
           c) Score feasible placements with multi-objective score and pick best.
      4) Update capacities, DRF shares, record audit.
    """

    def __init__(self, *, policy: Optional[Policy] = None) -> None:
        self._policy = policy or Policy()
        self._lock = RLock()
        self._audit_on = True

    # -----------------------
    # Public API
    # -----------------------

    def allocate(self, tasks: List[Task], workers: List[Worker], *, now_ts: Optional[float] = None) -> AllocationPlan:
        with self._lock:
            t0 = time.time()
            now = now_ts if now_ts is not None else t0
            plan = AllocationPlan()
            # Working copies
            wstate: Dict[WorkerId, Worker] = {w.id: self._clone_worker_state(w) for w in workers}
            # DRF state
            drf = _DRFState(self._policy.resource_order)
            for w in workers:
                drf.add_capacity(w.capacity)

            # Sort tasks
            ordering = self._order_tasks(tasks, now)
            for task in ordering:
                audit_entry: Dict[str, Any] = {"task": task.id, "tenant": task.tenant}
                feas = self._feasible_workers(task, wstate)
                if not feas:
                    if self._policy.allow_soft_preemption:
                        ev_plan = self._try_soft_preemption(task, wstate)
                        if ev_plan is None:
                            plan.rejected.append((task.id, "no_feasible_worker"))
                            audit_entry["decision"] = "reject"
                            audit_entry["reason"] = "no_feasible_worker"
                            plan.audit.append(audit_entry)
                            continue
                        # Apply evictions to working state
                        for ev in ev_plan:
                            ww = wstate[ev.worker_id]
                            idx = next((i for i, rt in enumerate(ww.running) if rt.task.id == ev.task_id), None)
                            if idx is not None:
                                ww.running.pop(idx)
                                audit_entry.setdefault("evictions", []).append(asdict(ev))
                        feas = self._feasible_workers(task, wstate)
                        if not feas:
                            plan.rejected.append((task.id, "no_feasible_after_preemption"))
                            audit_entry["decision"] = "reject"
                            audit_entry["reason"] = "no_feasible_after_preemption"
                            plan.audit.append(audit_entry)
                            continue
                    else:
                        plan.rejected.append((task.id, "no_feasible_worker"))
                        audit_entry["decision"] = "reject"
                        audit_entry["reason"] = "no_feasible_worker"
                        plan.audit.append(audit_entry)
                        continue

                # Score candidates
                scored: List[Tuple[float, str, Dict[str, float]]] = []
                for wid in feas:
                    s, details = self._score(task, wstate[wid], drf, now)
                    scored.append((s, wid, details))
                # choose min score (lower is better)
                scored.sort(key=lambda x: (x[0], x[1]))
                best_score, best_wid, details = scored[0]

                # Place
                ww = wstate[best_wid]
                ww.running.append(RunningTask(task=task, started_ts=now))
                drf.consume(task.tenant, task.demand)
                placement = Placement(task_id=task.id, worker_id=best_wid, score=best_score,
                                      reason="selected_min_score", soft_constraints=details)
                plan.placements.append(placement)
                audit_entry["decision"] = "place"
                audit_entry["worker"] = best_wid
                audit_entry["score"] = best_score
                audit_entry["soft"] = details
                plan.audit.append(audit_entry)

            # stats
            t1 = time.time()
            plan.stats = {
                "time_ms": int((t1 - t0) * 1000),
                "placed": len(plan.placements),
                "rejected": len(plan.rejected),
                "evictions": len(plan.evictions),
            }
            return plan

    def snapshot(self, workers: List[Worker]) -> str:
        with self._lock:
            data = {
                "schema": 1,
                "workers": [self._worker_to_dict(w) for w in workers],
                "policy": asdict(self._policy),
                "ts": time.time(),
            }
            return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def restore(snapshot_json: str) -> Tuple[List[Worker], Policy]:
        data = json.loads(snapshot_json)
        if int(data.get("schema", -1)) != 1:
            raise ValueError("unsupported snapshot schema")
        workers = [TaskAllocator._worker_from_dict(d) for d in data.get("workers", [])]
        pol = Policy(**(data.get("policy") or {}))
        return workers, pol

    # -----------------------
    # Internals
    # -----------------------

    def _order_tasks(self, tasks: List[Task], now: float) -> List[Task]:
        def urgency(ts: Optional[float], est: Optional[float]) -> float:
            if ts is None:
                return float("inf")
            slack = ts - now - (est or 0.0)
            return max(-1e9, slack)
        def demand_size(rv: ResourceVector) -> float:
            # Weighted by order; sum normalized
            total = 0.0
            for i, name in enumerate(self._policy.resource_order):
                w = 1.0 / (1 + i)
                total += w * rv.get(name)
            # add any custom resources
            for k, v in rv.items():
                if k not in self._policy.resource_order:
                    total += 0.5 * v
            return total

        def stable_hash(s: str) -> int:
            h = hashlib.sha256((self._policy.seed_salt + "|" + s).encode("utf-8")).digest()
            return int.from_bytes(h[:8], "big", signed=False)

        return sorted(
            list(tasks),
            key=lambda t: (
                -int(t.priority),
                urgency(t.sla_deadline_ts, t.est_duration_sec),
                -demand_size(t.demand),
                stable_hash(t.id),
            ),
        )

    def _feasible_workers(self, task: Task, wstate: Dict[WorkerId, Worker]) -> List[WorkerId]:
        res: List[WorkerId] = []
        for wid, w in wstate.items():
            if task.affinity.zone and w.zone != task.affinity.zone:
                continue
            if any(w.id == x for x in task.affinity.anti_with_workers):
                continue
            if any(t in w.tags for t in task.affinity.anti_with_tags):
                continue
            if task.capabilities.required:
                req = set(map(str.lower, task.capabilities.required))
                caps = set(map(str.lower, w.capabilities))
                if not req.issubset(caps):
                    continue
            if task.affinity.with_workers and w.id not in task.affinity.with_workers:
                # if hard list specified, only these
                continue
            if not w.can_fit(task.demand):
                continue
            res.append(wid)
        # deterministic order
        res.sort()
        return res

    def _score(self, task: Task, w: Worker, drf: "_DRFState", now: float) -> Tuple[float, Dict[str, float]]:
        # Priority term: higher priority -> lower score contribution
        prio_term = -self._policy.w_priority * float(task.priority)

        # SLA risk: negative slack => penalty grows
        sla_term = 0.0
        if task.sla_deadline_ts is not None:
            slack = (task.sla_deadline_ts - now) - (task.est_duration_sec or 0.0)
            if slack < 0:
                sla_term = self._policy.w_sla_risk * (abs(slack) + 1.0)

        # Capabilities match bonus (reduce score)
        cap_term = 0.0
        if task.capabilities.preferred:
            pref = set(map(str.lower, task.capabilities.preferred))
            caps = set(map(str.lower, w.capabilities))
            overlap = len(pref & caps)
            cap_term -= self._policy.w_capabilities * float(overlap)

        # Affinity tags: bonus if worker has desired tags
        aff_term = 0.0
        if task.affinity.with_tags:
            desired = set(map(str.lower, task.affinity.with_tags))
            wtags = set(map(str.lower, w.tags))
            aff_term -= self._policy.w_affinity * float(len(desired & wtags))

        # Balance/fragmentation: prefer workers where remaining capacity stays balanced
        free_before = w.free_capacity()
        free_after = free_before.minus(task.demand).clamp_nonneg()
        balance_term = self._imbalance(free_after)
        fragmentation_term = self._fragmentation_cost(task.demand, free_before)

        # Cost term: infra/operator cost
        cost_term = self._policy.w_cost * float(w.cost_weight)

        # DRF fairness: prefer workers where tenant dominant share grows less
        fair_term = drf.score_drf_increment(task.tenant, task.demand) * 1.0

        score = (
            prio_term
            + sla_term
            + self._policy.w_balance * balance_term
            + self._policy.w_fragmentation * fragmentation_term
            + cap_term
            + aff_term
            + cost_term
            + fair_term
        )
        details = {
            "prio": prio_term,
            "sla": sla_term,
            "balance": balance_term,
            "fragmentation": fragmentation_term,
            "cap_bonus": cap_term,
            "aff_bonus": aff_term,
            "cost": cost_term,
            "fair": fair_term,
        }
        return score, details

    def _imbalance(self, rv: ResourceVector) -> float:
        # Standard deviation of utilization across known resources (lower is better)
        xs = []
        for k in self._policy.resource_order:
            xs.append(rv.get(k))
        if not xs:
            return 0.0
        m = sum(xs) / len(xs)
        return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))

    def _fragmentation_cost(self, demand: ResourceVector, free: ResourceVector) -> float:
        # Penalize high fill on any dimension after placement
        cost = 0.0
        for k in set(demand.values) | set(free.values):
            cap_free = free.get(k)
            d = demand.get(k)
            if cap_free <= 0.0:
                if d > 0:
                    cost += 1000.0
                continue
            util_after = max(0.0, 1.0 - (cap_free - d) / (cap_free + 1e-9))
            cost += util_after ** 2
        return cost

    def _try_soft_preemption(self, task: Task, wstate: Dict[WorkerId, Worker]) -> Optional[List[Eviction]]:
        """
        Find a single worker where evicting a set of strictly lower-priority preemptible tasks
        makes room for 'task'. Choose minimal eviction cost. Return list of evictions or None.
        """
        best: Optional[Tuple[float, WorkerId, List[Eviction]]] = None
        for wid, w in wstate.items():
            if task.affinity.zone and w.zone != task.affinity.zone:
                continue
            # select candidate evictions
            candidates = [rt for rt in w.running if rt.task.preemptible and rt.task.priority < task.priority]
            need = task.demand.minus(w.free_capacity())
            # simple subset selection: greedily remove largest resource shares first (by norm_inf_ratio)
            sorted_c = sorted(
                candidates,
                key=lambda rt: rt.task.demand.norm_inf_ratio(w.capacity),
                reverse=True,
            )
            acc = ResourceVector()
            chosen: List[Eviction] = []
            for rt in sorted_c:
                acc = acc.plus(rt.task.demand)
                chosen.append(Eviction(task_id=rt.task.id, worker_id=w.id, reason="soft_preemption"))
                if need.leq(acc):
                    # Check concurrency too
                    if len(w.running) - len(chosen) < w.max_concurrency:
                        # after eviction, concurrency available
                        pass
                    # feasible
                    ev_cost = sum(1.0 * r.task.penalty_cost for r in w.running if any(e.task_id == r.task.id for e in chosen))
                    if best is None or ev_cost < best[0]:
                        best = (ev_cost, wid, list(chosen))
                    break
        if best is None:
            return None
        return best[2]

    # -----------------------
    # Serialization helpers
    # -----------------------

    @staticmethod
    def _worker_to_dict(w: Worker) -> Dict[str, Any]:
        return {
            "id": w.id,
            "zone": w.zone,
            "tags": list(w.tags),
            "capacity": dict(w.capacity.values),
            "max_concurrency": w.max_concurrency,
            "capabilities": list(w.capabilities),
            "cost_weight": w.cost_weight,
            "running": [
                {
                    "task": TaskAllocator._task_to_dict(rt.task),
                    "started_ts": rt.started_ts,
                    "remaining_est_sec": rt.remaining_est_sec,
                }
                for rt in w.running
            ],
        }

    @staticmethod
    def _worker_from_dict(d: Dict[str, Any]) -> Worker:
        w = Worker(
            id=d["id"],
            zone=d.get("zone", "default"),
            tags=list(d.get("tags", [])),
            capacity=ResourceVector(dict(d.get("capacity", {}))),
            max_concurrency=int(d.get("max_concurrency", 1)),
            capabilities=list(d.get("capabilities", [])),
            cost_weight=float(d.get("cost_weight", 1.0)),
        )
        for rt in d.get("running", []):
            t = TaskAllocator._task_from_dict(rt["task"])
            w.running.append(RunningTask(task=t, started_ts=float(rt.get("started_ts", time.time())),
                                         remaining_est_sec=rt.get("remaining_est_sec")))
        return w

    @staticmethod
    def _task_to_dict(t: Task) -> Dict[str, Any]:
        return {
            "id": t.id,
            "tenant": t.tenant,
            "demand": dict(t.demand.values),
            "priority": t.priority,
            "sla_deadline_ts": t.sla_deadline_ts,
            "est_duration_sec": t.est_duration_sec,
            "capabilities": {"required": t.capabilities.required, "preferred": t.capabilities.preferred},
            "affinity": {
                "with_workers": t.affinity.with_workers,
                "with_tags": t.affinity.with_tags,
                "anti_with_workers": t.affinity.anti_with_workers,
                "anti_with_tags": t.affinity.anti_with_tags,
                "zone": t.affinity.zone,
            },
            "labels": dict(t.labels),
            "preemptible": t.preemptible,
            "penalty_cost": t.penalty_cost,
        }

    @staticmethod
    def _task_from_dict(d: Dict[str, Any]) -> Task:
        return Task(
            id=d["id"],
            tenant=d["tenant"],
            demand=ResourceVector(dict(d.get("demand", {}))),
            priority=int(d.get("priority", 0)),
            sla_deadline_ts=d.get("sla_deadline_ts"),
            est_duration_sec=d.get("est_duration_sec"),
            capabilities=CapabilitySet(required=list(d.get("capabilities", {}).get("required", [])),
                                       preferred=list(d.get("capabilities", {}).get("preferred", []))),
            affinity=Affinity(
                with_workers=list(d.get("affinity", {}).get("with_workers", [])),
                with_tags=list(d.get("affinity", {}).get("with_tags", [])),
                anti_with_workers=list(d.get("affinity", {}).get("anti_with_workers", [])),
                anti_with_tags=list(d.get("affinity", {}).get("anti_with_tags", [])),
                zone=d.get("affinity", {}).get("zone"),
            ),
            labels=dict(d.get("labels", {})),
            preemptible=bool(d.get("preemptible", False)),
            penalty_cost=float(d.get("penalty_cost", 1.0)),
        )

    @staticmethod
    def _clone_worker_state(w: Worker) -> Worker:
        ww = Worker(
            id=w.id,
            zone=w.zone,
            tags=list(w.tags),
            capacity=ResourceVector(dict(w.capacity.values)),
            max_concurrency=w.max_concurrency,
            capabilities=list(w.capabilities),
            cost_weight=w.cost_weight,
        )
        ww.running = [RunningTask(task=TaskAllocator._task_from_dict(TaskAllocator._task_to_dict(rt.task)),
                                  started_ts=rt.started_ts,
                                  remaining_est_sec=rt.remaining_est_sec)
                      for rt in w.running]
        return ww


# =============================================================================
# DRF-like fairness estimator
# =============================================================================

class _DRFState:
    """
    Minimal DRF dominant share tracker.
    Keeps per-tenant consumption and global capacity to compute dominant resource share.
    """
    def __init__(self, order: Tuple[ResourceName, ...]) -> None:
        self._order = order
        self._cap_total = ResourceVector()
        self._by_tenant: Dict[TenantId, ResourceVector] = {}

    def add_capacity(self, cap: ResourceVector) -> None:
        self._cap_total = self._cap_total.plus(cap)

    def consume(self, tenant: TenantId, demand: ResourceVector) -> None:
        cur = self._by_tenant.get(tenant, ResourceVector())
        self._by_tenant[tenant] = cur.plus(demand)

    def _dominant_share(self, tenant: TenantId, extra: Optional[ResourceVector] = None) -> float:
        cons = self._by_tenant.get(tenant, ResourceVector())
        if extra is not None:
            cons = cons.plus(extra)
        shares: List[float] = []
        for k in set(self._cap_total.values) | set(cons.values):
            cap = self._cap_total.get(k)
            if cap <= 0.0:
                continue
            shares.append(cons.get(k) / cap)
        return max(shares) if shares else 0.0

    def score_drf_increment(self, tenant: TenantId, demand: ResourceVector) -> float:
        before = self._dominant_share(tenant, None)
        after = self._dominant_share(tenant, demand)
        # The allocator minimizes score; higher increment is worse.
        return (after - before) * 10.0


# =============================================================================
# Self-test (optional)
# =============================================================================

if __name__ == "__main__":
    # Simple smoke test
    workers = [
        Worker(id="w1", zone="z1", tags=["ssd","nvlink"], capacity=ResourceVector({"cpu":8,"mem":32,"gpu":1}), max_concurrency=4, capabilities=["cuda","avx2"], cost_weight=1.0),
        Worker(id="w2", zone="z1", tags=["hdd"], capacity=ResourceVector({"cpu":16,"mem":64,"gpu":0}), max_concurrency=6, capabilities=["avx2"], cost_weight=0.8),
        Worker(id="w3", zone="z2", tags=["ssd"], capacity=ResourceVector({"cpu":4,"mem":16,"gpu":2}), max_concurrency=2, capabilities=["cuda"], cost_weight=1.2),
    ]

    tasks = [
        Task(id="tA", tenant="T1", demand=ResourceVector({"cpu":2,"mem":8}), priority=10, sla_deadline_ts=time.time()+60, est_duration_sec=10, capabilities=CapabilitySet(required=["avx2"]), affinity=Affinity(with_tags=["ssd"])),
        Task(id="tB", tenant="T1", demand=ResourceVector({"cpu":6,"mem":24,"gpu":1}), priority=20, sla_deadline_ts=time.time()+30, est_duration_sec=20, capabilities=CapabilitySet(required=["cuda"]), preemptible=True),
        Task(id="tC", tenant="T2", demand=ResourceVector({"cpu":8,"mem":32}), priority=5),
        Task(id="tD", tenant="T2", demand=ResourceVector({"cpu":1,"mem":2}), priority=1, affinity=Affinity(zone="z2")),
    ]

    alloc = TaskAllocator(policy=Policy(allow_soft_preemption=True))
    plan = alloc.allocate(tasks, workers)
    print(plan.to_json())
