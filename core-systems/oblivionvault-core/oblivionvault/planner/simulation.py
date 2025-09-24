# SPDX-License-Identifier: Apache-2.0
# Industrial-grade retention & cost simulation engine for OblivionVault Core.
# No third-party deps. Python 3.10+

from __future__ import annotations

import dataclasses
import json
import math
import random
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, Iterable, List, Optional, Tuple


# ----------------------------- Domain enums & types -----------------------------

class StorageClass(str, Enum):
    STANDARD = "STANDARD"                 # hot
    STANDARD_IA = "STANDARD_IA"           # warm (infrequent access)
    GLACIER_IR = "GLACIER_IR"             # cold (instant retrieval)
    GLACIER_DEEP_ARCHIVE = "GLACIER_DEEP_ARCHIVE"  # deep cold
    CUSTOM = "CUSTOM"


class ImmutabilityMode(str, Enum):
    NONE = "none"
    GOVERNANCE = "governance"
    COMPLIANCE = "compliance"


@dataclass(frozen=True)
class Transition:
    after_days: int
    storage_class: StorageClass


@dataclass
class RetentionPolicy:
    profile: str  # "hot"|"warm"|"cold"|"legal"|custom
    retention_min_days: Optional[int] = None
    retention_max_days: Optional[int] = None  # 0 or None => infinite
    immutability_mode: ImmutabilityMode = ImmutabilityMode.NONE
    legal_hold_label: Optional[str] = None
    transitions: List[Transition] = field(default_factory=list)

    def validate(self) -> None:
        if self.retention_min_days is not None and self.retention_min_days < 0:
            raise ValueError("retention_min_days must be >= 0")
        if self.retention_max_days is not None and self.retention_max_days < 0:
            raise ValueError("retention_max_days must be >= 0")
        for t in self.transitions:
            if t.after_days < 0:
                raise ValueError("transition.after_days must be >= 0")
        # Sort transitions by time
        self.transitions.sort(key=lambda t: t.after_days)


@dataclass
class CostTier:
    storage_per_gb_month: float        # USD per GB-month
    retrieval_per_gb: float = 0.0      # retrieval fee per GB
    egress_per_gb: float = 0.0         # egress fee per GB
    put_per_1k: float = 0.0            # per 1k PUT/COPY/LIST (approx)
    get_per_1k: float = 0.0            # per 1k GET/SELECT (approx)
    restore_latency_p95_min: float = 5 # used for SLO estimation


@dataclass
class CostModel:
    tiers: Dict[StorageClass, CostTier]

    def tier(self, sc: StorageClass) -> CostTier:
        if sc not in self.tiers:
            raise KeyError(f"cost model missing tier {sc}")
        return self.tiers[sc]


@dataclass
class DRConfig:
    enabled: bool = True
    replication_factor: int = 2          # 1 = no extra copies; 2 = primary+DR
    cross_region_multiplier: float = 1.0 # multiplier for egress-like cost on replication
    mode: str = "async"                   # for reporting only


@dataclass
class DataReduction:
    compression_ratio: float = 0.5  # physical = logical * compression_ratio after compression
    dedup_ratio: float = 0.8        # physical = previous * dedup_ratio after dedup
    # Dedup convergence: not вся новая запись попадает в полный дедуп сразу
    dedup_half_life_days: int = 14  # половина эффекта достигается за N дней


@dataclass
class WorkloadSizeModel:
    # Lognormal on bytes: median & multiplicative sigma.
    median_bytes: float = 4 * 1024 * 1024  # 4 MiB
    sigma: float = 1.2  # multiplicative spread

    def draw_bytes(self, rnd: random.Random) -> int:
        # Convert median/sigma to mu/sigma for ln-dist
        # For lognormal: median = exp(mu); sigma_mult = exp(stddev)
        mu = math.log(self.median_bytes)
        s = math.log(self.sigma)
        val = rnd.lognormvariate(mu, s)  # returns ~lognormal
        return max(1, int(val))


@dataclass
class Workload:
    # New objects per day: either deterministic or Poisson(lambda)
    daily_new_objects: float = 10000.0
    poisson_arrivals: bool = True
    size: WorkloadSizeModel = field(default_factory=WorkloadSizeModel)

    # Reads and updates
    mean_reads_per_object_lifetime: float = 2.0
    mean_updates_per_object_lifetime: float = 0.2

    # Restore requests per day (used for retrieval/egress cost)
    restores_per_day: float = 50.0
    restore_selection_bias_hot: float = 0.7  # portion selects the hottest tier

    # Delete requests not governed by retention (e.g., user delete); applied only if immutability == NONE
    extra_delete_ratio: float = 0.0


@dataclass
class BudgetGuards:
    storage_budget_usd_month: Optional[float] = None
    egress_budget_usd_month: Optional[float] = None
    warn_threshold_pct: int = 80
    crit_threshold_pct: int = 95


# ----------------------------- Internal cohort model -----------------------------

@dataclass
class Cohort:
    """Cohort of objects with the same birthday and storage class."""
    birth_day: int
    age_days: int
    count: int
    logical_bytes: int
    storage_class: StorageClass

    def clone(self) -> Cohort:
        return dataclasses.replace(self)


# ----------------------------- Scenario & result models -----------------------------

@dataclass
class Scenario:
    name: str
    days: int
    retention: RetentionPolicy
    cost: CostModel
    dr: DRConfig = field(default_factory=DRConfig)
    reduction: DataReduction = field(default_factory=DataReduction)
    workload: Workload = field(default_factory=Workload)
    budgets: BudgetGuards = field(default_factory=BudgetGuards)
    seed: int = 1337  # deterministic by default
    start_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))

    def validate(self) -> None:
        if self.days <= 0:
            raise ValueError("days must be > 0")
        self.retention.validate()
        if self.workload.daily_new_objects < 0:
            raise ValueError("daily_new_objects must be >= 0")
        for _, tier in self.cost.tiers.items():
            if tier.storage_per_gb_month < 0:
                raise ValueError("cost tier storage_per_gb_month must be >= 0")


@dataclass
class DayMetrics:
    day_index: int
    date: str
    total_logical_gb: float
    total_physical_gb_primary: float
    total_physical_gb_with_dr: float
    by_tier_gb: Dict[str, float]
    # Operations
    puts: int
    gets: int
    restores: int
    egress_gb: float
    retrieval_gb: float
    # Cost
    storage_usd: float
    ops_usd: float
    egress_usd: float
    retrieval_usd: float
    total_usd: float
    # SLO proxy
    restore_p95_minutes: float
    # Budget flags
    budget_warn: bool
    budget_crit: bool


@dataclass
class SimulationReport:
    scenario: str
    days: int
    started_at: str
    ended_at: str
    totals: Dict[str, float]
    per_day: List[DayMetrics]

    def to_json(self) -> str:
        def _ser(o):
            if dataclasses.is_dataclass(o):
                return dataclasses.asdict(o)
            if isinstance(o, Enum):
                return o.value
            raise TypeError(f"Unserializable: {type(o)}")
        return json.dumps(self, default=_ser, ensure_ascii=False)


# ----------------------------- Simulation engine -----------------------------

class Simulation:
    """
    Discrete-time (daily) simulation.
    """
    def __init__(self, scenario: Scenario):
        scenario.validate()
        self.sc = scenario
        self.rnd = random.Random(scenario.seed)
        self._cohorts: List[Cohort] = []
        self._day: int = 0

        # Ops accounting
        self._ops_put: int = 0
        self._ops_get: int = 0
        self._ops_restores: int = 0
        self._egress_bytes: int = 0
        self._retrieval_bytes: int = 0

    # --------- Helpers for sizes and conversions ---------

    @staticmethod
    def _bytes_to_gb(x: int | float) -> float:
        return float(x) / (1024 ** 3)

    @staticmethod
    def _gb_to_bytes(x: float) -> int:
        return int(round(x * (1024 ** 3)))

    # --------- Data reduction modeling ---------

    def _apply_reduction_new(self, logical_bytes: int) -> int:
        """Apply compression and partial dedup on new data."""
        phys = logical_bytes
        # Compression: immediate
        phys = int(math.ceil(phys * self.sc.reduction.compression_ratio))
        # Dedup: converge using half-life; early days less efficient
        # Compute convergence factor c in [dedup_ratio, 1.0] depending on day
        # After k half-lives, effect approaches steady-state.
        hl = max(1, self.sc.reduction.dedup_half_life_days)
        k = self._day / hl
        target = self.sc.reduction.dedup_ratio
        c = 1.0 - (1.0 - target) * (1.0 - math.exp(-k * math.log(2)))
        phys = int(math.ceil(phys * c))
        return phys

    # --------- Retention & transitions ---------

    def _apply_transitions_and_retention(self) -> None:
        """Age cohorts, move between tiers, and delete by retention if allowed."""
        new_cohorts: List[Cohort] = []
        ret = self.sc.retention
        for cohort in self._cohorts:
            cohort.age_days += 1

            # Storage class transitions
            new_class = cohort.storage_class
            for tr in ret.transitions:
                if cohort.age_days >= tr.after_days:
                    new_class = tr.storage_class
            cohort.storage_class = new_class

            # Retention enforcement: deletion at max_days (if any)
            delete = False
            if ret.retention_max_days and ret.retention_max_days > 0:
                if cohort.age_days >= ret.retention_max_days:
                    delete = True

            # Immutability and legal hold override deletions
            immutable = ret.immutability_mode in (ImmutabilityMode.GOVERNANCE, ImmutabilityMode.COMPLIANCE)
            legal_hold = bool(ret.legal_hold_label)
            if (immutable or legal_hold) and delete:
                delete = False  # cannot delete

            if not delete:
                new_cohorts.append(cohort)

        self._cohorts = new_cohorts

    # --------- Workload synthesis ---------

    def _draw_new_objects(self) -> int:
        lam = max(0.0, self.sc.workload.daily_new_objects)
        if self.sc.workload.poisson_arrivals:
            # Knuth's algorithm approximation using random.expovariate is overkill here; use Poisson via RNG
            # Python doesn't have built-in Poisson; approximate by normal for large lambda
            if lam < 30:
                # direct thinning using geometric trials
                # rough: sum of exponentials -> Poisson; we fallback to round(lam + noise)
                return max(0, int(round(self.rnd.expovariate(1/lam))) if lam > 0 else 0)
            # normal approx
            val = int(round(self.rnd.normalvariate(lam, math.sqrt(lam))))
            return max(0, val)
        return int(round(lam))

    def _generate_new_cohort(self, count: int) -> Optional[Cohort]:
        if count <= 0:
            return None
        # Logical size: sum of independent lognormal sizes
        total_bytes = 0
        for _ in range(count):
            total_bytes += self.sc.workload.size.draw_bytes(self.rnd)
        logical = total_bytes
        physical = self._apply_reduction_new(logical)
        # Record as cohort with physical implied by reductions when costed;
        # keep logical for reporting; physical computed later per-tier.

        return Cohort(
            birth_day=self._day,
            age_days=0,
            count=count,
            logical_bytes=logical,
            storage_class=StorageClass.STANDARD,  # initial hot tier
        )

    # --------- Operations & costs ---------

    def _estimate_daily_ops(self, logical_bytes_new: int) -> Tuple[int, int, int, int, int]:
        """
        Estimate PUT/GET/RESTORE counts and egress/retrieval bytes for the day.
        Returns: (puts, gets, restores, egress_bytes, retrieval_bytes)
        """
        puts = 0
        gets = 0
        restores = 0
        egress = 0
        retrieval = 0

        # PUTs ~= number of new objects
        puts = sum(c.count for c in self._cohorts if c.birth_day == self._day)

        # Reads distributed proportionally across objects; for simplicity, use mean_reads_per_object_lifetime/retention window proxy
        reads_per_object_today = self.sc.workload.mean_reads_per_object_lifetime / max(1, (self.sc.retention.retention_max_days or 30))
        for c in self._cohorts:
            # expected reads today
            r = self.rnd.poissonvariate(reads_per_object_today * c.count) if hasattr(self.rnd, "poissonvariate") else int(round(reads_per_object_today * c.count))
            gets += max(0, r)
            # assume 10% of GETs are "retrieval-like" (charged) when tier is cold
            if c.storage_class in (StorageClass.GLACIER_IR, StorageClass.GLACIER_DEEP_ARCHIVE):
                charged = int(round(0.1 * r))
                avg_obj = (c.logical_bytes / max(1, c.count))
                retrieval += int(charged * avg_obj)

        # Restore jobs: a subset of reads that export data (egress)
        if self.sc.workload.restores_per_day > 0:
            base = self.sc.workload.restores_per_day
            restores = int(round(base))
            # split across tiers with bias to hot
            bias = self.sc.workload.restore_selection_bias_hot
            # rough split: hot vs others
            p_hot = bias
            hot_gb = cold_gb = 0.0
            for _ in range(restores):
                if self.rnd.random() < p_hot:
                    # sample some hot cohort by weight
                    hot = [c for c in self._cohorts if c.storage_class in (StorageClass.STANDARD, StorageClass.STANDARD_IA)]
                    if hot:
                        c = self.rnd.choice(hot)
                        egress += int((c.logical_bytes / max(1, c.count)) * 1.0)  # export full object
                else:
                    cold = [c for c in self._cohorts if c.storage_class in (StorageClass.GLACIER_IR, StorageClass.GLACIER_DEEP_ARCHIVE)]
                    if cold:
                        c = self.rnd.choice(cold)
                        size = int((c.logical_bytes / max(1, c.count)) * 1.0)
                        # cold restore implies retrieval bytes + egress
                        retrieval += size
                        egress += size

        return puts, gets, restores, egress, retrieval

    def _compute_storage_by_tier(self) -> Tuple[Dict[StorageClass, int], int, int]:
        """
        Compute physical storage bytes per tier and totals.
        Physical size approximated using data reduction.
        """
        by_tier: Dict[StorageClass, int] = {sc: 0 for sc in StorageClass}
        total_logical = 0
        for c in self._cohorts:
            total_logical += c.logical_bytes
            # physical: apply steady-state reduction (compression + target dedup)
            phys = int(math.ceil(c.logical_bytes * self.sc.reduction.compression_ratio * self.sc.reduction.dedup_ratio))
            by_tier[c.storage_class] = by_tier.get(c.storage_class, 0) + phys

        total_phys = sum(by_tier.values())
        total_phys_with_dr = total_phys * (self.sc.dr.replication_factor if self.sc.dr.enabled else 1)
        return by_tier, total_phys, total_phys_with_dr

    def _costs_for_day(
        self,
        by_tier_bytes: Dict[StorageClass, int],
        puts: int,
        gets: int,
        egress_bytes: int,
        retrieval_bytes: int,
    ) -> Tuple[float, float, float, float, float, float]:
        """
        Returns tuple: (storage_usd, ops_usd, egress_usd, retrieval_usd, total_usd, restore_p95_minutes)
        """
        # Storage cost: GB-month prorated by day (30-day month approximation)
        storage_usd = 0.0
        for tier, bytes_ in by_tier_bytes.items():
            gb = self._bytes_to_gb(bytes_)
            daily_factor = 1.0 / 30.0
            storage_usd += gb * self.sc.cost.tier(tier).storage_per_gb_month * daily_factor

        # DR amplification on storage cost (replicated copies)
        if self.sc.dr.enabled and self.sc.dr.replication_factor > 1:
            storage_usd *= self.sc.dr.replication_factor

        # Ops cost (approx)
        ops_usd = 0.0
        # Distribute ops proportionally across hot/warm vs cold for GET pricing
        get_cost_hot = get_cost_cold = 0.0
        if gets > 0:
            hot_gets = int(round(gets * 0.8))
            cold_gets = gets - hot_gets
            get_cost_hot = (hot_gets / 1000.0) * (self.sc.cost.tier(StorageClass.STANDARD).get_per_1k)
            get_cost_cold = (cold_gets / 1000.0) * (self.sc.cost.tier(StorageClass.GLACIER_IR).get_per_1k)
        put_cost = (puts / 1000.0) * (self.sc.cost.tier(StorageClass.STANDARD).put_per_1k)
        ops_usd += get_cost_hot + get_cost_cold + put_cost

        # Network and retrieval
        egress_usd = self._bytes_to_gb(egress_bytes) * statistics.fmean([
            self.sc.cost.tier(StorageClass.STANDARD).egress_per_gb,
            self.sc.cost.tier(StorageClass.STANDARD_IA).egress_per_gb,
        ])
        # DR cross-region "egress-like" cost (replication traffic)
        if self.sc.dr.enabled and self.sc.dr.replication_factor > 1 and self.sc.dr.cross_region_multiplier > 0:
            # charge fraction of physical bytes as replication traffic proxy (very rough)
            total_phys = sum(by_tier_bytes.values())
            egress_usd += self._bytes_to_gb(total_phys) * (self.sc.dr.replication_factor - 1) * \
                          self.sc.dr.cross_region_multiplier * 0.01  # small fraction per day

        retrieval_usd = self._bytes_to_gb(retrieval_bytes) * self.sc.cost.tier(StorageClass.GLACIER_IR).retrieval_per_gb

        total_usd = storage_usd + ops_usd + egress_usd + retrieval_usd

        # Restore SLO proxy: p95 as weighted max of tier latencies
        p95 = 0.0
        total_bytes = sum(by_tier_bytes.values())
        if total_bytes > 0:
            for tier, bytes_ in by_tier_bytes.items():
                weight = bytes_ / total_bytes if total_bytes else 0
                p95 = max(p95, weight * self.sc.cost.tier(tier).restore_latency_p95_min)

        return storage_usd, ops_usd, egress_usd, retrieval_usd, total_usd, p95

    # --------- Main loop ---------

    def step(self) -> DayMetrics:
        # 1) Apply retention and tier transitions to existing cohorts
        self._apply_transitions_and_retention()

        # 2) Generate new arrivals
        arrivals = self._draw_new_objects()
        c = self._generate_new_cohort(arrivals)
        if c:
            self._cohorts.append(c)

        # 3) Ops estimation for the day
        puts, gets, restores, egress, retrieval = self._estimate_daily_ops(
            logical_bytes_new=sum(x.logical_bytes for x in self._cohorts if x.birth_day == self._day)
        )
        self._ops_put += puts
        self._ops_get += gets
        self._ops_restores += restores
        self._egress_bytes += egress
        self._retrieval_bytes += retrieval

        # 4) Capacity aggregation
        by_tier, total_phys, total_phys_with_dr = self._compute_storage_by_tier()

        # 5) Costing
        storage_usd, ops_usd, egress_usd, retrieval_usd, total_usd, p95 = self._costs_for_day(
            by_tier, puts, gets, egress, retrieval
        )

        # 6) Budget flags (monthly projection based on current daily burn)
        budget_warn = budget_crit = False
        if self.sc.budgets.storage_budget_usd_month:
            projected = storage_usd * 30.0
            pct = 100.0 * projected / self.sc.budgets.storage_budget_usd_month
            budget_warn |= pct >= self.sc.budgets.warn_threshold_pct
            budget_crit |= pct >= self.sc.budgets.crit_threshold_pct
        if self.sc.budgets.egress_budget_usd_month and egress_usd > 0:
            projected = egress_usd * 30.0
            pct = 100.0 * projected / self.sc.budgets.egress_budget_usd_month
            budget_warn |= pct >= self.sc.budgets.warn_threshold_pct
            budget_crit |= pct >= self.sc.budgets.crit_threshold_pct

        # 7) Emit day metrics
        date = (self.sc.start_at + timedelta(days=self._day)).date().isoformat()
        m = DayMetrics(
            day_index=self._day,
            date=date,
            total_logical_gb=self._bytes_to_gb(sum(c.logical_bytes for c in self._cohorts)),
            total_physical_gb_primary=self._bytes_to_gb(total_phys),
            total_physical_gb_with_dr=self._bytes_to_gb(total_phys_with_dr),
            by_tier_gb={k.value: self._bytes_to_gb(v) for k, v in by_tier.items() if v > 0},
            puts=puts,
            gets=gets,
            restores=restores,
            egress_gb=self._bytes_to_gb(egress),
            retrieval_gb=self._bytes_to_gb(retrieval),
            storage_usd=round(storage_usd, 4),
            ops_usd=round(ops_usd, 4),
            egress_usd=round(egress_usd, 4),
            retrieval_usd=round(retrieval_usd, 4),
            total_usd=round(total_usd, 4),
            restore_p95_minutes=round(p95, 2),
            budget_warn=budget_warn,
            budget_crit=budget_crit,
        )

        self._day += 1
        return m

    def run(self) -> SimulationReport:
        per_day: List[DayMetrics] = []
        for _ in range(self.sc.days):
            per_day.append(self.step())

        # Final aggregates
        totals = {
            "logical_gb_end": per_day[-1].total_logical_gb if per_day else 0.0,
            "physical_gb_primary_end": per_day[-1].total_physical_gb_primary if per_day else 0.0,
            "physical_gb_with_dr_end": per_day[-1].total_physical_gb_with_dr if per_day else 0.0,
            "ops_put_total": self._ops_put,
            "ops_get_total": self._ops_get,
            "restores_total": self._ops_restores,
            "egress_gb_total": round(self._bytes_to_gb(self._egress_bytes), 4),
            "retrieval_gb_total": round(self._bytes_to_gb(self._retrieval_bytes), 4),
            "cost_storage_usd_total": round(sum(d.storage_usd for d in per_day), 2),
            "cost_ops_usd_total": round(sum(d.ops_usd for d in per_day), 2),
            "cost_egress_usd_total": round(sum(d.egress_usd for d in per_day), 2),
            "cost_retrieval_usd_total": round(sum(d.retrieval_usd for d in per_day), 2),
            "cost_total_usd": round(sum(d.total_usd for d in per_day), 2),
            "max_restore_p95_minutes": round(max((d.restore_p95_minutes for d in per_day), default=0.0), 2),
        }

        started = self.sc.start_at.isoformat()
        ended = (self.sc.start_at + timedelta(days=self.sc.days)).isoformat()
        return SimulationReport(
            scenario=self.sc.name,
            days=self.sc.days,
            started_at=started,
            ended_at=ended,
            totals=totals,
            per_day=per_day,
        )


# ----------------------------- Defaults & helpers -----------------------------

def default_cost_model() -> CostModel:
    """
    Default cost placeholders. Adjust per provider/contract before use.
    Note: Values are placeholders for modeling only.
    """
    return CostModel(
        tiers={
            StorageClass.STANDARD: CostTier(storage_per_gb_month=0.023, get_per_1k=0.0004, put_per_1k=0.005, egress_per_gb=0.09, restore_latency_p95_min=1),
            StorageClass.STANDARD_IA: CostTier(storage_per_gb_month=0.0125, get_per_1k=0.001, put_per_1k=0.01, egress_per_gb=0.09, restore_latency_p95_min=2),
            StorageClass.GLACIER_IR: CostTier(storage_per_gb_month=0.004, retrieval_per_gb=0.03, get_per_1k=0.001, egress_per_gb=0.09, restore_latency_p95_min=5),
            StorageClass.GLACIER_DEEP_ARCHIVE: CostTier(storage_per_gb_month=0.00099, retrieval_per_gb=0.1, get_per_1k=0.001, egress_per_gb=0.09, restore_latency_p95_min=720),
            StorageClass.CUSTOM: CostTier(storage_per_gb_month=0.02, restore_latency_p95_min=10),
        }
    )


def policy_hot_warm_cold_legal() -> RetentionPolicy:
    """
    Example policy aligned with earlier configs:
    - start in STANDARD
    - after 30 days -> STANDARD_IA
    - after 120 days -> GLACIER_IR
    - max retention 365 days
    """
    return RetentionPolicy(
        profile="warm",
        retention_min_days=7,
        retention_max_days=365,
        immutability_mode=ImmutabilityMode.GOVERNANCE,
        legal_hold_label=None,
        transitions=[
            Transition(after_days=30, storage_class=StorageClass.STANDARD_IA),
            Transition(after_days=120, storage_class=StorageClass.GLACIER_IR),
        ],
    )


# ----------------------------- CLI entry point (optional) -----------------------------

def _print_example() -> None:
    sc = Scenario(
        name="demo-dev",
        days=90,
        retention=policy_hot_warm_cold_legal(),
        cost=default_cost_model(),
        dr=DRConfig(enabled=True, replication_factor=2, cross_region_multiplier=1.0),
        reduction=DataReduction(compression_ratio=0.6, dedup_ratio=0.75, dedup_half_life_days=21),
        workload=Workload(
            daily_new_objects=8000,
            poisson_arrivals=True,
            mean_reads_per_object_lifetime=1.5,
            mean_updates_per_object_lifetime=0.1,
            restores_per_day=30,
            restore_selection_bias_hot=0.75,
            extra_delete_ratio=0.0,
        ),
        budgets=BudgetGuards(storage_budget_usd_month=3000, egress_budget_usd_month=800, warn_threshold_pct=80, crit_threshold_pct=95),
        seed=20250825,
    )
    sim = Simulation(sc)
    report = sim.run()
    print(report.to_json())


if __name__ == "__main__":
    # Example usage:
    #   python -m oblivionvault.planner.simulation > report.json
    _print_example()
