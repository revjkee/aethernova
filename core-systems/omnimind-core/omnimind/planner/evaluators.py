# -*- coding: utf-8 -*-
"""
Omnimind Planner — Evaluators
Industrial-grade evaluation framework for plans.

Python: 3.11+
Dependencies: stdlib only

Core features:
- Unified datamodel for plan evaluation inputs and outputs
- Base Evaluator interface with deterministic behavior and structured results
- Built-in evaluators:
  * GraphValidityEvaluator      — DAG, ссылки, циклы, орфанные зависимости
  * LengthBudgetEvaluator       — лимиты по шагам и приблизительным токенам
  * RiskHeuristicsEvaluator     — ключевые сигнатуры риска и опасных операций
  * SLAEvaluator                — бюджет времени на суммарную длительность
  * CostEstimatorEvaluator      — суммарная оценка стоимости и лимит
  * ConsistencyEvaluator        — соответствие outputs -> inputs между шагами
- CompositeEvaluator            — агрегирование нескольких оценок с весами
- Timeouts per-evaluator        — защита от зависаний
- Logging                       — единый логгер с корреляцией
- Registry & Config             — построение из словаря конфигурации
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import functools
import hashlib
import logging
import os
import random
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_LOG = logging.getLogger("omnimind.planner.eval")
if not _LOG.handlers:
    # Reasonable default; in production configure via logging config
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    _LOG.addHandler(handler)
_LOG.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class PlanStep:
    id: str
    action: str
    inputs: Mapping[str, Any] = field(default_factory=dict)
    outputs: Mapping[str, str] = field(default_factory=dict)
    depends_on: Tuple[str, ...] = field(default_factory=tuple)
    estimated_duration_ms: Optional[int] = None
    cost: Optional[float] = None
    meta: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvaluationInput:
    task_id: str
    instructions: str
    steps: Tuple[PlanStep, ...]
    context: Mapping[str, Any] = field(default_factory=dict)
    # Soft budgets
    max_steps: Optional[int] = None
    max_tokens_approx: Optional[int] = None
    time_budget_ms: Optional[int] = None
    cost_budget: Optional[float] = None
    # Determinism
    seed: Optional[int] = None

    def signature(self) -> str:
        """Stable signature of input for caching/traceability."""
        h = hashlib.sha256()
        h.update(self.task_id.encode("utf-8"))
        h.update(self.instructions.encode("utf-8"))
        for s in self.steps:
            h.update(str((s.id, s.action, tuple(sorted(s.inputs.items())), tuple(sorted(s.outputs.items())),
                          s.depends_on, s.estimated_duration_ms, s.cost)).encode("utf-8"))
        for k, v in sorted(self.context.items()):
            h.update(str((k, v)).encode("utf-8"))
        for k in ("max_steps", "max_tokens_approx", "time_budget_ms", "cost_budget", "seed"):
            h.update(str(getattr(self, k)).encode("utf-8"))
        return h.hexdigest()


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    evaluator: str
    version: str
    ok: bool
    score: float  # normalized [0,1]
    label: str    # human-readable label
    reasons: Tuple[str, ...] = field(default_factory=tuple)
    metrics: Mapping[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    seed: Optional[int] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Base interface and utils
# ---------------------------------------------------------------------------

class Evaluator:
    """Abstract evaluator with safe call and timeout."""

    name: str = "base"
    version: str = "1.0.0"
    default_timeout_s: float = 2.0

    def __init__(self, *, timeout_s: Optional[float] = None, weight: float = 1.0) -> None:
        self.timeout_s = timeout_s or self.default_timeout_s
        self.weight = max(0.0, float(weight))

    def evaluate(self, evin: EvaluationInput) -> EvaluationResult:  # pragma: no cover - abstract
        raise NotImplementedError

    # Safe wrapper with timeout
    def __call__(self, evin: EvaluationInput, *, request_id: Optional[str] = None) -> EvaluationResult:
        start = time.perf_counter()
        seed = _resolve_seed(evin.seed)
        rnd_state = random.Random(seed)

        result: Optional[EvaluationResult] = None
        err: Optional[str] = None

        def _run() -> None:
            nonlocal result, err
            try:
                # allow subclasses to use deterministic randomness via rnd_state if needed
                result = self.evaluate(evin)  # type: ignore
            except Exception as e:  # defensive
                err = f"{type(e).__name__}: {e}"

        with concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"eval-{self.name}") as tp:
            fut = tp.submit(_run)
            try:
                fut.result(timeout=self.timeout_s)
            except concurrent.futures.TimeoutError:
                err = "Timeout"
            except Exception as e:
                err = f"{type(e).__name__}: {e}"

        end = time.perf_counter()
        dur = int((end - start) * 1000)

        if err or result is None:
            _LOG.warning("Evaluator '%s' failed: %s request_id=%s", self.name, err, request_id)
            return EvaluationResult(
                evaluator=self.name, version=self.version, ok=False, score=0.0,
                label="error", reasons=(err or "unknown_error",), duration_ms=dur, seed=seed, error=err or "error"
            )

        # Enforce invariants
        score = min(max(result.score, 0.0), 1.0)
        ok = bool(result.ok)
        label = result.label or ("pass" if ok else "fail")
        final = dataclasses.replace(
            result,
            evaluator=self.name, version=self.version, score=score, ok=ok, label=label,
            duration_ms=dur, seed=seed
        )
        return final


def _resolve_seed(s: Optional[int]) -> int:
    if s is None:
        # mix process pid + time for traceability, but return stable int
        base = int(time.time_ns() ^ os.getpid())
    else:
        base = int(s)
    # Normalize to 32-bit positive int
    return base & 0x7FFFFFFF


def _approx_tokens(text: str) -> int:
    """
    Rough token approximation without external libs:
    average 0.75 tokens per word + 0.25 per 4 characters baseline.
    """
    words = len(re.findall(r"\w+", text, flags=re.UNICODE))
    chars = len(text)
    return int(0.75 * words + 0.25 * (chars / 4))


# ---------------------------------------------------------------------------
# Concrete evaluators
# ---------------------------------------------------------------------------

class GraphValidityEvaluator(Evaluator):
    """Check DAG validity, missing references, duplicate ids and cycles."""

    name = "graph_validity"
    version = "1.1.0"

    def evaluate(self, evin: EvaluationInput) -> EvaluationResult:
        steps = list(evin.steps)
        ids = [s.id for s in steps]
        reasons: List[str] = []
        metrics: Dict[str, Any] = {}

        # duplicates
        dup = _duplicates(ids)
        if dup:
            reasons.append(f"duplicate_ids: {sorted(dup)}")

        idset = set(ids)
        # missing deps
        missing: Dict[str, List[str]] = {}
        for s in steps:
            miss = [d for d in s.depends_on if d not in idset]
            if miss:
                missing[s.id] = miss
        if missing:
            reasons.append(f"missing_dependencies: {missing}")

        # cycles (Kahn's algorithm)
        graph = {s.id: set(s.depends_on) for s in steps}
        indeg = {n: len(v) for n, v in graph.items()}
        q = [n for n, d in indeg.items() if d == 0]
        visited = 0
        while q:
            n = q.pop()
            visited += 1
            for m, deps in graph.items():
                if n in deps:
                    deps.remove(n)
                    indeg[m] -= 1
                    if indeg[m] == 0:
                        q.append(m)
        acyclic = visited == len(steps)
        if not acyclic:
            reasons.append("cycle_detected")

        ok = not reasons
        score = 1.0 if ok else max(0.0, 1.0 - 0.25 * len(reasons))
        metrics.update({"nodes": len(steps), "duplicates": len(dup), "missing_edges": len(missing), "acyclic": acyclic})
        return EvaluationResult(self.name, self.version, ok, score, "pass" if ok else "fail",
                                tuple(reasons), metrics)


class LengthBudgetEvaluator(Evaluator):
    """Check steps count and token budget for instructions + actions."""

    name = "length_budget"
    version = "1.0.0"

    def __init__(self, *, max_steps: Optional[int] = None, max_tokens: Optional[int] = None,
                 timeout_s: Optional[float] = None, weight: float = 1.0) -> None:
        super().__init__(timeout_s=timeout_s, weight=weight)
        self.cfg_max_steps = max_steps
        self.cfg_max_tokens = max_tokens

    def evaluate(self, evin: EvaluationInput) -> EvaluationResult:
        max_steps = self.cfg_max_steps or evin.max_steps
        max_tokens = self.cfg_max_tokens or evin.max_tokens_approx

        steps = len(evin.steps)
        tokens = _approx_tokens(evin.instructions) + sum(_approx_tokens(s.action) for s in evin.steps)

        reasons: List[str] = []
        if max_steps is not None and steps > max_steps:
            reasons.append(f"steps_exceeded:{steps}>{max_steps}")
        if max_tokens is not None and tokens > max_tokens:
            reasons.append(f"tokens_exceeded:{tokens}>{max_tokens}")

        ok = not reasons
        # Graded score: each excess dimension penalizes
        score = 1.0
        if max_steps and steps > max_steps:
            score *= max(0.0, 1.0 - (steps - max_steps) / max(1.0, steps))
        if max_tokens and tokens > max_tokens:
            score *= max(0.0, 1.0 - (tokens - max_tokens) / max(1.0, tokens))
        return EvaluationResult(self.name, self.version, ok, score, "pass" if ok else "fail",
                                tuple(reasons), {"steps": steps, "tokens": tokens,
                                                 "max_steps": max_steps, "max_tokens": max_tokens})


class RiskHeuristicsEvaluator(Evaluator):
    """
    Detect risky operations by regex signatures and keyword sets.
    Scoring decreases with matched severity; configurable lists can be extended.
    """

    name = "risk_heuristics"
    version = "1.1.0"

    DEFAULT_PATTERNS = {
        "filesystem_danger": r"\brm\s+-rf\b|\bmkfs\W|\bumount\b|\bmount\s+-o\s+remount,rw\b",
        "db_destructive": r"\bDROP\s+TABLE\b|\bTRUNCATE\b|\bDELETE\s+FROM\b(?!.*\bWHERE\b)",
        "system_shutdown": r"\bshutdown\b|\breboot\b|\binit\s+[016]\b|\bsystemctl\s+(stop|disable)\b",
        "network_scan": r"\bnmap\b|\bnc\s+-z\b|\bmasscan\b",
        "priv_escalation": r"\bsudo\b.*-S|\bchmod\s+777\b|\bchown\s+root:root\b",
    }

    SEVERITY = {
        "filesystem_danger": 1.0,
        "db_destructive": 0.9,
        "system_shutdown": 0.8,
        "network_scan": 0.5,
        "priv_escalation": 0.7,
    }

    def __init__(self, *, extra_patterns: Optional[Mapping[str, str]] = None,
                 timeout_s: Optional[float] = None, weight: float = 1.0) -> None:
        super().__init__(timeout_s=timeout_s, weight=weight)
        patterns = dict(self.DEFAULT_PATTERNS)
        if extra_patterns:
            patterns.update(extra_patterns)
        self._compiled: List[Tuple[str, re.Pattern[str], float]] = [
            (name, re.compile(pattern, flags=re.IGNORECASE | re.MULTILINE), self.SEVERITY.get(name, 0.5))
            for name, pattern in patterns.items()
        ]

    def evaluate(self, evin: EvaluationInput) -> EvaluationResult:
        hits: Dict[str, List[str]] = {}
        for step in evin.steps:
            text = f"{step.action}\n{step.inputs}\n{step.meta}"
            for name, rx, sev in self._compiled:
                if rx.search(text):
                    hits.setdefault(name, []).append(step.id)

        reasons: List[str] = []
        risk_score = 1.0
        for name, ids in hits.items():
            reasons.append(f"risk_{name}:{ids}")
            risk_score *= max(0.0, 1.0 - self.SEVERITY.get(name, 0.5) * min(1.0, len(ids) / max(1, len(evin.steps))))

        ok = not hits
        score = risk_score if ok else max(0.0, risk_score * 0.85)  # extra penalty if any risk present
        return EvaluationResult(self.name, self.version, ok, score, "pass" if ok else "warn",
                                tuple(reasons), {"risk_categories": list(hits.keys()), "hits": hits})


class SLAEvaluator(Evaluator):
    """Check aggregated estimated duration against time budget."""

    name = "sla_time_budget"
    version = "1.0.0"

    def __init__(self, *, time_budget_ms: Optional[int] = None, timeout_s: Optional[float] = None,
                 weight: float = 1.0) -> None:
        super().__init__(timeout_s=timeout_s, weight=weight)
        self.cfg_budget = time_budget_ms

    def evaluate(self, evin: EvaluationInput) -> EvaluationResult:
        budget = self.cfg_budget or evin.time_budget_ms
        total = sum(int(s.estimated_duration_ms or 0) for s in evin.steps)
        reasons: List[str] = []
        if budget is not None and total > budget:
            reasons.append(f"time_budget_exceeded:{total}>{budget}")

        ok = not reasons
        score = 1.0 if ok else max(0.0, 1.0 - (total - budget) / max(1.0, total)) if budget else 0.0
        return EvaluationResult(self.name, self.version, ok, score, "pass" if ok else "fail",
                                tuple(reasons), {"total_ms": total, "budget_ms": budget})


class CostEstimatorEvaluator(Evaluator):
    """Sum step cost or estimate by heuristics; compare with budget."""

    name = "cost_estimator"
    version = "1.0.0"

    DEFAULT_COSTS = {
        # Fallback categories by keywords; very rough and safe defaults
        "api_call": 0.001,
        "db_query": 0.0005,
        "llm_inference": 0.02,
        "file_io": 0.0001,
        "network_request": 0.0004,
    }

    def __init__(self, *, cost_budget: Optional[float] = None, keyword_costs: Optional[Mapping[str, float]] = None,
                 timeout_s: Optional[float] = None, weight: float = 1.0) -> None:
        super().__init__(timeout_s=timeout_s, weight=weight)
        self.budget = cost_budget
        self.keyword_costs = dict(self.DEFAULT_COSTS)
        if keyword_costs:
            self.keyword_costs.update(keyword_costs)

    def _estimate_step_cost(self, step: PlanStep) -> float:
        if step.cost is not None:
            return float(step.cost)
        # heuristic: match on action keywords
        text = step.action.lower()
        for k, c in self.keyword_costs.items():
            if k in text:
                return float(c)
        return 0.0001  # min default

    def evaluate(self, evin: EvaluationInput) -> EvaluationResult:
        total = sum(self._estimate_step_cost(s) for s in evin.steps)
        budget = self.budget or evin.cost_budget
        reasons: List[str] = []
        if budget is not None and total > budget:
            reasons.append(f"cost_budget_exceeded:{total:.6f}>{budget:.6f}")

        ok = not reasons
        score = 1.0 if ok else max(0.0, 1.0 - (total - budget) / max(1e-9, total)) if budget else 0.0
        return EvaluationResult(self.name, self.version, ok, score, "pass" if ok else "fail",
                                tuple(reasons), {"total_cost": round(total, 8), "budget": budget})


class ConsistencyEvaluator(Evaluator):
    """
    Check that outputs of producing steps are referenced by consumer inputs as per depends_on.
    Heuristic: if step B depends_on A, at least one key from A.outputs should be referenced in B.inputs values.
    """

    name = "consistency"
    version = "1.0.0"

    def evaluate(self, evin: EvaluationInput) -> EvaluationResult:
        by_id = {s.id: s for s in evin.steps}
        reasons: List[str] = []
        ok_count = 0
        check_count = 0

        for s in evin.steps:
            for dep in s.depends_on:
                if dep not in by_id:
                    continue  # Graph evaluator will flag this
                prod = by_id[dep]
                if not prod.outputs:
                    reasons.append(f"no_outputs_from:{dep}->consumer:{s.id}")
                    check_count += 1
                    continue
                # values of consumer inputs
                values = [str(v) for v in s.inputs.values()]
                expected_keys = list(prod.outputs.values()) + list(prod.outputs.keys())
                matched = any(any(str(k) in val for val in values) for k in expected_keys)
                check_count += 1
                if matched:
                    ok_count += 1
                else:
                    reasons.append(f"unreferenced_output:{dep}->{s.id}")

        ok = not reasons
        score = 1.0 if check_count == 0 else ok_count / check_count
        return EvaluationResult(self.name, self.version, ok, score, "pass" if ok else "warn",
                                tuple(reasons), {"checks": check_count, "ok": ok_count})


# ---------------------------------------------------------------------------
# Composite evaluator and registry
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class WeightedEval:
    evaluator: Evaluator
    weight: float


class CompositeEvaluator(Evaluator):
    """
    Combine multiple evaluators using weighted geometric mean of scores.
    Any hard-fail (ok=False) can optionally be treated as zero score.
    """

    name = "composite"
    version = "1.1.0"

    def __init__(self, evaluators: Sequence[Evaluator], *, treat_fail_as_zero: bool = False,
                 timeout_s: Optional[float] = None, weight: float = 1.0) -> None:
        super().__init__(timeout_s=timeout_s, weight=weight)
        self._evals: Tuple[WeightedEval, ...] = tuple(WeightedEval(e, e.weight) for e in evaluators)
        self.treat_fail_as_zero = bool(treat_fail_as_zero)

    def evaluate(self, evin: EvaluationInput) -> EvaluationResult:
        request_id = str(uuid.uuid4())
        results: List[EvaluationResult] = []
        reasons: List[str] = []
        metrics: Dict[str, Any] = {}

        # Run sequentially to keep logs deterministic; can be parallelized if needed
        for w in self._evals:
            res = w.evaluator(evin, request_id=request_id)
            results.append(res)
            reasons.extend(f"{res.evaluator}:{r}" for r in res.reasons)
            metrics[f"{res.evaluator}.score"] = res.score
            metrics[f"{res.evaluator}.ok"] = res.ok
            metrics[f"{res.evaluator}.duration_ms"] = res.duration_ms

        # Weighted geometric mean
        total_weight = sum(max(1e-9, w.weight) for w in self._evals)
        log_sum = 0.0
        for w, res in zip(self._evals, results):
            s = res.score
            if self.treat_fail_as_zero and not res.ok:
                s = 0.0
            # clamp
            s = min(max(s, 1e-9), 1.0)
            log_sum += (w.weight / total_weight) * (0.0 if s == 1.0 else (0.0 if s <= 0 else (float(__import__("math").log(s)))))

        import math
        score = math.exp(log_sum) if log_sum != 0 else 1.0

        ok = all(r.ok for r in results)
        label = "pass" if ok else "fail"
        metrics["subresults"] = [dataclasses.asdict(r) for r in results]
        return EvaluationResult(self.name, self.version, ok, float(score), label, tuple(reasons), metrics)


# Registry for factory construction
_EVAL_REGISTRY: Dict[str, Callable[..., Evaluator]] = {
    GraphValidityEvaluator.name: lambda **kw: GraphValidityEvaluator(**kw),
    LengthBudgetEvaluator.name: lambda **kw: LengthBudgetEvaluator(**kw),
    RiskHeuristicsEvaluator.name: lambda **kw: RiskHeuristicsEvaluator(**kw),
    SLAEvaluator.name: lambda **kw: SLAEvaluator(**kw),
    CostEstimatorEvaluator.name: lambda **kw: CostEstimatorEvaluator(**kw),
    ConsistencyEvaluator.name: lambda **kw: ConsistencyEvaluator(**kw),
    CompositeEvaluator.name: lambda **kw: CompositeEvaluator(**kw),  # expects evaluators param
}


def build_evaluator_from_config(cfg: Mapping[str, Any]) -> Evaluator:
    """
    Build evaluator from dict config.
    Example:
        {
          "type": "composite",
          "treat_fail_as_zero": true,
          "evaluators": [
            {"type": "graph_validity"},
            {"type": "length_budget", "max_steps": 12, "max_tokens": 1200},
            {"type": "risk_heuristics"},
            {"type": "sla_time_budget", "time_budget_ms": 600000},
            {"type": "cost_estimator", "cost_budget": 1.0},
            {"type": "consistency"}
          ]
        }
    """
    etype = str(cfg.get("type", "")).strip().lower()
    if etype not in _EVAL_REGISTRY:
        raise ValueError(f"unknown evaluator type: {etype}")

    if etype == "composite":
        subs_cfg = cfg.get("evaluators", [])
        if not isinstance(subs_cfg, list) or not subs_cfg:
            raise ValueError("composite requires non-empty 'evaluators' list")
        subs = [build_evaluator_from_config(sc) for sc in subs_cfg]
        return CompositeEvaluator(
            subs,
            treat_fail_as_zero=bool(cfg.get("treat_fail_as_zero", False)),
            timeout_s=cfg.get("timeout_s"),
            weight=float(cfg.get("weight", 1.0)),
        )

    # Non-composite: pass kwargs except 'type'
    kwargs = {k: v for k, v in cfg.items() if k != "type"}
    return _EVAL_REGISTRY[etype](**kwargs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _duplicates(seq: Sequence[str]) -> List[str]:
    seen = set()
    dup = set()
    for x in seq:
        if x in seen:
            dup.add(x)
        else:
            seen.add(x)
    return list(dup)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

def default_production_suite() -> Evaluator:
    """
    Recommended production composite evaluator with sensible defaults.
    """
    return CompositeEvaluator(
        [
            GraphValidityEvaluator(),
            LengthBudgetEvaluator(max_steps=None, max_tokens=None),
            RiskHeuristicsEvaluator(),
            SLAEvaluator(time_budget_ms=None),
            CostEstimatorEvaluator(cost_budget=None),
            ConsistencyEvaluator(),
        ],
        treat_fail_as_zero=False,
    )


# ---------------------------------------------------------------------------
# Example usage (manual test)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    plan = (
        PlanStep(
            id="extract",
            action="api_call fetch customer data",
            outputs={"data": "customers_json"},
            estimated_duration_ms=1200,
            cost=0.001,
        ),
        PlanStep(
            id="transform",
            action="python process customers_json and anonymize",
            inputs={"input": "customers_json"},
            depends_on=("extract",),
            outputs={"dataset": "customers_anonymized"},
            estimated_duration_ms=2400,
        ),
        PlanStep(
            id="load",
            action="db_query INSERT anonymized rows into warehouse WITH COMMIT",
            inputs={"data": "customers_anonymized"},
            depends_on=("transform",),
            estimated_duration_ms=1800,
        ),
    )

    evin = EvaluationInput(
        task_id="demo-001",
        instructions="ETL customers into warehouse with anonymization.",
        steps=plan,
        max_steps=10,
        max_tokens_approx=1500,
        time_budget_ms=10_000,
        cost_budget=1.0,
        seed=42,
    )

    evaluator = default_production_suite()
    result = evaluator(evin)
    from pprint import pprint
    pprint(dataclasses.asdict(result))
