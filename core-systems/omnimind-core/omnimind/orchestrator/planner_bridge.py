# -*- coding: utf-8 -*-
"""
OmniMind Core — Planner Bridge
------------------------------

Назначение:
- Нормализация и строгая валидация планов (DAG) из внешних источников (LLM и др.).
- Идемпотентное создание плана в Planner-бэкенде.
- Запуск плана в Executor-бэкенде с экспоненциальными ретраями.
- Потоковая передача событий выполнения (async generator).
- Безопасное структурированное логирование с редакцией PII/секретов.
- Необязательная интеграция с OpenTelemetry при наличии.

Зависимости: только стандартная библиотека (опционально opentelemetry для трассировки).
Совместимость: Python 3.10+.

Интеграция:
    bridge = PlannerBridge(planner_client=..., executor_client=...)
    plan = bridge.normalize_plan(llm_json, tenant_id="omni")
    await bridge.validate_plan(plan)
    created = await bridge.create_plan(plan, idempotency_key="abc-123")
    async for event in bridge.execute_plan(created["name"], trace={"trace_id": "..."}, overrides=None):
        ...

Автор: OmniMind Platform Team
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Union,
)

# -----------------------------
# Опциональный OpenTelemetry
# -----------------------------
try:
    from opentelemetry import trace as ot_trace  # type: ignore
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False

# -----------------------------
# Контекст корреляции
# -----------------------------
_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("omni.request_id", default="")
_trace_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("omni.trace_id", default="")

def get_request_id() -> str:
    return _request_id_ctx.get()

def get_trace_id() -> str:
    return _trace_id_ctx.get()

# -----------------------------
# Константы и ограничения
# -----------------------------
MAX_STEPS_DEFAULT = 1000
MAX_LABEL_KEY = 63
MAX_LABEL_VAL = 256
STEP_ID_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,128}$")
PLAN_NAME_RE = re.compile(r"^plans/[a-zA-Z0-9._\-]{3,128}$")

# -----------------------------
# Примитивы логирования
# -----------------------------
class JsonLogger:
    def __init__(self, name: str = "omnimind.planner_bridge", level: int = logging.INFO):
        self._log = logging.getLogger(name)
        if not self._log.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("%(message)s"))
            self._log.addHandler(h)
        self._log.setLevel(level)

    def emit(self, level: int, payload: Mapping[str, Any]) -> None:
        try:
            self._log.log(level, json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        except Exception:
            self._log.log(level, str(payload))


# Редактор PII/секретов (простые паттерны)
_REDACT_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}"), "<email>"),
    (re.compile(r"(?i)\+?\d[\d\-\s()]{7,}\d"), "<phone>"),
    (re.compile(r"(?i)\b(?:\d[ -]*?){13,19}\b"), "<card>"),
    (re.compile(r'(?i)("password"\s*:\s*)"[^"]+"'), r'\1"***"'),
    (re.compile(r'(?i)("token"\s*:\s*)"[^"]+"'), r'\1"***"'),
    (re.compile(r'(?i)("secret"\s*:\s*)"[^"]+"'), r'\1"***"'),
]

def redact_text(text: str) -> str:
    out = text
    for rx, repl in _REDACT_PATTERNS:
        out = rx.sub(repl, out)
    return out

# -----------------------------
# Простейшие DTO (без внешних зависимостей)
# -----------------------------
@dataclass
class Timeout:
    execution_ms: int | None = None
    queue_ms: int | None = None

@dataclass
class RetryPolicy:
    max_attempts: int = 0
    initial_backoff_ms: int = 0
    multiplier: float = 2.0
    max_backoff_ms: int = 60000
    retry_on: Set[str] = field(default_factory=set)  # коды ошибок

@dataclass
class CachePolicy:
    enabled: bool = False
    cache_inputs: bool = False
    cache_outputs: bool = False
    ttl_seconds: int | None = None
    strategy: str | None = None
    cache_key_fields: List[str] = field(default_factory=list)

@dataclass
class Parameter:
    key: str
    value: Any = None
    required: bool = False
    type: str | None = None
    description: str | None = None

@dataclass
class FileRef:
    uri: str
    name: str | None = None
    mime_type: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None

@dataclass
class ToolInvocation:
    name: str
    inputs: Dict[str, Any] = field(default_factory=dict)
    parameters: List[Parameter] = field(default_factory=list)
    files: List[FileRef] = field(default_factory=list)

@dataclass
class Step:
    id: str
    name: str | None
    type: str  # TOOL|CODE|HTTP|CONTROL
    tool: str | None
    invocation: ToolInvocation | None = None
    when: str | None = None  # CEL-подобное условие (оценка на рантайме)
    depends_on: List[str] = field(default_factory=list)
    timeout: Timeout = field(default_factory=Timeout)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    concurrency_key: str | None = None
    cache: CachePolicy = field(default_factory=CachePolicy)

@dataclass
class Edge:
    frm: str
    to: str
    condition: str | None = None  # CEL-подобное условие

@dataclass
class Budget:
    wall_clock_ms: int | None = None
    max_tokens: int | None = None
    max_cost_usd: float | None = None
    max_steps: int | None = None

@dataclass
class SecurityContext:
    tenant_id: str
    actor_id: str | None = None
    roles: Set[str] = field(default_factory=set)
    allow_external_network: bool = False

@dataclass
class ExecutionPolicy:
    max_parallel: int = 0
    fail_fast: bool = False
    continue_on_error: bool = False
    concurrency_limits: Dict[str, int] = field(default_factory=dict)
    schedule: Dict[str, Any] | None = None  # {enabled, cron, not_before, not_after}

@dataclass
class PlanDTO:
    # name присваивается Planner’ом; при создании отсутствует
    name: str | None
    tenant_id: str
    display_name: str | None
    steps: List[Step]
    edges: List[Edge]
    params: Dict[str, Any] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    budget: Budget = field(default_factory=Budget)
    security: SecurityContext | None = None
    trace: Dict[str, Any] = field(default_factory=dict)
    idempotency_key: str | None = None
    execution_policy: ExecutionPolicy = field(default_factory=ExecutionPolicy)

    def to_planner_payload(self) -> Dict[str, Any]:
        """Преобразование в универсальный JSON для Planner API (grpc/http)."""
        def _timeout(t: Timeout) -> Dict[str, Any]:
            return {"execution": t.execution_ms, "queue": t.queue_ms}

        def _retry(r: RetryPolicy) -> Dict[str, Any]:
            return {
                "max_attempts": r.max_attempts,
                "initial_backoff_ms": r.initial_backoff_ms,
                "multiplier": r.multiplier,
                "max_backoff_ms": r.max_backoff_ms,
                "retry_on": sorted(list(r.retry_on)),
            }

        def _cache(c: CachePolicy) -> Dict[str, Any]:
            return {
                "enabled": c.enabled,
                "cache_inputs": c.cache_inputs,
                "cache_outputs": c.cache_outputs,
                "ttl_seconds": c.ttl_seconds,
                "strategy": c.strategy,
                "cache_key_fields": c.cache_key_fields,
            }

        def _inv(inv: ToolInvocation | None) -> Dict[str, Any] | None:
            if inv is None:
                return None
            return {
                "name": inv.name,
                "inputs": inv.inputs or {},
                "parameters": [{"key": p.key, "value": p.value, "required": p.required, "type": p.type, "description": p.description} for p in inv.parameters],
                "files": [{"uri": f.uri, "name": f.name, "mime_type": f.mime_type, "size_bytes": f.size_bytes, "sha256": f.sha256} for f in inv.files],
            }

        payload = {
            "tenant_id": self.tenant_id,
            "display_name": self.display_name,
            "params": self.params,
            "labels": self.labels,
            "budget": {
                "wall_clock_ms": self.budget.wall_clock_ms,
                "max_tokens": self.budget.max_tokens,
                "max_cost_usd": self.budget.max_cost_usd,
                "max_steps": self.budget.max_steps,
            },
            "security": {
                "tenant_id": self.security.tenant_id if self.security else self.tenant_id,
                "actor_id": self.security.actor_id if self.security else None,
                "roles": sorted(list(self.security.roles)) if self.security else [],
                "allow_external_network": self.security.allow_external_network if self.security else False,
            },
            "trace": self.trace,
            "idempotency_key": self.idempotency_key,
            "execution_policy": {
                "max_parallel": self.execution_policy.max_parallel,
                "fail_fast": self.execution_policy.fail_fast,
                "continue_on_error": self.execution_policy.continue_on_error,
                "concurrency_limits": self.execution_policy.concurrency_limits,
                "schedule": self.execution_policy.schedule,
            },
            "steps": [
                {
                    "id": s.id,
                    "name": s.name,
                    "type": s.type,
                    "tool": s.tool,
                    "invocation": _inv(s.invocation),
                    "when": s.when,
                    "depends_on": s.depends_on,
                    "timeout": _timeout(s.timeout),
                    "retry": _retry(s.retry),
                    "labels": s.labels,
                    "metadata": s.metadata,
                    "concurrency_key": s.concurrency_key,
                    "cache": _cache(s.cache),
                }
                for s in self.steps
            ],
            "edges": [{"from": e.frm, "to": e.to, "condition": e.condition} for e in self.edges],
        }
        return payload


# -----------------------------
# Контракты клиентов (Protocol)
# -----------------------------
class PlannerClient(Protocol):
    async def create_plan(self, plan_payload: Mapping[str, Any]) -> Mapping[str, Any]:
        """Должен вернуть объект плана, минимум: {"name": "plans/<id>", ...}"""
        ...

class ExecutorClient(Protocol):
    async def execute_plan(
        self,
        name: str,
        *,
        override_params: Optional[Mapping[str, Any]] = None,
        override_execution: Optional[Mapping[str, Any]] = None,
        override_budget: Optional[Mapping[str, Any]] = None,
        trace: Optional[Mapping[str, Any]] = None,
    ) -> AsyncIterator[Mapping[str, Any]]:
        """Должен возвращать асинхронный итератор событий выполнения."""
        ...


# -----------------------------
# Исключения
# -----------------------------
class PlanValidationError(Exception):
    def __init__(self, reasons: List[str]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


# -----------------------------
# Вспомогательные функции
# -----------------------------
def _hash_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _hash_obj(obj: Any) -> str:
    return _hash_bytes(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

def _monotonic_ms() -> int:
    return int(time.perf_counter() * 1000)

# -----------------------------
# Planner Bridge
# -----------------------------
class PlannerBridge:
    def __init__(
        self,
        *,
        planner_client: PlannerClient,
        executor_client: ExecutorClient,
        logger: Optional[JsonLogger] = None,
        max_steps: int = MAX_STEPS_DEFAULT,
        allow_step_types: Set[str] | None = None,  # {"TOOL","CODE","HTTP","CONTROL"}
        redact_logs: bool = True,
        create_retries: int = 3,
        execute_retries: int = 3,
        backoff_initial_ms: int = 250,
        backoff_max_ms: int = 10_000,
    ):
        self.planner_client = planner_client
        self.executor_client = executor_client
        self.log = logger or JsonLogger()
        self.max_steps = max_steps
        self.allow_step_types = allow_step_types or {"TOOL", "CODE", "HTTP", "CONTROL"}
        self.redact_logs = redact_logs
        self.create_retries = max(0, create_retries)
        self.execute_retries = max(0, execute_retries)
        self.backoff_initial_ms = backoff_initial_ms
        self.backoff_max_ms = backoff_max_ms

        # Идемпотентность на стороне моста (дополнительно к серверной)
        self._idempotency_cache: Dict[str, str] = {}  # key signature -> plan name

    # --------- Нормализация входа ---------
    def normalize_plan(
        self,
        raw: Mapping[str, Any],
        *,
        tenant_id: str,
        display_name: str | None = None,
        idempotency_key: str | None = None,
        default_timeout_ms: int | None = 300000,
    ) -> PlanDTO:
        """
        Превращает произвольный JSON (LLM/пользователь) в строгий PlanDTO.
        """
        steps_raw = list(raw.get("steps", []))
        edges_raw = list(raw.get("edges", []))
        params = dict(raw.get("params", {}))
        labels = dict(raw.get("labels", {}))

        steps: List[Step] = []
        for i, s in enumerate(steps_raw):
            sid = str(s.get("id") or f"step_{i+1}")
            stype = str(s.get("type", "TOOL")).upper()
            tool = s.get("tool")
            name = s.get("name")
            inv = s.get("invocation") or {}
            invocation = ToolInvocation(
                name=str(inv.get("name") or tool or sid),
                inputs=dict(inv.get("inputs") or {}),
                parameters=[Parameter(key=str(p.get("key")), value=p.get("value"), required=bool(p.get("required", False)), type=p.get("type"), description=p.get("description")) for p in (inv.get("parameters") or [])],
                files=[FileRef(uri=str(f.get("uri")), name=f.get("name"), mime_type=f.get("mime_type"), size_bytes=f.get("size_bytes"), sha256=f.get("sha256")) for f in (inv.get("files") or [])],
            ) if stype in {"TOOL", "HTTP", "CODE"} else None

            timeout = Timeout(
                execution_ms=int(s.get("timeout", {}).get("execution", default_timeout_ms) or 0) or None,
                queue_ms=int(s.get("timeout", {}).get("queue", 0) or 0) or None,
            )
            retry = RetryPolicy(
                max_attempts=int(s.get("retry", {}).get("max_attempts", 0) or 0),
                initial_backoff_ms=int(s.get("retry", {}).get("initial_backoff_ms", 0) or 0),
                multiplier=float(s.get("retry", {}).get("multiplier", 2.0) or 2.0),
                max_backoff_ms=int(s.get("retry", {}).get("max_backoff_ms", 60000) or 60000),
                retry_on=set(s.get("retry", {}).get("retry_on", []) or []),
            )
            cache = CachePolicy(
                enabled=bool(s.get("cache", {}).get("enabled", False)),
                cache_inputs=bool(s.get("cache", {}).get("cache_inputs", False)),
                cache_outputs=bool(s.get("cache", {}).get("cache_outputs", False)),
                ttl_seconds=(int(s.get("cache", {}).get("ttl_seconds")) if s.get("cache", {}).get("ttl_seconds") is not None else None),
                strategy=s.get("cache", {}).get("strategy"),
                cache_key_fields=list(s.get("cache", {}).get("cache_key_fields", []) or []),
            )

            steps.append(
                Step(
                    id=sid,
                    name=name,
                    type=stype,
                    tool=tool,
                    invocation=invocation,
                    when=s.get("when"),
                    depends_on=list(s.get("depends_on", []) or []),
                    timeout=timeout,
                    retry=retry,
                    labels=dict(s.get("labels", {}) or {}),
                    metadata=dict(s.get("metadata", {}) or {}),
                    concurrency_key=s.get("concurrency_key"),
                    cache=cache,
                )
            )

        edges: List[Edge] = [
            Edge(frm=str(e.get("from")), to=str(e.get("to")), condition=e.get("condition"))
            for e in edges_raw
            if e.get("from") and e.get("to")
        ]

        # SecurityContext по умолчанию
        sec = SecurityContext(tenant_id=tenant_id)

        # ExecutionPolicy по умолчанию
        exec_pol = ExecutionPolicy(
            max_parallel=int(raw.get("execution_policy", {}).get("max_parallel", 0) or 0),
            fail_fast=bool(raw.get("execution_policy", {}).get("fail_fast", False)),
            continue_on_error=bool(raw.get("execution_policy", {}).get("continue_on_error", False)),
            concurrency_limits=dict(raw.get("execution_policy", {}).get("concurrency_limits", {}) or {}),
            schedule=raw.get("execution_policy", {}).get("schedule"),
        )

        budget = Budget(
            wall_clock_ms=(int(raw.get("budget", {}).get("wall_clock_ms")) if raw.get("budget", {}).get("wall_clock_ms") is not None else None),
            max_tokens=(int(raw.get("budget", {}).get("max_tokens")) if raw.get("budget", {}).get("max_tokens") is not None else None),
            max_cost_usd=(float(raw.get("budget", {}).get("max_cost_usd")) if raw.get("budget", {}).get("max_cost_usd") is not None else None),
            max_steps=(int(raw.get("budget", {}).get("max_steps")) if raw.get("budget", {}).get("max_steps") is not None else None),
        )

        return PlanDTO(
            name=None,
            tenant_id=tenant_id,
            display_name=display_name,
            steps=steps,
            edges=edges,
            params=params,
            labels=labels,
            budget=budget,
            security=sec,
            trace={},
            idempotency_key=idempotency_key,
            execution_policy=exec_pol,
        )

    # --------- Валидация ---------
    async def validate_plan(self, plan: PlanDTO) -> None:
        reasons: List[str] = []

        # Размеры
        if len(plan.steps) == 0:
            reasons.append("plan has no steps")
        if len(plan.steps) > self.max_steps:
            reasons.append(f"too many steps: {len(plan.steps)} > {self.max_steps}")

        # Шаги: идентификаторы и типы
        ids: Set[str] = set()
        for s in plan.steps:
            if not STEP_ID_RE.match(s.id or ""):
                reasons.append(f"invalid step id: {s.id!r}")
            if s.id in ids:
                reasons.append(f"duplicate step id: {s.id}")
            ids.add(s.id)
            if s.type not in self.allow_step_types:
                reasons.append(f"unsupported step type: {s.type}")
            # labels ограничение
            for k, v in s.labels.items():
                if len(k) > MAX_LABEL_KEY or len(v) > MAX_LABEL_VAL:
                    reasons.append(f"label too long on step {s.id}: {k}={v}")

        # Рёбра: ссылки и self-loop
        for e in plan.edges:
            if e.frm == e.to:
                reasons.append(f"self-loop edge: {e.frm} -> {e.to}")
            if e.frm not in ids:
                reasons.append(f"edge.from not found: {e.frm}")
            if e.to not in ids:
                reasons.append(f"edge.to not found: {e.to}")

        # Зависимости steps.depends_on
        for s in plan.steps:
            for d in s.depends_on:
                if d not in ids:
                    reasons.append(f"depends_on of {s.id} references missing step {d}")

        # Ацикличность DAG (edges + depends_on)
        graph: Dict[str, List[str]] = {sid: [] for sid in ids}
        for e in plan.edges:
            if e.frm in graph:
                graph[e.frm].append(e.to)
        for s in plan.steps:
            for d in s.depends_on:
                graph[d].append(s.id)

        visited: Dict[str, int] = {sid: 0 for sid in ids}  # 0=white,1=grey,2=black
        cycle_path: List[str] = []

        def dfs(u: str) -> bool:
            visited[u] = 1
            cycle_path.append(u)
            for v in graph.get(u, []):
                if visited[v] == 0:
                    if dfs(v):
                        return True
                elif visited[v] == 1:
                    cycle_path.append(v)
                    return True
            visited[u] = 2
            cycle_path.pop()
            return False

        for sid in ids:
            if visited[sid] == 0 and dfs(sid):
                reasons.append(f"cycle detected in DAG: {' -> '.join(cycle_path)}")
                break

        # Бюджеты
        if plan.budget.max_steps is not None and plan.budget.max_steps < len(plan.steps):
            reasons.append(f"budget.max_steps {plan.budget.max_steps} < steps {len(plan.steps)}")

        if reasons:
            raise PlanValidationError(reasons)

    # --------- Идемпотентность ---------
    def _signature(self, plan: PlanDTO) -> str:
        payload = plan.to_planner_payload()
        # Исключим поля, изменяемые сервером
        payload.pop("trace", None)
        return _hash_obj(payload)

    # --------- Создание плана ---------
    async def create_plan(self, plan: PlanDTO, *, idempotency_key: str | None = None) -> Mapping[str, Any]:
        sig = self._signature(plan)
        # Кэш моста (быстрый путь)
        if sig in self._idempotency_cache:
            cached_name = self._idempotency_cache[sig]
            self._log_event("plan.create.cache_hit", {"name": cached_name, "sig": sig})
            return {"name": cached_name}

        payload = plan.to_planner_payload()
        if idempotency_key:
            payload["idempotency_key"] = idempotency_key
        elif plan.idempotency_key:
            payload["idempotency_key"] = plan.idempotency_key

        # Корреляция
        req_id = str(uuid.uuid4())
        _request_id_ctx.set(req_id)
        tr_id = ""
        if _HAS_OTEL:
            span = ot_trace.get_current_span()
            ctx = span.get_span_context() if span else None
            if ctx and ctx.is_valid:
                tr_id = f"{ctx.trace_id:032x}"
        _trace_id_ctx.set(tr_id)

        # Ретраи
        attempt = 0
        backoff = self.backoff_initial_ms
        while True:
            attempt += 1
            t0 = _monotonic_ms()
            try:
                created = await self.planner_client.create_plan(payload)
                name = str(created.get("name", ""))
                if not name or not PLAN_NAME_RE.match(name):
                    raise RuntimeError("planner_client.create_plan returned invalid name")
                self._idempotency_cache[sig] = name
                self._log_event("plan.create.ok", {"name": name, "attempt": attempt, "ms": _monotonic_ms() - t0})
                return created
            except Exception as e:  # pragma: no cover
                self._log_event("plan.create.error", {"error": str(e), "attempt": attempt})
                if attempt > self.create_retries:
                    raise
                await asyncio.sleep(min(backoff, self.backoff_max_ms) / 1000.0)
                backoff = min(int(backoff * 2), self.backoff_max_ms)

    # --------- Исполнение плана ---------
    async def execute_plan(
        self,
        name: str,
        *,
        overrides: Optional[Mapping[str, Any]] = None,
        trace: Optional[Mapping[str, Any]] = None,
        execution_override: Optional[Mapping[str, Any]] = None,
        budget_override: Optional[Mapping[str, Any]] = None,
    ) -> AsyncIterator[Mapping[str, Any]]:
        """Возвращает async-итератор событий PlanEvent из ExecutorClient."""
        if not PLAN_NAME_RE.match(name or ""):
            raise ValueError(f"invalid plan name: {name!r}")

        # Корреляция
        req_id = str(uuid.uuid4())
        _request_id_ctx.set(req_id)
        if trace and "trace_id" in (trace or {}):
            _trace_id_ctx.set(str(trace["trace_id"]))
        elif _HAS_OTEL:
            span = ot_trace.get_current_span()
            ctx = span.get_span_context() if span else None
            _trace_id_ctx.set(f"{ctx.trace_id:032x}" if ctx and ctx.is_valid else "")

        # Ретраи на открытие стрима
        attempt = 0
        backoff = self.backoff_initial_ms

        while True:
            attempt += 1
            try:
                self._log_event("plan.exec.start", {"name": name, "attempt": attempt})
                async for ev in self.executor_client.execute_plan(
                    name,
                    override_params=overrides,
                    override_execution=execution_override,
                    override_budget=budget_override,
                    trace={"request_id": get_request_id(), "trace_id": get_trace_id(), **(trace or {})},
                ):
                    yield self._sanitize_event(ev)
                self._log_event("plan.exec.end", {"name": name, "attempt": attempt})
                return
            except Exception as e:  # pragma: no cover
                self._log_event("plan.exec.error", {"error": str(e), "attempt": attempt})
                if attempt > self.execute_retries:
                    raise
                await asyncio.sleep(min(backoff, self.backoff_max_ms) / 1000.0)
                backoff = min(int(backoff * 2), self.backoff_max_ms)

    # --------- Вспомогательное ---------
    def _sanitize_event(self, ev: Mapping[str, Any]) -> Mapping[str, Any]:
        if not self.redact_logs:
            return dict(ev)
        ev2 = json.loads(json.dumps(ev))  # глубокая копия простым способом
        # Редакция текстовых фрагментов
        if "delta" in ev2 and isinstance(ev2["delta"], dict):
            for k in ("text",):
                if k in ev2["delta"] and isinstance(ev2["delta"][k], str):
                    ev2["delta"][k] = redact_text(ev2["delta"][k])
        if "error" in ev2 and isinstance(ev2["error"], dict) and "message" in ev2["error"]:
            ev2["error"]["message"] = redact_text(str(ev2["error"]["message"]))
        return ev2

    def _log_event(self, kind: str, fields: Mapping[str, Any]) -> None:
        payload = {
            "ts": int(time.time()),
            "kind": kind,
            "request_id": get_request_id(),
            "trace_id": get_trace_id(),
            **fields,
        }
        if self.redact_logs:
            payload = json.loads(json.dumps(payload))
            for k in ("error", "message"):
                if k in payload and isinstance(payload[k], str):
                    payload[k] = redact_text(payload[k])
        self.log.emit(logging.INFO, payload)
