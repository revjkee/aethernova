# neuroforge-core/neuroforge/prompts/tools.py
from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import json
import os
import random
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, Union

# =========================
# Метрики (абстракция)
# =========================

class MetricsSink(Protocol):
    async def inc(self, name: str, labels: Mapping[str, str], value: float = 1.0) -> None: ...
    async def observe(self, name: str, labels: Mapping[str, str], value: float) -> None: ...

class NoopMetrics(MetricsSink):
    async def inc(self, name: str, labels: Mapping[str, str], value: float = 1.0) -> None:
        return
    async def observe(self, name: str, labels: Mapping[str, str], value: float) -> None:
        return


# =========================
# Стандартизованные ошибки
# =========================

class ToolError(RuntimeError):
    def __init__(self, code: str, message: str, *, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message, "details": self.details}


# =========================
# Контекст выполнения
# =========================

@dataclass(frozen=True)
class ToolContext:
    user_id: str
    session_id: str
    request_id: str
    correlation_id: str
    locale: str = "en_US"
    timezone: str = "UTC"
    now_ts: float = field(default_factory=lambda: time.time())
    deadline_ts: Optional[float] = None
    extra: Dict[str, Any] = field(default_factory=dict)


# =========================
# Спецификация инструмента
# =========================

@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters_schema: Dict[str, Any]
    timeout_seconds: float = 10.0
    cache_ttl_seconds: float = 0.0
    rate_limit_per_sec: float = 50.0
    rate_burst: int = 200
    circuit_fail_threshold: int = 20
    circuit_reset_seconds: float = 30.0
    deterministic: bool = True


class Tool(Protocol):
    def spec(self) -> ToolSpec: ...
    async def run(self, args: Dict[str, Any], ctx: ToolContext) -> Any: ...


# =========================
# Вспомогательные компоненты
# =========================

def _canonicalize(obj: Any) -> str:
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        # на крайний случай — str
        return str(obj)


class _TTLCache:
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            ent = self._data.get(key)
            if not ent:
                return None
            exp, val = ent
            if exp < time.time():
                self._data.pop(key, None)
                return None
            return val

    async def put(self, key: str, value: Any, ttl: float) -> None:
        async with self._lock:
            self._data[key] = (time.time() + ttl, value)


class _TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = float(max(rate_per_sec, 0.0))
        self.capacity = float(max(burst, 1))
        self.tokens = self.capacity
        self.ts = time.time()
        self._lock = asyncio.Lock()

    async def allow(self) -> bool:
        async with self._lock:
            now = time.time()
            elapsed = max(0.0, now - self.ts)
            self.ts = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


class _CircuitBreaker:
    def __init__(self, fail_threshold: int, reset_seconds: float) -> None:
        self.fail_threshold = max(1, fail_threshold)
        self.reset_seconds = max(1.0, reset_seconds)
        self.fail_count = 0
        self.opened_at: Optional[float] = None
        self._lock = asyncio.Lock()

    async def on_call(self) -> None:
        async with self._lock:
            if self.opened_at is not None:
                if (time.time() - self.opened_at) >= self.reset_seconds:
                    # half-open
                    self.fail_count = 0
                    self.opened_at = None
                else:
                    raise ToolError("circuit_open", "circuit breaker is open")

    async def on_result(self, ok: bool) -> None:
        async with self._lock:
            if ok:
                self.fail_count = 0
                self.opened_at = None
            else:
                self.fail_count += 1
                if self.fail_count >= self.fail_threshold:
                    self.opened_at = time.time()


# =========================
# Результат выполнения
# =========================

@dataclass
class ToolResult:
    name: str
    ok: bool
    duration_ms: float
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None


# =========================
# Реестр инструментов и рантайм
# =========================

class ToolRegistry:
    """
    Реестр инструментов + безопасный рантайм исполнения с метриками, rate-limit, кэшем и circuit breaker.
    """
    def __init__(self, *, metrics: Optional[MetricsSink] = None) -> None:
        self._metrics = metrics or NoopMetrics()
        self._tools: Dict[str, Tool] = {}
        self._buckets: Dict[str, _TokenBucket] = {}
        self._circuits: Dict[str, _CircuitBreaker] = {}
        self._cache = _TTLCache()
        self._lock = asyncio.Lock()

    async def register(self, tool: Tool) -> None:
        spec = tool.spec()
        async with self._lock:
            if spec.name in self._tools:
                raise ValueError(f"tool already registered: {spec.name}")
            self._tools[spec.name] = tool
            self._buckets[spec.name] = _TokenBucket(spec.rate_limit_per_sec, spec.rate_burst)
            self._circuits[spec.name] = _CircuitBreaker(spec.circuit_fail_threshold, spec.circuit_reset_seconds)

    def specs(self) -> List[ToolSpec]:
        return [t.spec() for t in self._tools.values()]

    def to_openai_tools(self) -> List[Dict[str, Any]]:
        """
        Экспорт в формат OpenAI function calling.
        """
        out: List[Dict[str, Any]] = []
        for t in self._tools.values():
            spec = t.spec()
            out.append({
                "type": "function",
                "function": {
                    "name": spec.name,
                    "description": spec.description,
                    "parameters": spec.parameters_schema,
                },
            })
        return out

    async def execute(self, name: str, args: Dict[str, Any], ctx: ToolContext) -> ToolResult:
        tool = self._tools.get(name)
        if not tool:
            raise ToolError("not_found", f"tool not found: {name}")

        spec = tool.spec()
        labels = {"tool": spec.name}

        # дедлайн на уровне контекста
        if ctx.deadline_ts and time.time() > ctx.deadline_ts:
            raise ToolError("deadline_exceeded", "context deadline exceeded")

        # rate-limit
        bucket = self._buckets[name]
        allowed = await bucket.allow()
        if not allowed:
            await self._metrics.inc("tool_rl_dropped_total", labels)
            raise ToolError("rate_limited", "rate limit exceeded")

        # circuit breaker
        circuit = self._circuits[name]
        await circuit.on_call()

        # кэш
        cache_key = ""
        if spec.cache_ttl_seconds > 0 and spec.deterministic:
            cache_key = f"{name}|{_canonicalize(args)}"
            cached = await self._cache.get(cache_key)
            if cached is not None:
                await self._metrics.inc("tool_cache_hit_total", labels)
                return ToolResult(name=name, ok=True, duration_ms=0.0, result=cached)

        await self._metrics.inc("tool_calls_started_total", labels)
        t0 = time.perf_counter()
        ok = False
        try:
            res = await asyncio.wait_for(tool.run(args, ctx), timeout=spec.timeout_seconds)
            ok = True
            if spec.cache_ttl_seconds > 0 and spec.deterministic:
                await self._cache.put(cache_key, res, spec.cache_ttl_seconds)
            dur = (time.perf_counter() - t0) * 1000.0
            await self._metrics.observe("tool_call_latency_ms", labels, dur)
            await self._metrics.inc("tool_calls_success_total", labels)
            await circuit.on_result(True)
            return ToolResult(name=name, ok=True, duration_ms=dur, result=res)
        except asyncio.TimeoutError:
            await self._metrics.inc("tool_calls_timeout_total", labels)
            await circuit.on_result(False)
            raise ToolError("timeout", f"tool '{name}' timed out after {spec.timeout_seconds}s")
        except ToolError as te:
            await self._metrics.inc("tool_calls_error_total", {**labels, "code": te.code})
            await circuit.on_result(False)
            return ToolResult(name=name, ok=False, duration_ms=(time.perf_counter() - t0) * 1000.0, error=te.to_dict())
        except Exception as e:
            await self._metrics.inc("tool_calls_error_total", {**labels, "code": "internal"})
            await circuit.on_result(False)
            return ToolResult(
                name=name,
                ok=False,
                duration_ms=(time.perf_counter() - t0) * 1000.0,
                error=ToolError("internal", "unhandled exception", details={"type": type(e).__name__}).to_dict(),
            )


# =========================
# Безопасная арифметика (AST)
# =========================

import ast

class _SafeMath(ast.NodeVisitor):
    ALLOWED_NODES = {
        ast.Expression, ast.BinOp, ast.UnaryOp, ast.Num, ast.Load,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow, ast.USub, ast.UAdd,
        ast.FloorDiv, ast.Constant, ast.Call, ast.Name,
    }
    ALLOWED_FUNCS = {"abs": abs, "round": round, "min": min, "max": max}
    MAX_DEPTH = 12
    MAX_NODES = 64
    MAX_ABS = 1e100

    def __init__(self) -> None:
        self.node_count = 0
        self.depth = 0

    def generic_visit(self, node):
        self.node_count += 1
        if self.node_count > self.MAX_NODES:
            raise ToolError("math_too_complex", "expression too complex")
        if type(node) not in self.ALLOWED_NODES:
            raise ToolError("math_forbidden", f"node not allowed: {type(node).__name__}")
        self.depth += 1
        if self.depth > self.MAX_DEPTH:
            raise ToolError("math_too_deep", "expression too deep")
        super().generic_visit(node)
        self.depth -= 1

    def eval(self, expr: str) -> float:
        try:
            tree = ast.parse(expr, mode="eval")
        except SyntaxError:
            raise ToolError("math_syntax", "invalid expression syntax")
        self.visit(tree)
        return self._eval_node(tree.body)

    def _eval_node(self, node) -> float:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)):
                return float(node.value)
            raise ToolError("math_bad_const", "only numbers are allowed")
        if isinstance(node, ast.BinOp):
            l = self._eval_node(node.left)
            r = self._eval_node(node.right)
            if isinstance(node.op, ast.Add):
                v = l + r
            elif isinstance(node.op, ast.Sub):
                v = l - r
            elif isinstance(node.op, ast.Mult):
                v = l * r
            elif isinstance(node.op, ast.Div):
                if r == 0:
                    raise ToolError("math_div_zero", "division by zero")
                v = l / r
            elif isinstance(node.op, ast.FloorDiv):
                if r == 0:
                    raise ToolError("math_div_zero", "division by zero")
                v = l // r
            elif isinstance(node.op, ast.Mod):
                if r == 0:
                    raise ToolError("math_div_zero", "division by zero")
                v = l % r
            elif isinstance(node.op, ast.Pow):
                # ограничим степень
                if abs(r) > 20 or abs(l) > 1e6:
                    raise ToolError("math_pow_limit", "exponent out of allowed range")
                v = l ** r
            else:
                raise ToolError("math_op_unsupported", "unsupported operator")
            if not self._is_finite(v):
                raise ToolError("math_overflow", "numeric overflow")
            return float(v)
        if isinstance(node, ast.UnaryOp):
            v = self._eval_node(node.operand)
            if isinstance(node.op, ast.UAdd):
                return +v
            if isinstance(node.op, ast.USub):
                return -v
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in self.ALLOWED_FUNCS:
                args = [self._eval_node(a) for a in node.args]
                v = self.ALLOWED_FUNCS[node.func.id](*args)
                if not self._is_finite(v):
                    raise ToolError("math_overflow", "numeric overflow")
                return float(v)
            raise ToolError("math_func_forbidden", "function not allowed")
        raise ToolError("math_node_unsupported", "unsupported expression")

    def _is_finite(self, v: float) -> bool:
        try:
            return -self.MAX_ABS <= v <= self.MAX_ABS
        except Exception:
            return False


# =========================
# Встроенные инструменты
# =========================

class TimeTool(Tool):
    def __init__(self) -> None:
        self._spec = ToolSpec(
            name="time_now",
            description="Возвращает текущее время и преобразование в заданный часовой пояс (без внешних зависимостей).",
            parameters_schema={
                "type": "object",
                "properties": {
                    "tz": {"type": "string", "description": "Часовой пояс IANA или 'UTC'. Пример: 'UTC'."},
                    "format": {"type": "string", "description": "Формат ISO8601|epoch", "enum": ["ISO8601", "epoch"]},
                },
                "required": [],
                "additionalProperties": False,
            },
            timeout_seconds=0.1,
            cache_ttl_seconds=0.5,
            deterministic=False,
        )

    def spec(self) -> ToolSpec:
        return self._spec

    async def run(self, args: Dict[str, Any], ctx: ToolContext) -> Any:
        fmt = args.get("format", "ISO8601")
        # Простой UTC: без локальных зависимостей tzdb
        now = time.time()
        if fmt == "epoch":
            return {"epoch": now, "tz": "UTC"}
        # ISO8601 UTC
        import datetime as _dt
        return {"iso8601": _dt.datetime.utcfromtimestamp(now).replace(tzinfo=_dt.timezone.utc).isoformat(), "tz": "UTC"}


class MathTool(Tool):
    def __init__(self) -> None:
        self._spec = ToolSpec(
            name="math_eval",
            description="Безопасная арифметика над вещественными/целыми (AST-ограничения, без побочных эффектов).",
            parameters_schema={
                "type": "object",
                "properties": {
                    "expr": {"type": "string", "minLength": 1, "description": "Арифметическое выражение, например '2*(3+4)'."}
                },
                "required": ["expr"],
                "additionalProperties": False,
            },
            timeout_seconds=0.2,
            cache_ttl_seconds=60.0,
            deterministic=True,
        )
        self._engine = _SafeMath()

    def spec(self) -> ToolSpec:
        return self._spec

    async def run(self, args: Dict[str, Any], ctx: ToolContext) -> Any:
        expr = str(args.get("expr", "")).strip()
        if not expr:
            raise ToolError("bad_request", "expr is required")
        return {"value": self._engine.eval(expr)}


class UuidTool(Tool):
    def __init__(self) -> None:
        self._spec = ToolSpec(
            name="uuid_generate",
            description="Генерация UUIDv4. Можно запросить n штук.",
            parameters_schema={
                "type": "object",
                "properties": {"n": {"type": "integer", "minimum": 1, "maximum": 100}},
                "required": [],
                "additionalProperties": False,
            },
            timeout_seconds=0.05,
            cache_ttl_seconds=0.0,
            deterministic=False,
        )

    def spec(self) -> ToolSpec:
        return self._spec

    async def run(self, args: Dict[str, Any], ctx: ToolContext) -> Any:
        n = int(args.get("n", 1))
        return {"uuids": [str(uuid.uuid4()) for _ in range(n)]}


class RandomChoiceTool(Tool):
    def __init__(self) -> None:
        self._spec = ToolSpec(
            name="random_choice",
            description="Псевдослучайный выбор элемента/подмножества из списка (опционально с seed).",
            parameters_schema={
                "type": "object",
                "properties": {
                    "items": {"type": "array", "items": {}, "minItems": 1},
                    "k": {"type": "integer", "minimum": 1},
                    "seed": {"type": "integer"},
                },
                "required": ["items"],
                "additionalProperties": False,
            },
            timeout_seconds=0.05,
            cache_ttl_seconds=0.0,
            deterministic=False,
        )

    def spec(self) -> ToolSpec:
        return self._spec

    async def run(self, args: Dict[str, Any], ctx: ToolContext) -> Any:
        items = list(args["items"])
        k = int(args.get("k", 1))
        if k < 1 or k > len(items):
            raise ToolError("bad_request", "k must be between 1 and len(items)")
        rnd = random.Random(args.get("seed"))
        return {"items": rnd.sample(items, k)}


class Base64Tool(Tool):
    def __init__(self) -> None:
        self._spec = ToolSpec(
            name="base64",
            description="Кодирование/декодирование base64 для текстов (UTF-8).",
            parameters_schema={
                "type": "object",
                "properties": {
                    "mode": {"type": "string", "enum": ["encode", "decode"]},
                    "text": {"type": "string", "minLength": 0},
                },
                "required": ["mode", "text"],
                "additionalProperties": False,
            },
            timeout_seconds=0.05,
            cache_ttl_seconds=300.0,
            deterministic=True,
        )

    def spec(self) -> ToolSpec:
        return self._spec

    async def run(self, args: Dict[str, Any], ctx: ToolContext) -> Any:
        mode = args["mode"]
        text = args["text"]
        if mode == "encode":
            return {"base64": base64.b64encode(text.encode("utf-8")).decode("ascii")}
        else:
            try:
                return {"text": base64.b64decode(text.encode("ascii"), validate=True).decode("utf-8")}
            except Exception:
                raise ToolError("invalid_base64", "invalid base64 payload")


class HashTool(Tool):
    def __init__(self) -> None:
        self._spec = ToolSpec(
            name="hash",
            description="Подсчет хешей строки (sha256|md5).",
            parameters_schema={
                "type": "object",
                "properties": {
                    "algo": {"type": "string", "enum": ["sha256", "md5"]},
                    "text": {"type": "string"},
                },
                "required": ["algo", "text"],
                "additionalProperties": False,
            },
            timeout_seconds=0.05,
            cache_ttl_seconds=600.0,
            deterministic=True,
        )

    def spec(self) -> ToolSpec:
        return self._spec

    async def run(self, args: Dict[str, Any], ctx: ToolContext) -> Any:
        algo = args["algo"]
        text = args["text"].encode("utf-8")
        if algo == "sha256":
            return {"sha256": hashlib.sha256(text).hexdigest()}
        else:
            return {"md5": hashlib.md5(text).hexdigest()}


class RegexExtractTool(Tool):
    def __init__(self) -> None:
        self._spec = ToolSpec(
            name="regex_extract",
            description="Извлечение совпадений по регулярному выражению (без флагов DOTALL/многострочного по умолчанию).",
            parameters_schema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "minLength": 1},
                    "text": {"type": "string", "minLength": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                },
                "required": ["pattern", "text"],
                "additionalProperties": False,
            },
            timeout_seconds=0.1,
            cache_ttl_seconds=120.0,
            deterministic=True,
        )

    def spec(self) -> ToolSpec:
        return self._spec

    async def run(self, args: Dict[str, Any], ctx: ToolContext) -> Any:
        pat = args["pattern"]
        txt = args["text"]
        limit = int(args.get("limit", 50))
        try:
            rgx = re.compile(pat)
        except re.error as e:
            raise ToolError("regex_invalid", f"invalid regex: {e}")
        out: List[str] = []
        for m in rgx.finditer(txt):
            out.append(m.group(0))
            if len(out) >= limit:
                break
        return {"matches": out}


# =========================
# Комплект по умолчанию
# =========================

async def default_tool_registry(metrics: Optional[MetricsSink] = None) -> ToolRegistry:
    reg = ToolRegistry(metrics=metrics)
    for t in (TimeTool(), MathTool(), UuidTool(), RandomChoiceTool(), Base64Tool(), HashTool(), RegexExtractTool()):
        await reg.register(t)
    return reg


# =========================
# Док-пример
# =========================
"""
Пример использования:

    async def main():
        registry = await default_tool_registry()
        ctx = ToolContext(
            user_id="u1", session_id="s1", request_id="r1", correlation_id="c1",
            locale="ru_RU", timezone="UTC", deadline_ts=time.time()+2
        )

        # Экспорт спецификаций для LLM
        tools = registry.to_openai_tools()

        # Вызов инструмента
        res = await registry.execute("math_eval", {"expr": "2*(3+4)"}, ctx)
        if res.ok:
            print(res.result)  # {'value': 14.0}
        else:
            print("error", res.error)

    # asyncio.run(main())
"""
__all__ = [
    "Tool", "ToolSpec", "ToolContext", "ToolError", "ToolResult",
    "ToolRegistry", "default_tool_registry",
    "MetricsSink", "NoopMetrics",
    "TimeTool", "MathTool", "UuidTool", "RandomChoiceTool", "Base64Tool", "HashTool", "RegexExtractTool",
]
