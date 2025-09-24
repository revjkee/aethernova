# physical-integration-core/physical_integration/twin/rules.py
from __future__ import annotations

import ast
import math
import statistics
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, time as dtime
from enum import Enum
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Protocol, Tuple

# --------------------------------------------------------------------------------------
# Модели домена
# --------------------------------------------------------------------------------------

class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class TelemetryEvent:
    tenant_id: uuid.UUID
    device_id: uuid.UUID
    ts_ns: int  # unix time ns
    data: Dict[str, Any]  # плоский или вложенный словарь с измерениями


@dataclass(frozen=True)
class Action:
    type: str  # "emit_event" | "set_twin" | "dispatch_command"
    params: Dict[str, Any]
    severity: Severity
    dedup_key: str  # уникален в пределах кулдауна


class ActionSink(Protocol):
    async def emit(self, action: Action) -> None: ...


class MetricSink(Protocol):
    def incr(self, name: str, value: float = 1.0, tags: Optional[Dict[str, str]] = None) -> None: ...
    def gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None: ...
    def timing_ms(self, name: str, ms: float, tags: Optional[Dict[str, str]] = None) -> None: ...


@dataclass
class WindowSpec:
    seconds: float = 60.0  # длительность окна, сек
    max_points: int = 10_000  # защита от утечек памяти


@dataclass
class Hysteresis:
    # Для порогов: вход/выход. Если задан clear_expr — он имеет приоритет.
    rise: Optional[float] = None  # порог входа
    fall: Optional[float] = None  # порог выхода


@dataclass
class Rule:
    id: uuid.UUID
    name: str
    version: str = "1.0.0"
    enabled: bool = True
    priority: int = 100  # меньше — важнее
    expr: str = ""       # булево выражение (AST-песочница)
    clear_expr: Optional[str] = None  # условие снятия (если требуется «залипание»)
    signal: Optional[str] = None  # имя ключа для гистерезиса (если используется rise/fall)
    hysteresis: Optional[Hysteresis] = None
    debounce_s: float = 0.0
    cooldown_s: float = 60.0
    suppress_windows: List[Tuple[str, str]] = field(default_factory=list)  # [("22:00","06:00")]
    window: WindowSpec = field(default_factory=lambda: WindowSpec(60.0))
    severity: Severity = Severity.WARNING
    actions: List[Dict[str, Any]] = field(default_factory=list)  # список ActionSpec'ов (dict)
    tags: Dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------------------
# Безопасный вычислитель выражений (AST sandbox)
# --------------------------------------------------------------------------------------

_ALLOWED_NODES = {
    ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.IfExp,
    ast.Compare, ast.Call, ast.Name, ast.Load, ast.Constant, ast.Subscript,
    ast.Attribute, ast.List, ast.Tuple, ast.Dict, ast.And, ast.Or,
    ast.Eq, ast.NotEq, ast.Gt, ast.GtE, ast.Lt, ast.LtE,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow, ast.USub, ast.UAdd,
}

# Разрешённые функции в выражениях
def _safe_max(*vals): return max(v for v in vals if v is not None)
def _safe_min(*vals): return min(v for v in vals if v is not None)
def _safe_abs(v): return abs(v) if v is not None else None

_ALLOWED_FUNCS = {
    "max": _safe_max,
    "min": _safe_min,
    "abs": _safe_abs,
    # Оконные функции будут инжектированы динамически: mean(), p95(), std(), ema(), roc(), last()
}

class UnsafeExpression(Exception): ...
class EvalError(Exception): ...


class _Expr:
    def __init__(self, expr: str) -> None:
        try:
            self._ast = ast.parse(expr, mode="eval")
        except SyntaxError as e:
            raise UnsafeExpression(f"syntax error: {e}") from e
        for node in ast.walk(self._ast):
            if type(node) not in _ALLOWED_NODES:
                raise UnsafeExpression(f"node {type(node).__name__} not allowed")

    def eval(self, env: Dict[str, Any]) -> Any:
        try:
            return eval(compile(self._ast, "<expr>", "eval"), {"__builtins__": {}}, env)
        except Exception as e:
            raise EvalError(str(e)) from e


# --------------------------------------------------------------------------------------
# Оконное хранение и агрегаты
# --------------------------------------------------------------------------------------

@dataclass
class _Series:
    # Очередь точек (ts_ns, value)
    q: Deque[Tuple[int, float]] = field(default_factory=deque)

    def push(self, ts_ns: int, v: float, horizon_ns: int, max_points: int) -> None:
        self.q.append((ts_ns, v))
        # обрезка по времени
        cutoff = ts_ns - horizon_ns
        while self.q and self.q[0][0] < cutoff:
            self.q.popleft()
        # обрезка по размеру
        while len(self.q) > max_points:
            self.q.popleft()

    def values(self) -> List[float]:
        return [v for _, v in self.q]

    def last(self) -> Optional[float]:
        return self.q[-1][1] if self.q else None

    def mean(self) -> Optional[float]:
        vals = self.values()
        return sum(vals) / len(vals) if vals else None

    def p95(self) -> Optional[float]:
        vals = sorted(self.values())
        if not vals:
            return None
        k = int(round(0.95 * (len(vals) - 1)))
        return vals[k]

    def std(self) -> Optional[float]:
        vals = self.values()
        if len(vals) < 2:
            return 0.0 if vals else None
        return statistics.pstdev(vals)

    def min(self) -> Optional[float]:
        vals = self.values()
        return min(vals) if vals else None

    def max(self) -> Optional[float]:
        vals = self.values()
        return max(vals) if vals else None

    def ema(self, alpha: float = 0.2) -> Optional[float]:
        vals = self.values()
        if not vals:
            return None
        ema_val = vals[0]
        for v in vals[1:]:
            ema_val = alpha * v + (1 - alpha) * ema_val
        return ema_val

    def roc(self) -> Optional[float]:
        # rate of change per second (approx)
        if len(self.q) < 2:
            return 0.0 if self.q else None
        t0, v0 = self.q[0]
        t1, v1 = self.q[-1]
        dt = max(1e-9, (t1 - t0) / 1e9)
        return (v1 - v0) / dt


class _WindowStore:
    """
    Пер-девайс хранилище тайм-серий по ключам сигналов.
    """
    def __init__(self, spec: WindowSpec) -> None:
        self.spec = spec
        self._series: Dict[str, _Series] = defaultdict(_Series)
        self._horizon_ns = int(spec.seconds * 1e9)

    def observe(self, ts_ns: int, data: Dict[str, Any]) -> None:
        # Извлекаем численные измерения первого уровня и flatten selected вложенности
        def iter_numeric(prefix: str, obj: Any) -> Iterable[Tuple[str, float]]:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    yield from iter_numeric(f"{prefix}{k}.", v)
            else:
                if isinstance(obj, (int, float)):
                    yield (prefix[:-1], float(obj))

        for key, val in iter_numeric("", data):
            self._series[key].push(ts_ns, val, self._horizon_ns, self.spec.max_points)

    # Доступ к агрегатам для безопасных выражений
    def api(self) -> Dict[str, Callable[..., Optional[float]]]:
        def _getter(func: Callable[[_Series], Optional[float]]) -> Callable[[str], Optional[float]]:
            def inner(signal: str) -> Optional[float]:
                return func(self._series.get(signal, _Series()))
            return inner

        return {
            "last": _getter(lambda s: s.last()),
            "mean": _getter(lambda s: s.mean()),
            "min":  _getter(lambda s: s.min()),
            "max":  _getter(lambda s: s.max()),
            "std":  _getter(lambda s: s.std()),
            "p95":  _getter(lambda s: s.p95()),
            # ema и roc могут принимать опциональные параметры
            "ema":  lambda signal, alpha=0.2: self._series.get(signal, _Series()).ema(alpha=float(alpha)),
            "roc":  lambda signal: self._series.get(signal, _Series()).roc(),
        }


# --------------------------------------------------------------------------------------
# Внутреннее состояние правил (пер девайс)
# --------------------------------------------------------------------------------------

@dataclass
class _RuleRuntime:
    last_true_since_ns: Optional[int] = None
    active: bool = False
    last_fire_ns: int = 0


# --------------------------------------------------------------------------------------
# Движок правил
# --------------------------------------------------------------------------------------

class RulesEngine:
    def __init__(self, sink: ActionSink, metrics: Optional[MetricSink] = None) -> None:
        self._rules: List[Rule] = []
        self._sink = sink
        self._metrics = metrics
        self._windows: Dict[uuid.UUID, _WindowStore] = {}  # per device
        self._rt: Dict[Tuple[uuid.UUID, uuid.UUID], _RuleRuntime] = {}  # (device_id, rule_id) -> runtime
        self._compiled: Dict[uuid.UUID, _Expr] = {}
        self._compiled_clear: Dict[uuid.UUID, _Expr] = {}

    # Управление правилами
    def add_rule(self, rule: Rule) -> None:
        self._rules.append(rule)
        self._rules.sort(key=lambda r: (r.priority, r.name))
        self._compiled[rule.id] = _Expr(rule.expr) if rule.expr else _Expr("False")
        if rule.clear_expr:
            self._compiled_clear[rule.id] = _Expr(rule.clear_expr)

    def clear_rules(self) -> None:
        self._rules.clear()
        self._compiled.clear()
        self._compiled_clear.clear()

    # Основной метод
    async def process(self, event: TelemetryEvent) -> List[Action]:
        t0 = time.time()
        store = self._windows.setdefault(event.device_id, _WindowStore(WindowSpec()))  # default 60s
        # Подменяем spec на max из правил для этого устройства (чтобы покрыть длинные окна)
        max_win = max((r.window.seconds for r in self._rules if r.enabled), default=60.0)
        if store.spec.seconds < max_win:
            self._windows[event.device_id] = store = _WindowStore(WindowSpec(seconds=max_win, max_points=store.spec.max_points))

        store.observe(event.ts_ns, event.data)

        actions: List[Action] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            if not self._within_schedule(rule, event.ts_ns):
                continue
            rt = self._rt.setdefault((event.device_id, rule.id), _RuleRuntime())
            fired = await self._evaluate_rule(rule, event, store, rt)
            if fired:
                act = self._build_action(rule, event)
                actions.append(act)
                await self._sink.emit(act)

        if self._metrics:
            self._metrics.timing_ms("twin.rules.process_ms", (time.time() - t0) * 1000.0)
        return actions

    # Оценка одного правила
    async def _evaluate_rule(self, rule: Rule, ev: TelemetryEvent, store: _WindowStore, rt: _RuleRuntime) -> bool:
        now_ns = ev.ts_ns
        env = self._build_env(ev, store)
        cond = bool(self._compiled[rule.id].eval(env))

        # Гистерезис/clear
        if rule.clear_expr:
            clear = bool(self._compiled_clear[rule.id].eval(env))
            if rt.active and clear:
                rt.active = False
                rt.last_true_since_ns = None
            # если активен clear, не запрещаем новое срабатывание при cond True — пойдёт по дебаунсу
        elif rule.hysteresis and rule.signal:
            last_val = store.api()["last"](rule.signal)
            if last_val is not None:
                if not rt.active:
                    # вход
                    if rule.hysteresis.rise is not None and last_val >= rule.hysteresis.rise:
                        cond = True
                else:
                    # выход
                    if rule.hysteresis.fall is not None and last_val <= rule.hysteresis.fall:
                        # Снятие
                        rt.active = False
                        rt.last_true_since_ns = None
                    else:
                        # удержание активного состояния
                        cond = True

        # Дебаунс
        if cond:
            if rt.last_true_since_ns is None:
                rt.last_true_since_ns = now_ns
            dur_s = (now_ns - rt.last_true_since_ns) / 1e9
            if dur_s < rule.debounce_s:
                return False
        else:
            rt.last_true_since_ns = None
            return False

        # Кулдаун
        if (now_ns - rt.last_fire_ns) < int(rule.cooldown_s * 1e9):
            return False

        # Активируем и фиксируем время
        rt.active = True
        rt.last_fire_ns = now_ns
        return True

    def _build_env(self, ev: TelemetryEvent, store: _WindowStore) -> Dict[str, Any]:
        # плоский доступ к данным события через e["path.to.key"]
        e = self._flatten(ev.data)

        env: Dict[str, Any] = {"e": e}
        env.update(_ALLOWED_FUNCS)
        env.update(store.api())
        # Доп. константы
        env["ts_ns"] = ev.ts_ns
        env["ts_sec"] = ev.ts_ns / 1e9
        return env

    @staticmethod
    def _flatten(obj: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
            if isinstance(v, dict):
                out.update(RulesEngine._flatten(v, key))
            else:
                out[key] = v
        return out

    @staticmethod
    def _within_schedule(rule: Rule, ts_ns: int) -> bool:
        if not rule.suppress_windows:
            return True
        dt = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).timetz()
        for s, e in rule.suppress_windows:
            t_s = _parse_time(s)
            t_e = _parse_time(e)
            if _time_in_window(dt, t_s, t_e):
                return False
        return True

    def _build_action(self, rule: Rule, ev: TelemetryEvent) -> Action:
        # Идемпотентный ключ на базе кулдауна
        bucket = int((ev.ts_ns / 1e9) // max(1.0, rule.cooldown_s))
        dedup_key = f"{rule.id}:{ev.device_id}:{bucket}"
        # Пример: берём первый ActionSpec, остальные могут применяться внешним обработчиком
        spec = rule.actions[0] if rule.actions else {"type": "emit_event", "params": {"topic": "twin/alert"}}
        params = dict(spec.get("params", {}))
        # Подмешаем контекст
        params.update({
            "rule_id": str(rule.id), "rule_name": rule.name, "severity": rule.severity.value,
            "device_id": str(ev.device_id), "tenant_id": str(ev.tenant_id),
            "ts": datetime.fromtimestamp(ev.ts_ns / 1e9, tz=timezone.utc).isoformat(),
        })
        return Action(type=spec.get("type", "emit_event"), params=params, severity=rule.severity, dedup_key=dedup_key)


# --------------------------------------------------------------------------------------
# Вспомогательные функции времени
# --------------------------------------------------------------------------------------

def _parse_time(s: str) -> dtime:
    hh, mm = s.split(":")
    return dtime(hour=int(hh), minute=int(mm), tzinfo=timezone.utc)

def _time_in_window(t: dtime, start: dtime, end: dtime) -> bool:
    if start <= end:
        return start <= t <= end
    # окно через полночь
    return t >= start or t <= end


# --------------------------------------------------------------------------------------
# Пример «синков» по умолчанию
# --------------------------------------------------------------------------------------

class LoggingSink(ActionSink):
    async def emit(self, action: Action) -> None:
        # Лёгкий логгер; в проде замените на Kafka/NATS/HTTP и т.д.
        print(f"ACTION {action.type} dedup={action.dedup_key} params={action.params}")

class NullMetrics(MetricSink):
    def incr(self, name: str, value: float = 1.0, tags: Optional[Dict[str, str]] = None) -> None: ...
    def gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None: ...
    def timing_ms(self, name: str, ms: float, tags: Optional[Dict[str, str]] = None) -> None: ...


# --------------------------------------------------------------------------------------
# Пример использования (комментарий)
# --------------------------------------------------------------------------------------
#
# async def example():
#     engine = RulesEngine(sink=LoggingSink(), metrics=NullMetrics())
#     rule = Rule(
#         id=uuid.uuid4(),
#         name="Overheat with hysteresis",
#         priority=10,
#         expr="mean('sensor.temp',) is not None and mean('sensor.temp') > 85 or roc('sensor.temp') > 5",
#         signal="sensor.temp",
#         hysteresis=Hysteresis(rise=85.0, fall=80.0),
#         debounce_s=5.0,
#         cooldown_s=60.0,
#         suppress_windows=[("22:00","06:00")],
#         window=WindowSpec(seconds=120.0),
#         severity=Severity.CRITICAL,
#         actions=[{"type": "emit_event", "params": {"topic": "twin/alerts/overheat"}}],
#     )
#     engine.add_rule(rule)
#
#     ev = TelemetryEvent(tenant_id=uuid.uuid4(), device_id=uuid.uuid4(), ts_ns=time.time_ns(),
#                         data={"sensor": {"temp": 86.5}})
#     await engine.process(ev)
#
# Примечания:
#  - В выражениях доступны: e['path.to.key'], last('signal'), mean/min/max/std/p95('signal'),
#    ema('signal', alpha=0.2), roc('signal'), а также min/max/abs.
#  - Для устойчивости используйте debounce_s и cooldown_s.
#  - Для «залипания» условия (до separate clear) задайте clear_expr или hysteresis.
