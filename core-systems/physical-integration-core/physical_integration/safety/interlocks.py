# physical_integration/safety/interlocks.py
from __future__ import annotations

import asyncio
import time
import math
import uuid
import ast
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Literal, Set

__all__ = [
    "SignalSample", "InputSnapshot", "InputProvider", "Actuator", "EventSink", "KVStore",
    "Metrics", "NullMetrics",
    "ConditionResult", "Condition", "BoolIs", "Threshold", "Hysteresis",
    "Staleness", "RateOfChange", "TrueForWindow", "Edge", "Expr",
    "MooN", "InterlockConfig", "InterlockState", "InterlockEngine",
    "BypassToken", "PermissionDenied", "GuardDecision"
]

# ======================================================
# Базовые интерфейсы и типы
# ======================================================

@dataclass
class SignalSample:
    value: Any
    ts_ms: int  # эпоха, миллисекунды

class InputProvider:
    async def read(self, names: Set[str]) -> Dict[str, SignalSample]:
        """
        Возвращает сэмплы для запрошенных имен.
        Обязан возвращать только то, что есть; отсутствующие ключи считаются неизвестными (fail-safe).
        """
        raise NotImplementedError

class Actuator:
    async def safe_shutdown(self, reason: str, details: Dict[str, Any] | None = None) -> None:
        """Перевести систему в безопасное состояние. Должно быть идемпотентным."""
        raise NotImplementedError
    async def notify(self, title: str, payload: Dict[str, Any]) -> None:
        """Ненавязчивые уведомления (события, алерты). Не должно бросать исключения наружу."""
        return

class EventSink:
    async def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        raise NotImplementedError

class KVStore:
    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError
    async def set(self, key: str, value: Dict[str, Any]) -> None:
        raise NotImplementedError
    async def delete(self, key: str) -> None:
        raise NotImplementedError

class Metrics:
    def inc(self, name: str, **labels): ...
    def observe(self, name: str, value: float, **labels): ...
    def gauge(self, name: str, value: float, **labels): ...

class NullMetrics(Metrics):
    def inc(self, name: str, **labels): pass
    def observe(self, name: str, value: float, **labels): pass
    def gauge(self, name: str, value: float, **labels): pass

# ======================================================
# Снимок входов, безопасные get/prev
# ======================================================

@dataclass
class InputSnapshot:
    now_ms: int
    samples: Dict[str, SignalSample] = field(default_factory=dict)
    prev: Optional["InputSnapshot"] = None

    def has(self, name: str) -> bool:
        return name in self.samples

    def get(self, name: str, default: Any = None) -> Any:
        s = self.samples.get(name)
        return s.value if s is not None else default

    def age_ms(self, name: str) -> Optional[int]:
        s = self.samples.get(name)
        if s is None: return None
        return max(0, self.now_ms - s.ts_ms)

# ======================================================
# Результаты условий
# ======================================================

@dataclass
class ConditionResult:
    ok: bool
    reasons: List[str] = field(default_factory=list)

    @staticmethod
    def pass_() -> "ConditionResult":
        return ConditionResult(True, [])
    @staticmethod
    def fail(reason: str) -> "ConditionResult":
        return ConditionResult(False, [reason])
    def and_(self, other: "ConditionResult") -> "ConditionResult":
        return ConditionResult(self.ok and other.ok, ([] if self.ok and other.ok else self.reasons + other.reasons))

class Condition:
    name: str
    def required_signals(self) -> Set[str]: return set()
    async def evaluate(self, snap: InputSnapshot) -> ConditionResult: raise NotImplementedError

# ======================================================
# Предикаты
# ======================================================

@dataclass
class BoolIs(Condition):
    name: str
    expected: bool = True
    def required_signals(self) -> Set[str]: return {self.name}
    async def evaluate(self, snap: InputSnapshot) -> ConditionResult:
        if not snap.has(self.name): return ConditionResult.fail(f"{self.name} unknown")
        return ConditionResult.pass_() if bool(snap.get(self.name)) == self.expected else ConditionResult.fail(f"{self.name}={snap.get(self.name)} != {self.expected}")

@dataclass
class Threshold(Condition):
    name: str
    op: Literal[">",">=","<","<=","==","!="] = "<="
    value: float = 0.0
    def required_signals(self) -> Set[str]: return {self.name}
    async def evaluate(self, snap: InputSnapshot) -> ConditionResult:
        if not snap.has(self.name): return ConditionResult.fail(f"{self.name} unknown")
        v = snap.get(self.name)
        ok = {
            ">": v > self.value,
            ">=": v >= self.value,
            "<": v < self.value,
            "<=": v <= self.value,
            "==": v == self.value,
            "!=": v != self.value,
        }[self.op]
        return ConditionResult.pass_() if ok else ConditionResult.fail(f"{self.name}{self.op}{self.value} failed (v={v})")

@dataclass
class Hysteresis(Condition):
    """Порог с гистерезисом. Сохранение последнего состояния в self._state."""
    name: str
    low: float
    high: float
    initial_ok: bool = True
    _state_ok: Optional[bool] = field(default=None, init=False, repr=False)
    def required_signals(self) -> Set[str]: return {self.name}
    async def evaluate(self, snap: InputSnapshot) -> ConditionResult:
        if not snap.has(self.name): return ConditionResult.fail(f"{self.name} unknown")
        v = float(snap.get(self.name))
        if self._state_ok is None: self._state_ok = self.initial_ok
        if self._state_ok and v > self.high: self._state_ok = False
        elif not self._state_ok and v < self.low: self._state_ok = True
        return ConditionResult.pass_() if self._state_ok else ConditionResult.fail(f"{self.name} hysteresis not ok (v={v})")

@dataclass
class Staleness(Condition):
    """Устаревание сигнала (fail при age_ms > max_age_ms)."""
    name: str
    max_age_ms: int
    def required_signals(self) -> Set[str]: return {self.name}
    async def evaluate(self, snap: InputSnapshot) -> ConditionResult:
        age = snap.age_ms(self.name)
        if age is None: return ConditionResult.fail(f"{self.name} unknown")
        return ConditionResult.pass_() if age <= self.max_age_ms else ConditionResult.fail(f"{self.name} stale {age}ms>{self.max_age_ms}ms")

@dataclass
class RateOfChange(Condition):
    """Модуль производной не должен превышать max_abs_per_s."""
    name: str
    max_abs_per_s: float
    def required_signals(self) -> Set[str]: return {self.name}
    async def evaluate(self, snap: InputSnapshot) -> ConditionResult:
        if not snap.prev or not snap.prev.has(self.name) or not snap.has(self.name):
            return ConditionResult.fail(f"{self.name} derivative unknown")
        v0 = float(snap.prev.get(self.name)); t0 = snap.prev.now_ms
        v1 = float(snap.get(self.name)); t1 = snap.now_ms
        dt = max(1e-3, (t1 - t0)/1000.0)
        rate = abs((v1 - v0)/dt)
        return ConditionResult.pass_() if rate <= self.max_abs_per_s else ConditionResult.fail(f"{self.name} roc {rate:.3f}>{self.max_abs_per_s}")

@dataclass
class TrueForWindow(Condition):
    """Булев сигнал должен быть True непрерывно не менее duration_ms."""
    name: str
    duration_ms: int
    _since_ms: Optional[int] = field(default=None, init=False, repr=False)
    def required_signals(self) -> Set[str]: return {self.name}
    async def evaluate(self, snap: InputSnapshot) -> ConditionResult:
        if not snap.has(self.name): return ConditionResult.fail(f"{self.name} unknown")
        val = bool(snap.get(self.name))
        if val:
            if self._since_ms is None: self._since_ms = snap.now_ms
            ok = (snap.now_ms - self._since_ms) >= self.duration_ms
            return ConditionResult.pass_() if ok else ConditionResult.fail(f"{self.name} true for {(snap.now_ms - self._since_ms)}ms<{self.duration_ms}ms")
        else:
            self._since_ms = None
            return ConditionResult.fail(f"{self.name} is False")

@dataclass
class Edge(Condition):
    """Детекция фронта: rising/falling (использует prev снапшот)."""
    name: str
    kind: Literal["rising","falling"] = "rising"
    def required_signals(self) -> Set[str]: return {self.name}
    async def evaluate(self, snap: InputSnapshot) -> ConditionResult:
        if not snap.prev: return ConditionResult.fail("no prev snapshot")
        if not (snap.has(self.name) and snap.prev.has(self.name)): return ConditionResult.fail(f"{self.name} unknown")
        prev = bool(snap.prev.get(self.name)); cur = bool(snap.get(self.name))
        ok = (not prev and cur) if self.kind=="rising" else (prev and not cur)
        return ConditionResult.pass_() if ok else ConditionResult.fail(f"{self.name} no {self.kind} edge")

# Безопасные выражения: доступ к переменным через snap.get("<name>")
_ALLOWED_AST = {
    ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.Compare, ast.Name, ast.Load,
    ast.And, ast.Or, ast.Not, ast.USub, ast.UAdd,
    ast.Gt, ast.GtE, ast.Lt, ast.LtE, ast.Eq, ast.NotEq,
    ast.Num, ast.Constant, ast.Call, ast.Attribute
}

def _safe_eval_bool_expr(expr: str, snap: InputSnapshot) -> bool:
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        if type(node) not in _ALLOWED_AST:
            raise ValueError(f"disallowed syntax: {type(node).__name__}")
        if isinstance(node, ast.Call):
            # разрешаем только snap.get("name") и snap.age_ms("name")
            if not isinstance(node.func, ast.Attribute): raise ValueError("only attribute calls allowed")
            if node.func.attr not in ("get","age_ms"): raise ValueError("only snap.get/age_ms allowed")
    env = {"snap": snap, "math": math}  # math не используется в AST whitelist, но оставим для совместимости
    return bool(eval(compile(tree, "<expr>", "eval"), {"__builtins__":{}}, env))

@dataclass
class Expr(Condition):
    """Безопасное булево выражение на snap.get('var'), snap.age_ms('var')."""
    expr: str
    def required_signals(self) -> Set[str]:
        # Heuristic: вытащим имена из вида snap.get("name")
        names: Set[str] = set()
        try:
            tree = ast.parse(self.expr, mode="eval")
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr=="get":
                    if n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                        names.add(n.args[0].value)
        except Exception:
            pass
        return names
    async def evaluate(self, snap: InputSnapshot) -> ConditionResult:
        try:
            ok = _safe_eval_bool_expr(self.expr, snap)
            return ConditionResult.pass_() if ok else ConditionResult.fail(f"expr false: {self.expr}")
        except Exception as e:
            return ConditionResult.fail(f"expr error: {e}")

# ======================================================
# Комбинирование условий: M из N (MooN)
# ======================================================

@dataclass
class MooN(Condition):
    """M-из-N голосование (например, 1oo2, 2oo3)."""
    m: int
    conditions: List[Condition]
    label: str = "MooN"
    def required_signals(self) -> Set[str]:
        r: Set[str] = set()
        for c in self.conditions: r |= c.required_signals()
        return r
    async def evaluate(self, snap: InputSnapshot) -> ConditionResult:
        oks = 0; reasons: List[str] = []
        for c in self.conditions:
            res = await c.evaluate(snap)
            if res.ok: oks += 1
            else: reasons.extend(res.reasons)
        ok = oks >= self.m
        return ConditionResult.pass_() if ok else ConditionResult(False, [f"{self.label} need {self.m}/{len(self.conditions)} ok"] + reasons)

# ======================================================
# Конфигурация межблокировок
# ======================================================

@dataclass
class InterlockConfig:
    interlock_id: str
    title: str
    severity: Literal["low","medium","high","critical"] = "high"
    conditions: List[Condition] = field(default_factory=list)
    # После срабатывания держим LATCH до ручного сброса (или auto_reset_s)
    latch: bool = True
    auto_reset_s: Optional[float] = None
    # Требуется ли 2-персональный сброс (two-man rule)
    reset_roles: List[str] = field(default_factory=lambda: ["ot-maintainer"])
    reset_two_person: bool = False
    # Разрешены ли обходы и какие роли могут их создавать
    allow_bypass: bool = False
    bypass_roles: List[str] = field(default_factory=lambda: ["ot-maintainer"])
    max_bypass_minutes: int = 30
    # Истечение данных приводит к FAIL (fail-safe)
    required_signals: Set[str] = field(default_factory=set)
    evaluation_period_s: float = 0.5
    # При критичности — вызвать актуатор
    trigger_safe_shutdown: bool = True

@dataclass
class InterlockState:
    status: Literal["ok","violated","latched","bypassed"] = "ok"
    reasons: List[str] = field(default_factory=list)
    since_ms: int = 0
    last_change_ms: int = 0
    bypass_token_id: Optional[str] = None

@dataclass
class BypassToken:
    token_id: str
    interlock_id: str
    issued_by: str
    reason: str
    expires_ms: int

# ======================================================
# Исключения и решения охраны команд
# ======================================================

class PermissionDenied(Exception):
    pass

@dataclass
class GuardDecision:
    allowed: bool
    interlocks: Dict[str, InterlockState]
    reasons: List[str] = field(default_factory=list)

# ======================================================
# Движок межблокировок
# ======================================================

class InterlockEngine:
    def __init__(
        self,
        input_provider: InputProvider,
        actuator: Actuator,
        event_sink: Optional[EventSink] = None,
        kv: Optional[KVStore] = None,
        metrics: Optional[Metrics] = None,
        namespace: str = "safety"
    ):
        self.input = input_provider
        self.actuator = actuator
        self.sink = event_sink
        self.kv = kv
        self.metrics = metrics or NullMetrics()
        self.namespace = namespace

        self._configs: Dict[str, InterlockConfig] = {}
        self._states: Dict[str, InterlockState] = {}
        self._bypass: Dict[str, BypassToken] = {}
        self._lock = asyncio.Lock()
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._prev_snapshot: Optional[InputSnapshot] = None
        self._last_eval_ms: int = 0

    # ---------- Жизненный цикл ----------

    async def register(self, cfg: InterlockConfig) -> None:
        async with self._lock:
            self._configs[cfg.interlock_id] = cfg
            if cfg.interlock_id not in self._states:
                now = self._now_ms()
                self._states[cfg.interlock_id] = InterlockState(status="ok", since_ms=now, last_change_ms=now)
            # восстановление latch из KV
            if self.kv:
                persisted = await self.kv.get(self._kv_key(cfg.interlock_id))
                if persisted and persisted.get("status") in ("latched", "violated"):
                    st = self._states[cfg.interlock_id]
                    st.status = persisted["status"]
                    st.reasons = persisted.get("reasons", [])
                    st.since_ms = persisted.get("since_ms", st.since_ms)
                    st.last_change_ms = persisted.get("last_change_ms", st.last_change_ms)

    async def start(self) -> None:
        async with self._lock:
            if self._task: return
            self._stop.clear()
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try: await self._task
            except Exception: pass
            self._task = None

    # ---------- Управление обходами и сбросами ----------

    async def create_bypass(self, interlock_id: str, minutes: int, issued_by: str, reason: str, roles: List[str]) -> BypassToken:
        cfg = self._configs[interlock_id]
        if not cfg.allow_bypass: raise PermissionDenied("bypass disabled")
        if not any(r in cfg.bypass_roles for r in roles): raise PermissionDenied("insufficient role for bypass")
        minutes = min(minutes, cfg.max_bypass_minutes)
        token = BypassToken(
            token_id=str(uuid.uuid4()),
            interlock_id=interlock_id,
            issued_by=issued_by,
            reason=reason,
            expires_ms=self._now_ms() + minutes*60_000
        )
        async with self._lock:
            self._bypass[token.token_id] = token
            st = self._states[interlock_id]
            st.status = "bypassed"
            st.bypass_token_id = token.token_id
            st.last_change_ms = self._now_ms()
            await self._persist(interlock_id, st)
            await self._emit("bypass.created", interlock_id, {"by": issued_by, "reason": reason, "minutes": minutes})
        return token

    async def reset(self, interlock_id: str, requested_by: str, roles: List[str], co_sign: Optional[Tuple[str, List[str]]] = None) -> None:
        cfg = self._configs[interlock_id]
        if not any(r in cfg.reset_roles for r in roles):
            raise PermissionDenied("insufficient role for reset")
        if cfg.reset_two_person:
            if not co_sign or not any(r in cfg.reset_roles for r in co_sign[1]) or co_sign[0] == requested_by:
                raise PermissionDenied("two-person reset required")
        async with self._lock:
            st = self._states[interlock_id]
            st.status = "ok"; st.reasons = []; st.bypass_token_id = None; st.last_change_ms = self._now_ms(); st.since_ms = st.last_change_ms
            await self._persist(interlock_id, st)
            await self._emit("interlock.reset", interlock_id, {"by": requested_by})

    # ---------- Охрана команд ----------

    async def guard_command(self, impact_level: Literal["low","medium","high","critical"]) -> GuardDecision:
        """
        Возвращает разрешение на выполнение команды исходя из текущих состояний межблокировок.
        Политика: если существует interlock с severity >= impact_level и статус не "ok", команда запрещена.
        """
        ranking = {"low":1,"medium":2,"high":3,"critical":4}
        deny_reasons: List[str] = []
        async with self._lock:
            snapshot = {k:v for k,v in self._states.items()}
        for iid, st in snapshot.items():
            cfg = self._configs[iid]
            if ranking[cfg.severity] >= ranking[impact_level]:
                if st.status in ("violated","latched"):
                    deny_reasons.append(f"{iid}:{st.status}")
                elif st.status == "bypassed" and cfg.severity in ("high","critical"):
                    deny_reasons.append(f"{iid}:bypassed")
        return GuardDecision(allowed=(len(deny_reasons)==0), interlocks=snapshot, reasons=deny_reasons)

    # ---------- Основной цикл ----------

    async def _loop(self):
        try:
            while not self._stop.is_set():
                t0 = self._now_ms()
                try:
                    await self._evaluate_all()
                except Exception as e:
                    # любые исключения в цикле не должны ронять движок
                    self.metrics.inc("interlocks_eval_error", err=type(e).__name__)
                self._last_eval_ms = self._now_ms()
                # сторожевой таймер как gauge
                self.metrics.gauge("interlocks_last_eval_ms", float(self._last_eval_ms))
                # следующий тик — по минимальному evaluation_period среди конфигов
                period = min([c.evaluation_period_s for c in self._configs.values()] or [0.5])
                # не допускаем «бури» в случае очень маленьких периодов
                await asyncio.sleep(max(0.05, period))
        except asyncio.CancelledError:
            return

    async def _evaluate_all(self):
        # Собираем множество входов
        required: Set[str] = set()
        for cfg in self._configs.values():
            req = set(cfg.required_signals)
            for cond in cfg.conditions: req |= cond.required_signals()
            required |= req

        now_ms = self._now_ms()
        samples = await self.input.read(required) if required else {}
        snap = InputSnapshot(now_ms=now_ms, samples=samples, prev=self._prev_snapshot)

        # Обновляем каждый interlock
        for iid, cfg in self._configs.items():
            await self._evaluate_one(iid, cfg, snap)

        self._prev_snapshot = snap

    async def _evaluate_one(self, iid: str, cfg: InterlockConfig, snap: InputSnapshot):
        # Вычислить условие: все conditions должны быть ok
        reasons: List[str] = []
        ok = True
        for cond in cfg.conditions:
            res = await cond.evaluate(snap)
            if not res.ok:
                ok = False
                reasons += res.reasons

        # fail-safe при отсутствии обязательных сигналов
        for name in cfg.required_signals:
            if not snap.has(name):
                ok = False
                reasons.append(f"{name} missing")

        async with self._lock:
            st = self._states[iid]
            prev_status = st.status

            # Управление статусом
            if ok:
                if st.status in ("violated","latched"):
                    # auto_reset при наличии таймера
                    if cfg.auto_reset_s is not None:
                        if (snap.now_ms - st.since_ms) >= int(cfg.auto_reset_s*1000):
                            st.status = "ok"; st.reasons = []; st.bypass_token_id=None; st.since_ms=snap.now_ms; st.last_change_ms=snap.now_ms
                    else:
                        # ждём ручного сброса, оставляем latched
                        if st.status == "violated" and cfg.latch:
                            st.status = "latched"; st.last_change_ms=snap.now_ms
                        elif not cfg.latch:
                            st.status = "ok"; st.reasons=[]; st.since_ms=snap.now_ms; st.last_change_ms=snap.now_ms
                elif st.status == "bypassed":
                    # Обход истёк?
                    token = self._bypass.get(st.bypass_token_id or "")
                    if token and token.expires_ms <= snap.now_ms:
                        st.status = "ok"; st.reasons=[]; st.bypass_token_id=None; st.last_change_ms=snap.now_ms; st.since_ms=snap.now_ms
                else:
                    st.status = "ok"; st.reasons = []; st.since_ms = st.since_ms or snap.now_ms
            else:
                st.reasons = reasons or ["unspecified"]
                if cfg.latch and st.status in ("latched", "violated"):
                    st.status = "latched"
                else:
                    st.status = "violated"
                st.last_change_ms = snap.now_ms
                if st.since_ms == 0: st.since_ms = snap.now_ms

            # Эскалация на актуатор
            if st.status in ("violated","latched") and cfg.trigger_safe_shutdown and cfg.severity in ("high","critical"):
                await self._actuate_safe_shutdown(iid, cfg, st)

            # Событие статуса
            if st.status != prev_status:
                await self._emit("interlock.status", iid, {
                    "status": st.status, "prev": prev_status, "reasons": list(st.reasons),
                    "severity": cfg.severity, "ts_ms": snap.now_ms
                })
                await self._persist(iid, st)

            # Метрики
            self.metrics.gauge("interlock_status", {"ok":1,"violated":2,"latched":3,"bypassed":4}[st.status], id=iid)
            self.metrics.observe("interlock_eval_ms", 0.0, id=iid)  # заполнитель для совместимости

    async def _actuate_safe_shutdown(self, iid: str, cfg: InterlockConfig, st: InterlockState):
        try:
            await self.actuator.safe_shutdown(f"{iid}:{st.status}", {"reasons": st.reasons, "severity": cfg.severity})
            self.metrics.inc("interlock_safe_shutdown", id=iid, severity=cfg.severity)
        except Exception:
            # Актуатор не должен ломать цикл
            self.metrics.inc("interlock_safe_shutdown_error", id=iid)

    # ---------- Хранилище/события ----------

    def _kv_key(self, iid: str) -> str:
        return f"{self.namespace}:interlock:{iid}"

    async def _persist(self, iid: str, st: InterlockState):
        if not self.kv: return
        try:
            await self.kv.set(self._kv_key(iid), {
                "status": st.status, "reasons": st.reasons,
                "since_ms": st.since_ms, "last_change_ms": st.last_change_ms
            })
        except Exception:
            pass

    async def _emit(self, topic: str, iid: str, payload: Dict[str, Any]):
        if not self.sink: return
        body = {"interlock_id": iid, **payload}
        try:
            await self.sink.publish(f"{self.namespace}.{topic}", body)
        except Exception:
            pass

    # ---------- Утилиты ----------

    def _now_ms(self) -> int: return int(time.time()*1000)

# ======================================================
# Пример конфигурации и использования (док-строка)
# ======================================================

"""
Пример:
-------
Инициализация:

engine = InterlockEngine(input_provider=YourProvider(), actuator=YourActuator(), event_sink=YourSink(), kv=YourKV())

# Межблокировка «Перегрев + дверца открыта», 1oo2 из двух датчиков двери, гистерезис по температуре:
cfg = InterlockConfig(
    interlock_id="overtemp_guard",
    title="Overtemperature with door open",
    severity="critical",
    latch=True,
    allow_bypass=True, bypass_roles=["ot-maintainer"], max_bypass_minutes=10,
    required_signals={"temp_c","door_a","door_b","estop_ok"},
    conditions=[
        MooN(m=1, conditions=[
            BoolIs("door_a", expected=True),
            BoolIs("door_b", expected=True),
        ], label="door 1oo2"),
        Hysteresis("temp_c", low=70.0, high=75.0, initial_ok=True),
        BoolIs("estop_ok", expected=True)  # межблокировка активна только при исправной линии E-Stop
    ],
    evaluation_period_s=0.2,
    trigger_safe_shutdown=True
)

await engine.register(cfg)
await engine.start()

# Проверка охраны команды с высоким воздействием:
decision = await engine.guard_command(impact_level="high")
if not decision.allowed:
    # запретить выполнение команды
    pass

# Создать обход (break-glass) на 5 минут:
token = await engine.create_bypass("overtemp_guard", 5, issued_by="alice", reason="maintenance", roles=["ot-maintainer"])

# Ручной сброс защёлки:
await engine.reset("overtemp_guard", requested_by="bob", roles=["ot-maintainer"])

await engine.stop()
"""
