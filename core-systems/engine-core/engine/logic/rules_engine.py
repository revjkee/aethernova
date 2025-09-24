from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

# =========================
# Опциональные метрики
# =========================
_PROM = os.getenv("RULES_PROMETHEUS", "false").lower() == "true"
_prom = None
if _PROM:
    try:
        from prometheus_client import Counter, Histogram, Gauge  # type: ignore

        class _Prom:
            def __init__(self):
                self.facts = Gauge("rules_facts", "Facts in working memory", ["session"])
                self.index_keys = Gauge("rules_index_keys", "Indexed keys total", ["session"])
                self.activations = Gauge("rules_activations", "Pending activations", ["session"])
                self.firings = Counter("rules_firings_total", "Rule firings", ["session", "rule"])
                self.cycles = Counter("rules_cycles_total", "Run cycles", ["session"])
                self.step = Histogram("rules_step_seconds", "Single run() time", ["session"],
                                      buckets=[0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2])
        _prom = _Prom()
    except Exception:
        _prom = None


# =========================
# Исключения
# =========================
class RulesError(Exception): ...
class TimeoutError(RulesError): ...
class TooManyFiringsError(RulesError): ...
class NotFound(RulesError): ...
class ValidationError(RulesError): ...


# =========================
# Утилиты предикатов/операторов
# =========================
@dataclass(frozen=True)
class Var:
    """Переменная для унификации между паттернами по имени."""
    name: str

@dataclass(frozen=True)
class Op:
    """Оператор сравнения/проверки."""
    kind: str
    value: Any = None

    def __call__(self, x: Any) -> bool:
        k = self.kind
        v = self.value
        try:
            if k == "eq": return x == v
            if k == "ne": return x != v
            if k == "lt": return x < v
            if k == "le": return x <= v
            if k == "gt": return x > v
            if k == "ge": return x >= v
            if k == "contains": return v in x if x is not None else False
            if k == "in_set": return x in v
            if k == "regex":
                return re.search(v, str(x)) is not None
            if k == "exists":
                return bool(x is not None)
            raise ValidationError(f"Unknown operator: {k}")
        except Exception:
            return False

def EQ(x: Any) -> Op: return Op("eq", x)
def NE(x: Any) -> Op: return Op("ne", x)
def LT(x: Any) -> Op: return Op("lt", x)
def LE(x: Any) -> Op: return Op("le", x)
def GT(x: Any) -> Op: return Op("gt", x)
def GE(x: Any) -> Op: return Op("ge", x)
def CONTAINS(x: Any) -> Op: return Op("contains", x)
def IN_SET(xs: Iterable[Any]) -> Op: return Op("in_set", set(xs))
def REGEX(rx: Union[str, re.Pattern]) -> Op: return Op("regex", re.compile(rx) if isinstance(rx, str) else rx)
def EXISTS() -> Op: return Op("exists", None)

# Реестр кастомных предикатов: Callable(value, env)->bool
Predicate = Callable[[Any, Dict[str, Any]], bool]
_PREDICATES: Dict[str, Predicate] = {}

def register_predicate(name: str, fn: Predicate) -> None:
    _PREDICATES[name] = fn

@dataclass(frozen=True)
class Custom:
    name: str
    arg: Any = None
    def __call__(self, x: Any, env: Dict[str, Any]) -> bool:
        fn = _PREDICATES.get(self.name)
        if not fn:
            return False
        return bool(fn(x if self.arg is None else (x, self.arg), env))


# =========================
# Факты и рабочая память
# =========================
FactId = int

@dataclass
class Fact:
    id: FactId
    type: str
    data: Dict[str, Any]
    ts: float = field(default_factory=lambda: time.time())
    rev: int = 1
    origin: str = ""  # имя правила/источник (TMS)

    def to_json(self) -> Dict[str, Any]:
        return {"id": self.id, "type": self.type, "data": self.data, "ts": self.ts, "rev": self.rev, "origin": self.origin}


class _Index:
    """
    Индексы по точному совпадению значения: per (type, field) -> value -> set(fact_id).
    """
    def __init__(self) -> None:
        self.map: Dict[Tuple[str, str], Dict[Any, set[int]]] = {}
        self.by_type: Dict[str, set[int]] = {}

    def add(self, f: Fact) -> None:
        self.by_type.setdefault(f.type, set()).add(f.id)
        for k, v in f.data.items():
            self.map.setdefault((f.type, k), {}).setdefault(v, set()).add(f.id)

    def remove(self, f: Fact) -> None:
        self.by_type.get(f.type, set()).discard(f.id)
        for k, v in f.data.items():
            d = self.map.get((f.type, k))
            if not d: continue
            s = d.get(v)
            if not s: continue
            s.discard(f.id)
            if not s: d.pop(v, None)

    def update(self, f_old: Fact, f_new: Fact) -> None:
        # Наивно: remove+add (для простоты и надёжности)
        self.remove(f_old)
        self.add(f_new)

    def candidates(self, type_: str, field: Optional[str] = None, value: Any = None) -> Iterable[int]:
        if field is None:
            return list(self.by_type.get(type_, set()))
        return list(self.map.get((type_, field), {}).get(value, set()))


# =========================
# Шаблоны (паттерны) и правила
# =========================
@dataclass(frozen=True)
class Pattern:
    """
    tests: dict[field -> Op|Var|value|Custom|Callable(value, env)->bool]
    guard: Callable(data, env)->bool для сложной логики фильтра.
    """
    type: str
    tests: Dict[str, Any] = field(default_factory=dict)
    guard: Optional[Callable[[Dict[str, Any], Dict[str, Any]], bool]] = None

@dataclass
class Rule:
    name: str
    when: Sequence[Pattern]
    then: Callable[[Session, Dict[str, Any]], None]
    salience: int = 0
    no_loop: bool = True       # не запускать повторно из собственных действий в том же цикле
    unique: bool = True        # де-дуп одной и той же активации по env‑ключу
    enabled: bool = True


# =========================
# Активации/повестка
# =========================
@dataclass(frozen=True)
class Activation:
    rule: Rule
    env: Dict[str, Any]
    keys: Tuple[int, ...]           # набор fact ids, породивших активацию
    ts: float
    seq: int                        # монотонный порядковый, для детерминизма

    def sort_key(self) -> Tuple[int, float, int]:
        # salience desc, ts desc (recency), seq asc (FIFO)
        return (-self.rule.salience, -self.ts, self.seq)


# =========================
# Сессия правил
# =========================
class Session:
    """
    Потокобезопасная сессия (lock на mutating‑операциях), продукционная модель (forward‑chaining).
    """
    def __init__(self, name: str = "default") -> None:
        self.name = name
        self._facts: Dict[int, Fact] = {}
        self._index = _Index()
        self._rules: Dict[str, Rule] = {}
        self._next_id = 1
        self._agenda: List[Activation] = []
        self._activation_set: set[Tuple[str, Tuple[int, ...]]] = set()  # (rule, keys) для unique
        self._audit: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        self._seq = 0
        self._last_explain: List[Dict[str, Any]] = []

        if _prom:
            try:
                _prom.facts.labels(self.name).set(0)
                _prom.index_keys.labels(self.name).set(0)
                _prom.activations.labels(self.name).set(0)
            except Exception:
                pass

    # ----- Работа с правилами -----
    def add_rule(self, rule: Rule) -> None:
        with self._lock:
            self._rules[rule.name] = rule

    def remove_rule(self, name: str) -> None:
        with self._lock:
            self._rules.pop(name, None)

    # ----- Работа с фактами -----
    def assert_fact(self, type_: str, data: Dict[str, Any], *, origin: str = "") -> int:
        with self._lock:
            fid = self._next_id; self._next_id += 1
            f = Fact(fid, type_, dict(data), origin=origin)
            self._facts[fid] = f
            self._index.add(f)
            self._enqueue_from_fact(f, is_new=True)
            self._stat()
            return fid

    def retract_fact(self, fid: int) -> None:
        with self._lock:
            f = self._facts.pop(fid, None)
            if not f: raise NotFound(f"fact {fid} not found")
            self._index.remove(f)
            # чистим связанные активации
            self._agenda = [a for a in self._agenda if fid not in a.keys]
            self._activation_set = {k for k in self._activation_set if fid not in k[1]}
            self._stat()

    def modify_fact(self, fid: int, changes: Dict[str, Any]) -> None:
        with self._lock:
            f = self._facts.get(fid)
            if not f: raise NotFound(f"fact {fid} not found")
            old = Fact(f.id, f.type, dict(f.data), f.ts, f.rev, f.origin)
            f.data.update(changes)
            f.rev += 1; f.ts = time.time()
            self._index.update(old, f)
            self._enqueue_from_fact(f, is_new=False)
            self._stat()

    def facts(self, type_: Optional[str] = None) -> List[Fact]:
        with self._lock:
            if type_ is None:
                return list(self._facts.values())
            return [self._facts[i] for i in self._index.by_type.get(type_, set())]

    # ----- Запуск вывода -----
    def run(self, *, max_firings: int = 1000, max_ms: int = 1000) -> int:
        """
        Выполнить срабатывания до пустой повестки или лимитов.
        Возвращает число срабатываний.
        """
        t0 = time.perf_counter()
        firings = 0
        self._last_explain = []
        with self._lock:
            self._sort_agenda()

        while True:
            with self._lock:
                if not self._agenda:
                    break
                act = self._agenda.pop(0)
                self._activation_set.discard((act.rule.name, act.keys))
                if not act.rule.enabled:
                    continue
                # no_loop защита: если правило породило тот же набор фактов в этом же цикле — пропускаем
                if act.rule.no_loop and self._is_no_loop(act):
                    continue
            # Выполняем вне lock (позволяет действиям запускать новые факты)
            self._fire(act)
            firings += 1
            if _prom:
                try: _prom.firings.labels(self.name, act.rule.name).inc()
                except Exception: pass
            if firings >= max_firings:
                raise TooManyFiringsError(f"max_firings {max_firings} reached")
            if (time.perf_counter() - t0) * 1000.0 >= max_ms:
                raise TimeoutError(f"max_ms {max_ms} reached")

        if _prom:
            try:
                _prom.cycles.labels(self.name).inc()
                _prom.step.labels(self.name).observe(max(0.0, time.perf_counter() - t0))
            except Exception:
                pass
        return firings

    # ----- Объяснение/аудит -----
    def last_explain(self) -> List[Dict[str, Any]]:
        return list(self._last_explain)

    def audit_log(self, tail: int = 200) -> List[Dict[str, Any]]:
        return self._audit[-tail:]

    # ----- Снимок/восстановление -----
    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "facts": [f.to_json() for f in self._facts.values()],
                "agenda": [{"rule": a.rule.name, "keys": a.keys, "ts": a.ts, "seq": a.seq} for a in self._agenda],
            }

    def restore(self, snap: Dict[str, Any]) -> None:
        with self._lock:
            self._facts.clear(); self._index = _Index()
            for jf in snap.get("facts", []):
                f = Fact(jf["id"], jf["type"], dict(jf["data"]), jf.get("ts", time.time()), jf.get("rev", 1), jf.get("origin", ""))
                self._facts[f.id] = f
                self._index.add(f)
                self._next_id = max(self._next_id, f.id + 1)
            self._agenda.clear()
            self._activation_set.clear()
            self._stat()

    # =========================
    # Внутренние механизмы
    # =========================
    def _enqueue_from_fact(self, f: Fact, *, is_new: bool) -> None:
        """
        Инкрементально пытаемся сматчить новый/изменённый факт по всем правилам.
        Простейшая схема: ищем правила с первым паттерном по типу и равенствам, затем расширяем.
        """
        for rule in self._rules.values():
            if not rule.enabled or not rule.when:
                continue
            # быстрый фильтр по типу первого паттерна
            p0 = rule.when[0]
            if p0.type != f.type:
                continue
            # первичная проверка p0
            env0 = {}
            if not self._pattern_match(f, p0, env0):
                continue
            # расширяем на остальные паттерны
            envs = [env0]
            keys_sets = [(f.id,)]
            ok_envs, ok_keys = self._expand_patterns(rule.when[1:], envs, keys_sets)
            now = time.time()
            for e, ks in zip(ok_envs, ok_keys):
                self._queue_activation(rule, e, ks, now)

    def _expand_patterns(self, rest: Sequence[Pattern], envs: List[Dict[str, Any]], keys_sets: List[Tuple[int, ...]]) -> Tuple[List[Dict[str, Any]], List[Tuple[int, ...]]]:
        if not rest:
            return envs, keys_sets
        out_envs: List[Dict[str, Any]] = []
        out_keys: List[Tuple[int, ...]] = []
        p = rest[0]
        # кандидаты по типу
        for fid in self._index.candidates(p.type):
            f = self._facts.get(fid)
            if not f: continue
            for env, ks in zip(envs, keys_sets):
                # проверка унификации: нельзя использовать один и тот же факт дважды, если шаблон другой (для жёсткости)
                if fid in ks:
                    continue
                env_local = dict(env)
                if self._pattern_match(f, p, env_local):
                    out_envs.append(env_local)
                    out_keys.append(tuple(list(ks) + [fid]))
        return self._expand_patterns(rest[1:], out_envs, out_keys)

    def _pattern_match(self, f: Fact, p: Pattern, env: Dict[str, Any]) -> bool:
        d = f.data
        for field, cond in p.tests.items():
            val = d.get(field)
            if isinstance(cond, Var):
                # связываем или проверяем равенство
                if cond.name in env:
                    if env[cond.name] != val:
                        return False
                else:
                    env[cond.name] = val
            elif isinstance(cond, Op):
                if not cond(val):
                    return False
            elif isinstance(cond, Custom):
                if not cond(val, env):
                    return False
            elif callable(cond):
                try:
                    if not bool(cond(val, env)):  # ожидаем сигнатуру (value, env)->bool
                        return False
                except TypeError:
                    if not bool(cond(val)):
                        return False
            else:
                # литеральное сравнение
                if val != cond:
                    return False
        if p.guard:
            try:
                if not bool(p.guard(f.data, env)):
                    return False
            except Exception:
                return False
        return True

    def _queue_activation(self, rule: Rule, env: Dict[str, Any], keys: Tuple[int, ...], ts: float) -> None:
        key = (rule.name, keys)
        if rule.unique and key in self._activation_set:
            return
        self._seq += 1
        act = Activation(rule=rule, env=dict(env), keys=keys, ts=ts, seq=self._seq)
        self._agenda.append(act)
        self._activation_set.add(key)
        self._sort_agenda()
        self._stat()

    def _sort_agenda(self) -> None:
        self._agenda.sort(key=lambda a: a.sort_key())

    def _is_no_loop(self, act: Activation) -> bool:
        # Правило не должно повторно запускаться, если последнее действие добавляло факт с origin == rule.name
        # и набор входных фактов содержит такой факт.
        for fid in act.keys:
            f = self._facts.get(fid)
            if f and f.origin == act.rule.name:
                return True
        return False

    def _fire(self, act: Activation) -> None:
        before = time.time()
        explain_item = {
            "rule": act.rule.name,
            "env": dict(act.env),
            "keys": act.keys,
            "ts": act.ts,
        }
        try:
            act.rule.then(self, dict(act.env))
            explain_item["status"] = "ok"
        except Exception as e:
            explain_item["status"] = "error"
            explain_item["error"] = repr(e)
        finally:
            explain_item["took_ms"] = (time.time() - before) * 1000.0
            self._last_explain.append(explain_item)
            self._audit.append({
                "at": time.time(),
                "event": "firing",
                "detail": explain_item
            })

    def _stat(self) -> None:
        if _prom:
            try:
                _prom.facts.labels(self.name).set(len(self._facts))
                _prom.index_keys.labels(self.name).set(sum(len(v) for v in self._index.map.values()))
                _prom.activations.labels(self.name).set(len(self._agenda))
            except Exception:
                pass


# =========================
# Вспомогательные фабрики
# =========================
def pattern(type_: str, **tests: Any) -> Pattern:
    """
    pattern("order", id=Var("id"), amount=GT(100), status=IN_SET({"NEW","PAID"}))
    pattern("user", name=REGEX(r"^A"), guard=lambda d, env: d.get("age",0) >= 18)
    """
    guard = tests.pop("_guard", None)
    return Pattern(type_, tests, guard=guard)

def rule(name: str, when: Sequence[Pattern], then: Callable[[Session, Dict[str, Any]], None],
         *, salience: int = 0, no_loop: bool = True, unique: bool = True, enabled: bool = True) -> Rule:
    return Rule(name=name, when=list(when), then=then, salience=salience, no_loop=no_loop, unique=unique, enabled=enabled)


# =========================
# Пример использования (докстрока)
# =========================
"""
# Создание сессии и правил
s = Session("orders")

def action_high_value(session: Session, env: Dict[str, Any]) -> None:
    # пример действия: пометить заказ как VIP и добавить событие аудита
    oid = env["oid"]
    # находим факт заказа и обновляем
    for f in session.facts("order"):
        if f.data.get("id") == oid:
            session.modify_fact(f.id, {"vip": True})
            session.assert_fact("audit", {"kind": "vip_mark", "order_id": oid}, origin="high_value_rule")
            break

r1 = rule(
    "high_value_rule",
    when=[
        pattern("order", id=Var("oid"), amount=GT(1000), status=IN_SET({"NEW", "PAID"})),
        pattern("user", id=Var("uid"), tier=IN_SET({"gold","platinum"}), _guard=lambda d, env: d.get("active", True)),
        # связь через переменные: order.user_id == user.id
        pattern("link", order_id=Var("oid"), user_id=Var("uid")),
    ],
    then=action_high_value,
    salience=10,
)

s.add_rule(r1)

# Факты
fo = s.assert_fact("order", {"id": 42, "amount": 1500, "status": "NEW"})
fu = s.assert_fact("user", {"id": 7, "tier": "gold", "active": True})
fl = s.assert_fact("link", {"order_id": 42, "user_id": 7})

# Запуск
try:
    s.run(max_firings=100, max_ms=100)
except TimeoutError:
    pass

# Объяснение
print(s.last_explain())
"""


__all__ = [
    "Session",
    "Fact",
    "Pattern",
    "Rule",
    "Var",
    "Op",
    "Custom",
    "EQ", "NE", "LT", "LE", "GT", "GE", "CONTAINS", "IN_SET", "REGEX", "EXISTS",
    "register_predicate",
    "pattern",
    "rule",
    "RulesError", "TimeoutError", "TooManyFiringsError", "NotFound", "ValidationError",
]
