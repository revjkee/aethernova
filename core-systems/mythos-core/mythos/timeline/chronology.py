# mythos-core/mythos/timeline/chronology.py
"""
Хронология ленты Mythos Core: отбор, скоринг и размещение карточек по декларативным правилам.

Совместимость: шаблон правил из configs/templates/timeline_rules.example.yaml
(при необходимости можно передать уже распарсенный dict из YAML).

Ключевые возможности:
- Безопасная мини-DSL на базе AST (только сравнения, логика, математика, доступ к данным и whitelisted-функции).
- Приоритетные полосы (priority bands) с min/max квотами по итоговой выдаче.
- Слоты (top/main/bottom) с capacity и refill_policy=per_request.
- Дедупликация (group_by + window_s), cooldown между карточками одного издателя.
- Rate-limit (per_user/per_minute, per_user_per_hour, per_content_per_day).
- Детерминированный random(seed=user_id, request_id, rule_id) для антифлаппинга.
- Тэйкбрейкеры: score_desc → recency_desc → random (или из правил).
- Диагностика прохождения правил и причин отбраковки.

Замена стора:
- Реализуйте StateStore (get/set/zincr/ttl_keys) поверх Redis и передайте в Engine.

Автор: platform@mythos.local
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import math
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from zoneinfo import ZoneInfo

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # опционально

# ------------------------- Вспомогательные типы -------------------------

@dataclass
class Candidate:
    """Кандидат в ленту. Ожидается структура, совместимая с шаблоном правил."""
    id: str
    content: Dict[str, Any]
    event: Dict[str, Any] = field(default_factory=dict)
    publisher: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0
    rule_id: Optional[str] = None
    priority_band: Optional[str] = None
    slot: Optional[str] = None
    diagnostics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FeedRequest:
    user: Dict[str, Any]
    locale: str = "en"
    channel: str = "web"             # web|mobile|...
    timezone: str = "UTC"
    max_feed_size: int = 50
    request_id: Optional[str] = None


@dataclass
class FeedResult:
    items: List[Candidate]
    diagnostics: Dict[str, Any]


# ------------------------- Хранилище состояний (TTL) -------------------------

class StateStore:
    """Абстракция стора: можно заменить на Redis/KeyDB. Значения — эпемерные TTL метки и счётчики."""
    def get(self, key: str) -> Optional[Any]: raise NotImplementedError
    def set(self, key: str, value: Any, ttl_s: int) -> None: raise NotImplementedError
    def incr(self, key: str, ttl_s: int) -> int: raise NotImplementedError
    def ttl_keys(self, prefix: str) -> List[str]: raise NotImplementedError


class InMemoryTTLStore(StateStore):
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[Any, float]] = {}

    def _purge(self) -> None:
        now = time.time()
        dead = [k for k, (_, exp) in self._data.items() if exp is not None and exp < now]
        for k in dead:
            del self._data[k]

    def get(self, key: str) -> Optional[Any]:
        self._purge()
        val = self._data.get(key)
        if not val: return None
        v, exp = val
        if exp and exp < time.time():
            del self._data[key]
            return None
        return v

    def set(self, key: str, value: Any, ttl_s: int) -> None:
        self._purge()
        self._data[key] = (value, time.time() + ttl_s if ttl_s > 0 else None)

    def incr(self, key: str, ttl_s: int) -> int:
        self._purge()
        v = self.get(key)
        n = int(v or 0) + 1
        self.set(key, n, ttl_s)
        return n

    def ttl_keys(self, prefix: str) -> List[str]:
        self._purge()
        now = time.time()
        out = []
        for k, (_, exp) in self._data.items():
            if k.startswith(prefix) and (exp is None or exp > now):
                out.append(k)
        return out


# ------------------------- Безопасная мини-DSL -------------------------

class SafeEvalError(Exception): pass

class SafeEvaluator(ast.NodeVisitor):
    """
    Безопасный интерпретатор выражений:
    - поддерживает: литералы, имена, доступ к dict через attr/subscript, арифметику, сравнения, and/or/not,
      тернарный оператор, вызовы whitelisted-функций.
    - запрещает: импорт, comprehension, лямбды, генераторы, атрибуты с '__', присваивания и т.д.
    """
    ALLOWED_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow)
    ALLOWED_CMPOPS = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn)
    ALLOWED_UNARY = (ast.USub, ast.UAdd, ast.Not)

    def __init__(self, context: Dict[str, Any], functions: Dict[str, Callable[..., Any]]) -> None:
        self.ctx = context
        self.funcs = functions

    def visit(self, node: ast.AST):
        if isinstance(node, ast.Expression):
            return self.visit(node.body)
        elif isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Name):
            if node.id in self.ctx:
                return self.ctx[node.id]
            raise SafeEvalError(f"Unknown name: {node.id}")
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, self.ALLOWED_UNARY):
            v = self.visit(node.operand)
            if isinstance(node.op, ast.Not): return not bool(v)
            return -v if isinstance(node.op, ast.USub) else +v
        elif isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                val = True
                for v in node.values:
                    val = bool(self.visit(v))
                    if not val: return False
                return True
            elif isinstance(node.op, ast.Or):
                for v in node.values:
                    if bool(self.visit(v)): return True
                return False
        elif isinstance(node, ast.BinOp) and isinstance(node.op, self.ALLOWED_BINOPS):
            left, right = self.visit(node.left), self.visit(node.right)
            return self._apply_binop(node.op, left, right)
        elif isinstance(node, ast.Compare):
            left = self.visit(node.left)
            result = True
            for op, comparator in zip(node.ops, node.comparators):
                right = self.visit(comparator)
                if not self._apply_cmp(op, left, right): return False
                left = right
            return result
        elif isinstance(node, ast.IfExp):
            return self.visit(node.body) if self.visit(node.test) else self.visit(node.orelse)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                fname = node.func.id
                if fname not in self.funcs:
                    raise SafeEvalError(f"Function not allowed: {fname}")
                f = self.funcs[fname]
                args = [self.visit(a) for a in node.args]
                kwargs = {kw.arg: self.visit(kw.value) for kw in node.keywords}
                return f(*args, **kwargs)
            raise SafeEvalError("Only simple function calls are allowed")
        elif isinstance(node, ast.Attribute):
            base = self.visit(node.value)
            attr = node.attr
            if attr.startswith("__"): raise SafeEvalError("Dunder access is forbidden")
            if isinstance(base, dict):
                return base.get(attr)
            return getattr(base, attr, None)
        elif isinstance(node, ast.Subscript):
            base = self.visit(node.value)
            key = self.visit(node.slice) if not isinstance(node.slice, ast.Slice) else slice(
                self.visit(node.slice.lower) if node.slice.lower else None,
                self.visit(node.slice.upper) if node.slice.upper else None,
                self.visit(node.slice.step) if node.slice.step else None,
            )
            try:
                return base[key]
            except Exception:
                return None
        elif isinstance(node, ast.Tuple):
            return tuple(self.visit(elt) for elt in node.elts)
        elif isinstance(node, ast.List):
            return [self.visit(elt) for elt in node.elts]
        else:
            raise SafeEvalError(f"Unsupported expression: {type(node).__name__}")

    def _apply_binop(self, op, a, b):
        if isinstance(op, ast.Add): return a + b
        if isinstance(op, ast.Sub): return a - b
        if isinstance(op, ast.Mult): return a * b
        if isinstance(op, ast.Div): return a / b
        if isinstance(op, ast.Mod): return a % b
        if isinstance(op, ast.Pow): return a ** b
        raise SafeEvalError("Invalid binop")

    def _apply_cmp(self, op, a, b):
        if isinstance(op, ast.Eq): return a == b
        if isinstance(op, ast.NotEq): return a != b
        if isinstance(op, ast.Lt): return a < b
        if isinstance(op, ast.LtE): return a <= b
        if isinstance(op, ast.Gt): return a > b
        if isinstance(op, ast.GtE): return a >= b
        if isinstance(op, ast.In): return a in b if b is not None else False
        if isinstance(op, ast.NotIn): return a not in b if b is not None else True
        raise SafeEvalError("Invalid cmp")

def safe_eval(expr: str, context: Dict[str, Any], functions: Dict[str, Callable[..., Any]]) -> Any:
    tree = ast.parse(expr, mode="eval")
    return SafeEvaluator(context, functions).visit(tree)

# ------------------------- Встроенные функции DSL -------------------------

def _now_s() -> int:
    return int(time.time())

def _hours_since(dt_iso: str) -> float:
    if not dt_iso: return 1e9
    dt = datetime.fromisoformat(dt_iso.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds() / 3600.0

def _sigmoid(x: float, k: float = 10.0, x0: float = 0.0) -> float:
    try:
        return 1.0 / (1.0 + math.exp(-k * (x - x0)))
    except OverflowError:
        return 0.0 if x < x0 else 1.0

def _exp_decay(hours: float, half_life_hours: float = 8.0) -> float:
    if half_life_hours <= 0: return 1.0
    lam = math.log(2) / half_life_hours
    return math.exp(-lam * hours)

# ------------------------- Вспомогательные утилиты -------------------------

def _seeded_random(*parts: str) -> random.Random:
    h = hashlib.sha256(("|".join(parts)).encode("utf-8")).hexdigest()
    seed = int(h[:16], 16)
    return random.Random(seed)

def _match_time_windows(tz: str, windows: List[str]) -> bool:
    if not windows: return True
    now = datetime.now(ZoneInfo(tz)).time()
    for w in windows:
        try:
            a, b = w.split("-")
            h1, m1 = [int(x) for x in a.split(":")]
            h2, m2 = [int(x) for x in b.split(":")]
            t1 = timedelta(hours=h1, minutes=m1)
            t2 = timedelta(hours=h2, minutes=m2)
            cur = timedelta(hours=now.hour, minutes=now.minute)
            if t1 <= cur <= t2:
                return True
        except Exception:
            continue
    return False

def _dedup_key(fields: Iterable[str], ctx: Dict[str, Any]) -> str:
    values = []
    for f in fields:
        # поддержка dotted-path: "content_id", "edition_id", "publisher.id"
        cur = ctx
        for part in f.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                cur = getattr(cur, part, None)
        values.append(str(cur))
    return hashlib.sha256(("|".join(values)).encode("utf-8")).hexdigest()

# ------------------------- Движок хронологии -------------------------

class ChronologyEngine:
    def __init__(self, ruleset: Dict[str, Any], state: Optional[StateStore] = None) -> None:
        self.ruleset = ruleset or {}
        self.state = state or InMemoryTTLStore()
        self.globals = ruleset.get("globals", {})
        self.defaults = ruleset.get("defaults", {})
        self.priority_bands = ruleset.get("globals", {}).get("priority_bands", [])
        self.slots = ruleset.get("globals", {}).get("slots", [])
        self.rate_limits = ruleset.get("globals", {}).get("rate_limits", {})
        self.scoring = ruleset.get("globals", {}).get("scoring", {})
        self.tiebreakers = (ruleset.get("tiebreakers") or {}).get("order", ["score_desc", "recency_desc", "random"])
        self.rules = ruleset.get("rules", [])
        self.validation = ruleset.get("validation", {"strict": True})
        self._validate_ruleset()

    @staticmethod
    def from_yaml(text: str, state: Optional[StateStore] = None) -> "ChronologyEngine":
        if not yaml:
            raise RuntimeError("PyYAML не установлен, передайте dict в конструктор или добавьте зависимость 'PyYAML'")
        return ChronologyEngine(yaml.safe_load(text), state=state)

    def _validate_ruleset(self) -> None:
        # Базовая валидация структуры (не JSON Schema, но ловит критичные баги)
        if "globals" not in self.ruleset or "rules" not in self.ruleset:
            if self.validation.get("strict", True):
                raise ValueError("Некорректный ruleset: отсутствуют 'globals' или 'rules'")

    # --------------- Публичный API ---------------

    def build_feed(self, req: FeedRequest, candidates: List[Candidate]) -> FeedResult:
        diag: Dict[str, Any] = {"phases": []}
        # Шаг 1: фильтрация безопасности/комплаенса на уровне ruleset (если описано)
        candidates = self._apply_safety(req, candidates, diag)

        # Шаг 2: матчинг правил и скоринг
        matched: List[Candidate] = self._select_and_score(req, candidates, diag)

        # Шаг 3: распределение по priority bands и слотам + квоты/ёмкости
        placed: List[Candidate] = self._distribute(req, matched, diag)

        # Шаг 4: дедупликация/лимиты/кулдауны
        final: List[Candidate] = self._apply_limits(req, placed, diag)

        # Шаг 5: финальная сортировка по тэйкбрейкерам и обрезка до max_feed_size
        final = self._final_sort(req, final)[: req.max_feed_size]

        diag["summary"] = {
            "input": len(candidates),
            "matched": len(matched),
            "placed": len(placed),
            "final": len(final),
        }
        return FeedResult(items=final, diagnostics=diag)

    # --------------- Фаза 1: безопасность/комплаенс ---------------

    def _apply_safety(self, req: FeedRequest, cands: List[Candidate], diag: Dict[str, Any]) -> List[Candidate]:
        # Применяем suppression.hard_block / soft_block (если есть)
        sup = self.ruleset.get("suppression", {})
        hard = sup.get("hard_block") or []
        soft = sup.get("soft_block") or []
        out: List[Candidate] = []
        reasons = {"hard_blocked": 0, "soft_blocked": 0}
        for cand in cands:
            ctx = self._context(req, cand, rule=None)
            if any(self._eval_bool(expr, ctx) for expr in hard):
                reasons["hard_blocked"] += 1
                cand.diagnostics["suppressed"] = "hard"
                continue
            if any(self._eval_bool(expr, ctx) for expr in soft):
                # soft: пометим, но не исключаем (можно понизить score)
                reasons["soft_blocked"] += 1
                cand.diagnostics["suppressed"] = "soft"
            out.append(cand)
        diag["phases"].append({"phase": "safety", "reasons": reasons, "kept": len(out)})
        return out

    # --------------- Фаза 2: матчинг и скоринг ---------------

    def _select_and_score(self, req: FeedRequest, cands: List[Candidate], diag: Dict[str, Any]) -> List[Candidate]:
        results: List[Candidate] = []
        reasons = {"rule_hit": {}, "rule_skip": {}}
        for rule in self.rules:
            rule_id = rule.get("id")
            reasons["rule_hit"].setdefault(rule_id, 0)
            reasons["rule_skip"].setdefault(rule_id, 0)

        for cand in cands:
            hit_best: Optional[Candidate] = None
            for rule in self.rules:
                if not self._candidate_passes(req, cand, rule):
                    reasons["rule_skip"][rule.get("id")] += 1
                    continue
                # Скоринг
                score = self._score(req, cand, rule)
                clone = dataclasses.replace(cand)
                clone.score = score
                clone.rule_id = rule.get("id")
                clone.priority_band = rule.get("priority_band", "normal")
                clone.slot = (rule.get("placement") or {}).get("slot", (self.defaults.get("placement") or {}).get("slot", "main"))
                clone.diagnostics["hit_rule"] = rule.get("id")
                results.append(clone)
                reasons["rule_hit"][rule.get("id")] += 1
                hit_best = clone
                # По умолчанию "первый хит" или можно позволить кросс-матч; оставим мульти-хит, дальше распределение разрулит
            # если ни одно правило не сработало — пропускаем
        diag["phases"].append({"phase": "match+score", "reasons": reasons, "kept": len(results)})
        return results

    def _candidate_passes(self, req: FeedRequest, cand: Candidate, rule: Dict[str, Any]) -> bool:
        gates = rule.get("gates", {})
        locales = gates.get("locales", ["*"])
        channels = gates.get("channels", ["web", "mobile"])
        time_windows = gates.get("time_windows", [])
        audience = gates.get("audience", ["all"])  # список сегментов
        # locales: "*" или "!xx"
        if locales and "*" not in locales:
            if f"!{req.locale}" in locales:
                return False
            if req.locale not in locales:
                return False
        # channel
        if channels and req.channel not in channels:
            return False
        # time windows
        tz = self.globals.get("timezone", "UTC") or req.timezone
        if not _match_time_windows(tz, time_windows):
            return False
        # audience сегменты (если определены в ruleset)
        segments = {seg["id"]: seg for seg in self.ruleset.get("audience_segments", [])}
        for seg_id in audience:
            if seg_id == "all": 
                continue
            seg = segments.get(seg_id)
            if not seg:
                continue
            if not self._eval_bool(seg["filter"], self._context(req, cand, rule)):
                return False
        # match section
        match = rule.get("match", {})
        passed = True
        if "all" in match:
            passed = all(self._eval_bool(expr, self._context(req, cand, rule)) for expr in match["all"])
        if passed and "any" in match:
            passed = any(self._eval_bool(expr, self._context(req, cand, rule)) for expr in match["any"])
        return bool(passed)

    def _score(self, req: FeedRequest, cand: Candidate, rule: Dict[str, Any]) -> float:
        formula = (rule.get("score") or {}).get("formula", "0.0")
        min_score = (rule.get("score") or {}).get("min_score", None)
        cap = (rule.get("score") or {}).get("cap", None)
        ctx = self._context(req, cand, rule)
        # функции
        weights = self.scoring.get("weights", {})
        rnd = _seeded_random(req.user.get("id", "anon"), req.request_id or "0", rule.get("id", "r"))
        def _weight(name: str) -> float: return float(weights.get(name, 0.0))
        def _random() -> float: return rnd.random()
        funcs = {
            "now_s": _now_s,
            "hours_since": _hours_since,
            "sigmoid": _sigmoid,
            "exp_decay": _exp_decay,
            "weight": _weight,
            "random": _random,
        }
        try:
            value = float(safe_eval(formula, ctx, funcs))
        except Exception:
            value = 0.0
        if min_score is not None and value < float(min_score):
            value = -1e9  # отсекаем ниже порога
        if cap is not None:
            value = min(value, float(cap))
        # мягкое понижение для soft suppression
        if cand.diagnostics.get("suppressed") == "soft":
            value *= 0.5
        return value

    def _context(self, req: FeedRequest, cand: Optional[Candidate], rule: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "user": req.user,
            "content": (cand.content if cand else {}),
            "event": (cand.event if cand else {}),
            "publisher": (cand.publisher if cand else {}),
            "globals": self.globals,
            "rule": rule or {},
        }

    def _eval_bool(self, expr: str, ctx: Dict[str, Any]) -> bool:
        if not expr: return True
        funcs = {
            "now_s": _now_s,
            "hours_since": _hours_since,
            "sigmoid": _sigmoid,
            "exp_decay": _exp_decay,
            "random": lambda: 0.42,  # неиспользуемый в фильтрах
        }
        try:
            return bool(safe_eval(expr, ctx, funcs))
        except Exception:
            return False

    # --------------- Фаза 3: распределение по квотам/слотам ---------------

    def _distribute(self, req: FeedRequest, matched: List[Candidate], diag: Dict[str, Any]) -> List[Candidate]:
        # Группируем по priority_band → slot
        bands = self.priority_bands or [
            {"id": "urgent", "weight": 1.0, "min_quota": 0.0, "max_quota": 1.0},
            {"id": "high", "weight": 0.7, "min_quota": 0.0, "max_quota": 1.0},
            {"id": "normal", "weight": 0.4, "min_quota": 0.0, "max_quota": 1.0},
            {"id": "low", "weight": 0.2, "min_quota": 0.0, "max_quota": 1.0},
        ]
        slots = {s["id"]: s for s in (self.slots or [{"id": "main", "capacity": req.max_feed_size, "refill_policy": "per_request"}])}
        # Сортировка внутри band по score desc (tie-breakers применим позже)
        per_band: Dict[str, List[Candidate]] = {}
        for c in matched:
            per_band.setdefault(c.priority_band or "normal", []).append(c)
        for b_id, arr in per_band.items():
            arr.sort(key=lambda x: x.score, reverse=True)

        total_target = req.max_feed_size
        out: List[Candidate] = []
        band_diag = {}
        # Фаза 1: удовлетворяем min_quota
        for band in bands:
            bid = band["id"]
            arr = per_band.get(bid, [])
            min_take = int(band.get("min_quota", 0.0) * total_target)
            take = min(min_take, len(arr))
            picked = arr[:take]
            out.extend(picked)
            per_band[bid] = arr[take:]
            band_diag[bid] = {"min_take": take, "remaining": len(per_band[bid])}

        # Фаза 2: заполняем до max_feed_size, соблюдая max_quota
        remaining = total_target - len(out)
        if remaining > 0:
            # создаём пул кандидатов с весами полос
            weighted: List[Tuple[float, Candidate]] = []
            for band in bands:
                bid = band["id"]
                w = float(band.get("weight", 1.0))
                for c in per_band.get(bid, []):
                    weighted.append((w, c))
            # сортируем по score внутри полос, но учитываем веса (w*score)
            weighted.sort(key=lambda t: (t[0] * t[1].score), reverse=True)
            # применяем ограничения max_quota
            taken_per_band: Dict[str, int] = {b["id"]: 0 for b in bands}
            max_per_band: Dict[str, int] = {b["id"]: int(b.get("max_quota", 1.0) * total_target) for b in bands}
            for _, cand in weighted:
                if remaining <= 0: break
                bid = cand.priority_band or "normal"
                if taken_per_band[bid] >= max_per_band[bid]: 
                    continue
                out.append(cand)
                taken_per_band[bid] += 1
                remaining -= 1

        # Распределение по слотам (capacity)
        per_slot: Dict[str, List[Candidate]] = {}
        for c in out:
            per_slot.setdefault(c.slot or "main", []).append(c)
        final: List[Candidate] = []
        for sid, arr in per_slot.items():
            cap = int(slots.get(sid, {}).get("capacity", req.max_feed_size))
            final.extend(arr[:cap])

        diag["phases"].append({"phase": "distribute", "bands": band_diag, "out": len(final)})
        return final

    # --------------- Фаза 4: лимиты/дедуп/кулдауны ---------------

    def _apply_limits(self, req: FeedRequest, placed: List[Candidate], diag: Dict[str, Any]) -> List[Candidate]:
        result: List[Candidate] = []
        reasons = {"dedup": 0, "cooldown": 0, "rate_user": 0, "rate_content": 0}
        # глобальные настройки
        cooldown_s = int((self.globals.get("cooldowns") or {}).get("per_publisher_s", 0))
        dedup_conf = self.globals.get("deduplication") or {}
        dedup_fields = dedup_conf.get("group_by", ["content_id"])
        dedup_window_s = int(dedup_conf.get("window_s", 0))
        # rate limits
        rl_user_min = int((self.rate_limits or {}).get("per_user_per_minute", 0))
        rl_user_hour = int((self.rate_limits or {}).get("per_user_per_hour", 0))
        rl_content_day = int((self.rate_limits or {}).get("per_content_per_day", 0))

        user_id = str(req.user.get("id", "anon"))

        for c in placed:
            ctx = self._context(req, c, rule=None)

            # дедуп по group_by
            if dedup_window_s > 0 and dedup_fields:
                dkey = f"dedup:{_dedup_key(dedup_fields, {'content_id': c.content.get('content_id', c.id), **ctx})}"
                if self.state.get(dkey):
                    reasons["dedup"] += 1
                    continue
                self.state.set(dkey, 1, dedup_window_s)

            # cooldown по издателю
            pub_id = (c.publisher or {}).get("id") or c.content.get("publisher_id")
            if cooldown_s > 0 and pub_id:
                cd_key = f"cooldown:user:{user_id}:pub:{pub_id}"
                if self.state.get(cd_key):
                    reasons["cooldown"] += 1
                    continue
                self.state.set(cd_key, 1, cooldown_s)

            # rate per user per minute/hour
            if rl_user_min > 0:
                n = self.state.incr(f"rl:user:{user_id}:m:{int(time.time()//60)}", ttl_s=120)
                if n > rl_user_min:
                    reasons["rate_user"] += 1
                    continue
            if rl_user_hour > 0:
                n = self.state.incr(f"rl:user:{user_id}:h:{int(time.time()//3600)}", ttl_s=3700)
                if n > rl_user_hour:
                    reasons["rate_user"] += 1
                    continue

            # rate per content per day
            if rl_content_day > 0:
                cid = c.content.get("content_id", c.id)
                n = self.state.incr(f"rl:content:{cid}:d:{int(time.time()//86400)}", ttl_s=90000)
                if n > rl_content_day:
                    reasons["rate_content"] += 1
                    continue

            result.append(c)

        diag["phases"].append({"phase": "limits", "reasons": reasons, "kept": len(result)})
        return result

    # --------------- Фаза 5: финальная сортировка ---------------

    def _final_sort(self, req: FeedRequest, items: List[Candidate]) -> List[Candidate]:
        # Определяем ключи сортировки по self.tiebreakers
        rnd = _seeded_random(req.user.get("id", "anon"), req.request_id or "0", "final")
        # Вычисляем recency (чем меньше часов, тем выше)
        def recency(c: Candidate) -> float:
            pub = c.content.get("published_at")
            if not pub: return 1e9
            return _hours_since(pub)

        # создаём список (key tuple) в нужном порядке
        def sort_key(c: Candidate):
            keys = []
            for tb in self.tiebreakers:
                if tb == "score_desc":
                    keys.append((-c.score))
                elif tb == "recency_desc":
                    keys.append(-recency(c))
                elif tb == "random":
                    keys.append(-rnd.random())
                elif tb == "slot_capacity":
                    # здесь нет прямого ключа, оставим нейтрально
                    keys.append(0)
                elif tb == "priority_band":
                    # можно задать порядок полос вручную
                    order = {b["id"]: i for i, b in enumerate(self.priority_bands)}
                    keys.append(order.get(c.priority_band or "normal", 999))
                else:
                    keys.append(0)
            return tuple(keys)

        return sorted(items, key=sort_key)


# ------------------------- Пример интеграции -------------------------

def build_engine_from_file(path: str, state: Optional[StateStore] = None) -> ChronologyEngine:
    if not yaml:
        raise RuntimeError("PyYAML не установлен. Установите PyYAML или используйте ChronologyEngine(dict).")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return ChronologyEngine(data, state=state)


# ------------------------- Пример использования (dev) -------------------------

if __name__ == "__main__":
    # Мини-демо: запускается локально для проверки логики.
    example_rules = {
        "globals": {
            "timezone": "UTC",
            "max_feed_size": 10,
            "priority_bands": [
                {"id": "urgent", "weight": 1.0, "min_quota": 0.1, "max_quota": 0.6},
                {"id": "normal", "weight": 0.5, "min_quota": 0.2, "max_quota": 0.9},
            ],
            "slots": [
                {"id": "top", "capacity": 2, "refill_policy": "per_request"},
                {"id": "main", "capacity": 8, "refill_policy": "per_request"},
            ],
            "scoring": {"weights": {"recency": 0.4, "engagement": 0.3, "affinity": 0.2}},
            "deduplication": {"group_by": ["content_id"], "window_s": 3600},
            "cooldowns": {"per_publisher_s": 30},
            "rate_limits": {"per_user_per_minute": 60, "per_user_per_hour": 600, "per_content_per_day": 3},
        },
        "defaults": {
            "placement": {"slot": "main"}
        },
        "rules": [
            {
                "id": "breaking",
                "priority_band": "urgent",
                "match": {"any": ["'breaking' in content.tags"]},
                "gates": {"locales": ["*"], "channels": ["web", "mobile"], "time_windows": []},
                "score": {"formula": "1.0 * weight('recency')*exp_decay(hours_since(content.published_at), half_life_hours=4) + 0.2"},
                "placement": {"slot": "top", "ttl_s": 3600},
            },
            {
                "id": "default",
                "priority_band": "normal",
                "match": {"all": ["event.type == 'content_published'"]},
                "gates": {"locales": ["*"], "channels": ["web", "mobile"], "time_windows": []},
                "score": {"formula": "weight('recency')*exp_decay(hours_since(content.published_at), half_life_hours=8) + weight('engagement')*sigmoid(content.metrics.d1_ctr, k=10, x0=0.06)", "min_score": 0.01},
                "placement": {"slot": "main", "ttl_s": 21600},
            },
        ],
        "tiebreakers": {"order": ["score_desc", "recency_desc", "random"]},
    }

    engine = ChronologyEngine(example_rules, state=InMemoryTTLStore())

    now = datetime.now(timezone.utc).isoformat()
    req = FeedRequest(user={"id": "u1", "d30_sessions": 10, "locale": "en"}, locale="en", channel="web", max_feed_size=6)
    candidates = [
        Candidate(id="c1", content={"content_id": "c1", "tags": ["breaking"], "published_at": now, "metrics": {"d1_ctr": 0.12}}, event={"type": "content_published"}, publisher={"id": "p1"}),
        Candidate(id="c2", content={"content_id": "c2", "tags": ["misc"], "published_at": now, "metrics": {"d1_ctr": 0.03}}, event={"type": "content_published"}, publisher={"id": "p2"}),
        Candidate(id="c3", content={"content_id": "c3", "tags": ["misc"], "published_at": now, "metrics": {"d1_ctr": 0.09}}, event={"type": "content_published"}, publisher={"id": "p2"}),
    ]

    feed = engine.build_feed(req, candidates)
    print("FEED:", [f"{c.rule_id}:{c.id}:{c.slot}:{round(c.score,3)}" for c in feed.items])
    print("DIAG:", feed.diagnostics)
