# path: veilmind-core/veilmind/risk/k_anonymity.py
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime
from statistics import median
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

try:
    import pandas as pd  # type: ignore
except Exception:  # pragma: no cover
    pd = None  # type: ignore

Record = Dict[str, Any]
Dataset = Union[List[Record], "pd.DataFrame"]  # type: ignore[name-defined]

Severity = Literal["low", "medium", "high", "critical"]

# ======================================================================
# Конфигурация и отчёты
# ======================================================================

@dataclass(frozen=True)
class GeneralizerSpec:
    """
    Описание генерализатора для одного столбца.

    kind:
      - numeric_bin: числовая биновка (width или bins)
      - datetime: уровни ('minute','hour','day','week','month','quarter','year')
      - ip: префиксная агрегация (CIDR /8..../128)
      - email: обрезка до домена или маска локальной части
      - taxonomy: иерархическая карта категорий (leaf -> parent chain)
      - string_prefix: усечение строки по длине
      - passthrough: без генерализации (для совместимости планов)
    """
    kind: Literal["numeric_bin", "datetime", "ip", "email", "taxonomy", "string_prefix", "passthrough"]
    params: Dict[str, Any] = None  # noqa: UP007

    def __post_init__(self):
        if self.params is None:
            object.__setattr__(self, "params", {})


@dataclass(frozen=True)
class RiskConfig:
    quasi_identifiers: Tuple[str, ...]
    sensitive_attributes: Tuple[str, ...] = tuple()
    target_k: int = 5
    target_l: Optional[int] = None
    target_t: Optional[float] = None  # 0..1, Earth Mover's Distance surrogate (TV distance)
    max_suppression_rate: float = 0.02  # не более 2% записей под нож
    generalizers: Dict[str, GeneralizerSpec] = None  # noqa: UP007
    metrics: Tuple[str, ...] = ("k", "avg_risk", "ncp", "dp")

    def __post_init__(self):
        if self.generalizers is None:
            object.__setattr__(self, "generalizers", {})


@dataclass(frozen=True)
class RiskReport:
    rows: int
    quasi_identifiers: Tuple[str, ...]
    min_k: int
    avg_reident_risk: float  # средний 1/|EC|
    risky_fraction: float    # доля записей в EC с размером < target_k
    l_diversity_ok: Optional[bool]
    t_closeness_ok: Optional[bool]
    ec_histogram: Dict[int, int]  # размер EC -> сколько EC
    severity: Severity


@dataclass(frozen=True)
class PlanStep:
    column: str
    level_before: int
    level_after: int
    info_loss_delta: float
    min_k_after: int


@dataclass(frozen=True)
class AnonymizationPlan:
    """
    Уровни генерализации по столбцам (целые уровни, трактовка зависит от генерализатора).
    """
    levels: Dict[str, int]
    steps: Tuple[PlanStep, ...]


@dataclass(frozen=True)
class AnonymizationResult:
    report_before: RiskReport
    report_after: RiskReport
    plan: AnonymizationPlan
    suppressed: int
    suppression_rate: float
    info_loss_ncp: float
    info_loss_dp: int


# ======================================================================
# Утилиты
# ======================================================================

def _is_dataframe(data: Dataset) -> bool:
    return pd is not None and isinstance(data, pd.DataFrame)  # type: ignore[name-defined]

def _iter_records(data: Dataset) -> Iterable[Record]:
    if _is_dataframe(data):
        for _, row in data.iterrows():  # type: ignore[no-any-return]
            yield row.to_dict()
    else:
        yield from data  # type: ignore[misc]

def _safe_get(rec: Record, key: str) -> Any:
    v = rec.get(key, None)
    # нормализация дат
    if isinstance(v, datetime):
        return v
    if isinstance(v, date):
        return datetime(v.year, v.month, v.day)
    return v

def _bucket_numeric(x: Any, width: Optional[float], bins: Optional[int], current_level: int) -> Any:
    if x is None:
        return None
    try:
        val = float(x)
    except Exception:
        return x
    # увеличиваем ширину с уровнем: width * 2^level
    if width:
        w = width * (2 ** current_level)
        a = math.floor(val / w) * w
        b = a + w
        return f"[{a:.4g},{b:.4g})"
    if bins:
        # уровень повышает агрегацию: фактически уменьшаем число бинов в 2^level раз
        eff_bins = max(1, bins // (2 ** current_level))
        # применим простую равную ширину в [min,max] на лету — без полного прохода это приблизительно
        # для стабильности округлим к десяткам/сотням
        w = 10 ** max(0, int(math.log10(abs(val) + 1)) - 2)
        w = max(w, 1.0)
        k = math.floor(val / (w * eff_bins))
        a = k * w * eff_bins
        b = a + w * eff_bins
        return f"[{a:.4g},{b:.4g})"
    return x

def _generalize_datetime(x: Any, level: int, base: str = "day") -> Any:
    if x is None:
        return None
    if not isinstance(x, (datetime, date)):
        # попытка парсинга ISO
        try:
            x = datetime.fromisoformat(str(x))
        except Exception:
            return x
    if isinstance(x, date) and not isinstance(x, datetime):
        x = datetime(x.year, x.month, x.day)
    # уровни по возрастанию обобщения
    order = ["minute", "hour", "day", "week", "month", "quarter", "year"]
    if base in order:
        base_idx = order.index(base)
    else:
        base_idx = 2  # day
    idx = min(base_idx + level, len(order) - 1)
    kind = order[idx]
    if kind == "minute":
        return x.replace(second=0, microsecond=0).isoformat(timespec="minutes")
    if kind == "hour":
        return x.replace(minute=0, second=0, microsecond=0).isoformat(timespec="hours")
    if kind == "day":
        return x.date().isoformat()
    if kind == "week":
        y, w, _ = x.isocalendar()
        return f"{y}-W{w:02d}"
    if kind == "month":
        return f"{x.year:04d}-{x.month:02d}"
    if kind == "quarter":
        q = (x.month - 1) // 3 + 1
        return f"{x.year:04d}-Q{q}"
    if kind == "year":
        return f"{x.year:04d}"
    return x

def _generalize_ip(x: Any, level: int, base_prefix: int = 24) -> Any:
    if x is None:
        return None
    try:
        ip = ipaddress.ip_address(str(x))
    except Exception:
        return x
    # расширяем сеть: уменьшаем префикс на level*2 (чем больше level, тем короче префикс)
    maxbits = 128 if ip.version == 6 else 32
    pref = max(0, min(maxbits, base_prefix - level * 2))
    net = ipaddress.ip_network(f"{ip}/{pref}", strict=False)
    return str(net)

def _generalize_email(x: Any, level: int, mode: str = "domain") -> Any:
    if x is None:
        return None
    s = str(x)
    if "@" not in s:
        return s
    user, dom = s.split("@", 1)
    if mode == "domain":
        # level 0: user@domain, 1: *@domain, 2: *@*.tld
        if level <= 0:
            return f"{user}@{dom}"
        if level == 1:
            return f"*@" + dom
        # попытка обобщить домен
        parts = dom.split(".")
        if len(parts) >= 2:
            return f"*@" + "*." + parts[-1]
        return "*@*"
    # mode == "mask"
    # level 0: u***@dom, 1: **@dom, 2: *@dom
    if level <= 0:
        return (user[:1] + "***") + "@" + dom
    if level == 1:
        return "**@" + dom
    return "*@" + dom

def _generalize_string_prefix(x: Any, level: int) -> Any:
    if x is None:
        return None
    s = str(x)
    keep = max(0, len(s) - level * 2)
    if keep == 0:
        return "*"
    return s[:keep] + "*"

def _taxonomy_up(value: Any, level: int, chain_map: Dict[str, List[str]]) -> Any:
    """
    chain_map: leaf -> [parent1, parent2, ...] (где parentN самый общий)
    level: сколько уровней вверх подняться
    """
    if value is None:
        return None
    key = str(value)
    chain = chain_map.get(key)
    if not chain:
        return key
    idx = min(level - 1, len(chain) - 1) if level > 0 else -1
    if idx < 0:
        return key
    return chain[idx]

def _ec_signature(rec: Record, qis: Sequence[str]) -> Tuple[Any, ...]:
    return tuple(_safe_get(rec, c) for c in qis)

def _equivalence_classes(records: Iterable[Record], qis: Sequence[str]) -> Dict[Tuple[Any, ...], int]:
    counter: Dict[Tuple[Any, ...], int] = defaultdict(int)
    for r in records:
        sig = _ec_signature(r, qis)
        counter[sig] += 1
    return counter

def _avg_reident_risk(ec_sizes: Iterable[int]) -> float:
    # средний риск = (1/N) * sum_{EC}( |EC| * (1/|EC|) ) = (#EC) / N
    sizes = list(ec_sizes)
    if not sizes:
        return 0.0
    N = sum(sizes)
    return len(sizes) / float(N)

def _severity(min_k: int, target_k: int, risky_frac: float) -> Severity:
    if min_k >= target_k and risky_frac == 0:
        return "low"
    if min_k >= max(2, target_k // 2) and risky_frac <= 0.05:
        return "medium"
    if min_k >= 2:
        return "high"
    return "critical"

# ======================================================================
# Метрики потерь информации
# ======================================================================

def _ncp_column(original: List[Any], generalized: List[Any]) -> float:
    """
    Normalized Certainty Penalty (0..1) для одного столбца.
    Здесь упрощённая версия:
      - числовые интервалы вида [a,b) -> (b-a)/(max-min)
      - даты: шкала в днях
      - категории/строки: доля слияний (число уникальных значений до / после)
    """
    if not original:
        return 0.0
    # различим числовые интервалы
    def parse_interval(s: str) -> Optional[Tuple[float, float]]:
        m = re.match(r"^\[\s*([\-0-9\.eE]+)\s*,\s*([\-0-9\.eE]+)\s*\)$", s or "")
        if not m:
            return None
        return float(m.group(1)), float(m.group(2))

    # диапазоны исходных значений
    nums = []
    dates = []
    for v in original:
        if isinstance(v, (int, float)):
            nums.append(float(v))
        elif isinstance(v, (datetime, date)):
            dates.append(v if isinstance(v, datetime) else datetime(v.year, v.month, v.day))
    if nums:
        minv, maxv = min(nums), max(nums)
        rng = max(maxv - minv, 1e-9)
        acc = 0.0
        for g in generalized:
            iv = parse_interval(str(g))
            if iv:
                acc += (iv[1] - iv[0]) / rng
            else:
                acc += 1.0  # полная потеря если не интервал
        return min(1.0, acc / len(generalized))
    if dates:
        minv, maxv = min(dates), max(dates)
        rng = max((maxv - minv).days, 1)
        acc = 0.0
        for g in generalized:
            s = str(g)
            # грубая оценка ширины по шаблонам
            if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
                w = 1
            elif re.match(r"^\d{4}-W\d{2}$", s):
                w = 7
            elif re.match(r"^\d{4}-\d{2}$", s):
                w = 30
            elif re.match(r"^\d{4}-Q[1-4]$", s):
                w = 90
            elif re.match(r"^\d{4}$", s):
                w = 365
            else:
                w = rng
            acc += w / rng
        return min(1.0, acc / len(generalized))
    # категориальные
    uniq_before = len(set(map(str, original)))
    uniq_after = len(set(map(str, generalized))) or 1
    return min(1.0, max(0.0, 1.0 - (uniq_after / uniq_before)))

def _discernibility_penalty(ec_sizes: Iterable[int]) -> int:
    # DP = sum(|EC|^2) — чем меньше, тем лучше
    return sum(s * s for s in ec_sizes)

# ======================================================================
# Вычисление k, l, t
# ======================================================================

def evaluate_risk(data: Dataset, cfg: RiskConfig) -> RiskReport:
    records = list(_iter_records(data))
    N = len(records)
    if N == 0:
        return RiskReport(
            rows=0,
            quasi_identifiers=cfg.quasi_identifiers,
            min_k=0,
            avg_reident_risk=0.0,
            risky_fraction=0.0,
            l_diversity_ok=None,
            t_closeness_ok=None,
            ec_histogram={},
            severity="low",
        )

    ecs = _equivalence_classes(records, cfg.quasi_identifiers)
    sizes = list(ecs.values())
    min_k = min(sizes) if sizes else 0
    risky_recs = sum(c for c in sizes if c < cfg.target_k)
    risky_fraction = risky_recs / float(N)
    avg_risk = _avg_reident_risk(sizes)

    # l‑diversity: минимальная мощность множества значений по каждому чувств. атрибуту в каждом EC
    l_ok: Optional[bool] = None
    if cfg.target_l and cfg.sensitive_attributes:
        l_ok = True
        for key, cnt in ecs.items():
            members = [r for r in records if _ec_signature(r, cfg.quasi_identifiers) == key]
            for sa in cfg.sensitive_attributes:
                vals = set(str(_safe_get(r, sa)) for r in members)
                if len(vals) < cfg.target_l:
                    l_ok = False
                    break
            if l_ok is False:
                break

    # t‑closeness (замена EMD на Total Variation distance)
    t_ok: Optional[bool] = None
    if cfg.target_t and cfg.sensitive_attributes:
        # глобальные распределения
        global_dist: Dict[str, Counter] = {sa: Counter(str(_safe_get(r, sa)) for r in records) for sa in cfg.sensitive_attributes}
        for sa, c in global_dist.items():
            s = sum(c.values()) or 1
            for k in list(c.keys()):
                c[k] = c[k] / s  # type: ignore[assignment]
        t_ok = True
        for key, cnt in ecs.items():
            members = [r for r in records if _ec_signature(r, cfg.quasi_identifiers) == key]
            for sa in cfg.sensitive_attributes:
                loc = Counter(str(_safe_get(r, sa)) for r in members)
                s = sum(loc.values()) or 1
                for k in list(loc.keys()):
                    loc[k] = loc[k] / s  # type: ignore[assignment]
                # TVD
                keys = set(global_dist[sa].keys()) | set(loc.keys())
                tv = 0.5 * sum(abs(global_dist[sa].get(k, 0.0) - loc.get(k, 0.0)) for k in keys)
                if tv > float(cfg.target_t):
                    t_ok = False
                    break
            if t_ok is False:
                break

    sev = _severity(min_k, cfg.target_k, risky_fraction)
    hist: Dict[int, int] = Counter(sizes)  # type: ignore[assignment]
    return RiskReport(
        rows=N,
        quasi_identifiers=cfg.quasi_identifiers,
        min_k=min_k,
        avg_reident_risk=avg_risk,
        risky_fraction=risky_fraction,
        l_diversity_ok=l_ok,
        t_closeness_ok=t_ok,
        ec_histogram=dict(sorted(hist.items())),
        severity=sev,
    )

# ======================================================================
# Генерализация и подавление
# ======================================================================

def _apply_generalization(rec: Record, col: str, level: int, spec: GeneralizerSpec) -> Any:
    v = _safe_get(rec, col)
    if spec.kind == "numeric_bin":
        width = spec.params.get("width")
        bins = spec.params.get("bins")
        return _bucket_numeric(v, width, bins, level)
    if spec.kind == "datetime":
        base = spec.params.get("base", "day")
        return _generalize_datetime(v, level, base=base)
    if spec.kind == "ip":
        base_pref = int(spec.params.get("base_prefix", 24))
        return _generalize_ip(v, level, base_prefix=base_pref)
    if spec.kind == "email":
        mode = spec.params.get("mode", "domain")
        return _generalize_email(v, level, mode=mode)
    if spec.kind == "string_prefix":
        return _generalize_string_prefix(v, level)
    if spec.kind == "taxonomy":
        mapping = spec.params.get("chain_map", {}) or {}
        return _taxonomy_up(v, level, mapping)
    return v  # passthrough

def _transform_dataset(data: Dataset, plan_levels: Dict[str, int], specs: Dict[str, GeneralizerSpec]) -> List[Record]:
    out: List[Record] = []
    for rec in _iter_records(data):
        newr = dict(rec)
        for col, lvl in plan_levels.items():
            spec = specs.get(col, GeneralizerSpec("passthrough"))
            newr[col] = _apply_generalization(rec, col, lvl, spec)
        out.append(newr)
    return out

def _compute_info_loss(data: Dataset, transformed: List[Record], qi_cols: Sequence[str]) -> Tuple[float, int]:
    # NCP по каждому QI и Discernibility Penalty по EC
    orig_cols: Dict[str, List[Any]] = defaultdict(list)
    gen_cols: Dict[str, List[Any]] = defaultdict(list)
    for r, g in zip(_iter_records(data), transformed):
        for c in qi_cols:
            orig_cols[c].append(_safe_get(r, c))
            gen_cols[c].append(_safe_get(g, c))
    ncp_vals = [_ncp_column(orig_cols[c], gen_cols[c]) for c in qi_cols]
    ecs = _equivalence_classes(transformed, qi_cols)
    dp = _discernibility_penalty(ecs.values())
    return (sum(ncp_vals) / max(1, len(ncp_vals))), dp

def suppress_outliers(records: List[Record], qi_cols: Sequence[str], target_k: int, max_rate: float) -> Tuple[List[Record], int]:
    """
    Подавляет записи из наименьших EC до достижения min_k>=target_k в разумных пределах.
    """
    ecs_map: Dict[Tuple[Any, ...], List[int]] = defaultdict(list)
    for idx, r in enumerate(records):
        ecs_map[_ec_signature(r, qi_cols)].append(idx)
    sizes = {k: len(v) for k, v in ecs_map.items()}
    N = len(records)
    suppressed = set()
    # сортируем EC по возрастанию размера
    for sig, idxs in sorted(ecs_map.items(), key=lambda kv: len(kv[1])):
        if len(idxs) >= target_k:
            continue
        need = min(len(idxs), target_k - len(idxs))
        # подавим целиком EC, если это самые мелкие
        for i in idxs[:need]:
            suppressed.add(i)
        if len(suppressed) / float(N) >= max_rate:
            break
    new_records = [r for i, r in enumerate(records) if i not in suppressed]
    return new_records, len(suppressed)

# ======================================================================
# Планирование генерализации (жадный оптимизатор)
# ======================================================================

def plan_anonymization(data: Dataset, cfg: RiskConfig, max_level_per_col: int = 6) -> AnonymizationPlan:
    """
    Жадно увеличивает уровни генерализации столбцов, выбирая шаг с минимальным ростом NCP,
    пока не будет достигнут min_k >= target_k или пока уровни не исчерпаны.
    """
    levels: Dict[str, int] = {c: 0 for c in cfg.quasi_identifiers}
    steps: List[PlanStep] = []

    def current_report(plan_levels: Dict[str, int]) -> Tuple[RiskReport, float, int, List[Record]]:
        transformed = _transform_dataset(data, plan_levels, cfg.generalizers)
        rep = evaluate_risk(transformed, cfg)
        ncp, dp = _compute_info_loss(data, transformed, cfg.quasi_identifiers)
        return rep, ncp, dp, transformed

    base_rep, base_ncp, base_dp, base_trans = current_report(levels)
    if base_rep.min_k >= cfg.target_k:
        return AnonymizationPlan(levels=levels, steps=tuple())

    report = base_rep
    ncp = base_ncp
    dp = base_dp
    transformed = base_trans

    for _ in range(len(cfg.quasi_identifiers) * max_level_per_col):
        best_step: Optional[PlanStep] = None
        best_levels: Optional[Dict[str, int]] = None
        best_rep: Optional[RiskReport] = None
        best_ncp: Optional[float] = None
        best_dp: Optional[int] = None
        # перебираем возможные инкременты по каждому столбцу
        for col in cfg.quasi_identifiers:
            if levels[col] >= max_level_per_col:
                continue
            cand = dict(levels)
            cand[col] = levels[col] + 1
            cand_rep, cand_ncp, cand_dp, _ = current_report(cand)
            step = PlanStep(
                column=col,
                level_before=levels[col],
                level_after=cand[col],
                info_loss_delta=max(0.0, cand_ncp - ncp),
                min_k_after=cand_rep.min_k,
            )
            # приоритет: достигнуть target_k -> минимальный NCP delta -> минимальный DP
            better = False
            if (best_rep is None) or (cand_rep.min_k > (best_rep.min_k if best_rep else -1)):
                better = True
            elif cand_rep.min_k == (best_rep.min_k if best_rep else -1):
                if step.info_loss_delta < (best_step.info_loss_delta if best_step else float("inf")):
                    better = True
                elif math.isclose(step.info_loss_delta, (best_step.info_loss_delta if best_step else 0.0), rel_tol=1e-9):
                    if cand_dp < (best_dp if best_dp is not None else float("inf")):
                        better = True
            if better:
                best_step = step
                best_levels = cand
                best_rep = cand_rep
                best_ncp = cand_ncp
                best_dp = cand_dp

        if not best_step or not best_levels or not best_rep or best_ncp is None or best_dp is None:
            break

        # применяем лучший шаг
        levels = best_levels
        steps.append(best_step)
        report = best_rep
        ncp = best_ncp
        dp = best_dp

        if report.min_k >= cfg.target_k:
            break

    return AnonymizationPlan(levels=levels, steps=tuple(steps))

# ======================================================================
# Публичный API: полный цикл
# ======================================================================

def anonymize_to_k(data: Dataset, cfg: RiskConfig) -> AnonymizationResult:
    """
    Выполняет:
      1) первичную оценку риска,
      2) планирование генерализации,
      3) генерализацию,
      4) допустимое подавление аутлаеров.

    Возвращает отчёт и итоговые метрики потерь.
    """
    report_before = evaluate_risk(data, cfg)

    plan = plan_anonymization(data, cfg)
    transformed = _transform_dataset(data, plan.levels, cfg.generalizers)

    # При необходимости — подавление для оставшихся мелких EC
    transformed_after_suppress = transformed
    suppressed = 0
    if evaluate_risk(transformed, cfg).min_k < cfg.target_k and cfg.max_suppression_rate > 0:
        transformed_after_suppress, suppressed = suppress_outliers(
            transformed, cfg.quasi_identifiers, cfg.target_k, cfg.max_suppression_rate
        )

    report_after = evaluate_risk(transformed_after_suppress, cfg)
    ncp, dp = _compute_info_loss(data, transformed_after_suppress, cfg.quasi_identifiers)

    return AnonymizationResult(
        report_before=report_before,
        report_after=report_after,
        plan=plan,
        suppressed=suppressed,
        suppression_rate=(suppressed / float(report_before.rows)) if report_before.rows else 0.0,
        info_loss_ncp=ncp,
        info_loss_dp=dp,
    )

# ======================================================================
# Примеры генерализаторов по умолчанию (можно использовать в конфиге)
# ======================================================================

def default_generalizers(qi_cols: Sequence[str]) -> Dict[str, GeneralizerSpec]:
    specs: Dict[str, GeneralizerSpec] = {}
    for c in qi_cols:
        cname = c.lower()
        if "date" in cname or "time" in cname or "ts" in cname:
            specs[c] = GeneralizerSpec("datetime", {"base": "day"})
        elif "ip" in cname:
            specs[c] = GeneralizerSpec("ip", {"base_prefix": 24})
        elif "email" in cname or "mail" in cname:
            specs[c] = GeneralizerSpec("email", {"mode": "domain"})
        elif "zip" in cname or "post" in cname:
            specs[c] = GeneralizerSpec("string_prefix", {})
        else:
            specs[c] = GeneralizerSpec("numeric_bin", {"width": 1.0})
    return specs

# ======================================================================
# Пример self‑test (можно дергать из CI)
# ======================================================================

if __name__ == "__main__":  # pragma: no cover
    # Синтетический набор
    data = [
        {"user_id": "u1", "age": 23, "zip": "10001", "ip": "203.0.113.10", "ts": "2025-08-01T12:34:00", "diagnosis": "A"},
        {"user_id": "u2", "age": 24, "zip": "10002", "ip": "203.0.113.11", "ts": "2025-08-01T12:35:00", "diagnosis": "B"},
        {"user_id": "u3", "age": 25, "zip": "10003", "ip": "203.0.113.12", "ts": "2025-08-01T12:36:00", "diagnosis": "B"},
        {"user_id": "u4", "age": 29, "zip": "10009", "ip": "203.0.113.13", "ts": "2025-08-02T09:10:00", "diagnosis": "A"},
        {"user_id": "u5", "age": 31, "zip": "10010", "ip": "203.0.113.14", "ts": "2025-08-03T11:00:00", "diagnosis": "C"},
        {"user_id": "u6", "age": 32, "zip": "10010", "ip": "203.0.113.15", "ts": "2025-08-03T11:05:00", "diagnosis": "C"},
    ]
    cfg = RiskConfig(
        quasi_identifiers=("age", "zip", "ip", "ts"),
        sensitive_attributes=("diagnosis",),
        target_k=3,
        target_l=2,
        target_t=0.4,
        generalizers={
            "age": GeneralizerSpec("numeric_bin", {"width": 2.0}),
            "zip": GeneralizerSpec("string_prefix", {}),
            "ip": GeneralizerSpec("ip", {"base_prefix": 24}),
            "ts": GeneralizerSpec("datetime", {"base": "day"}),
        },
        max_suppression_rate=0.1,
    )

    before = evaluate_risk(data, cfg)
    print("Before:", before)

    result = anonymize_to_k(data, cfg)
    print("Plan:", result.plan)
    print("After:", result.report_after)
    print("Suppressed:", result.suppressed, f"({result.suppression_rate*100:.2f}%)")
    print("NCP:", round(result.info_loss_ncp, 4), "DP:", result.info_loss_dp)
