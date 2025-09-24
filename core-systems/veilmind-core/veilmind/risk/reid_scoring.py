# File: veilmind-core/veilmind/risk/reid_scoring.py
from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

Number = Union[int, float]
Record = Mapping[str, Any]
Key = Tuple[Any, ...]
Generalizer = Callable[[Any], Any]

# =============================================================================
# Конфигурация и модели атак
# =============================================================================

@dataclass(frozen=True)
class AttackerModel:
    """
    Модель атакующего — определяет трактовку вероятности присутствия цели в датасете
    и правило для пересчета размера эквивалентного класса в риск.

    Опорные предпосылки (модельные, для практического скоринга):
      - Prosecutor: злоумышленник знает, что цель присутствует в датасете -> риск ~ 1/k.
      - Journalist: выбирает жертву среди тех, кто есть в датасете -> риск ~ 1/k.
      - Marketer: выбирает случайную персону из популяции -> риск ~ s/k, где s — доля выборки (sampling fraction).
    """
    name: str  # 'prosecutor' | 'journalist' | 'marketer'
    sampling_fraction: float = 1.0  # s \in (0,1]; для marketer < 1
    weight: float = 1.0            # вклад модели в итоговый скор

    def record_risk(self, k: int) -> float:
        if k <= 0:
            return 1.0
        base = 1.0 / float(k)
        if self.name == "marketer":
            return min(1.0, max(0.0, self.sampling_fraction) * base)
        # prosecutor, journalist
        return base


@dataclass(frozen=True)
class ScoringWeights:
    """
    Веса компонентов итогового скора.
    Все веса нормируются так, чтобы сумма была 1.0.
    """
    attacker: float = 0.7          # вклад моделей атак
    l_diversity: float = 0.2       # штраф за низкую l-diversity
    t_closeness: float = 0.1       # штраф за высокую t-closeness (дистанцию)

    def normalized(self) -> "ScoringWeights":
        s = max(1e-12, self.attacker + self.l_diversity + self.t_closeness)
        return ScoringWeights(self.attacker / s, self.l_diversity / s, self.t_closeness / s)


@dataclass(frozen=True)
class ReidConfig:
    """
    Конфигурация скоринга риска повторной идентификации.
    """
    quasi_identifiers: Sequence[str]
    sensitive_attributes: Sequence[str] = ()
    generalizers: Mapping[str, Generalizer] = field(default_factory=dict)
    attacker_models: Sequence[AttackerModel] = field(default_factory=lambda: (
        AttackerModel("prosecutor", sampling_fraction=1.0, weight=0.5),
        AttackerModel("journalist", sampling_fraction=1.0, weight=0.3),
        AttackerModel("marketer", sampling_fraction=0.1, weight=0.2),
    ))
    weights: ScoringWeights = field(default_factory=ScoringWeights)
    missing_as_category: bool = True      # пропуски в QI считать отдельной категорией
    max_categories_for_t: int = 200       # ограничение числа категорий при t-closeness
    t_distance: str = "tv"                # 'tv' (total variation) | 'emd' (1D EMD по рангу)
    score_scale_max: float = 100.0        # итоговый скор в [0, score_scale_max]


# =============================================================================
# Утилиты обобщения значений (format/generalization helpers)
# =============================================================================

def gen_identity(x: Any) -> Any:
    return x

def gen_str_lower(x: Any) -> Any:
    return None if x is None else str(x).strip().lower()

def gen_numeric_bin(width: Number) -> Generalizer:
    w = float(width)
    if w <= 0:
        raise ValueError("width must be > 0")
    def _g(v: Any) -> Any:
        if v is None:
            return None
        x = float(v)
        b = math.floor(x / w) * w
        return f"[{b:g},{b + w:g})"
    return _g

def gen_date_trunc(unit: str = "month") -> Generalizer:
    unit = unit.lower()
    if unit not in ("year", "month", "day"):
        raise ValueError("unit must be year|month|day")
    def _g(v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, datetime):
            d = v.date()
        elif isinstance(v, date):
            d = v
        else:
            s = str(v)
            for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y-%m", "%Y/%m", "%Y"):
                try:
                    d = datetime.strptime(s, fmt).date()
                    break
                except Exception:
                    d = None  # type: ignore[assignment]
            if d is None:
                return s
        if unit == "year":
            return f"{d.year:04d}"
        if unit == "month":
            return f"{d.year:04d}-{d.month:02d}"
        return f"{d.isoformat()}"
    return _g


# =============================================================================
# Основной скорер
# =============================================================================

@dataclass
class EquivalenceClass:
    key: Key
    size: int
    sensitive_counts: Dict[str, Counter]  # attr -> Counter(value -> count)

    def k(self) -> int:
        return self.size

    def l_diversity(self, attr: str) -> int:
        c = self.sensitive_counts.get(attr)
        return 0 if c is None else len([v for v, n in c.items() if n > 0])

@dataclass
class RecordScore:
    index: int
    key: Key
    k: int
    # Сырые компоненты риска
    attacker_risk: float
    l_penalty: float
    t_penalty: float
    # Итоговый скор (0..scale_max)
    score: float
    # Пояснения
    explain: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DatasetReport:
    n_records: int
    n_classes: int
    unique_ratio: float
    k_min: int
    k_p05: int
    k_p50: int
    k_p95: int
    l_min: Dict[str, int]
    l_avg: Dict[str, float]
    t_avg: Dict[str, float]
    class_size_histogram: Dict[int, int]  # k -> count of classes
    notes: List[str] = field(default_factory=list)


class ReidScorer:
    """
    Оценка риска повторной идентификации.

    Потоковый подсчёт:
      1) fit(records) — строит эквивалентные классы по квазиидентификаторам.
      2) score_records(records) — выдаёт скор для каждой записи (в исходном порядке).
      3) report() — агрегированные метрики датасета.
    """

    def __init__(self, cfg: ReidConfig):
        self.cfg = cfg
        self._qi = list(cfg.quasi_identifiers)
        self._sa = list(cfg.sensitive_attributes)
        self._gen = {name: cfg.generalizers.get(name, gen_identity) for name in self._qi}
        self._classes: Dict[Key, EquivalenceClass] = {}
        self._global_sa_freq: Dict[str, Counter] = {a: Counter() for a in self._sa}
        self._n = 0

    # -------------------- построение эквивалентных классов --------------------

    def fit(self, records: Iterable[Record]) -> "ReidScorer":
        classes_counts: Dict[Key, int] = defaultdict(int)
        sa_counts: Dict[Key, Dict[str, Counter]] = defaultdict(lambda: {a: Counter() for a in self._sa})
        global_sa = {a: Counter() for a in self._sa}

        for rec in records:
            self._n += 1
            key = self._key_for(rec)
            classes_counts[key] += 1
            for a in self._sa:
                val = rec.get(a, None)
                if val is None and not self.cfg.missing_as_category:
                    continue
                gval = val
                global_sa[a][gval] += 1
                sa_counts[key][a][gval] += 1

        # материализация классов
        self._classes.clear()
        for k, cnt in classes_counts.items():
            self._classes[k] = EquivalenceClass(key=k, size=cnt, sensitive_counts=sa_counts.get(k, {}))
        self._global_sa_freq = global_sa
        return self

    # ------------------------------ скоринг -----------------------------------

    def score_records(self, records: Iterable[Record]) -> Iterator[RecordScore]:
        weights = self.cfg.weights.normalized()
        # предрасчёт t‑closeness для классов (по каждому SA)
        t_by_class_attr: Dict[Tuple[Key, str], float] = {}
        if self._sa:
            for key, eq in self._classes.items():
                for a in self._sa:
                    t_by_class_attr[(key, a)] = self._t_closeness(eq, a)

        # подготовка нормировки по l (для штрафа)
        # Чем меньше l, тем выше штраф; l==1 -> 1.0, l>=L_ref -> ~0
        l_ref = 5  # референсный уровень разнообразия
        for idx, rec in enumerate(records):
            key = self._key_for(rec)
            eq = self._classes.get(key)
            if not eq:
                # запись вне обучающей выборки — максимально консервативный риск
                base_risk = 1.0
                lpen = 1.0 if self._sa else 0.0
                tpen = 1.0 if self._sa else 0.0
                final = self._aggregate_score(base_risk, lpen, tpen, weights)
                yield RecordScore(index=idx, key=key, k=0, attacker_risk=base_risk, l_penalty=lpen, t_penalty=tpen, score=final, explain={"unknown_class": True})
                continue

            k = max(1, eq.k())
            # риск по моделям атак
            a_risks, a_expl = self._attacker_risks(k)
            attacker_risk = sum(a_risks)

            # l‑diversity штраф: усредним по SA
            l_vals: List[float] = []
            l_detail: Dict[str, int] = {}
            for a in self._sa:
                l = eq.l_diversity(a)
                l_detail[a] = l
                l_pen = 1.0 if l <= 1 else max(0.0, (l_ref - min(l, l_ref)) / (l_ref - 1))
                l_vals.append(l_pen)
            l_penalty = float(sum(l_vals) / len(l_vals)) if l_vals else 0.0

            # t‑closeness штраф: усредним по SA
            t_vals: List[float] = []
            t_detail: Dict[str, float] = {}
            for a in self._sa:
                tval = t_by_class_attr.get((key, a), 0.0)
                t_detail[a] = tval
                # нормируем TV/EMD в [0,1] (TV уже в [0,1], EMD по рангу тоже ограничим 1)
                t_vals.append(max(0.0, min(1.0, tval)))
            t_penalty = float(sum(t_vals) / len(t_vals)) if t_vals else 0.0

            final = self._aggregate_score(attacker_risk, l_penalty, t_penalty, weights)
            yield RecordScore(
                index=idx,
                key=key,
                k=k,
                attacker_risk=attacker_risk,
                l_penalty=l_penalty,
                t_penalty=t_penalty,
                score=final,
                explain={
                    "models": a_expl,
                    "l_diversity": l_detail,
                    "t_closeness": t_detail,
                },
            )

    # ------------------------------ отчёт -------------------------------------

    def report(self) -> DatasetReport:
        if not self._classes:
            return DatasetReport(
                n_records=0, n_classes=0, unique_ratio=0.0,
                k_min=0, k_p05=0, k_p50=0, k_p95=0,
                l_min={}, l_avg={}, t_avg={}, class_size_histogram={}
            )
        sizes = [c.size for c in self._classes.values()]
        n = max(1, self._n)
        hist: Dict[int, int] = Counter(sizes)
        k_sorted = sorted(sizes)
        def _quantile(q: float) -> int:
            if not k_sorted:
                return 0
            i = int(max(0, min(len(k_sorted)-1, round(q * (len(k_sorted)-1)))))
            return int(k_sorted[i])

        # l/t агрегаты
        l_min: Dict[str, int] = {}
        l_avg: Dict[str, float] = {}
        t_avg: Dict[str, float] = {}
        for a in self._sa:
            ls = [eq.l_diversity(a) for eq in self._classes.values()]
            l_min[a] = min(ls) if ls else 0
            l_avg[a] = float(sum(ls)/len(ls)) if ls else 0.0
            ts = [self._t_closeness(eq, a) for eq in self._classes.values()]
            t_avg[a] = float(sum(ts)/len(ts)) if ts else 0.0

        return DatasetReport(
            n_records=n,
            n_classes=len(self._classes),
            unique_ratio=float(sum(1 for s in sizes if s == 1)) / len(sizes),
            k_min=min(sizes),
            k_p05=_quantile(0.05),
            k_p50=_quantile(0.50),
            k_p95=_quantile(0.95),
            l_min=l_min,
            l_avg=l_avg,
            t_avg=t_avg,
            class_size_histogram=dict(hist),
            notes=[]
        )

    # =============================================================================
    # Внутренние методы
    # =============================================================================

    def _key_for(self, rec: Record) -> Key:
        vals: List[Any] = []
        for name in self._qi:
            v = rec.get(name, None)
            if v is None and not self.cfg.missing_as_category:
                vals.append(None)
                continue
            g = self._gen.get(name, gen_identity)
            vals.append(g(v))
        return tuple(vals)

    def _attacker_risks(self, k: int) -> Tuple[float, List[Dict[str, Any]]]:
        total_weight = sum(max(0.0, m.weight) for m in self.cfg.attacker_models) or 1.0
        risks = []
        expl = []
        for m in self.cfg.attacker_models:
            r = m.record_risk(k)
            w = max(0.0, m.weight) / total_weight
            risks.append(r * w)
            expl.append({"model": m.name, "risk": r, "weight": w})
        return sum(risks), expl

    def _aggregate_score(self, attacker_risk: float, l_penalty: float, t_penalty: float, w: ScoringWeights) -> float:
        w = w.normalized()
        # Итог: взвешенная сумма компонент, затем калибровка в [0, scale_max]
        raw = (
            w.attacker * attacker_risk +
            w.l_diversity * l_penalty +
            w.t_closeness * t_penalty
        )
        raw = max(0.0, min(1.0, raw))
        return raw * float(self.cfg.score_scale_max)

    def _t_closeness(self, eq: EquivalenceClass, attr: str) -> float:
        """
        t‑closeness как total variation (TV) между условным распределением SA в классе
        и глобальным распределением. TV(P,Q) = 0.5 * sum |p_i - q_i|.
        Для числовых SA при больших доменах допускается ранговая EMD по квантилям.
        """
        local = eq.sensitive_counts.get(attr)
        global_c = self._global_sa_freq.get(attr)
        if not local or not global_c:
            return 0.0
        # ограничим количество категорий (хвост «прочее»)
        if self.cfg.t_distance == "tv":
            p, q = self._align_probs(local, global_c, self.cfg.max_categories_for_t)
            tv = 0.5 * sum(abs(pi - qi) for pi, qi in zip(p, q))
            return float(max(0.0, min(1.0, tv)))
        elif self.cfg.t_distance == "emd":
            # 1D EMD по ранговым позициям (псевдо-оценка)
            pvals, qvals = self._align_probs(local, global_c, self.cfg.max_categories_for_t)
            # приближенно возьмем L1 расстояние кумсум
            c1 = list(_cumsum(pvals))
            c2 = list(_cumsum(qvals))
            emd = sum(abs(a - b) for a, b in zip(c1, c2))
            return float(max(0.0, min(1.0, emd)))
        else:
            return 0.0

    @staticmethod
    def _align_probs(local: Counter, global_c: Counter, max_cats: int) -> Tuple[List[float], List[float]]:
        # Отберём top-(max_cats-1) категорий, остальное сольём в 'other'
        total_l = sum(local.values()) or 1
        total_g = sum(global_c.values()) or 1
        top = [k for k, _ in global_c.most_common(max(1, max_cats - 1))]
        cats = set(top) | set(local.keys())
        if len(cats) >= max_cats:
            # принудительно ограничим
            cats = set(top)  # остальное в 'other'
        p, q = [], []
        other_l = 0
        other_g = 0
        for c in local.keys():
            if c not in cats:
                other_l += local[c]
        for c in global_c.keys():
            if c not in cats:
                other_g += global_c[c]
        for c in cats:
            p.append(local.get(c, 0) / total_l)
            q.append(global_c.get(c, 0) / total_g)
        # добавим «other», если есть
        if other_l > 0 or other_g > 0:
            p.append(other_l / total_l)
            q.append(other_g / total_g)
        # нормализуем (на случай численной погрешности)
        _normalize(p)
        _normalize(q)
        return p, q


# =============================================================================
# Вспомогательные функции
# =============================================================================

def _normalize(xs: List[float]) -> None:
    s = sum(xs)
    if s <= 0:
        n = len(xs)
        if n == 0:
            return
        for i in range(n):
            xs[i] = 1.0 / n
        return
    for i in range(len(xs)):
        xs[i] = xs[i] / s

def _cumsum(xs: Iterable[float]) -> Iterator[float]:
    s = 0.0
    for x in xs:
        s += x
        yield s


# =============================================================================
# Пример использования
# =============================================================================

if __name__ == "__main__":
    # Мини‑демо с синтетическими данными
    data = [
        {"age": 33, "zip3": "123", "sex": "F", "diagnosis": "A"},
        {"age": 35, "zip3": "123", "sex": "F", "diagnosis": "B"},
        {"age": 33, "zip3": "123", "sex": "M", "diagnosis": "B"},
        {"age": 60, "zip3": "999", "sex": "F", "diagnosis": "C"},
        {"age": 60, "zip3": "999", "sex": "F", "diagnosis": "C"},
    ]

    cfg = ReidConfig(
        quasi_identifiers=("age", "zip3", "sex"),
        sensitive_attributes=("diagnosis",),
        generalizers={
            "age": gen_numeric_bin(5),   # биннинг по 5 лет
            "zip3": gen_str_lower,
            "sex": gen_identity,
        },
        attacker_models=(
            AttackerModel("prosecutor", sampling_fraction=1.0, weight=0.45),
            AttackerModel("journalist", sampling_fraction=1.0, weight=0.35),
            AttackerModel("marketer", sampling_fraction=0.02, weight=0.20),
        ),
        weights=ScoringWeights(attacker=0.7, l_diversity=0.2, t_closeness=0.1),
        t_distance="tv",
        score_scale_max=100.0,
    )

    scorer = ReidScorer(cfg).fit(data)
    print("=== REPORT ===")
    r = scorer.report()
    print("records:", r.n_records, "classes:", r.n_classes, "unique_ratio:", f"{r.unique_ratio:.2%}")
    print("k_min/k50/k95:", r.k_min, r.k_p50, r.k_p95)
    print("l_min:", r.l_min, "l_avg:", r.l_avg, "t_avg:", r.t_avg)
    print("hist:", r.class_size_histogram)

    print("\n=== SCORES ===")
    for s in scorer.score_records(data):
        print(f"i={s.index} key={s.key} k={s.k} risk={s.attacker_risk:.3f} lpen={s.l_penalty:.3f} tpen={s.t_penalty:.3f} score={s.score:.2f}")
        # print("  explain:", s.explain)
