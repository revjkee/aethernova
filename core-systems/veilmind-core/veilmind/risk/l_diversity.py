# -*- coding: utf-8 -*-
"""
VeilMind Core — l-diversity evaluator

Поддерживаемые определения:
  1) DISTINCT l-diversity:    |{SA}| >= l
  2) ENTROPY  l-diversity:    H(G) >= log_b(l)   (b=2 по умолчанию)
  3) RECURSIVE (c,l)-diversity: r1 < c * sum_{i=l..k} r_i (частоты убывающие)

Где:
  - G — эквивалентный класс (группа) по квазиидентификаторам (QI)
  - SA — чувствительный атрибут
  - r_i — частоты значений SA в группе (отсортированные по убыванию)
  - H(G) — энтропия Шеннона для распределения SA внутри группы

Особенности:
  - Потоковая агрегация без обязательного pandas (но поддерживается при наличии).
  - Настраиваемая обработка пропусков (исключать или считать отдельной категорией).
  - Приватные отчёты (без раскрытия сырых SA; опционально хеш‑превью).
  - Вычисление минимально достижимого l по каждой метрике на класс и в целом.
  - Оценка доли нарушающих групп при заданных параметрах (l, c).
  - Строгая типизация, без внешних рантайм‑зависимостей.

Автор: VeilMind Team
Лицензия: Apache-2.0
"""

from __future__ import annotations

import math
import os
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple, Union, DefaultDict
from collections import defaultdict

try:  # опционально ускоряемся, если установлен pandas
    import pandas as _pd  # type: ignore
    _HAS_PANDAS = True
except Exception:  # pragma: no cover
    _HAS_PANDAS = False


JsonLikeRecord = Mapping[str, Any]
RecordIterable = Iterable[JsonLikeRecord]


# =========================
# Конфиг и модели результатов
# =========================

@dataclass(frozen=True)
class LDiversityConfig:
    qi_columns: Tuple[str, ...]
    sensitive_column: str
    # База логарифма для энтропийного критерия (2 — биты)
    entropy_log_base: float = 2.0
    # Поведение при пропусках в SA:
    #  - "drop": игнорировать записи с SA == None/NaN
    #  - "as_value": учитывать как отдельную категорию "<NULL>"
    na_policy: str = "drop"
    # Ограничение на размер списка "нарушающих" групп в отчёте
    max_list_violators: int = 100
    # Приватный отчёт: не выводить реальные значения SA (только хеш‑превью)
    privacy_preserve: bool = True
    # Соль для хеша превью (если privacy_preserve=True)
    preview_hash_salt_env: str = "VEILMIND_PII_SALT"


@dataclass(frozen=True)
class GroupStats:
    key: Tuple[Any, ...]                  # ключ группы = значения QI
    size: int                             # |G|
    distinct: int                         # |{SA}|
    entropy: float                        # H(G) в выбранной базе
    p1: float                             # доля наиболее частого значения
    tail_sums: List[float]                # tail_sums[l] = sum_{i=l..k} p_i (l начиная с 1)
    # Для приватного отчёта (без сырых SA): словарь hash(value)->count
    preview: Optional[Dict[str, int]] = None


@dataclass(frozen=True)
class GroupDecision:
    key: Tuple[Any, ...]
    size: int
    # Минимально достижимое l по каждому определению
    min_l_distinct: int
    min_l_entropy: int
    # Для recursive: при заданном c минимальное l (если возможно), иначе 1
    min_l_recursive_c: Optional[int]
    # Признак соответствия при заданных порогах
    ok_distinct: bool
    ok_entropy: bool
    ok_recursive_c: Optional[bool]


@dataclass(frozen=True)
class LDiversityReport:
    total_groups: int
    records_total: int
    # Минимальные l по всем группам (dataset‑wide)
    dataset_min_l_distinct: int
    dataset_min_l_entropy: int
    dataset_min_l_recursive_c: Optional[int]
    # Доля групп, соответствующих заданным порогам
    share_ok_distinct: float
    share_ok_entropy: float
    share_ok_recursive_c: Optional[float]
    # Списки нарушителей (ключи групп), усечённые до max_list_violators
    violators_distinct: List[Tuple[Any, ...]] = field(default_factory=list)
    violators_entropy: List[Tuple[Any, ...]] = field(default_factory=list)
    violators_recursive_c: Optional[List[Tuple[Any, ...]]] = None
    # При необходимости — подробная статистика по группам
    groups: Optional[List[GroupStats]] = None
    decisions: Optional[List[GroupDecision]] = None


# =========================
# Утилиты
# =========================

_NULL_TOKEN = "<NULL>"

def _is_na(x: Any) -> bool:
    if x is None:
        return True
    try:
        # float('nan') != float('nan')
        return isinstance(x, float) and math.isnan(x)
    except Exception:
        return False

def _hash_preview(val: Any, salt: str) -> str:
    s = f"{val}".encode("utf-8", errors="ignore")
    h = hashlib.sha256()
    if salt:
        h.update(salt.encode("utf-8"))
        h.update(b"|")
    h.update(s)
    return "sha256:" + h.hexdigest()[:16]

def _log(x: float, base: float) -> float:
    return math.log(x) / math.log(base)


# =========================
# Основная логика
# =========================

class LDiversityEvaluator:
    """
    Вычисляет метрики l‑diversity на эквивалентных классах G (QI) по чувствительному атрибуту SA.
    """

    def __init__(self, config: LDiversityConfig) -> None:
        self.cfg = config
        if self.cfg.na_policy not in ("drop", "as_value"):
            raise ValueError("na_policy must be 'drop' or 'as_value'")
        if self.cfg.entropy_log_base <= 1.0:
            raise ValueError("entropy_log_base must be > 1.0")

    # ---------- публичные API ----------

    def evaluate(
        self,
        data: Union[RecordIterable, "._pd.DataFrame"],  # type: ignore[name-defined]
        *,
        l_threshold: int = 2,
        c_recursive: Optional[float] = None,
        include_group_stats: bool = False,
    ) -> LDiversityReport:
        """
        Вычисляет сводный отчёт по датасету.

        Параметры:
          - l_threshold: порог l для проверок distinct/entropy
          - c_recursive: параметр c для recursive (c,l); если None — не считать
          - include_group_stats: включить подробные GroupStats/GroupDecision (дороже)
        """
        groups, total_records = self._aggregate(data)
        salt = os.getenv(self.cfg.preview_hash_salt_env, "") if self.cfg.privacy_preserve else ""

        group_stats: List[GroupStats] = []
        decisions: List[GroupDecision] = []

        # Метрики для агрегирования
        dataset_min_l_distinct = float("inf")
        dataset_min_l_entropy = float("inf")
        dataset_min_l_recursive_c = float("inf") if c_recursive is not None else None

        ok_cnt_distinct = 0
        ok_cnt_entropy = 0
        ok_cnt_recursive = 0 if c_recursive is not None else None

        viol_distinct: List[Tuple[Any, ...]] = []
        viol_entropy: List[Tuple[Any, ...]] = []
        viol_recursive: List[Tuple[Any, ...]] = [] if c_recursive is not None else None

        for key, counter in groups.items():
            size = sum(counter.values())
            # распределение вероятностей
            probs = _sorted_probs(counter)
            entropy = _entropy(probs, self.cfg.entropy_log_base)
            distinct = len(probs)
            p1 = probs[0] if probs else 0.0
            tail_sums = _tail_sums(probs)  # индексация с 1: tail_sums[1] ~ sum_{i=1..k} = 1.0

            # минимально достижимое l для distinct: просто число уникальных
            min_l_distinct = distinct

            # для entropy: минимальное l такое, что H >= log_b(l)
            # l <= b^H  => минимально достижимое l = floor(b^H)
            min_l_entropy = max(1, int(math.floor(self.cfg.entropy_log_base ** 0)))  # placeholder
            exp_val = self.cfg.entropy_log_base ** (entropy / _log(self.cfg.entropy_log_base, self.cfg.entropy_log_base))
            # exp_val == b^(H_b) = e^(H_ln) — но мы храним H уже в базе b; поэтому:
            exp_val = self.cfg.entropy_log_base ** (entropy / 1.0)
            # В действительности: если H_b >= log_b(l), то l <= b^H_b => достижимый l = floor(b^H_b)
            min_l_entropy = max(1, int(math.floor(self.cfg.entropy_log_base ** (entropy))))
            # защитимся от дрожания из-за fp:
            if (self.cfg.entropy_log_base ** entropy) - min_l_entropy < 1e-12:
                min_l_entropy = int(round(self.cfg.entropy_log_base ** entropy))

            # для recursive (c,l): найдём минимальное l в [2..distinct], при котором r1 < c * sum_{i=l..k} r_i
            min_l_recursive_c: Optional[int] = None
            ok_recursive = None
            if c_recursive is not None:
                min_l_recursive_c = _min_l_recursive(probs, c_recursive)
                ok_recursive = min_l_recursive_c is not None and min_l_recursive_c >= l_threshold

            ok_distinct = (distinct >= l_threshold)
            ok_entropy = (entropy >= _log(l_threshold, self.cfg.entropy_log_base))

            # агрегируем min‑l на датасет
            dataset_min_l_distinct = min(dataset_min_l_distinct, min_l_distinct)
            dataset_min_l_entropy = min(dataset_min_l_entropy, min_l_entropy)
            if c_recursive is not None and min_l_recursive_c is not None:
                dataset_min_l_recursive_c = min(dataset_min_l_recursive_c, min_l_recursive_c)  # type: ignore[assignment]

            # счётчики соответствия
            ok_cnt_distinct += int(ok_distinct)
            ok_cnt_entropy += int(ok_entropy)
            if ok_cnt_recursive is not None:
                ok_cnt_recursive += int(bool(ok_recursive))  # type: ignore[operator]

            # нарушители
            if not ok_distinct and len(viol_distinct) < self.cfg.max_list_violators:
                viol_distinct.append(key)
            if not ok_entropy and len(viol_entropy) < self.cfg.max_list_violators:
                viol_entropy.append(key)
            if c_recursive is not None and not ok_recursive and viol_recursive is not None and len(viol_recursive) < self.cfg.max_list_violators:
                viol_recursive.append(key)

            if include_group_stats:
                preview = None
                if self.cfg.privacy_preserve:
                    preview = { _hash_preview(k, salt): v for k, v in counter.items() }
                group_stats.append(GroupStats(
                    key=key, size=size, distinct=distinct, entropy=entropy, p1=p1, tail_sums=tail_sums, preview=preview
                ))
                decisions.append(GroupDecision(
                    key=key, size=size,
                    min_l_distinct=min_l_distinct,
                    min_l_entropy=min_l_entropy,
                    min_l_recursive_c=min_l_recursive_c,
                    ok_distinct=ok_distinct,
                    ok_entropy=ok_entropy,
                    ok_recursive_c=ok_recursive
                ))

        total_groups = len(groups)
        share_ok_distinct = ok_cnt_distinct / total_groups if total_groups else 1.0
        share_ok_entropy = ok_cnt_entropy / total_groups if total_groups else 1.0
        share_ok_recursive = (ok_cnt_recursive / total_groups) if (ok_cnt_recursive is not None and total_groups) else None

        # если не было ни одной группы, задаём корректные минимумы
        if total_groups == 0:
            dataset_min_l_distinct = 0
            dataset_min_l_entropy = 0
            if dataset_min_l_recursive_c is not None:
                dataset_min_l_recursive_c = 0

        return LDiversityReport(
            total_groups=total_groups,
            records_total=total_records,
            dataset_min_l_distinct=int(dataset_min_l_distinct) if dataset_min_l_distinct != float("inf") else 0,
            dataset_min_l_entropy=int(dataset_min_l_entropy) if dataset_min_l_entropy != float("inf") else 0,
            dataset_min_l_recursive_c=int(dataset_min_l_recursive_c) if (dataset_min_l_recursive_c not in (None, float("inf"))) else None,
            share_ok_distinct=share_ok_distinct,
            share_ok_entropy=share_ok_entropy,
            share_ok_recursive_c=share_ok_recursive,
            violators_distinct=viol_distinct,
            violators_entropy=viol_entropy,
            violators_recursive_c=viol_recursive,
            groups=group_stats if include_group_stats else None,
            decisions=decisions if include_group_stats else None,
        )

    # ---------- агрегатор ----------

    def _aggregate(
        self,
        data: Union[RecordIterable, "._pd.DataFrame"],  # type: ignore[name-defined]
    ) -> Tuple[Dict[Tuple[Any, ...], Dict[Any, int]], int]:
        """
        Строит частоты SA по группам QI.
        Возвращает: (map: key(QI)-> {SA -> count}, total_records)
        """
        counters: Dict[Tuple[Any, ...], Dict[Any, int]] = {}
        total = 0

        if _HAS_PANDAS and _is_pandas_df(data):
            # Быстрый путь через pandas groupby
            df = data  # type: ignore[assignment]
            qi = list(self.cfg.qi_columns)
            sa = self.cfg.sensitive_column

            # обработка NA
            if self.cfg.na_policy == "drop":
                df = df[~df[sa].isna()]
            else:
                df = df.copy()
                df[sa] = df[sa].where(~df[sa].isna(), _NULL_TOKEN)

            grouped = df.groupby(qi)[sa].value_counts(dropna=False)
            # grouped — Series с MultiIndex: (qi..., sa) -> count
            counters = defaultdict(dict)
            for idx, count in grouped.items():
                *qi_vals, sa_val = idx
                key = tuple(qi_vals)
                counters[key][sa_val] = int(count)
                total += int(count)
            return dict(counters), total

        # Общий путь без pandas
        counters = defaultdict(lambda: defaultdict(int))  # type: ignore[assignment]
        for rec in _iter_records(data):
            try:
                key = tuple(rec.get(col) for col in self.cfg.qi_columns)
                sa_val = rec.get(self.cfg.sensitive_column, None)
            except Exception:
                # пропускаем сломанные записи
                continue
            # обработка NA
            if _is_na(sa_val):
                if self.cfg.na_policy == "drop":
                    continue
                sa_val = _NULL_TOKEN
            counters[key][sa_val] += 1
            total += 1
        return dict(counters), total


# =========================
# Вспомогательные функции
# =========================

def _iter_records(obj: Union[RecordIterable, Any]) -> Iterator[JsonLikeRecord]:
    """
    Унифицированный итератор по данным:
      - iterable of mappings: как есть;
      - pandas.DataFrame: итерация по dict‑записям;
      - pyarrow.Table: поддержка через to_pylist() без зависимости (лениво).
    """
    # pandas
    if _HAS_PANDAS and _is_pandas_df(obj):
        df = obj  # type: ignore[assignment]
        for rec in df.to_dict("records"):
            yield rec  # type: ignore[misc]
        return
    # pyarrow (опционально, без импорта)
    if hasattr(obj, "to_pylist"):
        try:
            for rec in obj.to_pylist():  # type: ignore[attr-defined]
                if isinstance(rec, Mapping):
                    yield rec
        except Exception:
            pass
        return
    # общее iterable
    if isinstance(obj, Iterable):
        for rec in obj:
            if isinstance(rec, Mapping):
                yield rec  # type: ignore[misc]

def _sorted_probs(counter: Mapping[Any, int]) -> List[float]:
    total = float(sum(counter.values()))
    if total <= 0:
        return []
    probs = sorted((c / total for c in counter.values()), reverse=True)
    return probs

def _entropy(probs: List[float], base: float) -> float:
    if not probs:
        return 0.0
    s = 0.0
    for p in probs:
        if p > 0:
            s -= p * _log(p, base)
    return s

def _tail_sums(probs: List[float]) -> List[float]:
    """
    tail_sums[l] = сумма от i=l..k, l начиная с 1 (индексация человека).
    Для удобства вставляем dummy в tail_sums[0] = 1.0
    """
    k = len(probs)
    res = [1.0] * (k + 1)
    acc = 0.0
    for i in range(k - 1, -1, -1):
        acc += probs[i]
        res[i + 1] = acc
    res[0] = 1.0
    return res

def _min_l_recursive(probs: List[float], c: float) -> Optional[int]:
    """
    Возвращает минимальное l >= 2 такое, что r1 < c * sum_{i=l..k} r_i.
    Если не существует (слишком доминирующий р1), возвращает None.
    """
    if not probs:
        return None
    r1 = probs[0]
    k = len(probs)
    tails = _tail_sums(probs)
    # l в [2..k]
    best: Optional[int] = None
    for l in range(2, k + 1):
        tail = tails[l]  # sum_{i=l..k}
        if r1 < c * tail:
            best = l
            break
    return best


# =========================
# Пример использования (doctest)
# =========================
"""
>>> data = [
...   {"age_band": "20-29", "zip3": "123", "disease": "A"},
...   {"age_band": "20-29", "zip3": "123", "disease": "A"},
...   {"age_band": "20-29", "zip3": "123", "disease": "B"},
...   {"age_band": "20-29", "zip3": "124", "disease": "C"},
... ]
>>> cfg = LDiversityConfig(qi_columns=("age_band","zip3"), sensitive_column="disease")
>>> rep = LDiversityEvaluator(cfg).evaluate(data, l_threshold=2, c_recursive=1.5, include_group_stats=True)
>>> rep.total_groups
2
>>> rep.dataset_min_l_distinct >= 1
True
>>> 0.0 <= rep.share_ok_distinct <= 1.0
True
"""


# =========================
# (Необязательно) CLI для оффлайн‑проверки
# =========================

def _cli() -> int:  # pragma: no cover
    import argparse, json, sys
    p = argparse.ArgumentParser(description="VeilMind l-diversity evaluator")
    p.add_argument("--data", required=True, help="Путь к JSONL/NDJSON или CSV")
    p.add_argument("--qi", required=True, help="Список колонок QI через запятую")
    p.add_argument("--sa", required=True, help="Имя колонки чувствительного атрибута")
    p.add_argument("--format", choices=["jsonl","csv"], default="jsonl")
    p.add_argument("--l", type=int, default=2)
    p.add_argument("--c", type=float, default=None)
    p.add_argument("--base", type=float, default=2.0)
    p.add_argument("--na", choices=["drop","as_value"], default="drop")
    p.add_argument("--details", action="store_true")
    args = p.parse_args()

    # загрузка
    records: List[Dict[str, Any]] = []
    if args.format == "jsonl":
        with open(args.data, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                records.append(json.loads(line))
    else:
        import csv
        with open(args.data, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append(row)

    cfg = LDiversityConfig(
        qi_columns=tuple([x.strip() for x in args.qi.split(",") if x.strip()]),
        sensitive_column=args.sa,
        entropy_log_base=args.base,
        na_policy=args.na,
    )
    rep = LDiversityEvaluator(cfg).evaluate(
        records,
        l_threshold=args.l,
        c_recursive=args.c,
        include_group_stats=args.details,
    )
    out = {
        "total_groups": rep.total_groups,
        "records_total": rep.records_total,
        "dataset_min_l_distinct": rep.dataset_min_l_distinct,
        "dataset_min_l_entropy": rep.dataset_min_l_entropy,
        "dataset_min_l_recursive_c": rep.dataset_min_l_recursive_c,
        "share_ok_distinct": rep.share_ok_distinct,
        "share_ok_entropy": rep.share_ok_entropy,
        "share_ok_recursive_c": rep.share_ok_recursive_c,
        "violators_distinct": rep.violators_distinct,
        "violators_entropy": rep.violators_entropy,
        "violators_recursive_c": rep.violators_recursive_c,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_cli())
