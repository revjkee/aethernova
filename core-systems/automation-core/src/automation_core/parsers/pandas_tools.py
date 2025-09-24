# SPDX-License-Identifier: MIT
"""
automation_core.parsers.pandas_tools

Промышленный набор инструментов для безопасного и предсказуемого чтения/нормализации/валидации
табличных данных на базе pandas.

Основные возможности:
- Унифицированное чтение CSV/TSV, Excel, JSON (records/lines), Parquet.
- Семплинг и инференс dtypes с последующим детерминированным чтением.
- Нормализация имён столбцов (snake_case), дедупликация конфликтов, обрезка пробелов.
- Приведение типов к pandas nullable dtypes (string, Int64, Float64, boolean, datetime64[ns]).
- Мягкая валидация по декларативной схеме (обязательность, типы, min/max, regex, категории, уникальность).
- Заполнение пропусков по схеме, безопасное «даункастинг» числовых типов, отчёт об экономии памяти.
- Запись в Parquet (опционально pyarrow), CSV; безопасная обработка потенциальных CSV-инъекций.
- Подробные docstring, типизация, отсутствие сторонних зависимостей (кроме pandas/опционально pyarrow).

Примечание:
- Для Parquet предпочтителен pyarrow; при его отсутствии запись отключается с понятной ошибкой.
"""

from __future__ import annotations

import io
import json
import math
import os
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Literal, Mapping, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

try:
    import pyarrow as pa  # type: ignore
    import pyarrow.parquet as pq  # type: ignore

    _HAS_PYARROW = True
except Exception:  # pragma: no cover
    _HAS_PYARROW = False


# =====================================================================================
# Вспомогательные сущности и типы
# =====================================================================================

Readable = os.PathLike[str] | str | io.StringIO | io.BytesIO
Writable = os.PathLike[str] | str

NullableDtype = Literal["string", "Int64", "Float64", "boolean", "datetime64[ns]", "category", "object"]
FileFormat = Literal["csv", "tsv", "excel", "json", "jsonl", "parquet"]

CSV_DIALECTS = {
    "csv": ",",
    "tsv": "\t",
}


# =====================================================================================
# Конфигурации чтения/нормализации
# =====================================================================================

@dataclass
class ReadConfig:
    """Общая конфигурация чтения табличных данных."""
    encoding: str = "utf-8"
    # CSV/TSV
    delimiter: Optional[str] = None
    header: int | None = 0
    comment: Optional[str] = None
    quotechar: str = '"'
    escapechar: Optional[str] = None
    na_values: Sequence[str] = field(default_factory=lambda: ["", "NA", "NaN", "NULL", "null"])
    keep_default_na: bool = False
    thousands: Optional[str] = None
    decimal: str = "."
    # Excel
    sheet_name: int | str | None = 0
    # JSON
    json_orient: Optional[str] = None  # "records" / "columns" / ...
    json_lines: Optional[bool] = None
    # Общие
    parse_dates: Sequence[str] | None = None
    dayfirst: bool = False
    infer_datetime_format: bool = True
    dtype_overrides: Mapping[str, NullableDtype] = field(default_factory=dict)
    sample_rows_for_inference: int = 5000
    use_nullable_dtypes: bool = True
    strip_whitespace: bool = True
    normalize_headers: bool = True
    drop_empty_rows: bool = True
    # Производительность/память
    low_memory: bool = False
    chunksize: Optional[int] = None  # при необходимости построчной обработки
    # Безопасность
    neutralize_csv_injection: bool = False  # префикс "'" для ячеек начинающихся с = + - @


@dataclass
class SchemaField:
    name: str
    dtype: NullableDtype
    required: bool = False
    allow_null: bool = True
    min_value: Decimal | float | int | None = None
    max_value: Decimal | float | int | None = None
    regex: Optional[str] = None  # для string
    categories: Optional[Sequence[str]] = None  # для category
    fillna: Any = None  # значение по умолчанию, если allow_null=False


@dataclass
class DataFrameSchema:
    fields: Sequence[SchemaField]
    primary_key: Sequence[str] = field(default_factory=tuple)
    unique: Sequence[Sequence[str]] = field(default_factory=tuple)  # наборы колонок


@dataclass
class ValidationIssue:
    row: int | None
    column: str | None
    kind: str
    detail: str


@dataclass
class ValidationReport:
    ok: bool
    issues: list[ValidationIssue]
    memory_before_mb: float | None = None
    memory_after_mb: float | None = None

    def summarize(self) -> str:
        if self.ok:
            return "Validation OK"
        lines = [f"{i.kind}: col={i.column} row={i.row} {i.detail}" for i in self.issues[:50]]
        more = "" if len(self.issues) <= 50 else f" ... and {len(self.issues)-50} more"
        return "\n".join(lines) + more


# =====================================================================================
# Нормализация имён столбцов и безопасные операции
# =====================================================================================

_SNAKE_CACHE: dict[str, str] = {}


def _snake_case(name: str) -> str:
    """Перевод в snake_case с учётом unicode, кэшируем для скорости."""
    if name in _SNAKE_CACHE:
        return _SNAKE_CACHE[name]
    # normalize unicode -> NFKD, убрать не алфанумерик
    n = unicodedata.normalize("NFKD", name).strip()
    n = re.sub(r"[^\w\s\-]+", " ", n, flags=re.UNICODE)
    n = n.replace("-", " ")
    n = re.sub(r"\s+", "_", n).strip("_").lower()
    if not n:
        n = "col"
    _SNAKE_CACHE[name] = n
    return n


def normalize_headers(df: pd.DataFrame, deduplicate: bool = True) -> pd.DataFrame:
    """Нормализовать имена столбцов: trim -> snake_case, опциональная дедупликация."""
    cols = []
    seen: dict[str, int] = {}
    for c in df.columns:
        base = str(c).strip()
        sn = _snake_case(base)
        if deduplicate:
            if sn in seen:
                seen[sn] += 1
                sn = f"{sn}_{seen[sn]}"
            else:
                seen[sn] = 0
        cols.append(sn)
    df = df.copy()
    df.columns = cols
    return df


def neutralize_csv_injection(df: pd.DataFrame) -> pd.DataFrame:
    """
    Префиксуем одинарной кавычкой значения, начинающиеся с '=', '+', '-', '@' (как в Excel).
    Применяется только к строковым столбцам.
    """
    pref = ("=", "+", "-", "@")
    out = df.copy()
    for c in out.select_dtypes(include=["string", "object"]).columns:
        s = out[c].astype("string")
        mask = s.str.startswith(pref, na=False)
        out.loc[mask, c] = "'" + s[mask]  # type: ignore[operator]
    return out


# =====================================================================================
# Приведение типов, даункаст, дата-парсинг
# =====================================================================================

_NULLABLE_MAP: dict[NullableDtype, str] = {
    "string": "string",
    "Int64": "Int64",
    "Float64": "Float64",
    "boolean": "boolean",
    "datetime64[ns]": "datetime64[ns]",
    "category": "category",
    "object": "object",
}


def coerce_series_dtype(s: pd.Series, target: NullableDtype) -> pd.Series:
    """Аккуратно привести Series к требуемому nullable-dtype."""
    if target == "datetime64[ns]":
        return pd.to_datetime(s, errors="coerce", utc=False, infer_datetime_format=True)
    if target == "category":
        return s.astype("string").astype("category")
    if target in ("string", "boolean", "Int64", "Float64", "object"):
        try:
            return s.astype(target)
        except Exception:
            # безопасный путь: через pandas convert_dtypes -> затем cast
            return s.convert_dtypes().astype(target, errors="ignore")
    return s


def coerce_dtypes(df: pd.DataFrame, mapping: Mapping[str, NullableDtype]) -> pd.DataFrame:
    """Привести типы DataFrame по словарю 'col -> nullable dtype'."""
    out = df.copy()
    for col, dt in mapping.items():
        if col in out.columns:
            out[col] = coerce_series_dtype(out[col], dt)
    return out


def downcast_numeric(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, str]]:
    """
    Попробовать уменьшить размер числовых столбцов (downcast).
    Возвращает df и словарь 'колонка -> новый dtype', только если это уменьшает память.
    """
    out = df.copy()
    changed: Dict[str, str] = {}
    for col in out.select_dtypes(include=[np.number]).columns:
        s = out[col]
        before = s.memory_usage(deep=True)
        # Для float: попробуем float32
        if pd.api.types.is_float_dtype(s):
            s2 = pd.to_numeric(s, errors="coerce", downcast="float")
        else:
            s2 = pd.to_numeric(s, errors="coerce", downcast="integer")
        after = s2.memory_usage(deep=True)
        if after < before:
            out[col] = s2
            changed[col] = str(s2.dtype)
    return out, changed


def parse_date_columns(df: pd.DataFrame, cols: Sequence[str], dayfirst: bool = False) -> pd.DataFrame:
    """Привести перечисленные столбцы к datetime64[ns] с безопасным coerce."""
    out = df.copy()
    for c in cols:
        if c in out.columns:
            out[c] = pd.to_datetime(out[c], errors="coerce", dayfirst=dayfirst, infer_datetime_format=True)
    return out


# =====================================================================================
# Схема данных и валидация
# =====================================================================================

def _validate_unique(df: pd.DataFrame, cols: Sequence[str]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not cols:
        return issues
    dups = df.duplicated(list(cols), keep=False)
    if bool(dups.any()):
        for idx in df.index[dups]:
            issues.append(ValidationIssue(int(idx), ",".join(cols), "unique_violation", "duplicate key"))
    return issues


def _validate_field(df: pd.DataFrame, f: SchemaField) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if f.name not in df.columns:
        if f.required:
            issues.append(ValidationIssue(None, f.name, "missing_column", "required column missing"))
        return issues

    s = df[f.name]
    # nullability
    if not f.allow_null and s.isna().any():
        for ridx in df.index[s.isna()]:
            issues.append(ValidationIssue(int(ridx), f.name, "null_violation", "null not allowed"))

    # dtype checks (мягкие — только репортим)
    target = _NULLABLE_MAP.get(f.dtype, "object")
    # сравним семью типов
    def _family(dtype: Any) -> str:
        if pd.api.types.is_bool_dtype(dtype):
            return "boolean"
        if pd.api.types.is_integer_dtype(dtype):
            return "integer"
        if pd.api.types.is_float_dtype(dtype):
            return "float"
        if pd.api.types.is_datetime64_any_dtype(dtype):
            return "datetime"
        if pd.api.types.is_categorical_dtype(dtype):
            return "category"
        if pd.api.types.is_string_dtype(dtype) or str(dtype) == "string":
            return "string"
        return "object"

    if f.dtype != "object":
        fam_series = _family(s.dtype)
        fam_target = _family(target)
        if fam_series != fam_target:
            issues.append(ValidationIssue(None, f.name, "dtype_mismatch", f"{fam_series} != {fam_target}"))

    # min/max for numeric or datetime
    if f.min_value is not None:
        mask = s.dropna() < f.min_value  # type: ignore[operator]
        for ridx in s.dropna().index[mask]:
            issues.append(ValidationIssue(int(ridx), f.name, "min_violation", f"< {f.min_value}"))
    if f.max_value is not None:
        mask = s.dropna() > f.max_value  # type: ignore[operator]
        for ridx in s.dropna().index[mask]:
            issues.append(ValidationIssue(int(ridx), f.name, "max_violation", f"> {f.max_value}"))

    # regex for strings
    if f.regex and (pd.api.types.is_string_dtype(s) or str(s.dtype) == "string"):
        pat = re.compile(f.regex)
        mask = s.dropna().astype(str).map(lambda x: bool(pat.fullmatch(x)))
        bad = s.dropna().index[~mask]
        for ridx in bad:
            issues.append(ValidationIssue(int(ridx), f.name, "regex_mismatch", "pattern not matched"))

    # categories
    if f.categories and pd.api.types.is_categorical_dtype(s):
        allowed = set(map(str, f.categories))
        actual = set(map(str, s.dropna().astype(str).cat.categories))
        extra = actual.difference(allowed)
        if extra:
            issues.append(ValidationIssue(None, f.name, "category_extra", f"unexpected: {sorted(extra)}"))
    return issues


def apply_schema(df: pd.DataFrame, schema: DataFrameSchema, fill_missing: bool = True) -> Tuple[pd.DataFrame, ValidationReport]:
    """
    Применить схему: привести типы, опционально заполнить пропуски, затем провалидировать и вернуть отчёт.
    """
    before_mb = df.memory_usage(index=True, deep=True).sum() / (1024 * 1024)

    # 1) Приведение типов
    mapping = {f.name: f.dtype for f in schema.fields}
    df2 = coerce_dtypes(df, mapping)

    # 2) Заполнение пропусков по схеме
    if fill_missing:
        for f in schema.fields:
            if f.fillna is not None and f.name in df2.columns:
                df2[f.name] = df2[f.name].fillna(f.fillna)

    # 3) Валидация
    issues: list[ValidationIssue] = []
    for f in schema.fields:
        issues.extend(_validate_field(df2, f))
    if schema.primary_key:
        issues.extend(_validate_unique(df2, list(schema.primary_key)))
    for uq in schema.unique:
        issues.extend(_validate_unique(df2, list(uq)))

    after_mb = df2.memory_usage(index=True, deep=True).sum() / (1024 * 1024)
    report = ValidationReport(ok=len(issues) == 0, issues=issues, memory_before_mb=before_mb, memory_after_mb=after_mb)
    return df2, report


# =====================================================================================
# Инфер dtypes по семплу
# =====================================================================================

def _infer_dtypes_from_sample(sample: pd.DataFrame, overrides: Mapping[str, NullableDtype]) -> Dict[str, NullableDtype]:
    """
    Грубый инференс nullable-dtype из семпла: сначала convert_dtypes(), затем маппинг к нужным именам.
    """
    tmp = sample.convert_dtypes()
    mapping: Dict[str, NullableDtype] = {}
    for col, dt in tmp.dtypes.items():
        sdt = str(dt)
        if "Int" in sdt:
            mapping[col] = "Int64"
        elif sdt == "Float64":
            mapping[col] = "Float64"
        elif sdt == "string":
            mapping[col] = "string"
        elif sdt == "boolean":
            mapping[col] = "boolean"
        elif "datetime64" in sdt:
            mapping[col] = "datetime64[ns]"
        else:
            mapping[col] = "object"
    # применяем overrides
    for k, v in overrides.items():
        mapping[k] = v
    return mapping


# =====================================================================================
# Определение формата и чтение
# =====================================================================================

def guess_format(path: Readable, default: FileFormat = "csv") -> FileFormat:
    """Грубое определение формата по расширению/флагам."""
    if hasattr(path, "read"):
        return default
    p = Path(str(path)).suffix.lower()
    if p in {".csv"}:
        return "csv"
    if p in {".tsv", ".tab"}:
        return "tsv"
    if p in {".xlsx", ".xls"}:
        return "excel"
    if p in {".json"}:
        return "json"
    if p in {".jsonl", ".ndjson"}:
        return "jsonl"
    if p in {".parquet", ".pq"}:
        return "parquet"
    return default


def _read_sample_for_inference(
    path: Readable,
    fmt: FileFormat,
    cfg: ReadConfig,
    sample_rows: int,
) -> pd.DataFrame:
    """Прочитать небольшой семпл для инференса dtypes и нормализации."""
    if fmt in ("csv", "tsv"):
        delimiter = cfg.delimiter or CSV_DIALECTS.get(fmt, ",")
        sample = pd.read_csv(
            path,
            nrows=sample_rows,
            encoding=cfg.encoding,
            sep=delimiter,
            header=cfg.header,
            comment=cfg.comment,
            quotechar=cfg.quotechar,
            escapechar=cfg.escapechar,
            na_values=list(cfg.na_values),
            keep_default_na=cfg.keep_default_na,
            thousands=cfg.thousands,
            decimal=cfg.decimal,
        )
    elif fmt == "excel":
        sample = pd.read_excel(path, sheet_name=cfg.sheet_name, nrows=sample_rows)
    elif fmt in ("json", "jsonl"):
        if fmt == "jsonl" or cfg.json_lines:
            # читаем первых sample_rows строк jsonl
            rows = []
            with (open(path, "r", encoding=cfg.encoding) if isinstance(path, (str, os.PathLike)) else path) as fh:  # type: ignore[arg-type]
                for i, line in enumerate(fh):
                    if i >= sample_rows:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    rows.append(json.loads(line))
            sample = pd.DataFrame.from_records(rows)
        else:
            sample = pd.read_json(path, orient=cfg.json_orient)
            if isinstance(sample, dict):  # edge case
                sample = pd.DataFrame(sample)
            if isinstance(sample, list):
                sample = pd.DataFrame.from_records(sample)
    elif fmt == "parquet":
        sample = pd.read_parquet(path, engine="pyarrow" if _HAS_PYARROW else None, columns=None)
        if len(sample) > sample_rows:
            sample = sample.head(sample_rows)
    else:  # fallback
        sample = pd.DataFrame()
    return sample


def read_table(path: Readable, *, fmt: Optional[FileFormat] = None, config: Optional[ReadConfig] = None) -> pd.DataFrame:
    """
    Унифицированное чтение табличных данных с инференсом и нормализацией.
    Порядок:
      1) Определить формат (или взять из аргумента).
      2) Прочитать семпл -> инференс nullable dtypes.
      3) Прочитать полный набор с фиксированными dtype (где применимо).
      4) Нормализовать имена столбцов, обрезать пробелы, привести типы/даты/NA.
    """
    cfg = config or ReadConfig()
    fmt = fmt or guess_format(path)

    # 1. Семпл и инференс
    sample = _read_sample_for_inference(path, fmt, cfg, cfg.sample_rows_for_inference)
    if cfg.normalize_headers and not sample.empty:
        sample = normalize_headers(sample)
    inferred = _infer_dtypes_from_sample(sample, cfg.dtype_overrides)

    # 2. Полное чтение
    if fmt in ("csv", "tsv"):
        delimiter = cfg.delimiter or CSV_DIALECTS.get(fmt, ",")
        df = pd.read_csv(
            path,
            encoding=cfg.encoding,
            sep=delimiter,
            header=cfg.header,
            comment=cfg.comment,
            quotechar=cfg.quotechar,
            escapechar=cfg.escapechar,
            na_values=list(cfg.na_values),
            keep_default_na=cfg.keep_default_na,
            thousands=cfg.thousands,
            decimal=cfg.decimal,
            dtype={k: v for k, v in inferred.items() if k in sample.columns and v != "datetime64[ns]"},
            low_memory=cfg.low_memory,
        )
    elif fmt == "excel":
        df = pd.read_excel(path, sheet_name=cfg.sheet_name)
    elif fmt in ("json", "jsonl"):
        if fmt == "jsonl" or cfg.json_lines:
            rows = []
            with (open(path, "r", encoding=cfg.encoding) if isinstance(path, (str, os.PathLike)) else path) as fh:  # type: ignore[arg-type]
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    rows.append(json.loads(line))
            df = pd.DataFrame.from_records(rows)
        else:
            df = pd.read_json(path, orient=cfg.json_orient)
            if isinstance(df, dict):  # safety
                df = pd.DataFrame(df)
            if isinstance(df, list):
                df = pd.DataFrame.from_records(df)
    elif fmt == "parquet":
        df = pd.read_parquet(path, engine="pyarrow" if _HAS_PYARROW else None)
    else:
        raise ValueError(f"Unsupported format: {fmt}")

    # 3. Постобработка/нормализация
    if cfg.normalize_headers:
        df = normalize_headers(df)
        # переименуем mapping для дат/типов после нормализации заголовков
        inferred = { _snake_case(k): v for k, v in inferred.items() }

    # убираем целиком пустые строки (все NA)
    if cfg.drop_empty_rows and not df.empty:
        df = df.dropna(how="all")

    # обрезаем пробелы у строк
    if cfg.strip_whitespace:
        for c in df.columns:
            if pd.api.types.is_string_dtype(df[c]) or str(df[c].dtype) == "string" or df[c].dtype == object:
                df[c] = df[c].astype("string").str.strip()

    # парсим даты, если заданы явно
    if cfg.parse_dates:
        df = parse_date_columns(df, [c for c in cfg.parse_dates if c in df.columns], dayfirst=cfg.dayfirst)

    # приведение типов, если включено
    if cfg.use_nullable_dtypes:
        df = coerce_dtypes(df, inferred)

    # нейтрализация CSV-инъекций
    if cfg.neutralize_csv_injection:
        df = neutralize_csv_injection(df)

    return df


# =====================================================================================
# Метрики памяти и простейшая очистка/обогащение
# =====================================================================================

def memory_report(df: pd.DataFrame) -> dict[str, Any]:
    """Краткий отчёт об использовании памяти."""
    total = float(df.memory_usage(index=True, deep=True).sum())
    by_col = {
        c: float(df[c].memory_usage(index=False, deep=True))
        for c in df.columns
    }
    return {
        "total_bytes": total,
        "total_mb": round(total / (1024 * 1024), 3),
        "by_column_bytes": by_col,
    }


def fillna_defaults(df: pd.DataFrame, defaults: Mapping[str, Any]) -> pd.DataFrame:
    """Заполнить пропуски по словарю значений по умолчанию."""
    out = df.copy()
    for c, v in defaults.items():
        if c in out.columns:
            out[c] = out[c].fillna(v)
    return out


def clip_outliers_zscore(df: pd.DataFrame, cols: Sequence[str], z: float = 4.0) -> pd.DataFrame:
    """
    Простейший анти-выбросный клиппинг по Z-оценке.
    """
    out = df.copy()
    for c in cols:
        if c in out.columns and pd.api.types.is_numeric_dtype(out[c]):
            s = out[c].astype("Float64")
            m = s.mean(skipna=True)
            sd = s.std(skipna=True)
            if sd and not math.isclose(sd, 0.0):
                lower = m - z * sd
                upper = m + z * sd
                out[c] = s.clip(lower, upper)
    return out


# =====================================================================================
# Запись данных
# =====================================================================================

def to_parquet(df: pd.DataFrame, path: Writable, *, partition_cols: Sequence[str] | None = None, compression: str = "snappy") -> None:
    """
    Записать DataFrame в Parquet. Требуется pyarrow (при отсутствии будет брошено понятное исключение).
    """
    if not _HAS_PYARROW:
        raise RuntimeError("pyarrow is required to write parquet files")
    table = pa.Table.from_pandas(df, preserve_index=False)
    path = str(path)
    if partition_cols:
        pq.write_to_dataset(table, root_path=path, compression=compression, partition_cols=list(partition_cols))
    else:
        pq.write_table(table, where=path, compression=compression)  # type: ignore[arg-type]


def to_csv(df: pd.DataFrame, path: Writable, *, delimiter: str = ",", encoding: str = "utf-8", index: bool = False) -> None:
    """
    Записать DataFrame в CSV.
    """
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, sep=delimiter, encoding=encoding, index=index)


# =====================================================================================
# Примитивные конвейеры «прочитать -> нормализовать -> валидация -> отчёт»
# =====================================================================================

def load_and_validate(
    source: Readable,
    *,
    fmt: Optional[FileFormat] = None,
    read_config: Optional[ReadConfig] = None,
    schema: Optional[DataFrameSchema] = None,
) -> Tuple[pd.DataFrame, Optional[ValidationReport]]:
    """
    Высокоуровневая функция: прочитать табличный источник по правилам ReadConfig и опционально провалидировать по схеме.
    """
    df = read_table(source, fmt=fmt, config=read_config)
    if schema is None:
        return df, None
    df2, rep = apply_schema(df, schema, fill_missing=True)
    return df2, rep


# =====================================================================================
# Примеры применения (doctest-стиль)
# =====================================================================================

if __name__ == "__main__":  # простая ручная проверка
    data = io.StringIO("Name,Value,Date\n Alice , 1 ,2022-01-01\nBob, ,2022-02-03\n")
    cfg = ReadConfig(parse_dates=["date"])
    df = read_table(data, fmt="csv", config=cfg)
    print(df.dtypes)
    schema = DataFrameSchema(
        fields=[
            SchemaField("name", "string", required=True, allow_null=False, regex=r"[A-Za-z ]+"),
            SchemaField("value", "Int64", allow_null=True, min_value=0, fillna=0),
            SchemaField("date", "datetime64[ns]", required=True, allow_null=False),
        ],
        primary_key=("name",),
    )
    df2, rep = apply_schema(df, schema)
    print(rep.ok, rep.summarize())
