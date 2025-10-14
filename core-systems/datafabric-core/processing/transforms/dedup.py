# datafabric/processing/transforms/dedup.py
# Industrial-grade, deterministic deduplication for PySpark
# - Complex composite keys
# - Deterministic priority & tie-breakers (multi-column, null-safe)
# - Optional domain-agnostic canonicalization of string columns
# - Group hashing for diagnostics
# - Rich metrics (before/after, duplicates removed, groups, skew hints)
# - JSON structured logging
# - Pure stdlib + PySpark

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple
from datetime import datetime, timezone
import json

from pyspark.sql import DataFrame, Window
from pyspark.sql import functions as F
from pyspark.sql.types import StringType

# ----------------------------
# JSON Structured Logger
# ----------------------------

def _jlog(level: str, msg: str, **kwargs) -> None:
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level.upper(),
        "message": msg,
        "component": "datafabric.transforms.dedup",
    }
    rec.update(kwargs or {})
    print(json.dumps(rec, ensure_ascii=False), flush=True)

def _info(msg: str, **kwargs) -> None:
    _jlog("INFO", msg, **kwargs)

def _warn(msg: str, **kwargs) -> None:
    _jlog("WARN", msg, **kwargs)

def _error(msg: str, **kwargs) -> None:
    _jlog("ERROR", msg, **kwargs)

# ----------------------------
# Configuration
# ----------------------------

SortDir = Literal["asc", "desc"]
NullsPos = Literal["nulls_first", "nulls_last"]
KeepPolicy = Literal["first", "last", "max_by", "min_by"]

@dataclass
class OrderBy:
    """
    Order specification for tie-breaking and priority selection.
    Example: OrderBy(col="event_ts", dir="desc", nulls="nulls_last")
    """
    col: str
    dir: SortDir = "desc"
    nulls: NullsPos = "nulls_last"

@dataclass
class DedupConfig:
    # Keys defining duplicates (composite supported)
    keys: List[str]

    # Global keep policy if order_by is empty:
    # - "first"/"last" in data order after optional canonicalization
    # When order_by is provided, it is used as primary determinant.
    keep: KeepPolicy = "first"

    # Multi-column deterministic order (priority, tiebreakers)
    order_by: List[OrderBy] = field(default_factory=list)

    # Optional pre-filter to exclude noisy rows before dedup (SQL expression)
    where: Optional[str] = None

    # Canonicalization options (string columns only)
    canonicalize_strings: bool = True
    strip: bool = True
    to_lower: bool = False
    collapse_spaces: bool = True  # turn multiple spaces into one

    # Additional user tiebreaker when all else equal (stable, unique-ish)
    final_tiebreaker_cols: List[str] = field(default_factory=list)

    # Optional prefer-non-null list: columns where non-null values preferred in winners
    prefer_non_null: List[str] = field(default_factory=list)

    # Diagnostics
    compute_group_hash: bool = True
    group_hash_alg: str = "sha2"  # sha2
    group_hash_len: int = 256

    # Performance knobs
    repartition_by_keys: Optional[int] = None  # e.g., 400
    cache_intermediate: bool = False

    # Metrics sample top-N duplicate groups for debugging
    sample_groups_n: int = 5

# ----------------------------
# Helpers
# ----------------------------

def _null_safe_col(col_name: str) -> F.Column:
    # Normalizes NULLs for ordering when needed
    return F.col(col_name)

def _order_expr(ob: OrderBy) -> F.Column:
    c = _null_safe_col(ob.col)
    if ob.dir == "asc":
        c = c.asc()
    else:
        c = c.desc()
    # Null positioning
    if ob.nulls == "nulls_first":
        c = c.nullsFirst()
    else:
        c = c.nullsLast()
    return c

def _maybe_canonicalize_strings(df: DataFrame, cfg: DedupConfig) -> DataFrame:
    if not cfg.canonicalize_strings:
        return df
    out = df
    for f in out.schema.fields:
        if isinstance(f.dataType, StringType):
            col = F.col(f.name)
            if cfg.strip:
                col = F.trim(col)
            if cfg.collapse_spaces:
                col = F.regexp_replace(col, r"\s+", " ")
            if cfg.to_lower:
                col = F.lower(col)
            out = out.withColumn(f.name, col)
    return out

def _add_group_hash(df: DataFrame, keys: Sequence[str], cfg: DedupConfig) -> DataFrame:
    if not cfg.compute_group_hash or not keys:
        return df
    concat_expr = F.concat_ws("§", *[F.coalesce(F.col(k).cast("string"), F.lit("∅")) for k in keys])
    if cfg.group_hash_alg == "sha2":
        h = F.sha2(concat_expr, cfg.group_hash_len)
    else:
        # default to sha2 if algorithm unknown
        h = F.sha2(concat_expr, cfg.group_hash_len)
    return df.withColumn("_group_hash", h)

def _apply_prefer_non_null(df: DataFrame, cols: Sequence[str]) -> DataFrame:
    """
    Adds per-column preference score: non-null -> 1 else 0; aggregated later in order_by.
    """
    out = df
    for c in cols:
        out = out.withColumn(f"_prefnn_{c}", F.when(F.col(c).isNotNull(), F.lit(1)).otherwise(F.lit(0)))
    if cols:
        # total preference to be used early in ordering
        pref_cols = [F.col(f"_prefnn_{c}") for c in cols]
        out = out.withColumn("_prefnn_total", F.coalesce(sum(pref_cols), F.lit(0)))
    else:
        out = out.withColumn("_prefnn_total", F.lit(0))
    return out

def _build_order_columns(cfg: DedupConfig) -> List[F.Column]:
    cols: List[F.Column] = []
    # Prefer non-null total first, if configured
    if cfg.prefer_non_null:
        cols.append(F.col("_prefnn_total").desc().nullsLast())

    # User-defined order
    for ob in cfg.order_by:
        cols.append(_order_expr(ob))

    # Stable final tie-breakers if provided
    for c in cfg.final_tiebreaker_cols:
        # Put nulls last for stability
        cols.append(F.col(c).asc_nulls_last())

    return cols

# ----------------------------
# Core API
# ----------------------------

def deduplicate(df: DataFrame, cfg: DedupConfig) -> Tuple[DataFrame, Dict[str, Any]]:
    """
    Deterministic deduplication with rich metrics.
    Returns: (deduplicated_df, metrics_dict)
    """
    if not cfg.keys:
        raise ValueError("DedupConfig.keys must not be empty")

    # Pre-filter and canonicalization
    if cfg.where:
        df = df.where(cfg.where)

    df = _maybe_canonicalize_strings(df, cfg)
    df = _apply_prefer_non_null(df, cfg.prefer_non_null)

    # Optional repartitioning by keys for large datasets
    if cfg.repartition_by_keys and cfg.repartition_by_keys > 0:
        df = df.repartition(cfg.repartition_by_keys, *[F.col(k) for k in cfg.keys])

    if cfg.cache_intermediate:
        df = df.persist()

    # Diagnostics: group hash
    df = _add_group_hash(df, cfg.keys, cfg)

    total_before = df.count()

    # Window over keys with deterministic ordering
    order_cols = _build_order_columns(cfg)
    if not order_cols:
        # Fallback by keep policy
        if cfg.keep == "first":
            order_cols = [F.monotonically_increasing_id().asc()]
        elif cfg.keep == "last":
            order_cols = [F.monotonically_increasing_id().desc()]
        else:
            # For max_by/min_by without provided order_by, this is undefined
            raise ValueError("keep set to max_by/min_by but no order_by provided")

    w = Window.partitionBy(*[F.col(k) for k in cfg.keys]).orderBy(*order_cols)
    df_ranked = df.withColumn("_rn", F.row_number().over(w))

    # Winner selection
    winners = df_ranked.filter(F.col("_rn") == 1).drop("_rn")
    total_after = winners.count()

    # Basic metrics
    duplicates_removed = total_before - total_after

    # Group-level metrics
    group_sizes = (
        df.groupBy(*[F.col(k) for k in cfg.keys])
          .count()
          .withColumnRenamed("count", "group_size")
    )
    groups_total = group_sizes.count()
    multi_groups = group_sizes.filter(F.col("group_size") > 1).count()

    # Sample top-N duplicate groups for debugging
    sample_groups = (
        group_sizes.orderBy(F.col("group_size").desc(), *[F.col(k).asc_nulls_last() for k in cfg.keys])
                   .limit(cfg.sample_groups_n)
                   .collect()
    )
    sample_payload = [row.asDict(recursive=True) for row in sample_groups]

    metrics: Dict[str, Any] = {
        "rows_before": total_before,
        "rows_after": total_after,
        "duplicates_removed": duplicates_removed,
        "groups_total": groups_total,
        "groups_with_duplicates": multi_groups,
        "sample_largest_groups": sample_payload,
        "keys": cfg.keys,
        "order_by": [ob.__dict__ for ob in cfg.order_by],
        "prefer_non_null": cfg.prefer_non_null,
        "canonicalize_strings": cfg.canonicalize_strings,
    }

    _info("Dedup metrics", **metrics)

    # Cleanup helper columns
    drop_cols = ["_prefnn_total"] + [f"_prefnn_{c}" for c in cfg.prefer_non_null]
    if "_group_hash" in winners.columns and not cfg.compute_group_hash:
        drop_cols.append("_group_hash")
    winners = winners.drop(*[c for c in drop_cols if c in winners.columns])

    return winners, metrics

# ----------------------------
# Convenience: max_by/min_by helpers
# ----------------------------

def max_by(df: DataFrame, keys: List[str], by: List[OrderBy], **kwargs) -> Tuple[DataFrame, Dict[str, Any]]:
    cfg = DedupConfig(keys=keys, keep="max_by", order_by=by, **kwargs)
    return deduplicate(df, cfg)

def min_by(df: DataFrame, keys: List[str], by: List[OrderBy], **kwargs) -> Tuple[DataFrame, Dict[str, Any]]:
    cfg = DedupConfig(keys=keys, keep="min_by", order_by=by, **kwargs)
    return deduplicate(df, cfg)

# ----------------------------
# Example config (reference):
# keys = ["user_id", "event_id"]
# order_by = [
#     OrderBy(col="quality_score", dir="desc", nulls="nulls_last"),
#     OrderBy(col="event_ts", dir="desc", nulls="nulls_last"),
# ]
# prefer_non_null = ["email", "phone"]
# cfg = DedupConfig(
#     keys=keys,
#     order_by=order_by,
#     keep="first",
#     prefer_non_null=prefer_non_null,
#     canonicalize_strings=True,
#     to_lower=True,
#     collapse_spaces=True,
#     final_tiebreaker_cols=["record_id"],
#     compute_group_hash=True,
#     repartition_by_keys=400,
#     cache_intermediate=False,
#     sample_groups_n=5,
# )
# winners, metrics = deduplicate(df, cfg)
# ----------------------------
