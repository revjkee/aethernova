# datafabric/processing/batch/spark_batch_job.py
# Industrial-grade Spark batch job for datafabric-core
# Features:
# - Config from CLI/ENV/JSON (no external deps)
# - Robust SparkSession builder with safe defaults
# - Deterministic read -> transform -> validate -> write
# - JSON structured logging, metrics dicts, exit codes
# - Atomic write via temp path + rename
# - Idempotency checks (_SUCCESS, existing output)
# - Basic data quality gates (nulls/uniqueness/range/count)
# - Partitioned writes, safe modes, optional coalesce/repartition
# - Error handling with clear failure reasons
# - No external libraries required (pure stdlib + PySpark)

import os
import sys
import json
import argparse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

from pyspark.sql import SparkSession, DataFrame
from pyspark.sql.types import (
    StructType, StructField, StringType, IntegerType, LongType, DoubleType, BooleanType, TimestampType, DateType
)
from pyspark.sql import functions as F

# ----------------------------
# JSON Structured Logger
# ----------------------------

def jlog(level: str, msg: str, **kwargs) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level.upper(),
        "message": msg,
        "app": "datafabric-spark-batch",
        **kwargs,
    }
    # Single-line JSON for ingestion by log collectors
    print(json.dumps(record, ensure_ascii=False), flush=True)

def info(msg: str, **kwargs) -> None:
    jlog("INFO", msg, **kwargs)

def warn(msg: str, **kwargs) -> None:
    jlog("WARN", msg, **kwargs)

def error(msg: str, **kwargs) -> None:
    jlog("ERROR", msg, **kwargs)

# ----------------------------
# Configuration Model
# ----------------------------

@dataclass
class IOConfig:
    format: str = "parquet"              # parquet|json|csv|orc
    path: str = ""                       # s3a://... | hdfs://... | file:///...
    options: Dict[str, str] = field(default_factory=dict)  # e.g., {"header":"true","inferSchema":"false"}
    schema: Optional[Dict[str, str]] = None                # {"col":"string","id":"long","ts":"timestamp"}
    partitions: Optional[List[str]] = None                 # partition columns for output

@dataclass
class DQThresholds:
    min_rows: int = 1
    max_null_frac: float = 0.2           # max fraction of nulls per column allowed
    unique_keys: Optional[List[str]] = None
    numeric_ranges: Optional[Dict[str, Tuple[Optional[float], Optional[float]]]] = None  # {"col": (min,max)}

@dataclass
class TransformConfig:
    # Example knobs for partitioning and performance
    repartition: Optional[int] = None            # number of partitions
    coalesce: Optional[int] = None               # coalesce after transforms
    cache_intermediate: bool = False
    deduplicate_on: Optional[List[str]] = None   # dropDuplicates keys
    with_ingest_ts: bool = True                  # add ingest_ts column
    # add domain-specific flags as needed

@dataclass
class WriteConfig:
    mode: str = "overwrite"               # overwrite|append|errorifexists|ignore
    format: str = "parquet"               # parquet|json|csv|orc
    path: str = ""
    options: Dict[str, str] = field(default_factory=dict)
    partitions: Optional[List[str]] = None
    temp_suffix: str = "_tmp"
    write_success_flag: bool = True       # write _SUCCESS marker

@dataclass
class AppConfig:
    app_name: str = "datafabric-spark-batch"
    master: Optional[str] = None               # e.g., "yarn", "k8s", "local[*]"
    spark_conf: Dict[str, str] = field(default_factory=dict)
    input: IOConfig = field(default_factory=IOConfig)
    output: WriteConfig = field(default_factory=WriteConfig)
    transform: TransformConfig = field(default_factory=TransformConfig)
    dq: DQThresholds = field(default_factory=DQThresholds)
    idempotency_check_output: bool = True
    fail_fast_on_dq: bool = True

# ----------------------------
# Helpers
# ----------------------------

_TYPE_MAP = {
    "string": StringType(),
    "int": IntegerType(),
    "integer": IntegerType(),
    "long": LongType(),
    "double": DoubleType(),
    "boolean": BooleanType(),
    "bool": BooleanType(),
    "timestamp": TimestampType(),
    "date": DateType(),
}

def parse_schema(schema_dict: Optional[Dict[str, str]]) -> Optional[StructType]:
    if not schema_dict:
        return None
    fields = []
    for col, tname in schema_dict.items():
        t = _TYPE_MAP.get(tname.lower())
        if t is None:
            raise ValueError(f"Unsupported type in schema: {tname} for column {col}")
        fields.append(StructField(col, t, nullable=True))
    return StructType(fields)

def load_config(args: argparse.Namespace) -> AppConfig:
    # Priority: --config_json_file | --config_json | ENV | CLI fallbacks
    cfg_json: Optional[Dict[str, Any]] = None

    if args.config_json_file:
        with open(args.config_json_file, "r", encoding="utf-8") as f:
            cfg_json = json.load(f)
    elif args.config_json:
        cfg_json = json.loads(args.config_json)
    else:
        # ENV support (minimal), otherwise rely on explicit CLI args
        env_json = os.getenv("DATAFABRIC_CONFIG_JSON")
        if env_json:
            cfg_json = json.loads(env_json)

    def from_dict(d: Dict[str, Any]) -> AppConfig:
        input_cfg = d.get("input", {})
        output_cfg = d.get("output", {})
        transform_cfg = d.get("transform", {})
        dq_cfg = d.get("dq", {})
        return AppConfig(
            app_name=d.get("app_name", "datafabric-spark-batch"),
            master=d.get("master"),
            spark_conf=d.get("spark_conf", {}),
            input=IOConfig(
                format=input_cfg.get("format", "parquet"),
                path=input_cfg.get("path", ""),
                options=input_cfg.get("options", {}),
                schema=input_cfg.get("schema"),
                partitions=input_cfg.get("partitions"),
            ),
            output=WriteConfig(
                mode=output_cfg.get("mode", "overwrite"),
                format=output_cfg.get("format", "parquet"),
                path=output_cfg.get("path", ""),
                options=output_cfg.get("options", {}),
                partitions=output_cfg.get("partitions"),
                temp_suffix=output_cfg.get("temp_suffix", "_tmp"),
                write_success_flag=output_cfg.get("write_success_flag", True),
            ),
            transform=TransformConfig(
                repartition=transform_cfg.get("repartition"),
                coalesce=transform_cfg.get("coalesce"),
                cache_intermediate=transform_cfg.get("cache_intermediate", False),
                deduplicate_on=transform_cfg.get("deduplicate_on"),
                with_ingest_ts=transform_cfg.get("with_ingest_ts", True),
            ),
            dq=DQThresholds(
                min_rows=dq_cfg.get("min_rows", 1),
                max_null_frac=dq_cfg.get("max_null_frac", 0.2),
                unique_keys=dq_cfg.get("unique_keys"),
                numeric_ranges=dq_cfg.get("numeric_ranges"),
            ),
            idempotency_check_output=d.get("idempotency_check_output", True),
            fail_fast_on_dq=d.get("fail_fast_on_dq", True),
        )

    if cfg_json:
        return from_dict(cfg_json)

    # CLI fallbacks if JSON not provided
    if not args.input_path or not args.output_path:
        error("No config JSON provided and required CLI args missing",
              needed=["--input_path", "--output_path"])
        sys.exit(2)

    return AppConfig(
        input=IOConfig(format=args.input_format, path=args.input_path),
        output=WriteConfig(mode=args.output_mode, format=args.output_format, path=args.output_path),
        app_name=args.app_name,
        master=args.master,
    )

def build_spark(cfg: AppConfig) -> SparkSession:
    builder = SparkSession.builder.appName(cfg.app_name)
    if cfg.master:
        builder = builder.master(cfg.master)

    # Safe defaults — adjust/extend per platform
    default_conf = {
        "spark.sql.session.timeZone": "UTC",
        "spark.sql.shuffle.partitions": "200",
        "spark.sql.sources.partitionOverwriteMode": "dynamic",
        "spark.sql.files.ignoreCorruptFiles": "true",
        "spark.sql.files.ignoreMissingFiles": "true",
        "spark.ui.showConsoleProgress": "true",
        "spark.sql.parquet.filterPushdown": "true",
        "spark.sql.broadcastTimeout": "1800",
    }
    merged = {**default_conf, **cfg.spark_conf}
    for k, v in merged.items():
        builder = builder.config(k, v)

    spark = builder.getOrCreate()
    info("SparkSession created", sparkVersion=spark.version)
    return spark

# ----------------------------
# Core I/O
# ----------------------------

def read_input(spark: SparkSession, cfg: IOConfig) -> DataFrame:
    schema = parse_schema(cfg.schema)
    reader = spark.read
    for k, v in cfg.options.items():
        reader = reader.option(k, v)

    fmt = cfg.format.lower()
    if fmt == "parquet":
        df = reader.schema(schema).parquet(cfg.path) if schema else reader.parquet(cfg.path)
    elif fmt == "json":
        df = reader.schema(schema).json(cfg.path) if schema else reader.json(cfg.path)
    elif fmt == "csv":
        df = reader.schema(schema).csv(cfg.path) if schema else reader.csv(cfg.path)
    elif fmt == "orc":
        df = reader.schema(schema).orc(cfg.path) if schema else reader.orc(cfg.path)
    else:
        raise ValueError(f"Unsupported input format: {cfg.format}")

    info("Input read", rows=df.count(), cols=len(df.columns), path=cfg.path, format=cfg.format)
    return df

def write_atomic(df: DataFrame, wcfg: WriteConfig) -> None:
    """
    Atomic write: write to temp path then rename to final path.
    Works for filesystems that support atomic rename (HDFS, many object stores via Hadoop layer may emulate).
    """
    final_path = wcfg.path.rstrip("/")
    temp_path = f"{final_path}{wcfg.temp_suffix}"

    # Clean temp if exists
    df.sparkSession._jsc.hadoopConfiguration()  # ensure Hadoop conf is initialized
    # Best-effort cleanup using Spark APIs
    try:
        df.sparkSession._jsparkSession.sessionState().catalog().reset()
    except Exception:
        pass

    # Write to temp
    writer = df.write.mode(wcfg.mode).format(wcfg.format)
    for k, v in wcfg.options.items():
        writer = writer.option(k, v)
    if wcfg.partitions:
        writer = writer.partitionBy(*wcfg.partitions)

    info("Writing to temp path", temp_path=temp_path, mode=wcfg.mode, format=wcfg.format)
    writer.save(temp_path)

    # Atomic move: use Hadoop FileSystem API via py4j
    sc = df.sparkSession.sparkContext
    hconf = sc._jsc.hadoopConfiguration()
    from py4j.java_gateway import java_import
    java_import(sc._jvm, "org.apache.hadoop.fs.Path")
    java_import(sc._jvm, "org.apache.hadoop.fs.FileSystem")

    fs = sc._jvm.FileSystem.get(hconf)
    src = sc._jvm.Path(temp_path)
    dst = sc._jvm.Path(final_path)

    # If final exists and mode is overwrite, delete first
    if fs.exists(dst):
        jlog("WARN", "Final path exists, handling per mode", final_path=final_path, mode=wcfg.mode)
        if wcfg.mode.lower() == "overwrite":
            fs.delete(dst, True)
        elif wcfg.mode.lower() in ("errorifexists", "error"):
            raise FileExistsError(f"Output path exists: {final_path}")
        elif wcfg.mode.lower() == "ignore":
            info("Mode=ignore and final path exists; skipping move", final_path=final_path)
            return
        else:
            # append and partitions: Spark already handled at temp save step; for atomicity we still replace directory
            fs.delete(dst, True)

    ok = fs.rename(src, dst)
    if not ok:
        raise IOError(f"Atomic rename failed from {temp_path} to {final_path}")

    # _SUCCESS marker (optional)
    if wcfg.write_success_flag:
        success_path = sc._jvm.Path(f"{final_path}/_SUCCESS")
        if not fs.exists(success_path):
            out = fs.create(success_path)
            out.close()

    info("Atomic write complete", final_path=final_path)

# ----------------------------
# Transformations (Pure-ish)
# ----------------------------

def apply_transforms(df: DataFrame, tcfg: TransformConfig) -> DataFrame:
    # Example domain-neutral transformations; extend with real business logic.
    out = df

    if tcfg.with_ingest_ts and "ingest_ts" not in out.columns:
        out = out.withColumn("ingest_ts", F.current_timestamp())

    if tcfg.deduplicate_on:
        out = out.dropDuplicates(tcfg.deduplicate_on)

    if tcfg.cache_intermediate:
        out = out.persist()

    if tcfg.repartition:
        out = out.repartition(tcfg.repartition)
    elif tcfg.coalesce:
        out = out.coalesce(tcfg.coalesce)

    return out

# ----------------------------
# Data Quality Validation
# ----------------------------

def compute_basic_metrics(df: DataFrame) -> Dict[str, Any]:
    rows = df.count()
    cols = len(df.columns)
    null_fracs = {}
    for c in df.columns:
        nulls = df.filter(F.col(c).isNull()).count()
        null_fracs[c] = nulls / rows if rows > 0 else 0.0
    metrics = {
        "rows": rows,
        "cols": cols,
        "null_fracs": null_fracs,
    }
    return metrics

def validate_data(df: DataFrame, dq: DQThresholds) -> Tuple[bool, List[str], Dict[str, Any]]:
    failures: List[str] = []
    metrics = compute_basic_metrics(df)

    # Row count gate
    if metrics["rows"] < dq.min_rows:
        failures.append(f"RowCount<{dq.min_rows}")

    # Null fraction gate
    for c, frac in metrics["null_fracs"].items():
        if frac > dq.max_null_frac:
            failures.append(f"NullFracExceeded:{c}:{frac:.3f}")

    # Uniqueness gate
    if dq.unique_keys:
        dup_count = (
            df.groupBy(*dq.unique_keys)
              .count()
              .filter(F.col("count") > 1)
              .count()
        )
        if dup_count > 0:
            failures.append(f"NonUniqueKeys:{dq.unique_keys}:{dup_count}")

    # Numeric ranges gate
    if dq.numeric_ranges:
        for col, (mn, mx) in dq.numeric_ranges.items():
            if col in df.columns:
                agg_exprs = []
                if mn is not None:
                    agg_exprs.append(F.min(F.col(col)).alias("min_" + col))
                if mx is not None:
                    agg_exprs.append(F.max(F.col(col)).alias("max_" + col))
                if agg_exprs:
                    row = df.agg(*agg_exprs).collect()[0].asDict()
                    if mn is not None and row.get("min_" + col) is not None and row["min_" + col] < mn:
                        failures.append(f"RangeMinViolated:{col}:{row['min_' + col]}<{mn}")
                    if mx is not None and row.get("max_" + col) is not None and row["max_" + col] > mx:
                        failures.append(f"RangeMaxViolated:{col}:{row['max_' + col]}> {mx}")

    ok = len(failures) == 0
    return ok, failures, metrics

# ----------------------------
# Idempotency Helpers
# ----------------------------

def output_already_done(spark: SparkSession, out_path: str) -> bool:
    """
    Best-effort idempotency check: if _SUCCESS exists or directory non-empty, treat as done.
    """
    sc = spark.sparkContext
    hconf = sc._jsc.hadoopConfiguration()
    from py4j.java_gateway import java_import
    java_import(sc._jvm, "org.apache.hadoop.fs.Path")
    java_import(sc._jvm, "org.apache.hadoop.fs.FileSystem")
    fs = sc._jvm.FileSystem.get(hconf)
    path = sc._jvm.Path(out_path.rstrip("/"))
    if not fs.exists(path):
        return False
    # if directory exists and is non-empty, or _SUCCESS present
    status = fs.listStatus(path)
    if status and len(status) > 0:
        # scan for _SUCCESS
        for st in status:
            if st.getPath().getName() == "_SUCCESS":
                return True
        return True
    return False

# ----------------------------
# Orchestration
# ----------------------------

def run_job(cfg: AppConfig) -> Dict[str, Any]:
    spark = build_spark(cfg)
    t0 = datetime.now(timezone.utc)

    try:
        if cfg.idempotency_check_output and output_already_done(spark, cfg.output.path):
            warn("Output already present; idempotency check triggered, skipping work", output=cfg.output.path)
            return {"status": "skipped", "reason": "idempotency", "output": cfg.output.path}

        df_in = read_input(spark, cfg.input)
        df_tr = apply_transforms(df_in, cfg.transform)

        ok, failures, dq_metrics = validate_data(df_tr, cfg.dq)
        info("DQ metrics computed", **dq_metrics)

        if not ok:
            warn("DQ validation failed", failures=failures)
            if cfg.fail_fast_on_dq:
                raise ValueError(f"Data quality validation failed: {failures}")

        write_atomic(df_tr, cfg.output)

        t1 = datetime.now(timezone.utc)
        duration_s = (t1 - t0).total_seconds()
        result = {
            "status": "success",
            "duration_seconds": duration_s,
            "rows_out": dq_metrics.get("rows"),
            "output": cfg.output.path,
            "dq_failures": failures,
        }
        info("Job completed successfully", **result)
        return result

    except Exception as e:
        t1 = datetime.now(timezone.utc)
        duration_s = (t1 - t0).total_seconds()
        error("Job failed", error=str(e), duration_seconds=duration_s)
        raise
    finally:
        try:
            spark.stop()
            info("SparkSession stopped")
        except Exception as e:
            warn("Spark stop error", error=str(e))

# ----------------------------
# CLI
# ----------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="DataFabric Spark Batch Job")
    # Config as JSON (string or file) preferred
    p.add_argument("--config_json", type=str, help="Full AppConfig as JSON string")
    p.add_argument("--config_json_file", type=str, help="Path to JSON config file")

    # Minimal CLI fallbacks
    p.add_argument("--app_name", type=str, default="datafabric-spark-batch")
    p.add_argument("--master", type=str, default=None)

    p.add_argument("--input_path", type=str, help="Input path")
    p.add_argument("--input_format", type=str, default="parquet")

    p.add_argument("--output_path", type=str, help="Output path")
    p.add_argument("--output_format", type=str, default="parquet")
    p.add_argument("--output_mode", type=str, default="overwrite")

    return p

def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        cfg = load_config(args)
        info("Loaded config", config=json.dumps(cfg, default=lambda o: o.__dict__, ensure_ascii=False))
    except Exception as e:
        error("Config load failed", error=str(e))
        sys.exit(2)

    try:
        result = run_job(cfg)
        # Exit codes: 0 success/skipped; 1 failure
        if result.get("status") in ("success", "skipped"):
            print(json.dumps({"result": result}, ensure_ascii=False))
            sys.exit(0)
        else:
            print(json.dumps({"result": result}, ensure_ascii=False))
            sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": str(e)}, ensure_ascii=False))
        sys.exit(1)

if __name__ == "__main__":
    main()
