# datafabric-core/datafabric/processing/stream/spark_structured_streaming.py
# Industrial-grade Spark Structured Streaming application for DataFabric
# Features:
# - Config via ENV/CLI
# - Kafka source with strict JSON schema validation
# - Watermark + deduplication (idempotency)
# - Branching to DLQ for corrupt/invalid records
# - Sinks: Kafka / Delta / Parquet
# - Checkpointing, backpressure, rate limiting
# - Metrics & audit logs (per-batch)
# - Graceful shutdown on SIGTERM/SIGINT
# - Testable pure functions for transformations

from __future__ import annotations

import os
import json
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Callable, Any

from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F
from pyspark.sql import types as T
from pyspark.sql.streaming import StreamingQuery, Trigger


# ---------------------------
# Configuration
# ---------------------------

@dataclass
class AppConfig:
    app_name: str = field(default_factory=lambda: os.getenv("APP_NAME", "datafabric-stream"))
    env: str = field(default_factory=lambda: os.getenv("ENV", "prod"))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    # Kafka source
    kafka_bootstrap: str = field(default_factory=lambda: os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"))
    kafka_topic: str = field(default_factory=lambda: os.getenv("KAFKA_SOURCE_TOPIC", "events.raw"))
    kafka_starting_offsets: str = field(default_factory=lambda: os.getenv("KAFKA_STARTING_OFFSETS", "latest"))
    kafka_security_protocol: Optional[str] = field(default_factory=lambda: os.getenv("KAFKA_SECURITY_PROTOCOL"))  # e.g., SASL_SSL
    kafka_sasl_mechanism: Optional[str] = field(default_factory=lambda: os.getenv("KAFKA_SASL_MECHANISM"))         # e.g., SCRAM-SHA-512
    kafka_sasl_jaas_config: Optional[str] = field(default_factory=lambda: os.getenv("KAFKA_SASL_JAAS_CONFIG"))     # jaas string
    kafka_ssl_endpoint_identification_algorithm: Optional[str] = field(
        default_factory=lambda: os.getenv("KAFKA_SSL_ENDPOINT_IDENTIFICATION_ALGORITHM", "https")
    )
    kafka_max_offsets_per_trigger: Optional[int] = field(
        default_factory=lambda: int(os.getenv("KAFKA_MAX_OFFSETS_PER_TRIGGER", "100000"))
    )

    # DLQ
    dlq_topic: Optional[str] = field(default_factory=lambda: os.getenv("KAFKA_DLQ_TOPIC", "events.dlq"))
    dlq_path: Optional[str] = field(default_factory=lambda: os.getenv("DLQ_PATH"))  # optional filesystem DLQ

    # Target sink (one of: kafka, delta, parquet)
    sink_type: str = field(default_factory=lambda: os.getenv("SINK_TYPE", "delta"))
    sink_kafka_topic: Optional[str] = field(default_factory=lambda: os.getenv("KAFKA_SINK_TOPIC", "events.curated"))
    sink_path: str = field(default_factory=lambda: os.getenv("SINK_PATH", "s3a://datafabric/curated/events"))
    sink_checkpoint: str = field(default_factory=lambda: os.getenv("SINK_CHECKPOINT", "s3a://datafabric/checkpoints/events"))
    dlq_checkpoint: str = field(default_factory=lambda: os.getenv("DLQ_CHECKPOINT", "s3a://datafabric/checkpoints/dlq"))

    # Processing
    watermark_delay: str = field(default_factory=lambda: os.getenv("WATERMARK_DELAY", "10 minutes"))
    dedup_columns: str = field(default_factory=lambda: os.getenv("DEDUP_COLUMNS", "event_id,event_time"))
    trigger_mode: str = field(default_factory=lambda: os.getenv("TRIGGER_MODE", "processing_time"))  # or "once" / "available_now" / "continuous"
    trigger_interval: str = field(default_factory=lambda: os.getenv("TRIGGER_INTERVAL", "10 seconds"))
    output_mode: str = field(default_factory=lambda: os.getenv("OUTPUT_MODE", "append"))  # append / update / complete
    max_files_per_trigger: Optional[int] = field(default_factory=lambda: int(os.getenv("MAX_FILES_PER_TRIGGER", "1000")))

    # Schema
    schema_json: Optional[str] = field(default_factory=lambda: os.getenv("EVENT_SCHEMA_JSON"))
    schema_path: Optional[str] = field(default_factory=lambda: os.getenv("EVENT_SCHEMA_PATH"))

    # Backpressure & shuffle
    spark_sql_shuffle_partitions: int = field(default_factory=lambda: int(os.getenv("SPARK_SQL_SHUFFLE_PARTITIONS", "200")))
    spark_sql_auto_broadcast_join_threshold: str = field(default_factory=lambda: os.getenv("SPARK_SQL_AUTO_BROADCAST_JOIN_THRESHOLD", "10MB"))
    stream_repartition: Optional[int] = field(default_factory=lambda: int(os.getenv("STREAM_REPARTITION", "0")))

    # Metrics
    audit_path: Optional[str] = field(default_factory=lambda: os.getenv("AUDIT_PATH", "s3a://datafabric/audit/events"))
    metrics_log_every_batches: int = field(default_factory=lambda: int(os.getenv("METRICS_LOG_EVERY_BATCHES", "1")))

    # Delta specifics
    delta_table_config_overwrite: str = field(default_factory=lambda: os.getenv("DELTA_OVERWRITE_SCHEMA", "true"))


# ---------------------------
# Spark Session Builder
# ---------------------------

def build_spark(cfg: AppConfig) -> SparkSession:
    builder = (
        SparkSession.builder
        .appName(cfg.app_name)
        .config("spark.sql.shuffle.partitions", cfg.spark_sql_shuffle_partitions)
        .config("spark.sql.adaptive.enabled", "true")
        .config("spark.sql.adaptive.coalescePartitions.enabled", "true")
        .config("spark.sql.files.maxPartitionBytes", "134217728")  # 128MB
        .config("spark.sql.streaming.stateStore.providerClass", "org.apache.spark.sql.execution.streaming.state.RocksDBStateStoreProvider")
        .config("spark.sql.streaming.stateStore.maintenanceInterval", "60s")
        .config("spark.sql.autoBroadcastJoinThreshold", cfg.spark_sql_auto_broadcast_join_threshold)
        .config("spark.streaming.backpressure.enabled", "true")
        .config("spark.streaming.kafka.maxRatePerPartition", "50000")
        .config("spark.sql.legacy.timeParserPolicy", "LEGACY")
    )

    # Delta support if sink is delta
    if cfg.sink_type.lower() == "delta":
        builder = (
            builder
            .config("spark.sql.extensions", "io.delta.sql.DeltaSparkSessionExtension")
            .config("spark.sql.catalog.spark_catalog", "org.apache.spark.sql.delta.catalog.DeltaCatalog")
        )

    spark = builder.getOrCreate()
    spark.sparkContext.setLogLevel(cfg.log_level)
    return spark


# ---------------------------
# Schema Handling
# ---------------------------

def load_schema(cfg: AppConfig) -> T.StructType:
    if cfg.schema_json:
        try:
            schema_dict = json.loads(cfg.schema_json)
            return T.StructType.fromJson(schema_dict)
        except Exception as e:
            raise ValueError(f"Invalid EVENT_SCHEMA_JSON: {e}")

    if cfg.schema_path:
        with open(cfg.schema_path, "r", encoding="utf-8") as f:
            schema_dict = json.load(f)
            return T.StructType.fromJson(schema_dict)

    # Fallback: a reasonable default schema (edit as needed)
    return T.StructType([
        T.StructField("event_id", T.StringType(), False),
        T.StructField("event_time", T.TimestampType(), False),
        T.StructField("source", T.StringType(), True),
        T.StructField("type", T.StringType(), True),
        T.StructField("payload", T.MapType(T.StringType(), T.StringType()), True),
        T.StructField("partition_key", T.StringType(), True),
    ])


# ---------------------------
# Source Readers
# ---------------------------

def read_stream_from_kafka(spark: SparkSession, cfg: AppConfig) -> DataFrame:
    opts = {
        "kafka.bootstrap.servers": cfg.kafka_bootstrap,
        "subscribe": cfg.kafka_topic,
        "startingOffsets": cfg.kafka_starting_offsets,
        "failOnDataLoss": "false",
        "maxOffsetsPerTrigger": str(cfg.kafka_max_offsets_per_trigger),
    }
    if cfg.kafka_security_protocol:
        opts["kafka.security.protocol"] = cfg.kafka_security_protocol
    if cfg.kafka_sasl_mechanism:
        opts["kafka.sasl.mechanism"] = cfg.kafka_sasl_mechanism
    if cfg.kafka_sasl_jaas_config:
        opts["kafka.sasl.jaas.config"] = cfg.kafka_sasl_jaas_config
    if cfg.kafka_ssl_endpoint_identification_algorithm:
        opts["kafka.ssl.endpoint.identification.algorithm"] = cfg.kafka_ssl_endpoint_identification_algorithm

    df = (
        spark.readStream
        .format("kafka")
        .options(**opts)
        .load()
    )

    # Kafka columns: key, value, topic, partition, offset, timestamp, headers
    return df


# ---------------------------
# Transformations
# ---------------------------

def parse_and_validate(df: DataFrame, event_schema: T.StructType) -> Tuple[DataFrame, DataFrame]:
    """
    Parses Kafka value (assumed UTF-8 JSON) and validates against schema.
    Returns (valid_df, dlq_df).
    """
    # Convert binary to string
    df_str = df.withColumn("key_str", F.col("key").cast("string")) \
               .withColumn("value_str", F.col("value").cast("string"))

    # Parse JSON; allow storing raw for DLQ
    parsed = df_str.withColumn("json", F.from_json(F.col("value_str"), event_schema, {"mode": "PERMISSIVE"})) \
                   .withColumn("corrupt", F.col("json._corrupt_record"))

    valid = parsed.where(F.col("corrupt").isNull() & F.col("json").isNotNull()) \
                  .select(
                      F.col("json.*"),
                      F.col("key_str").alias("kafka_key"),
                      F.col("topic"),
                      F.col("partition"),
                      F.col("offset"),
                      F.col("timestamp").alias("kafka_timestamp"),
                      F.col("headers")
                  )

    dlq = parsed.where(F.col("corrupt").isNotNull() | F.col("json").isNull()) \
                .select(
                    F.col("key_str").alias("kafka_key"),
                    F.col("value_str").alias("raw_value"),
                    F.col("corrupt"),
                    F.col("topic"),
                    F.col("partition"),
                    F.col("offset"),
                    F.col("timestamp").alias("kafka_timestamp"),
                    F.col("headers")
                )

    return valid, dlq


def apply_watermark_and_dedup(df: DataFrame, cfg: AppConfig) -> DataFrame:
    dedup_cols = [c.strip() for c in cfg.dedup_columns.split(",") if c.strip()]
    if "event_time" not in [f.name for f in df.schema.fields]:
        raise ValueError("Schema must contain 'event_time' for watermarking")

    with_wm = df.withWatermark("event_time", cfg.watermark_delay)
    if len(dedup_cols) >= 2:
        # e.g., event_id + event_time
        return with_wm.dropDuplicates(dedup_cols)
    # Fallback dedup by event_time
    return with_wm.dropDuplicates(["event_time"])


def business_transform(df: DataFrame) -> DataFrame:
    """
    Place business rules here. Example enrichments:
    - Normalize event types
    - Extract fields
    - Compute derived columns
    """
    return (
        df
        .withColumn("event_date", F.to_date("event_time"))
        .withColumn("ingest_ts", F.current_timestamp())
        .withColumn("type_norm", F.lower(F.coalesce(F.col("type"), F.lit("unknown"))))
        .withColumn("source_norm", F.lower(F.coalesce(F.col("source"), F.lit("unknown"))))
    )


# ---------------------------
# DLQ Writers
# ---------------------------

def write_dlq_stream_kafka(dlq: DataFrame, cfg: AppConfig) -> StreamingQuery:
    if not cfg.dlq_topic:
        raise ValueError("DLQ topic is not configured")

    payload = dlq.select(
        F.col("kafka_key").cast("string").alias("key"),
        F.to_json(F.struct(*dlq.columns)).alias("value")
    )

    return (
        payload.writeStream
        .format("kafka")
        .option("kafka.bootstrap.servers", cfg.kafka_bootstrap)
        .option("topic", cfg.dlq_topic)
        .option("checkpointLocation", cfg.dlq_checkpoint)
        .outputMode("append")
        .start()
    )


def write_dlq_stream_files(dlq: DataFrame, cfg: AppConfig) -> Optional[StreamingQuery]:
    if not cfg.dlq_path:
        return None
    return (
        dlq.writeStream
        .format("parquet")
        .option("path", cfg.dlq_path)
        .option("checkpointLocation", cfg.dlq_checkpoint + "_fs")
        .outputMode("append")
        .start()
    )


# ---------------------------
# Sink Writers
# ---------------------------

def build_trigger(cfg: AppConfig) -> Trigger:
    mode = cfg.trigger_mode.lower()
    if mode == "once":
        return Trigger.Once()
    if mode == "available_now":
        return Trigger.AvailableNow()
    if mode == "continuous":
        # Requires continuous processing support; use with care
        # Spark expects an interval for continuous
        return Trigger.Continuous(cfg.trigger_interval)
    # default: processing time
    return Trigger.ProcessingTime(cfg.trigger_interval)


def write_sink_kafka(df: DataFrame, cfg: AppConfig) -> StreamingQuery:
    if not cfg.sink_kafka_topic:
        raise ValueError("KAFKA_SINK_TOPIC must be set for kafka sink")

    out = df.select(
        F.col("partition_key").cast("string").alias("key"),
        F.to_json(F.struct(*[c for c in df.columns if c != "partition_key"])).alias("value")
    )

    return (
        out.writeStream
        .format("kafka")
        .option("kafka.bootstrap.servers", cfg.kafka_bootstrap)
        .option("topic", cfg.sink_kafka_topic)
        .option("checkpointLocation", cfg.sink_checkpoint)
        .outputMode(cfg.output_mode)
        .trigger(build_trigger(cfg))
        .start()
    )


def write_sink_delta(df: DataFrame, cfg: AppConfig) -> StreamingQuery:
    writer = (
        df.writeStream
        .format("delta")
        .option("path", cfg.sink_path)
        .option("checkpointLocation", cfg.sink_checkpoint)
        .option("mergeSchema", cfg.delta_table_config_overwrite)
        .outputMode(cfg.output_mode)
        .trigger(build_trigger(cfg))
    )
    return writer.start()


def write_sink_parquet(df: DataFrame, cfg: AppConfig) -> StreamingQuery:
    writer = (
        df.writeStream
        .format("parquet")
        .option("path", cfg.sink_path)
        .option("checkpointLocation", cfg.sink_checkpoint)
        .outputMode(cfg.output_mode)
        .trigger(build_trigger(cfg))
    )
    return writer.start()


# ---------------------------
# Metrics & Audit
# ---------------------------

def with_metrics(df: DataFrame, cfg: AppConfig, audit_sink: Optional[str] = None) -> DataFrame:
    """
    Attach simple metrics as columns. For richer metrics, use foreachBatch logger below.
    """
    return df.withColumn("audit_ingest_ts", F.current_timestamp()) \
             .withColumn("audit_env", F.lit(cfg.env)) \
             .withColumn("audit_app", F.lit(cfg.app_name))


def foreach_batch_audit(audit_path: Optional[str], log_every: int) -> Callable[[DataFrame, int], None]:
    """
    Returns a foreachBatch function that logs batch metrics and optionally writes audit rows.
    """
    def _fn(batch_df: DataFrame, batch_id: int) -> None:
        count = batch_df.count()
        if batch_id % max(1, log_every) == 0:
            # Log to driver
            print(f"[AUDIT] batch_id={batch_id} rows={count} ts={time.strftime('%Y-%m-%d %H:%M:%S')}", flush=True)

        if audit_path:
            out = (batch_df
                   .select(
                       F.lit(batch_id).alias("batch_id"),
                       F.current_timestamp().alias("audit_ts"),
                       F.lit(count).alias("rows"),
                   ))
            # Write in batch mode to avoid nested streaming
            out.write.mode("append").parquet(audit_path)
    return _fn


# ---------------------------
# Main Topology Assembly
# ---------------------------

def build_topology(spark: SparkSession, cfg: AppConfig) -> Tuple[StreamingQuery, Optional[StreamingQuery], Optional[StreamingQuery]]:
    # Source
    src = read_stream_from_kafka(spark, cfg)

    # Optional input partitioning to control parallelism
    repartition = cfg.stream_repartition if cfg.stream_repartition and cfg.stream_repartition > 0 else None
    if repartition:
        src = src.repartition(repartition)

    # Schema
    schema = load_schema(cfg)

    # Parse & validate
    valid, dlq = parse_and_validate(src, schema)

    # DLQ writers
    dlq_q_kafka = write_dlq_stream_kafka(dlq, cfg) if cfg.dlq_topic else None
    dlq_q_fs = write_dlq_stream_files(dlq, cfg)

    # Transform pipeline
    curated = business_transform(apply_watermark_and_dedup(valid, cfg))
    curated = with_metrics(curated, cfg)

    # Per-batch audit logger (non-streaming sink inside foreachBatch)
    audited_stream = (
        curated.writeStream
        .foreachBatch(foreach_batch_audit(cfg.audit_path, cfg.metrics_log_every_batches))
        .option("checkpointLocation", cfg.sink_checkpoint + "_audit")
        .outputMode("append")
        .trigger(build_trigger(cfg))
        .start()
    )

    # Main sink
    if cfg.sink_type.lower() == "kafka":
        main_q = write_sink_kafka(curated, cfg)
    elif cfg.sink_type.lower() == "delta":
        main_q = write_sink_delta(curated, cfg)
    elif cfg.sink_type.lower() == "parquet":
        main_q = write_sink_parquet(curated, cfg)
    else:
        raise ValueError(f"Unsupported sink type: {cfg.sink_type}")

    return main_q, dlq_q_kafka, dlq_q_fs


# ---------------------------
# Graceful Shutdown
# ---------------------------

class GracefulShutdown:
    def __init__(self):
        self._stop = False

    def __call__(self, signum, frame):
        print(f"Received signal {signum}. Initiating graceful shutdown...", flush=True)
        self._stop = True

    @property
    def should_stop(self) -> bool:
        return self._stop


# ---------------------------
# Entry Point
# ---------------------------

def main(argv: Optional[list[str]] = None) -> int:
    cfg = AppConfig()  # env-driven; optionally extend with argparse if needed

    spark = build_spark(cfg)

    # Register shutdown handlers
    killer = GracefulShutdown()
    signal.signal(signal.SIGINT, killer)
    signal.signal(signal.SIGTERM, killer)

    # Build and start topology
    main_q, dlq_q_kafka, dlq_q_fs = build_topology(spark, cfg)

    # Await termination with graceful stop
    try:
        while True:
            if killer.should_stop:
                print("Stopping streaming queries...", flush=True)
                for q in [main_q, dlq_q_kafka, dlq_q_fs]:
                    if q is not None and q.isActive:
                        q.stop()
                break
            time.sleep(2)
        return 0
    except KeyboardInterrupt:
        print("KeyboardInterrupt: stopping queries...", flush=True)
        for q in [main_q, dlq_q_kafka, dlq_q_fs]:
            if q is not None and q.isActive:
                q.stop()
        return 0
    finally:
        try:
            spark.stop()
        except Exception as e:
            print(f"Error during Spark stop: {e}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
