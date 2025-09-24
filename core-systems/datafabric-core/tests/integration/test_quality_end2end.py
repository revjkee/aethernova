# tests/integration/test_quality_end2end.py
# Integration tests for DataFabric data quality (PySpark required).
# Склады: pytest -q tests/integration/test_quality_end2end.py

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

pyspark = pytest.importorskip("pyspark", reason="PySpark is required for integration DQ tests")
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql import types as T


@pytest.fixture(scope="session")
def spark():
    spark = (
        SparkSession.builder.appName("datafabric-tests-qa")
        .master("local[2]")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.shuffle.partitions", "2")
        .getOrCreate()
    )
    yield spark
    spark.stop()


@pytest.fixture
def tmpdir_path(tmp_path: Path) -> Path:
    return tmp_path


def _make_df_ok(spark: SparkSession):
    schema = T.StructType(
        [
            T.StructField("id", T.LongType(), nullable=False),
            T.StructField("name", T.StringType(), nullable=False),
            T.StructField("amount", T.DoubleType(), nullable=False),
            T.StructField("dt", T.StringType(), nullable=False),
        ]
    )
    rows = [
        (1, "Alice", 10.5, "2025-01-01"),
        (2, "Bob", 5.0, "2025-01-01"),
        (3, "Carol", 12.7, "2025-01-02"),
    ]
    return spark.createDataFrame(rows, schema=schema)


def _make_df_bad(spark: SparkSession):
    schema = T.StructType(
        [
            T.StructField("id", T.LongType(), nullable=True),
            T.StructField("name", T.StringType(), nullable=True),
            T.StructField("amount", T.DoubleType(), nullable=True),
            T.StructField("dt", T.StringType(), nullable=True),
        ]
    )
    rows = [
        (1, "Alice", 10.5, "2025-01-01"),
        (1, "Alice", 11.0, "2025-01-01"),  # duplicate id
        (None, "Bob", 5.0, "2025-01-01"),  # null id
        (3, None, 12.7, "2025-01-02"),     # null name
    ]
    return spark.createDataFrame(rows, schema=schema)


def test_dq_happy_path(spark):
    # Импортируем ожидания и раннер
    from datafabric.quality.expectations import (
        SuiteConfig,
        expect_schema,
        expect_not_null,
        expect_unique,
        run_suite,
        report_to_json,
    )

    df = _make_df_ok(spark)

    suite = SuiteConfig(
        expectations=[
            # схема: допустим строгая проверка типов и наличия колонок
            expect_schema({"id": "long", "name": "string", "amount": "double", "dt": "string"}, unknown_ok=False),
            expect_not_null(["id", "name", "amount", "dt"]),
            expect_unique(["id"], allow_nulls=False),
        ],
        fail_fast=False,
        dataset_metrics=True,
    )

    report = run_suite(df, suite)

    # Проверки отчета
    assert report.success is True
    assert report.row_count == df.count()
    assert isinstance(report.metrics, dict)
    assert "null_counts" in report.metrics
    assert "distinct_counts" in report.metrics

    # Сериализация/десериализация JSON
    blob = report_to_json(report)
    loaded = json.loads(blob)
    assert loaded["success"] is True
    assert loaded["row_count"] == 3
    assert loaded["expectations"][0]["name"] == "expect_schema"


def test_dq_failures(spark):
    from datafabric.quality.expectations import (
        SuiteConfig,
        expect_schema,
        expect_not_null,
        expect_unique,
        run_suite,
    )

    df = _make_df_bad(spark)

    suite = SuiteConfig(
        expectations=[
            expect_schema({"id": "long", "name": "string", "amount": "double", "dt": "string"}, unknown_ok=False),
            expect_not_null(["id", "name"]),
            expect_unique(["id"], allow_nulls=False),
        ],
        fail_fast=False,
        dataset_metrics=True,
    )

    report = run_suite(df, suite)

    assert report.success is False
    # как минимум два провала: not_null и unique
    failed = [e for e in report.expectations if e.get("success") is False]
    names = {e.get("name") for e in failed}
    assert {"expect_not_null", "expect_unique"}.issubset(names)


@pytest.mark.parametrize("fmt", ["csv", "parquet"])
def test_cli_dq_run_end2end(tmpdir_path: Path, spark, fmt: str, monkeypatch):
    """
    Проверяем CLI datafabric dq run на реальном файле (CSV/Parquet).
    Успешный кейс -> exit code 0; провальный -> exit code 14 (CONFLICT).
    """
    # Подготовим данные
    ok_df = _make_df_ok(spark)
    bad_df = _make_df_bad(spark)

    ok_path = tmpdir_path / f"ok.{fmt}"
    bad_path = tmpdir_path / f"bad.{fmt}"

    if fmt == "parquet":
        ok_df.write.mode("overwrite").parquet(str(ok_path))
        bad_df.write.mode("overwrite").parquet(str(bad_path))
    else:
        ok_df.coalesce(1).write.mode("overwrite").option("header", True).csv(str(ok_path))
        bad_df.coalesce(1).write.mode("overwrite").option("header", True).csv(str(bad_path))
        # Переписываем в единый файл (Spark создает папку)
        def _single_csv(dir_path: Path) -> Path:
            part = next(iter((dir_path).glob("part-*.csv")))
            out = dir_path.with_suffix(".csv")
            out.write_text(part.read_text(encoding="utf-8"), encoding="utf-8")
            return out
        ok_path = _single_csv(ok_path)
        bad_path = _single_csv(bad_path)

    # Импортируем CLI и вызываем main() напрямую
    from datafabric.cli.main import main as cli_main, Exit

    schema_json = json.dumps({"id": "long", "name": "string", "amount": "double", "dt": "string"}, ensure_ascii=False)

    # Успешный прогон
    code_ok = cli_main(
        [
            "dq",
            "run",
            "--input",
            str(ok_path),
            "--schema",
            schema_json,
            "--require-not-null",
            "id,name,amount,dt",
            "--unique",
            "id",
        ]
    )
    assert code_ok == Exit.OK

    # Провальный прогон
    code_bad = cli_main(
        [
            "dq",
            "run",
            "--input",
            str(bad_path),
            "--schema",
            schema_json,
            "--require-not-null",
            "id,name",
            "--unique",
            "id",
        ]
    )
    assert code_bad == Exit.CONFLICT
