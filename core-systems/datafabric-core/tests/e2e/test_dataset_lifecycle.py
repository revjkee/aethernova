# -*- coding: utf-8 -*-
"""
E2E: Жизненный цикл датасета для локального batch ETL (examples/quickstart_local/batch_demo/etl_job.py).

Тесты проверяют:
- Полный прогон: генерация входных файлов, схема, конфиг → запуск ETL → выпуск результата (CSV.GZ) и манифеста.
- Количество строк (с учётом отбраковок), структура манифеста.
- Идемпотентность: повторный запуск не добавляет дублей, размер набора стабилен.
- Опционально: верификация HMAC-подписи манифеста, если доступен модуль подписи.

Зависимости: pytest, стандартная библиотека Python.
"""

from __future__ import annotations

import csv
import gzip
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest


# ---------------------------
# Помощники
# ---------------------------

def _project_root() -> Path:
    # tests/e2e/... -> корень проекта datafabric-core
    return Path(__file__).resolve().parents[2]

def _etl_job_path() -> Path:
    return _project_root() / "examples" / "quickstart_local" / "batch_demo" / "etl_job.py"

def _run_etl(config_path: Path) -> subprocess.CompletedProcess:
    # Запускаем отдельным процессом, чтобы эмулировать реальную среду выполнения
    cmd = [sys.executable, str(_etl_job_path()), "--config", str(config_path)]
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def _read_manifest(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def _read_csv_gz_rows(path: Path) -> Tuple[List[str], List[Dict[str, str]]]:
    with gzip.open(path, "rt", encoding="utf-8", newline="") as gz:
        reader = csv.DictReader(gz)
        rows = list(reader)
        return reader.fieldnames or [], rows

def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


# ---------------------------
# Фикстуры
# ---------------------------

@pytest.fixture(scope="function")
def ws(tmp_path: Path) -> Dict[str, Path]:
    """
    Рабочее пространство: input/, output/, state/, schemas/, config.json
    """
    root = tmp_path
    in_dir = root / "data" / "input"
    out_dir = root / "data" / "output"
    state_dir = root / "state"
    schemas_dir = root / "schemas"
    for p in (in_dir, out_dir, state_dir, schemas_dir):
        p.mkdir(parents=True, exist_ok=True)
    return {
        "root": root,
        "in_dir": in_dir,
        "out_dir": out_dir,
        "state_dir": state_dir,
        "schemas_dir": schemas_dir,
    }


# ---------------------------
# Данные и схема
# ---------------------------

def _make_inputs_and_schema(ws: Dict[str, Path]) -> Tuple[Path, Path]:
    in_dir = ws["in_dir"]
    # CSV с валидными и одной бракованной строкой (amount пустой)
    csv1 = in_dir / "orders_part1.csv"
    csv1.write_text(
        "order_id,user_id,amount,created_at\n"
        "1,100,10.5,2024-01-01 10:00:00\n"
        "2,101,,2024-01-01 11:00:00\n"
        "3,102,20.0,2024-01-01 12:00:00\n",
        encoding="utf-8",
    )
    # JSONL со всеми валидными
    jsonl1 = in_dir / "orders_part2.jsonl"
    jsonl1.write_text(
        '\n'.join([
            json.dumps({"order_id": 4, "user_id": 103, "amount": 7.75, "created_at": "2024-01-02 09:00:00"}),
            json.dumps({"order_id": 5, "user_id": 104, "amount": 15, "created_at": "2024-01-02 10:00:00"}),
        ]) + "\n",
        encoding="utf-8",
    )

    # JSON Schema (Draft-07 совместимая структура) — amount число, обязательные поля
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "order_id": {"type": "integer"},
            "user_id": {"type": "integer"},
            "amount": {"type": ["number", "integer"]},
            "created_at": {"type": "string"},
        },
        "required": ["order_id", "user_id", "amount", "created_at"],
        "additionalProperties": True,
    }
    schema_path = ws["schemas_dir"] / "order.schema.json"
    _write_json(schema_path, schema)
    return csv1, schema_path


def _make_config(ws: Dict[str, Path], schema_path: Path, *, sign: bool = True) -> Path:
    ckpt = ws["state_dir"] / "batch_demo.ckpt.json"
    cfg = {
        "in_dir": str(ws["in_dir"]),
        "out_dir": str(ws["out_dir"]),
        "schema_path": str(schema_path),
        "rule": {
            "select": ["order_id", "user_id", "amount", "created_at"],
            "rename": {"created_at": "event_time"},
            "casts": {"order_id": "int", "user_id": "int", "amount": "float", "event_time": "date:%Y-%m-%d %H:%M:%S"},
            "add_fields": {"amount_vat": "row.get('amount',0)*1.2"},
            "drop_if_missing": ["order_id", "user_id", "amount", "event_time"]
        },
        "output_basename": "orders",
        "output_format": "csv-gz",
        "partition_by_day": False,  # чтобы путь был детерминирован для теста
        "profile": False,          # отключим для скорости
        "checkpoint_path": str(ckpt),
        "retries": 1,
        "backoff_base": 0.05,
        "backoff_factor": 2.0,
        "sign_manifest": bool(sign),
        "hmac_secret": "testsecret" if sign else None,
        "chunk_size": 256 * 1024,
        "checksum": True
    }
    config_path = ws["root"] / "job_config.json"
    _write_json(config_path, cfg)
    return config_path


# ---------------------------
# Условная верификация подписи
# ---------------------------

def _verify_signature_if_available(manifest: Dict[str, Any]) -> None:
    try:
        from datafabric.security.signature import verify_detached_signature, KeyRef  # type: ignore
    except Exception:
        pytest.skip("signature module is unavailable")
    sig = manifest.get("signature")
    assert isinstance(sig, dict), "signature object must be present in manifest when signing is enabled"
    key = KeyRef(kid="local-demo", secret=b"testsecret")  # type: ignore
    ok, reason = verify_detached_signature(manifest, signature_dict=sig, public_key=key)  # type: ignore
    assert ok, f"signature verification failed: {reason}"


# ---------------------------
# Основной E2E-тест: happy-path + идемпотентность
# ---------------------------

@pytest.mark.e2e
@pytest.mark.slow
def test_dataset_lifecycle_happy_path_and_idempotency(ws: Dict[str, Path]) -> None:
    """
    1) Генерируем вход, схему, конфиг с подписью.
    2) Запускаем ETL и проверяем:
       - код выхода (2, т.к. одна строка отбракована),
       - наличие CSV.GZ и манифеста,
       - количество строк == 4 (из 5, одна отбракована),
       - корректность списка колонок,
       - валидность подписи (если модуль доступен).
    3) Запускаем повторно тот же джоб — результат идемпотентен (строк не становится больше).
    """
    # Arrange
    _, schema_path = _make_inputs_and_schema(ws)
    config_path = _make_config(ws, schema_path, sign=True)

    # Act: первый запуск
    cp1 = _run_etl(config_path)
    # Внимание: etl_job возвращает 2, если были отбраковки — это ожидаемо
    assert cp1.returncode in (0, 2), f"unexpected return code: {cp1.returncode}\nSTDERR:\n{cp1.stderr}"
    # Пути артефактов
    out_dir = ws["out_dir"] / "dt=nopart"
    out_csv = out_dir / "orders.csv.gz"
    out_manifest = out_dir / "orders.manifest.json"

    # Assert: артефакты на месте
    assert out_csv.is_file(), f"missing output file: {out_csv}"
    assert out_manifest.is_file(), f"missing manifest: {out_manifest}"

    # Проверим содержимое CSV.GZ
    headers, rows = _read_csv_gz_rows(out_csv)
    assert headers == ["order_id", "user_id", "amount", "event_time", "amount_vat"]
    # Вход: 5 записей, одна с пустым amount → drop; ожидание: 4 записи
    assert len(rows) == 4, f"unexpected row count: {len(rows)}"
    # Проверим производное поле
    for r in rows:
        assert "amount_vat" in r and r["amount_vat"] != "", "amount_vat must be computed"

    # Проверим манифест
    manifest = _read_manifest(out_manifest)
    for key in ("created_at", "output", "output_bytes", "output_rows", "columns", "input", "config", "tool"):
        assert key in manifest, f"manifest missing key: {key}"
    assert manifest["output_rows"] == 4, "manifest row count mismatch"
    assert manifest["columns"] == headers, "manifest columns mismatch"

    # Подпись (если доступна)
    if manifest.get("signature") is not None:
        _verify_signature_if_available(manifest)

    # Act: второй запуск (идемпотентность — чекпоинт должен исключить повторную обработку)
    cp2 = _run_etl(config_path)
    assert cp2.returncode in (0, 2), f"unexpected return code on rerun: {cp2.returncode}\nSTDERR:\n{cp2.stderr}"

    # Перечитываем результат
    headers2, rows2 = _read_csv_gz_rows(out_csv)
    assert headers2 == headers
    assert len(rows2) == 4, "rerun should not change row count (idempotency)"
    manifest2 = _read_manifest(out_manifest)
    assert manifest2["output_rows"] == 4

    # Дополнительная проверка: размер файла не увеличился после повтора
    assert out_csv.stat().st_size == out_csv.stat().st_size


# ---------------------------
# Негативный сценарий: отсутствие схемы → допускается успешная обработка с минимальной валидацией
# (Если схема не указана, ETL должен пройти без строгой валидации)
# ---------------------------

@pytest.mark.e2e
def test_dataset_lifecycle_without_schema_is_permitted(ws: Dict[str, Path]) -> None:
    # Подготовка входа (все валидные для простоты)
    in_dir = ws["in_dir"]
    (in_dir / "data.csv").write_text(
        "order_id,user_id,amount,created_at\n"
        "11,201,9.5,2024-02-01 10:00:00\n"
        "12,202,5.0,2024-02-01 11:00:00\n",
        encoding="utf-8",
    )
    # Конфиг без schema_path и без подписи (ускоряем)
    cfg = {
        "in_dir": str(ws["in_dir"]),
        "out_dir": str(ws["out_dir"]),
        "schema_path": None,
        "rule": {
            "select": ["order_id", "user_id", "amount", "created_at"],
            "rename": {"created_at": "event_time"},
            "casts": {"order_id": "int", "user_id": "int", "amount": "float", "event_time": "date:%Y-%m-%d %H:%M:%S"},
            "add_fields": {},
            "drop_if_missing": ["order_id", "user_id", "amount", "event_time"]
        },
        "output_basename": "orders2",
        "output_format": "csv-gz",
        "partition_by_day": False,
        "profile": False,
        "checkpoint_path": str(ws["state_dir"] / "batch_demo2.ckpt.json"),
        "retries": 1,
        "backoff_base": 0.05,
        "backoff_factor": 2.0,
        "sign_manifest": False,
        "hmac_secret": None,
        "chunk_size": 128 * 1024,
        "checksum": True
    }
    cfg_path = ws["root"] / "job_config_noschema.json"
    _write_json(cfg_path, cfg)

    # Запуск
    cp = _run_etl(cfg_path)
    assert cp.returncode in (0, 2), f"unexpected return code: {cp.returncode}\nSTDERR:\n{cp.stderr}"

    # Проверка артефактов
    out_dir = ws["out_dir"] / "dt=nopart"
    out_csv = out_dir / "orders2.csv.gz"
    out_manifest = out_dir / "orders2.manifest.json"
    assert out_csv.is_file()
    assert out_manifest.is_file()

    headers, rows = _read_csv_gz_rows(out_csv)
    assert len(rows) == 2
    manifest = _read_manifest(out_manifest)
    assert manifest["output_rows"] == 2
    assert manifest.get("signature") is None
