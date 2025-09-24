# cybersecurity-core/tests/unit/test_sigma_engine.py
# -*- coding: utf-8 -*-
"""
Промышленный набор unit-тестов для cli/tools/import_sigma.py

Особенности:
- Динамическая загрузка модуля по пути (папка проекта содержит дефис, импорт по пакету невозможен).
- Тестирование:
  * детекции дубликатов ключей в YAML (безопасный загрузчик),
  * базовой валидации структуры Sigma,
  * детерминированного хеша правил,
  * атомарной записи JSONL и gzip JSONL,
  * вставки и чтения из SQLite (WAL, ACID),
  * дедупликации правил по rule_id,
  * команд validate/import на уровне внутренних функций (без подпроцесса).

Зависимости тестов: pytest, pyyaml (для самого модуля).
"""

from __future__ import annotations

import io
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, Tuple
import importlib.util
import importlib.machinery
import types
import gzip

import pytest


# ---------- Утилиты для подгрузки тестируемого модуля ----------

def _load_import_sigma() -> types.ModuleType:
    """
    Динамически загружает cybersecurity-core/cli/tools/import_sigma.py как модуль.
    Это обходит невозможность импорта пакета с дефисом в имени (cybersecurity-core).
    """
    # Путь текущего тестового файла: cybersecurity-core/tests/unit/test_sigma_engine.py
    here = Path(__file__).resolve()
    project_root = here.parents[2]  # cybersecurity-core/
    module_path = project_root / "cli" / "tools" / "import_sigma.py"
    assert module_path.exists(), f"File not found: {module_path}"

    loader = importlib.machinery.SourceFileLoader("import_sigma", str(module_path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


# ---------- Фикстуры ----------

@pytest.fixture(scope="module")
def import_sigma():
    return _load_import_sigma()


@pytest.fixture
def tmpdir_path(tmp_path: Path) -> Path:
    return tmp_path


# ---------- Тестовые данные ----------

VALID_SIGMA: str = """\
title: Suspicious LSASS Access
id: 123e4567-e89b-12d3-a456-426614174000
status: stable
description: Detects suspicious access to LSASS process memory.
level: high
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: \\lsass.exe
    CallTrace|contains: "sechost.dll"
  condition: selection
tags:
  - attack.credential_access
references:
  - https://example.org/rule
author: Blue Team
date: 2021/09/01
modified: 2022/10/01
falsepositives:
  - Security product accessing LSASS
"""

INVALID_SIGMA_MISSING_FIELDS: str = """\
title: No Detection
logsource: {}
detection: {}
"""

DUP_KEY_YAML: str = """\
title: Duplicate Keys
logsource:
  product: windows
  product: linux
detection:
  selection:
    EventID: 1
  condition: selection
"""


# ---------- Тесты парсинга и валидации ----------

def test_yaml_duplicate_key_detection(import_sigma):
    # Проверяем, что загрузчик YAML падает при дубликате ключей
    with pytest.raises(Exception):
        import_sigma.parse_sigma_yaml(DUP_KEY_YAML, src_path=None)


def test_basic_validation_ok(import_sigma):
    payload = import_sigma.parse_sigma_yaml(VALID_SIGMA, src_path=None)
    ok, errors = import_sigma.validate_sigma_payload(payload)
    assert ok is True
    assert errors == []


def test_basic_validation_missing_required(import_sigma):
    payload = import_sigma.parse_sigma_yaml(INVALID_SIGMA_MISSING_FIELDS, src_path=None)
    ok, errors = import_sigma.validate_sigma_payload(payload)
    assert ok is False
    # Оба поля имеют некорректные значения (по логике валидатора)
    assert any("detection" in e for e in errors)
    assert any("logsource" in e for e in errors)


# ---------- Тесты детерминированного хеширования ----------

def test_deterministic_rule_hash_stability(import_sigma):
    payload = import_sigma.parse_sigma_yaml(VALID_SIGMA, src_path=None)
    h1 = import_sigma.deterministic_rule_hash(payload)
    h2 = import_sigma.deterministic_rule_hash(payload)
    assert isinstance(h1, str) and len(h1) == 64
    assert h1 == h2, "Хеш должен быть детерминированным для неизменного payload"

    # Незначительные перестановки списков tags не должны менять нормализованный хеш (они сортируются)
    payload2 = dict(payload)
    payload2["tags"] = list(reversed(payload.get("tags", [])))
    h3 = import_sigma.deterministic_rule_hash(payload2)
    assert h1 == h3, "Сортировка тегов должна обеспечивать инвариантность хеша"


# ---------- Тесты сборки SigmaRule и стратегий идентификаторов ----------

@pytest.mark.parametrize("strategy", ["hash", "uuid", "sigma_id"])
def test_build_sigma_rule_id_strategies(import_sigma, strategy, tmpdir_path: Path):
    p = tmpdir_path / "rule.yml"
    p.write_text(VALID_SIGMA, encoding="utf-8")
    payload = import_sigma.parse_sigma_yaml(VALID_SIGMA, src_path=p)
    rule = import_sigma.build_sigma_rule(payload, path=p, id_strategy=strategy)
    assert rule.title == "Suspicious LSASS Access"
    assert rule.file_path == str(p)
    assert rule.file_hash is not None and len(rule.file_hash) == 64
    assert rule.rule_id and isinstance(rule.rule_id, str)
    if strategy == "sigma_id":
        assert rule.rule_id == payload["id"] or rule.rule_id == import_sigma.deterministic_rule_hash(payload)


# ---------- Тесты выходного формата JSONL (включая .gz) ----------

@pytest.mark.parametrize("gz", [False, True])
def test_jsonl_atomic_write_and_read(import_sigma, tmpdir_path: Path, gz: bool):
    rows = [
        {"rule_id": "a", "title": "A"},
        {"rule_id": "b", "title": "B"},
    ]
    out = tmpdir_path / ("rules.jsonl.gz" if gz else "rules.jsonl")
    import_sigma.write_jsonl_atomic(out, rows)

    assert out.exists()
    # Читаем и проверяем содержимое
    content = []
    if gz:
        with gzip.open(out, "rt", encoding="utf-8") as f:
            for line in f:
                content.append(json.loads(line))
    else:
        for line in out.read_text(encoding="utf-8").splitlines():
            content.append(json.loads(line))

    assert content == rows


# ---------- Тесты SQLite пути: инициализация, вставка, запрос ----------

def test_sqlite_insert_and_query(import_sigma, tmpdir_path: Path):
    db = tmpdir_path / "sigma.db"
    conn = import_sigma.sqlite_connect(db)
    try:
        import_sigma.sqlite_init(conn)

        # Готовим два правила, второе — дубликат по rule_id (дедуп не здесь, а на этапе сбора)
        payload = import_sigma.parse_sigma_yaml(VALID_SIGMA, src_path=None)
        rule1 = import_sigma.build_sigma_rule(payload, path=None, id_strategy="hash")
        # Симулируем дубликат
        rule2 = import_sigma.dataclasses.replace(rule1)

        inserted = import_sigma.sqlite_insert_rules(conn, [rule1, rule2])
        # INSERT OR REPLACE — заменит запись тем же ключом; итоговая вставка report'ится как 2 операций.
        assert inserted == 2

        # Проверим чтение
        cur = conn.execute("SELECT rule_id, title, level FROM rules")
        rows = cur.fetchall()
        # В таблице физически одна запись (PRIMARY KEY), но executed rowcount может быть 2
        assert len(rows) == 1
        assert rows[0][0] == rule1.rule_id
        assert rows[0][1] == rule1.title
    finally:
        conn.close()


# ---------- Тесты файлового конвейера: process_file + импорт в JSONL/SQLite ----------

def _write_file(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_process_file_valid_and_invalid(import_sigma, tmpdir_path: Path):
    good = _write_file(tmpdir_path / "ok.yml", VALID_SIGMA)
    bad = _write_file(tmpdir_path / "bad.yml", INVALID_SIGMA_MISSING_FIELDS)

    rule, errs = import_sigma.process_file(good, strict=False, schema=None, id_strategy="hash")
    assert rule is not None and errs == []

    rule2, errs2 = import_sigma.process_file(bad, strict=False, schema=None, id_strategy="hash")
    assert rule2 is None and errs2, "Для невалидного файла должны возвращаться ошибки"


def test_command_import_jsonl_with_dedup(import_sigma, tmpdir_path: Path, capsys):
    # Два одинаковых правила — одно будет дедуплицировано
    f1 = _write_file(tmpdir_path / "r1.yml", VALID_SIGMA)
    f2 = _write_file(tmpdir_path / "r2.yml", VALID_SIGMA)

    out = tmpdir_path / "out.jsonl"
    args = import_sigma.argparse.Namespace(
        command="import",
        input=[str(tmpdir_path)],
        recursive=False,
        workers=2,
        schema=None,
        id_strategy="hash",
        strict=False,
        verbose=True,
        log_json=False,
        output=str(out),
        format="jsonl",
        func=import_sigma.command_import,
    )
    rc = import_sigma.command_import(args)
    assert rc == 0
    assert out.exists()

    # Убедимся, что записалось ровно одно правило
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    obj = json.loads(lines[0])
    assert obj["title"] == "Suspicious LSASS Access"


def test_command_import_sqlite(import_sigma, tmpdir_path: Path):
    f1 = _write_file(tmpdir_path / "r1.yml", VALID_SIGMA)
    out = tmpdir_path / "out.sqlite"
    args = import_sigma.argparse.Namespace(
        command="import",
        input=[str(f1)],
        recursive=False,
        workers=2,
        schema=None,
        id_strategy="hash",
        strict=False,
        verbose=False,
        log_json=True,
        output=str(out),
        format="sqlite",
        func=import_sigma.command_import,
    )
    rc = import_sigma.command_import(args)
    assert rc == 0
    assert out.exists()

    # Проверяем содержимое БД
    conn = sqlite3.connect(str(out))
    try:
        cur = conn.execute("SELECT title, level FROM rules")
        row = cur.fetchone()
        assert row is not None
        assert row[0] == "Suspicious LSASS Access"
        assert row[1] == "high"
    finally:
        conn.close()


def test_command_validate_success_and_fail(import_sigma, tmpdir_path: Path):
    okf = _write_file(tmpdir_path / "ok.yml", VALID_SIGMA)
    badf = _write_file(tmpdir_path / "bad.yml", INVALID_SIGMA_MISSING_FIELDS)

    # Успешный случай
    args_ok = import_sigma.argparse.Namespace(
        command="validate",
        input=[str(okf)],
        recursive=False,
        workers=1,
        schema=None,
        id_strategy="hash",
        strict=False,
        verbose=False,
        log_json=False,
        func=import_sigma.command_validate,
    )
    rc_ok = import_sigma.command_validate(args_ok)
    assert rc_ok == 0

    # С ошибками
    args_bad = import_sigma.argparse.Namespace(
        command="validate",
        input=[str(badf)],
        recursive=False,
        workers=1,
        schema=None,
        id_strategy="hash",
        strict=False,
        verbose=False,
        log_json=False,
        func=import_sigma.command_validate,
    )
    rc_bad = import_sigma.command_validate(args_bad)
    assert rc_bad in (1, 2)  # 1 — есть ошибки, 2 — если вдруг не найден файл


# ---------- Краевые случаи ----------

def test_infer_format_from_output(import_sigma):
    assert import_sigma.infer_format_from_output("x.db") == "sqlite"
    assert import_sigma.infer_format_from_output("x.sqlite") == "sqlite"
    assert import_sigma.infer_format_from_output("x.sqlite3") == "sqlite"
    assert import_sigma.infer_format_from_output("x.jsonl") == "jsonl"


def test_sha256_helpers(import_sigma, tmpdir_path: Path):
    assert len(import_sigma.sha256_hex("abc")) == 64
    p = tmpdir_path / "file.txt"
    p.write_text("content", encoding="utf-8")
    assert len(import_sigma.file_sha256_hex(p)) == 64


def test_open_atomic_write_and_replace(import_sigma, tmpdir_path: Path):
    # Проверяем, что open_atomic создает временный файл в нужной директории
    target = tmpdir_path / "artifact.bin"
    tmp = import_sigma.open_atomic(target, mode="wb")
    try:
        tmp.write(b"data")
        tmppath = Path(tmp.name)
    finally:
        tmp.close()

    assert tmppath.exists()
    # Завершаем атомарную замену
    tmppath.replace(target)
    assert target.exists()
    assert target.read_bytes() == b"data"
