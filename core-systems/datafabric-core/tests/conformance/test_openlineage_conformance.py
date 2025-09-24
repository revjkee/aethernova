# -*- coding: utf-8 -*-
"""
tests/conformance/test_openlineage_conformance.py

Промышленный набор тестов на соответствие OpenLineage-пейлоадов:
- Валидация базовой структуры RunEvent (минимальная JSON-схема).
- Дополнительные инварианты: UUID, ISO8601 с таймзоной, producer/schemaURL, допустимые eventType.
- Проверка согласованности последовательности START → COMPLETE (runId/job неизменны, время не убывает).
- Проверка inputs/outputs: наличие namespace/name, разумная нормализация, отсутствие дубликатов.
- Проверка фасетов: объектная форма, непустые ключи, ограниченная "кардинальность" имен.

Источники данных для тестов (по приоритету):
1) Окружение DF_OL_EVENTS_DIR — путь к каталогу с *.json событиями (по одному объекту на файл).
2) Реальный адаптер DataFabric (если присутствует модуль и предоставляет capture-эмиттер).
3) Сгенерированные sample-события (для smoke; не проверяют интеграцию, только валидатор).

Зависимости:
- pytest (обязателен).
- jsonschema (опционально; при отсутствии часть проверок выполнится вручную).
- python-dateutil (опционально; используется, если доступен).

Запуск:
    pytest -q tests/conformance/test_openlineage_conformance.py
    DF_OL_EVENTS_DIR=./artifacts/openlineage pytest -q ...

© DataFabric Core. MIT License.
"""
from __future__ import annotations

import json
import os
import re
import uuid
import glob
import pathlib
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pytest

# Опциональные зависимости (мягкий импорт)
try:
    import jsonschema  # type: ignore
except Exception:  # pragma: no cover
    jsonschema = None  # type: ignore

try:
    from dateutil import parser as dateparser  # type: ignore
except Exception:  # pragma: no cover
    dateparser = None  # type: ignore


pytestmark = pytest.mark.conformance


# ============================== Утилиты/валидаторы ===========================

_EVENT_TYPES = {"START", "RUNNING", "COMPLETE", "ABORT", "FAIL"}

_MIN_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["eventType", "eventTime", "run", "job", "producer", "schemaURL"],
    "properties": {
        "eventType": {"type": "string", "enum": sorted(list(_EVENT_TYPES))},
        "eventTime": {"type": "string"},  # формат проверяется отдельно
        "producer": {"type": "string", "minLength": 3},
        "schemaURL": {"type": "string", "minLength": 3},
        "run": {
            "type": "object",
            "required": ["runId"],
            "properties": {"runId": {"type": "string", "minLength": 1}, "facets": {"type": "object"}},
        },
        "job": {
            "type": "object",
            "required": ["namespace", "name"],
            "properties": {
                "namespace": {"type": "string", "minLength": 1},
                "name": {"type": "string", "minLength": 1},
                "facets": {"type": "object"},
            },
        },
        "inputs": {"type": "array", "items": {"$ref": "#/$defs/dataset"}},
        "outputs": {"type": "array", "items": {"$ref": "#/$defs/dataset"}},
    },
    "$defs": {
        "dataset": {
            "type": "object",
            "required": ["namespace", "name"],
            "properties": {"namespace": {"type": "string"}, "name": {"type": "string"}, "facets": {"type": "object"}},
        }
    },
}

_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_ISO_Z_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+\-]\d{2}:\d{2})$"
)


def _is_uuid(s: str) -> bool:
    try:
        uuid.UUID(str(s))
        return True
    except Exception:
        return False


def _validate_event_basic(ev: Dict[str, Any]) -> None:
    """
    Базовая структурная валидация + ключевые инварианты OpenLineage RunEvent.
    """
    # JSONSchema (если доступна)
    if jsonschema is not None:
        jsonschema.validate(instance=ev, schema=_MIN_SCHEMA)  # type: ignore
    else:
        # Ручные обязательные поля
        for k in ["eventType", "eventTime", "run", "job", "producer", "schemaURL"]:
            assert k in ev, f"missing required field: {k}"
        assert isinstance(ev["run"], dict) and "runId" in ev["run"], "run.runId missing"
        assert isinstance(ev["job"], dict) and "namespace" in ev["job"] and "name" in ev["job"], "job fields missing"

    # eventType допустим
    et = ev.get("eventType")
    assert et in _EVENT_TYPES, f"unexpected eventType: {et}"

    # Время ISO8601 с таймзоной
    ts = str(ev.get("eventTime"))
    assert _ISO_Z_RE.match(ts), f"eventTime must be ISO8601 with timezone: {ts}"
    if dateparser is not None:
        _ = dateparser.isoparse(ts)

    # runId UUID
    assert _is_uuid(ev["run"]["runId"]), f"runId is not a valid UUID: {ev['run']['runId']}"

    # URL-поля — валидные схемы
    prod = str(ev.get("producer"))
    sch = str(ev.get("schemaURL"))
    assert _URL_RE.match(prod), f"producer must be a URL: {prod}"
    assert _URL_RE.match(sch), f"schemaURL must be a URL: {sch}"

    # inputs/outputs — массивы датасетов с namespace/name
    for coll_name in ("inputs", "outputs"):
        coll = ev.get(coll_name, [])
        if coll is None:
            coll = []
        assert isinstance(coll, list), f"{coll_name} must be a list"
        for ds in coll:
            assert isinstance(ds, dict), f"{coll_name} item must be object"
            assert ds.get("namespace") and ds.get("name"), f"{coll_name} dataset requires namespace and name"
            # facets объект
            if "facets" in ds:
                assert isinstance(ds["facets"], dict), f"{coll_name}.facets must be object"

    # facets на run/job — если есть, то объект
    if "facets" in ev.get("run", {}):
        assert isinstance(ev["run"]["facets"], dict)
    if "facets" in ev.get("job", {}):
        assert isinstance(ev["job"]["facets"], dict)


def _normalize_sequence(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(list(events), key=lambda e: str(e.get("eventTime", "")))


def _dedup_dataset_keys(datasets: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    seen: List[Tuple[str, str]] = []
    for ds in datasets:
        key = (str(ds.get("namespace", "")), str(ds.get("name", "")))
        if key not in seen:
            seen.append(key)
    return seen


# ============================== Фикстуры источников ==========================

def _load_events_from_dir(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for fp in sorted(glob.glob(os.path.join(path, "*.json"))):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                ev = json.load(f)
                if isinstance(ev, dict):
                    out.append(ev)
                elif isinstance(ev, list):
                    out.extend([x for x in ev if isinstance(x, dict)])
        except Exception:
            continue
    return out


def _sample_events_sequence() -> List[Dict[str, Any]]:
    """
    Генератор эталонной (минимальной) последовательности START -> COMPLETE.
    Не привязан к реализациям DataFabric; используется как fallback.
    """
    rid = str(uuid.uuid4())
    base = {
        "run": {"runId": rid},
        "job": {"namespace": "datafabric.tests", "name": "sample_job"},
        "producer": "https://datafabric.example/producer",
        "schemaURL": "https://openlineage.io/spec/1-0-5/OpenLineage.json",
        "inputs": [{"namespace": "s3", "name": "bucket/path/input.csv"}],
        "outputs": [{"namespace": "s3", "name": "bucket/path/output.csv"}],
    }
    return [
        {
            **base,
            "eventType": "START",
            "eventTime": "2025-08-15T12:00:00Z",
        },
        {
            **base,
            "eventType": "COMPLETE",
            "eventTime": "2025-08-15T12:00:05Z",
        },
    ]


@pytest.fixture(scope="session")
def openlineage_events() -> Tuple[List[Dict[str, Any]], str]:
    """
    Возвращает (events, source), где source:
      - "dir"   — события взяты из DF_OL_EVENTS_DIR
      - "real"  — события, собранные из реального эмиттера (если будет добавлен)
      - "sample"— сгенерированные sample-события
    Сейчас поддерживаются "dir" и "sample". Под "real" оставлены расширяемые зацепки.
    """
    # 1) События из каталога
    path = os.getenv("DF_OL_EVENTS_DIR")
    if path and os.path.isdir(path):
        evs = _load_events_from_dir(path)
        if evs:
            return (evs, "dir")

    # 2) Место для интеграции с реальным адаптером (пока не используется).
    # Попытка импорта/захвата может быть добавлена в будущем без изменения тестов.

    # 3) Fallback — sample
    return (_sample_events_sequence(), "sample")


# ============================== Тесты соответствия ===========================

def test_min_schema_conformance(openlineage_events):
    events, source = openlineage_events
    assert events, "no events to validate"

    for ev in events:
        _validate_event_basic(ev)


def test_sequence_consistency(openlineage_events):
    events, source = openlineage_events
    # Отбираем события одного запуска по runId (берем первый встретившийся)
    events = _normalize_sequence(events)
    first = events[0]
    rid = first["run"]["runId"]
    job_ns = first["job"]["namespace"]
    job_name = first["job"]["name"]

    seq = [e for e in events if e.get("run", {}).get("runId") == rid]
    assert seq, "no events for selected runId"

    # Порядок времени не убывает
    prev_ts = None
    for e in seq:
        ts = e["eventTime"]
        if prev_ts is not None:
            assert ts >= prev_ts, f"eventTime not increasing: {prev_ts} -> {ts}"
        prev_ts = ts

        # job неизменен
        assert e["job"]["namespace"] == job_ns
        assert e["job"]["name"] == job_name

    # Допустимая терминальная стадия
    terminal = {e["eventType"] for e in seq if e["eventType"] in {"COMPLETE", "FAIL", "ABORT"}}
    assert terminal, "no terminal event in sequence"


def test_inputs_outputs_datasets(openlineage_events):
    events, source = openlineage_events
    events = _normalize_sequence(events)
    # Смотрим на финальное событие (чаще всего полнее)
    last = events[-1]

    inputs = last.get("inputs", []) or []
    outputs = last.get("outputs", []) or []

    # Нет дубликатов по (namespace, name)
    assert len(_dedup_dataset_keys(inputs)) == len(inputs), "duplicate inputs detected"
    assert len(_dedup_dataset_keys(outputs)) == len(outputs), "duplicate outputs detected"

    # Разумная нормализация: без пустых строк и пробельных имён
    for ds in inputs + outputs:
        assert isinstance(ds["namespace"], str) and ds["namespace"].strip()
        assert isinstance(ds["name"], str) and ds["name"].strip()


def test_facets_shape(openlineage_events):
    events, source = openlineage_events
    # Проверяем, что run/job/dataset facets имеют объектную форму и строковые ключи
    for ev in events:
        for path in [("run",), ("job",)]:
            node = ev
            for k in path:
                node = node.get(k, {})
            facets = node.get("facets", {})
            if facets:
                assert isinstance(facets, dict)
                for fk, fv in facets.items():
                    assert isinstance(fk, str) and fk.strip(), "facet name must be non-empty string"
                    assert isinstance(fv, dict), "facet value must be object"

        for coll in ("inputs", "outputs"):
            for ds in ev.get(coll, []) or []:
                facets = ds.get("facets", {})
                if facets:
                    assert isinstance(facets, dict)
                    for fk, fv in facets.items():
                        assert isinstance(fk, str) and fk.strip()
                        assert isinstance(fv, dict)


@pytest.mark.parametrize("terminal", ["COMPLETE", "FAIL", "ABORT"])
def test_allowed_terminal_types(terminal):
    # Убеждаемся, что терминальные статусы входят в допустимое множество
    assert terminal in _EVENT_TYPES


def test_producer_and_schema_urls(openlineage_events):
    events, source = openlineage_events
    for ev in events:
        prod = str(ev.get("producer"))
        sch = str(ev.get("schemaURL"))
        assert _URL_RE.match(prod), f"invalid producer url: {prod}"
        assert _URL_RE.match(sch), f"invalid schema url: {sch}"
        # Нейтральная проверка: schemaURL ссылается на openlineage.io
        assert "openlineage" in sch.lower()


# ============================== Скипы/диагностика ============================

def test_diagnostics_print_source(openlineage_events, capsys):
    """
    Нефункциональный тест печати источника событий — помогает в CI-логах понять,
    из чего именно шла проверка (dir|real|sample). Не влияет на прохождение.
    """
    events, source = openlineage_events
    print(f"[diagnostics] openlineage events source={source}, count={len(events)}")
    captured = capsys.readouterr()
    assert f"source={source}" in captured.out
