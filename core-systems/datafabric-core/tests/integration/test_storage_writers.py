# -*- coding: utf-8 -*-
"""
Интеграционные тесты для модулей записи хранилища (storage writers) в DataFabric.

Контракт (ожидаемый минимальный API врайтера):
- Конструктор принимает как минимум: base_path (или root_dir), а также опции партиционирования/ротации.
- Асинхронные методы:
    await writer.start()
    await writer.write(record: dict)                 # запись одной записи
    await writer.write_batch(records: list[dict])    # (опционально) батч
    await writer.flush()
    await writer.close()
- Свойства/поведение:
    writer должен атомарно коммитить файлы (без .tmp после close)
    поддерживать партиционирование по полю (например, "event_type")
    поддерживать ротацию по max_bytes и/или max_records
    (опционально) дедуп по msg_id при включении опции deduplicate=True
    (опционально) запись манифеста/индекса (manifest.json) с контрольными суммами

Тесты пытаются обнаружить реализации в модуле datafabric.storage.writers:
- FileJSONLinesWriter
- ParquetWriter
Если модуль/класс или зависимость отсутствуют — тест помечается как skipped.

Важно: Эти тесты не используют внешние сервисы и добиваются детерминированного окружения.
"""

from __future__ import annotations

import asyncio
import importlib
import io
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

# Хэш‑утилиты DataFabric (fallback на hashlib внутри модуля при отсутствии)
try:
    from datafabric.utils.hashing import hash_json_canonical, HashConfig  # type: ignore
    def _jhash(obj: Any) -> str:
        return hash_json_canonical(obj, HashConfig(algo="sha256")).hex
except Exception:  # pragma: no cover
    import hashlib
    def _jhash(obj: Any) -> str:
        data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(data).hexdigest()


# -----------------------------------------------------------------------------
# Вспомогательные генераторы тестовых записей
# -----------------------------------------------------------------------------

def make_record(i: int, *, et: str = "order.created") -> Dict[str, Any]:
    order_id = f"O-{i:08d}"
    cust_id = f"C-{(i * 7) % 1000000:08d}"
    rec = {
        "msg_id": f"m-{i:016d}",
        "ts": f"2025-08-15T00:00:{i%60:02d}.000Z",
        "dataset": "sales",
        "event_type": et,
        "key": {"order_id": order_id, "customer_id": cust_id},
        "payload": {"amount_cents": i * 5 + 123, "currency": "USD", "items": [{"sku": f"SKU-{i%9999:04d}", "qty": (i%5)+1}]},
    }
    rec["_meta"] = {"schema": "demo.order.v1", "hash": "sha256:" + _jhash({"event_type": et, "key": rec["key"], "payload": rec["payload"]})}
    return rec


def make_records(n: int, *, et_cycle: Tuple[str, ...] = ("order.created", "order.updated", "order.paid")) -> List[Dict[str, Any]]:
    out = []
    for i in range(n):
        et = et_cycle[i % len(et_cycle)]
        out.append(make_record(i, et=et))
    return out


# -----------------------------------------------------------------------------
# Динамическое обнаружение доступных врайтеров
# -----------------------------------------------------------------------------

@pytest.fixture(scope="session")
def writers_module():
    try:
        return importlib.import_module("datafabric.storage.writers")
    except Exception as e:
        pytest.skip(f"Модуль datafabric.storage.writers не найден: {e}")


def _get_writer_cls(mod, name: str):
    return getattr(mod, name, None)


@pytest.fixture(params=["FileJSONLinesWriter", "ParquetWriter"])
def writer_cls(request, writers_module):
    cls = _get_writer_cls(writers_module, request.param)
    if cls is None:
        pytest.skip(f"{request.param} отсутствует в datafabric.storage.writers")
    # Для Parquet проверим pyarrow
    if request.param == "ParquetWriter":
        try:
            import pyarrow  # noqa: F401
            import pyarrow.parquet  # noqa: F401
        except Exception as e:
            pytest.skip(f"pyarrow недоступен: {e}")
    return cls


# -----------------------------------------------------------------------------
# Универсальные тесты (для всех врайтеров)
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_basic_write_flush_close(tmp_path: Path, writer_cls):
    base = tmp_path / "out"
    base.mkdir(parents=True, exist_ok=True)

    # Попробуем общий конструктор. Поддержим разные сигнатуры.
    kw = {
        "base_path": str(base),
        "root_dir": str(base),
        "max_bytes": 1024 * 1024,
        "max_records": 10000,
        "partition_by": None,
        "deduplicate": False,
        "file_prefix": "events",
    }
    # Отфильтруем неподдерживаемые параметры по сигнатуре
    from inspect import signature
    sig = signature(writer_cls)
    ctor_kwargs = {k: v for k, v in kw.items() if k in sig.parameters}

    writer = writer_cls(**ctor_kwargs)
    # Наличие write_batch — опционально
    has_batch = hasattr(writer, "write_batch")

    await writer.start()
    recs = make_records(100)
    if has_batch:
        await writer.write_batch(recs)  # type: ignore[attr-defined]
    else:
        for r in recs:
            await writer.write(r)

    await writer.flush()
    await writer.close()

    # Проверим, что что‑то записалось
    assert any(base.rglob("*")), "Выходные файлы не созданы"

    # Не должно быть .tmp после close()
    tmp_left = list(p for p in base.rglob("*") if p.suffix == ".tmp")
    assert not tmp_left, f"Неожиданные временные файлы: {tmp_left}"

    # Если это NDJSON‑путь — посчитаем записи
    ndjson_files = [p for p in base.rglob("*") if p.suffix in (".ndjson", ".jsonl")]
    if ndjson_files:
        total = 0
        for f in ndjson_files:
            with f.open("rb") as fin:
                for line in fin:
                    if not line.strip():
                        continue
                    obj = json.loads(line.decode("utf-8"))
                    assert "msg_id" in obj and "payload" in obj
                    total += 1
        assert total == len(recs)

    # Если есть manifest.json — провалидируем контрольные суммы
    manifests = list(base.rglob("manifest.json"))
    for mf in manifests:
        data = json.loads(mf.read_text(encoding="utf-8"))
        files = data.get("files") or []
        for ent in files:
            path = base / ent["path"]
            algo, hexv = ent["hash"].split(":", 1)
            # Простой пересчет SHA‑256 содержимого файла
            import hashlib
            h = hashlib.new(algo)
            h.update(path.read_bytes())
            assert h.hexdigest() == hexv, f"Несовпадение хэша для {path}"


@pytest.mark.asyncio
async def test_partitioning_by_field(tmp_path: Path, writer_cls):
    base = tmp_path / "part"
    base.mkdir(parents=True, exist_ok=True)

    # Параметр партиционирования может называться по‑разному
    ctor = {}
    for k in ("partition_by", "partition_field", "partition"):
        ctor[k] = "event_type"
    for k in ("base_path", "root_dir"):
        ctor[k] = str(base)
    writer = writer_cls(**{k: v for k, v in ctor.items() if k in __import__("inspect").signature(writer_cls).parameters})

    await writer.start()
    recs = make_records(120, et_cycle=("order.created", "order.updated", "order.paid"))
    # Пишем батчами по 20
    for i in range(0, len(recs), 20):
        batch = recs[i : i + 20]
        if hasattr(writer, "write_batch"):
            await writer.write_batch(batch)  # type: ignore[attr-defined]
        else:
            for r in batch:
                await writer.write(r)
    await writer.flush()
    await writer.close()

    # Проверим, что создано минимум 3 партиции
    subdirs = set()
    for p in base.rglob("*"):
        if p.is_dir():
            # Папки вида event_type=order.created или просто order.created
            if "event_type=" in p.name:
                val = p.name.split("event_type=", 1)[1]
                subdirs.add(val)
            elif p.name in ("order.created", "order.updated", "order.paid"):
                subdirs.add(p.name)
    assert subdirs >= {"order.created", "order.updated", "order.paid"}, f"Партиции не обнаружены: {subdirs}"


@pytest.mark.asyncio
async def test_rotation_limits(tmp_path: Path, writer_cls):
    base = tmp_path / "rotate"
    base.mkdir(parents=True, exist_ok=True)

    sig = __import__("inspect").signature(writer_cls)
    kwargs = {}
    for k in ("base_path", "root_dir"):
        if k in sig.parameters:
            kwargs[k] = str(base)
    if "max_records" in sig.parameters:
        kwargs["max_records"] = 50
    if "max_bytes" in sig.parameters:
        kwargs["max_bytes"] = 12 * 1024  # маленький лимит для гарантированной ротации
    writer = writer_cls(**kwargs)

    await writer.start()
    recs = make_records(200)
    if hasattr(writer, "write_batch"):
        for i in range(0, len(recs), 25):
            await writer.write_batch(recs[i : i + 25])  # type: ignore[attr-defined]
    else:
        for r in recs:
            await writer.write(r)
    await writer.flush()
    await writer.close()

    # Должно быть создано несколько файлов (или каталогов)
    files = [p for p in base.rglob("*") if p.is_file()]
    assert len(files) > 1, "Не произошло ротации: получен один файл"


@pytest.mark.asyncio
async def test_concurrent_writes(tmp_path: Path, writer_cls):
    base = tmp_path / "concurrency"
    base.mkdir(parents=True, exist_ok=True)

    sig = __import__("inspect").signature(writer_cls)
    kw = {k: str(base) for k in ("base_path", "root_dir") if k in sig.parameters}
    writer = writer_cls(**kw)

    await writer.start()

    async def worker(offset: int, n: int):
        for i in range(n):
            await writer.write(make_record(offset + i))

    # 4 конкурентных воркера по 50 записей
    await asyncio.gather(*[worker(i * 50, 50) for i in range(4)])
    await writer.flush()
    await writer.close()

    # Проверка на содержимое (для NDJSON)
    ndjson = [p for p in base.rglob("*") if p.suffix in (".ndjson", ".jsonl")]
    if ndjson:
        total = 0
        ids = set()
        for f in ndjson:
            with f.open("rb") as fin:
                for line in fin:
                    if not line.strip():
                        continue
                    obj = json.loads(line.decode("utf-8"))
                    ids.add(obj["msg_id"])
                    total += 1
        assert total == 200 and len(ids) == 200, "Потеря или дублирование записей при конкурентной записи"


@pytest.mark.asyncio
async def test_idempotency_by_msg_id(tmp_path: Path, writer_cls):
    base = tmp_path / "idem"
    base.mkdir(parents=True, exist_ok=True)

    sig = __import__("inspect").signature(writer_cls)
    kw = {k: str(base) for k in ("base_path", "root_dir") if k in sig.parameters}
    if "deduplicate" in sig.parameters:
        kw["deduplicate"] = True
    else:
        pytest.skip("Врайтер не поддерживает deduplicate=True")

    writer = writer_cls(**kw)
    await writer.start()

    recs = make_records(50)
    # Дублируем первые 10 msg_id
    recs_dup = recs + [dict(recs[i]) for i in range(10)]
    if hasattr(writer, "write_batch"):
        await writer.write_batch(recs_dup)  # type: ignore[attr-defined]
    else:
        for r in recs_dup:
            await writer.write(r)
    await writer.flush()
    await writer.close()

    ndjson = [p for p in base.rglob("*") if p.suffix in (".ndjson", ".jsonl")]
    if ndjson:
        ids = set()
        total = 0
        for f in ndjson:
            with f.open("rb") as fin:
                for line in fin:
                    if not line.strip():
                        continue
                    obj = json.loads(line.decode("utf-8"))
                    ids.add(obj["msg_id"])
                    total += 1
        # Если включён dedup — уникальных должно быть 50
        assert len(ids) == 50, f"Идемпотентность не соблюдена: уникальных {len(ids)}"
        assert total == 50, f"Ожидалось 50 записей, получено {total}"


# -----------------------------------------------------------------------------
# Специальные тесты для Parquet (если доступно)
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_parquet_schema_compat(tmp_path: Path, writers_module):
    ParquetWriter = getattr(writers_module, "ParquetWriter", None)
    if ParquetWriter is None:
        pytest.skip("ParquetWriter отсутствует")
    try:
        import pyarrow as pa  # type: ignore
        import pyarrow.parquet as pq  # type: ignore
    except Exception as e:
        pytest.skip(f"pyarrow недоступен: {e}")

    base = tmp_path / "pq"
    base.mkdir(parents=True, exist_ok=True)

    sig = __import__("inspect").signature(ParquetWriter)
    kw = {k: str(base) for k in ("base_path", "root_dir") if k in sig.parameters}
    # Небольшая ротация, чтобы получить несколько файлов
    if "max_records" in sig.parameters:
        kw["max_records"] = 25

    writer = ParquetWriter(**kw)
    await writer.start()

    # Пишем сначала базовую схему
    recs_a = make_records(50, et_cycle=("order.created",))
    await (writer.write_batch(recs_a) if hasattr(writer, "write_batch") else asyncio.gather(*[writer.write(r) for r in recs_a]))  # type: ignore

    # Затем схему с дополнительным полем
    recs_b = []
    for i in range(50, 80):
        r = make_record(i, et="order.updated")
        r["payload"]["new_field"] = f"v-{i}"
        recs_b.append(r)
    if hasattr(writer, "write_batch"):
        await writer.write_batch(recs_b)  # type: ignore[attr-defined]
    else:
        for r in recs_b:
            await writer.write(r)

    await writer.flush()
    await writer.close()

    pq_files = [p for p in base.rglob("*.parquet")]
    assert pq_files, "Parquet файлы не созданы"

    # Чтение и проверка наличия колонок
    cols_all = set()
    total_rows = 0
    for f in pq_files:
        tbl = pq.read_table(f)
        cols_all.update(tbl.column_names)
        total_rows += tbl.num_rows

    assert total_rows == len(recs_a) + len(recs_b), "Число строк в Parquet не совпадает"
    # Доп. поле должно попасть хотя бы в часть файлов
    assert "payload.new_field" in cols_all or "new_field" in cols_all, "Колонка для нового поля не обнаружена"


# -----------------------------------------------------------------------------
# Утилиты
# -----------------------------------------------------------------------------

def _list_all_files(root: Path) -> List[Path]:
    return [p for p in root.rglob("*") if p.is_file()]
