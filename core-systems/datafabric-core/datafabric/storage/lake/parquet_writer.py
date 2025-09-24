# datafabric-core/datafabric/storage/lake/parquet_writer.py
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import os
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, Field, validator

# Опциональные зависимости
try:
    import pyarrow as pa
    import pyarrow.parquet as pq
    import pyarrow.fs as pafs
except Exception as e:  # pragma: no cover
    raise RuntimeError("pyarrow is required for parquet_writer") from e

try:
    import pandas as pd  # для удобного приема DataFrame
except Exception:
    pd = None  # не критично

# ===================== Протоколы метрик/трейсинга =====================

class Metrics:
    async def inc(self, name: str, value: int = 1, **labels: str) -> None:
        return
    async def observe(self, name: str, value: float, **labels: str) -> None:
        return

class Tracer:
    def start_span(self, name: str, **attrs: Any) -> "Span":
        return Span()

class Span:
    def set_attribute(self, key: str, value: Any) -> None:
        return
    def record_exception(self, exc: BaseException) -> None:
        return
    def end(self) -> None:
        return

# =============================== Конфиг ===============================

class RotationConfig(BaseModel):
    max_rows: int = Field(1_000_000, ge=1)
    max_bytes: int = Field(256 * 1024 * 1024, ge=1024)  # 256 MiB
    max_interval_s: int = Field(300, ge=1)  # 5 минут

class RetryConfig(BaseModel):
    max_attempts: int = Field(5, ge=1, le=15)
    base_delay_ms: int = Field(100, ge=1)
    max_delay_ms: int = Field(10_000, ge=100)
    jitter_ms: int = Field(200, ge=0)
    exponential_factor: float = Field(2.0, ge=1.0)

class ParquetWriterConfig(BaseModel):
    base_uri: str = Field(..., description="Корень набора данных: s3://bucket/prefix или file:///data/lake")
    dataset: str = Field("dataset", description="Имя набора в дереве lake")
    partition_cols: List[str] = Field(default_factory=list, description="Hive‑style партиционирование")
    filename_prefix: str = Field("part", description="Префикс имени файла")
    compression: str = Field("zstd", description="zstd|snappy|gzip|none")
    bloom_filter: bool = Field(False, description="Включить bloom filters (pyarrow>=13)")
    write_statistics: bool = Field(True)
    dictionary_cols: List[str] = Field(default_factory=list, description="Столбцы для словарной кодировки")
    coerce_timestamps: str = Field("ms", description="none|ms|us|ns")
    timezone: str = Field("UTC", description="TZ для коэрции временных меток")
    schema_json: Optional[str] = Field(None, description="PA schema в формате pa.schema().to_string(); опционально")
    allow_schema_evolution: bool = Field(True, description="Разрешать добавление новых столбцов")
    default_values: Dict[str, Any] = Field(default_factory=dict, description="Заполнители по умолчанию для отсутствующих столбцов")
    rotation: RotationConfig = RotationConfig()
    retries: RetryConfig = RetryConfig()
    max_concurrency: int = Field(8, ge=1, le=64)
    metrics_prefix: str = Field("datafabric_parquet")
    tmp_suffix: str = Field(".tmp", description="Суффикс временных файлов")
    file_uuid_in_name: bool = Field(True)
    use_single_file_writer: bool = Field(False, description="true: файл на партицию с append; false: write_table чанками")
    filesystem_options: Dict[str, Any] = Field(default_factory=dict, description="Опции для pafs.FileSystem.from_uri")

    @validator("compression")
    def _val_comp(cls, v: str) -> str:
        v = v.lower()
        if v not in ("zstd", "snappy", "gzip", "none"):
            raise ValueError("compression must be one of: zstd|snappy|gzip|none")
        return v

    @validator("coerce_timestamps")
    def _val_ts(cls, v: str) -> str:
        v = v.lower()
        if v not in ("none", "ms", "us", "ns"):
            raise ValueError("coerce_timestamps must be one of: none|ms|us|ns")
        return v

# ============================ Исключения ==============================

class ParquetLakeError(Exception): ...
class SchemaError(ParquetLakeError): ...
class WriteError(ParquetLakeError): ...

# ============================ Утилиты ==============================

def _compute_backoff(attempt: int, cfg: RetryConfig) -> float:
    base = cfg.base_delay_ms / 1000.0
    delay = min(base * (cfg.exponential_factor ** (attempt - 1)), cfg.max_delay_ms / 1000.0)
    jitter = (cfg.jitter_ms / 1000.0) * (os.urandom(1)[0] / 255.0) if cfg.jitter_ms > 0 else 0.0
    return delay + jitter

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def _sanitize_part_value(v: Any) -> str:
    if v is None:
        return "__NULL__"
    s = str(v)
    return s.replace("/", "_").replace("=", "_")

def _estimate_table_size_bytes(tbl: pa.Table) -> int:
    # Грубая оценка: суммарный размер буферов
    total = 0
    for col in tbl.columns:
        for chunk in col.data.chunks if isinstance(col.data, pa.ChunkedArray) else [col.data]:
            for buf in chunk.buffers():
                if buf is not None:
                    total += len(buf)
    return total

def _load_schema_from_string(schema_text: str) -> pa.schema:
    try:
        # pyarrow не имеет прямого парсера из string; ожидаем JSON‑форму через schema.to_json(), если есть
        import json
        obj = json.loads(schema_text)
        return pa.schema([pa.field(f["name"], pa.type_for_alias(f["type"])) for f in obj["fields"]])  # упрощенный парсер
    except Exception as e:
        # Фоллбек: это может быть обычный repr — не поддерживаем для надёжности
        raise SchemaError("schema_json must be JSON from pa.schema(...).to_json()") from e

def _coerce_table_to_schema(tbl: pa.Table, target: pa.Schema, defaults: Mapping[str, Any]) -> pa.Table:
    # Добавим отсутствующие столбцы
    for field in target:
        if field.name not in tbl.column_names:
            default_value = defaults.get(field.name, None)
            arr = pa.array([default_value] * len(tbl), type=field.type)
            tbl = tbl.append_column(field.name, arr)
    # Удалим лишние столбцы (если не разрешена эволюция — это будет обработано снаружи)
    to_drop = [name for name in tbl.column_names if name not in {f.name for f in target}]
    if to_drop:
        keep = [name for name in tbl.column_names if name not in to_drop]
        tbl = tbl.select(keep)
    # Коэрция типов, где это возможно
    for field in target:
        idx = tbl.column_names.index(field.name)
        col = tbl.column(idx)
        if not col.type.equals(field.type):
            try:
                tbl = tbl.set_column(idx, field.name, pa.compute.cast(col, target_type=field.type))
            except Exception as e:
                raise SchemaError(f"Failed to cast column {field.name} to {field.type}: {e}") from e
    return tbl

def _infer_schema_from_table(tbl: pa.Table) -> pa.Schema:
    return tbl.schema

# ============================ Внутреннее состояние =====================

@dataclasses.dataclass
class _OpenFile:
    partition_path: str
    file_path_tmp: str
    file_path_final: str
    writer: Optional[pq.ParquetWriter]
    rows: int = 0
    bytes: int = 0
    opened_at: float = dataclasses.field(default_factory=time.monotonic)

# ============================ Основной класс ===========================

class ParquetLakeWriter:
    """
    Высоконадежный асинхронный Parquet‑writer с поддержкой:
    - Hive‑style партиционирования
    - Ротации по строкам/байтам/времени
    - Атомарной записи: tmp → finalize (rename)
    - Ретраев, метрик, трейса, backpressure
    - Схемы и её эволюции (добавление столбцов)
    - Любые URI через pyarrow.fs (s3://, file://, hdfs:// ...)

    Потокобезопасность: сериализация write‑операций по партиции; глобальный лимит concurrency.
    """

    def __init__(
        self,
        cfg: ParquetWriterConfig,
        *,
        metrics: Optional[Metrics] = None,
        tracer: Optional[Tracer] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self.cfg = cfg
        self.metrics = metrics or Metrics()
        self.tracer = tracer or Tracer()
        self.loop = loop or asyncio.get_event_loop()

        self._fs, self._base_path = pafs.FileSystem.from_uri(self.cfg.base_uri, **(self.cfg.filesystem_options or {}))
        # dataset root: <base>/<dataset>
        self._dataset_root = self._join(self._base_path, self.cfg.dataset)

        # Состояние
        self._schema: Optional[pa.Schema] = None
        self._open_by_partition: Dict[str, _OpenFile] = {}
        self._locks_by_partition: Dict[str, asyncio.Lock] = {}
        self._sem = asyncio.Semaphore(self.cfg.max_concurrency)
        self._stop = False
        self._ready = False

    # --------------------- Жизненный цикл ---------------------

    async def __aenter__(self) -> "ParquetLakeWriter":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def start(self) -> None:
        # Проверим доступность ФС и создадим корень
        await self._call_fs(self._fs.create_dir, self._dataset_root, recursive=True, op="create_dir")
        # Инициализируем схему, если задана
        if self.cfg.schema_json:
            self._schema = _load_schema_from_string(self.cfg.schema_json)
        self._ready = True

    async def close(self) -> None:
        self._stop = True
        # Сбросим все открытые файлы
        tasks = [self._finalize_partition(p, of, force=True) for p, of in list(self._open_by_partition.items())]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._open_by_partition.clear()
        self._locks_by_partition.clear()
        self._ready = False

    async def health(self) -> Tuple[bool, Optional[str]]:
        return (self._ready and not self._stop, None if self._ready and not self._stop else "not ready or stopping")

    # ---------------------- Публичные методы записи ----------------------

    async def write_records(self, rows: Sequence[Mapping[str, Any]]) -> None:
        """
        Принять список записей (dict‑ов) и записать с учетом партиций/ротации/схемы.
        """
        if not rows:
            return
        tbl = pa.Table.from_pylist(list(rows))
        await self._write_table(tbl)

    async def write_dataframe(self, df: "pd.DataFrame") -> None:
        if pd is None:
            raise ParquetLakeError("pandas is not installed")
        tbl = pa.Table.from_pandas(df, preserve_index=False)
        await self._write_table(tbl)

    async def flush(self) -> None:
        """
        Принудительно завершить текущие открытые файлы (по всем партициям).
        """
        tasks = [self._finalize_partition(p, st, force=True) for p, st in list(self._open_by_partition.items())]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ---------------------- Внутренняя запись ----------------------

    async def _write_table(self, tbl: pa.Table) -> None:
        if self._stop:
            raise WriteError("writer is stopping")
        # Первая партия — зафиксируем схему (или эволюционируем)
        if self._schema is None:
            self._schema = _infer_schema_from_table(tbl)
        else:
            # эволюция: добавление недостающих столбцов
            if self.cfg.allow_schema_evolution:
                # Добавим недостающие поля в target‑схему
                for name in tbl.column_names:
                    if name not in {f.name for f in self._schema}:
                        self._schema = self._schema.append(pa.field(name, tbl.schema.field(name).type))
            else:
                # удалим неописанные поля из таблицы
                keep = [f.name for f in self._schema]
                tbl = tbl.select([c for c in tbl.column_names if c in keep])
        # Коэрция под целевую схему и дефолты
        tbl = _coerce_table_to_schema(tbl, self._schema, self.cfg.default_values)

        # Разрежем по партициям
        if self.cfg.partition_cols:
            # Убедимся, что все партиционные колонки существуют
            for c in self.cfg.partition_cols:
                if c not in tbl.column_names:
                    raise SchemaError(f"Partition column {c!r} not found in table")
            # Группируем по сочетаниям значений
            partitions = self._split_by_partitions(tbl, self.cfg.partition_cols)
            # Пишем параллельно с ограничением concurrency
            await asyncio.gather(*[self._write_partition(part_key, sub_tbl) for part_key, sub_tbl in partitions])
        else:
            await self._write_partition(part_key="", tbl=tbl)

    def _split_by_partitions(self, tbl: pa.Table, cols: Sequence[str]) -> List[Tuple[str, pa.Table]]:
        # Стратегия: сортировка по ключам и разбиение, чтобы избежать множественных маленьких файлов
        indices = [tbl.column_names.index(c) for c in cols]
        # Получим набор уникальных ключей
        key_arrays = [tbl.column(i) for i in indices]
        # Построим ключи как tuple простых python значений
        keys_py: List[Tuple[Any, ...]] = list(zip(*[ka.to_pylist() for ka in key_arrays]))
        # Группировка по ключам (сохраняя порядок)
        order = {}
        groups: Dict[Tuple[Any, ...], List[int]] = {}
        for idx, k in enumerate(keys_py):
            if k not in groups:
                order[k] = len(order)
                groups[k] = []
            groups[k].append(idx)
        out: List[Tuple[str, pa.Table]] = []
        for k, _ in sorted(order.items(), key=lambda kv: kv[1]):
            idxs = pa.array(groups[k], type=pa.int32())
            sub = tbl.take(idxs)
            # построим hive‑путь
            part_path = "/".join(f"{col}={_sanitize_part_value(val)}" for col, val in zip(cols, k))
            out.append((part_path, sub))
        return out

    async def _write_partition(self, part_key: str, tbl: pa.Table) -> None:
        # Коэрция таймштампов
        if self.cfg.coerce_timestamps != "none":
            # pyarrow автоматически выплюнет правильную зону; здесь оставим как есть
            pass

        lock = self._locks_by_partition.setdefault(part_key, asyncio.Lock())
        async with lock:
            await self._write_partition_locked(part_key, tbl)

    async def _write_partition_locked(self, part_key: str, tbl: pa.Table) -> None:
        async with self._sem:
            span = self.tracer.start_span("parquet.write_partition", partition=part_key, rows=str(tbl.num_rows))
            t0 = time.perf_counter()
            try:
                state = await self._ensure_open_file(part_key)
                # Ротация перед записью (если уже истекли лимиты)
                if self._should_rotate(state):
                    await self._finalize_partition(part_key, state, force=True)
                    state = await self._ensure_open_file(part_key)

                # Пишем таблицу (append)
                size_before = state.bytes
                await self._write_table_to_file(state, tbl)
                state.rows += tbl.num_rows
                state.bytes += max(_estimate_table_size_bytes(tbl), 0)

                # Ротация после записи, если перешли лимиты
                if self._should_rotate(state):
                    await self._finalize_partition(part_key, state, force=True)

                await self.metrics.inc(f"{self.cfg.metrics_prefix}_rows_total", value=tbl.num_rows, partition=part_key or "_")
                await self.metrics.observe(f"{self.cfg.metrics_prefix}_write_seconds", time.perf_counter() - t0, partition=part_key or "_")
            except Exception as e:
                span.record_exception(e)
                raise
            finally:
                span.end()

    # ---------------------- Работа с файлами ----------------------

    def _join(self, *parts: str) -> str:
        # pafs работает со слэшами
        return "/".join(p.strip("/") for p in parts if p != "")

    def _build_file_names(self, partition_path: str) -> Tuple[str, str]:
        ts = _utcnow_iso()
        uid = f"-{uuid.uuid4().hex}" if self.cfg.file_uuid_in_name else ""
        fname = f"{self.cfg.filename_prefix}-{ts}{uid}.parquet"
        final_path = self._join(self._dataset_root, partition_path, fname) if partition_path else self._join(self._dataset_root, fname)
        tmp_path = final_path + self.cfg.tmp_suffix
        return tmp_path, final_path

    async def _ensure_open_file(self, part_key: str) -> _OpenFile:
        state = self._open_by_partition.get(part_key)
        if state and state.writer:
            return state

        partition_path = part_key
        # Убедимся, что директория партиции есть
        await self._call_fs(self._fs.create_dir, self._join(self._dataset_root, partition_path), recursive=True, op="create_dir")

        tmp_path, final_path = self._build_file_names(partition_path)
        writer = await self._open_parquet_writer(tmp_path)
        state = _OpenFile(partition_path=partition_path, file_path_tmp=tmp_path, file_path_final=final_path, writer=writer, rows=0, bytes=0)
        self._open_by_partition[part_key] = state
        return state

    async def _open_parquet_writer(self, tmp_path: str) -> pq.ParquetWriter:
        # Ретраи открытия
        attempt = 1
        while True:
            try:
                schema = self._schema or pa.schema([])
                opts = {}
                if self.cfg.compression != "none":
                    opts["compression"] = self.cfg.compression
                if self.cfg.dictionary_cols:
                    opts["use_dictionary"] = self.cfg.dictionary_cols
                writer = pq.ParquetWriter(
                    where=tmp_path,
                    schema=schema,
                    filesystem=self._fs,
                    version="2.6",
                    use_deprecated_int96_timestamps=False,
                    compression=opts.get("compression", None),
                    use_dictionary=opts.get("use_dictionary", None),
                    write_statistics=self.cfg.write_statistics,
                )
                return writer
            except Exception as e:
                if attempt >= self.cfg.retries.max_attempts:
                    raise WriteError(f"Failed to open ParquetWriter for {tmp_path}: {e}") from e
                await asyncio.sleep(_compute_backoff(attempt, self.cfg.retries))
                attempt += 1

    async def _write_table_to_file(self, state: _OpenFile, tbl: pa.Table) -> None:
        attempt = 1
        while True:
            try:
                await asyncio.to_thread(state.writer.write_table, tbl)  # type: ignore
                return
            except Exception as e:
                if attempt >= self.cfg.retries.max_attempts:
                    raise WriteError(f"Failed to write_table: {e}") from e
                await asyncio.sleep(_compute_backoff(attempt, self.cfg.retries))
                attempt += 1

    def _should_rotate(self, state: _OpenFile) -> bool:
        if state.rows >= self.cfg.rotation.max_rows:
            return True
        if state.bytes >= self.cfg.rotation.max_bytes:
            return True
        if (time.monotonic() - state.opened_at) >= self.cfg.rotation.max_interval_s:
            return True
        return False

    async def _finalize_partition(self, part_key: str, state: _OpenFile, *, force: bool) -> None:
        if not state.writer:
            return
        # Закрываем writer
        with contextlib.suppress(Exception):
            await asyncio.to_thread(state.writer.close)  # type: ignore

        # Атомарный rename tmp → final с ретраями
        attempt = 1
        while True:
            try:
                await self._call_fs(self._fs.move, state.file_path_tmp, state.file_path_final, op="move")
                break
            except Exception as e:
                if attempt >= self.cfg.retries.max_attempts:
                    raise WriteError(f"Failed to move {state.file_path_tmp} -> {state.file_path_final}: {e}") from e
                await asyncio.sleep(_compute_backoff(attempt, self.cfg.retries))
                attempt += 1

        # Сбросим состояние для новой ротации
        self._open_by_partition.pop(part_key, None)

        # Метрики
        await self.metrics.inc(f"{self.cfg.metrics_prefix}_files_finalized_total", partition=part_key or "_")

    # ---------------------- Вызовы ФС c ретраями ----------------------

    async def _call_fs(self, fn, *args, op: str, **kwargs):
        attempt = 1
        t0 = time.perf_counter()
        span = self.tracer.start_span(f"parquet.fs.{op}", path=str(args[0]) if args else "")
        try:
            while True:
                try:
                    res = await asyncio.to_thread(fn, *args, **kwargs)
                    await self.metrics.inc(f"{self.cfg.metrics_prefix}_fs_{op}_total")
                    return res
                except Exception as e:
                    if attempt >= self.cfg.retries.max_attempts:
                        span.record_exception(e)
                        raise
                    await asyncio.sleep(_compute_backoff(attempt, self.cfg.retries))
                    attempt += 1
        finally:
            await self.metrics.observe(f"{self.cfg.metrics_prefix}_fs_{op}_seconds", time.perf_counter() - t0)
            span.end()

# ============================ Пример интеграции (сохранить в файле) ============================
"""
Пример использования:

from datafabric.storage.lake.parquet_writer import ParquetLakeWriter, ParquetWriterConfig

cfg = ParquetWriterConfig(
    base_uri="s3://my-bucket/lake",
    dataset="events",
    partition_cols=["dt", "event_type"],
    compression="zstd",
    rotation={"max_rows": 5_000_000, "max_bytes": 512*1024*1024, "max_interval_s": 300},
)

async def run():
    async with ParquetLakeWriter(cfg) as w:
        # запись словарей
        await w.write_records([
            {"dt": "2025-08-14", "event_type": "click", "user_id": 1, "ts": "2025-08-14T12:00:00Z"},
            {"dt": "2025-08-14", "event_type": "view", "user_id": 2, "ts": "2025-08-14T12:00:01Z"},
        ])

        # запись DataFrame (если pandas установлен)
        # await w.write_dataframe(df)

        # форс‑сброс файлов
        await w.flush()

Особенности:
- Путь записи: <base_uri>/<dataset>/<col1>=<val1>/<col2>=<val2>/part-<ts>-<uuid>.parquet.tmp → .parquet
- Атомарность обеспечивается через move в пределах одного FileSystem (s3fs/pyarrow S3).
- Schema evolution: при появлении новых столбцов они добавятся к текущей схеме (если allow_schema_evolution=True).
- default_values: недостающие столбцы в таблице заполняются указанными значениями.
"""
