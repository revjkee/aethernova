# datafabric-core/datafabric/ingest/sources/file_ingest.py
from __future__ import annotations

import asyncio
import fnmatch
import io
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Tuple

from pydantic import BaseModel, Field, PositiveInt, root_validator, validator

# Импорт протоколов/моделей из ядра ingestion
from datafabric.ingest.manager import (
    IngestRecord,
    CheckpointStore,
    Metrics,
    Tracer,
    Span,
)

# ============ Конфигурация источника ============

class FileFormat(str):
    NDJSON = "ndjson"   # по строке JSON на линию
    LINES = "lines"     # произвольный текст по строке
    BYTES = "bytes"     # читать чанками (max_bytes_per_record)

class FileIngestConfig(BaseModel):
    root_dir: Path = Field(..., description="Корневая директория для чтения")
    include_globs: List[str] = Field(default_factory=lambda: ["**/*.log", "**/*.json", "**/*.ndjson"])
    exclude_globs: List[str] = Field(default_factory=list)
    recursive: bool = True

    file_format: str = Field(FileFormat.NDJSON, description="ndjson|lines|bytes")
    encoding: str = Field("utf-8")
    newline: str = Field("\n", description="Разделитель строк для 'lines' и 'ndjson'")
    max_bytes_per_record: PositiveInt = Field(2_000_000, description="Лимит размера одной записи")

    tail: bool = Field(True, description="Следить за ростом файлов")
    poll_interval_ms: PositiveInt = Field(500, description="Интервал опроса файловой системы")
    start_from_beginning: bool = Field(True, description="Начинать с начала (иначе — с конца существующих файлов)")
    track_by_inode: bool = Field(True, description="Отслеживать ротации по inode")

    move_processed_to: Optional[Path] = Field(None, description="Куда перемещать полностью обработанные файлы")
    delete_after: bool = Field(False, description="Удалять файл после полного чтения")
    quarantine_dir: Optional[Path] = Field(None, description="Куда складывать проблемные записи (при nack)")

    checkpoint_key: str = Field("file_ingest", description="Ключ в хранилище чекпоинтов")
    metrics_prefix: str = Field("datafabric_file_ingest")

    @validator("file_format")
    def _fmt(cls, v: str) -> str:
        v = v.lower()
        if v not in (FileFormat.NDJSON, FileFormat.LINES, FileFormat.BYTES):
            raise ValueError("file_format must be ndjson|lines|bytes")
        return v

    @root_validator
    def _paths(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        root_dir: Path = values["root_dir"]
        if not root_dir:
            raise ValueError("root_dir is required")
        values["root_dir"] = Path(root_dir).resolve()
        for k in ("move_processed_to", "quarantine_dir"):
            p = values.get(k)
            if p:
                values[k] = Path(p).resolve()
        return values


# ============ Внутренние структуры состояния ============

@dataclass
class _FileState:
    path: Path
    inode: int
    size: int
    mtime: float
    committed_offset: int = 0   # подтверждённый оффсет (последний ack)
    read_offset: int = 0        # сколько уже отдали наружу
    done: bool = False          # файл дочитан до EOF и подтвержден

@dataclass
class _Pending:
    file_key: str   # inode как строка либо путь
    end_offset: int


# ============ Утилиты ============

def _get_inode(p: Path) -> int:
    st = p.stat()
    return getattr(st, "st_ino", 0)

def _file_key(state: _FileState, track_by_inode: bool) -> str:
    return f"{state.inode}" if track_by_inode else str(state.path)

def _match_globs(rel: str, includes: Iterable[str], excludes: Iterable[str]) -> bool:
    if excludes and any(fnmatch.fnmatch(rel, pat) for pat in excludes):
        return False
    return any(fnmatch.fnmatch(rel, pat) for pat in includes)


# ============ Основной источник ============

class FileIngestSource:
    """
    Async‑источник файлов для IngestManager.

    Модель подтверждения:
      - Отдаём запись с end_offset в headers.
      - На ack: committed_offset = max(committed_offset, end_offset).
      - На nack: запись сохраняем в quarantine_dir (если задан), оффсет не продвигаем.
      - commit(): сохраняет карту {file_key: committed_offset} через CheckpointStore.

    Перемещение/удаление файла выполняется, когда committed_offset >= текущий размер и файл не растёт.
    """

    def __init__(
        self,
        config: FileIngestConfig,
        checkpoint: Optional[CheckpointStore] = None,
        metrics: Optional[Metrics] = None,
        tracer: Optional[Tracer] = None,
    ) -> None:
        self.cfg = config
        self._cp = checkpoint
        self._metrics = metrics
        self._tracer = tracer

        self._files: Dict[str, _FileState] = {}        # file_key -> state
        self._pendings: Dict[int, _Pending] = {}       # id(record) -> pending
        self._stop = False
        self._lock = asyncio.Lock()
        self._loaded_checkpoint = False

        # создаём директории, если нужны
        if self.cfg.move_processed_to:
            self.cfg.move_processed_to.mkdir(parents=True, exist_ok=True)
        if self.cfg.quarantine_dir:
            self.cfg.quarantine_dir.mkdir(parents=True, exist_ok=True)

    # --------- Протокол Source ---------

    async def __aiter__(self) -> AsyncIterator[IngestRecord]:
        span = self._span("file_source.iter", root=str(self.cfg.root_dir))
        try:
            while not self._stop:
                # инициализация чекпоинта и первичное сканирование
                if not self._loaded_checkpoint:
                    await self._load_checkpoint()
                    await self._scan_files(initial=True)
                    self._loaded_checkpoint = True

                # основной цикл: скан + чтение доступных данных
                await self._scan_files(initial=False)
                produced = 0
                async for rec in self._drain_records():
                    produced += 1
                    yield rec

                # если ничего не отдали — ждём
                if produced == 0:
                    await asyncio.sleep(self.cfg.poll_interval_ms / 1000.0)
        finally:
            span.end()

    async def ack(self, record: IngestRecord) -> None:
        p = self._pendings.pop(id(record), None)
        if not p:
            return
        st = self._files.get(p.file_key)
        if not st:
            return
        # продвигаем подтверждение
        if p.end_offset > st.committed_offset:
            st.committed_offset = p.end_offset
        # если дочитали и файл не растет — финализируем
        await self._try_finalize_file(st)

    async def nack(self, record: IngestRecord, reason: str) -> None:
        # сохраняем запись в карантин
        try:
            if self.cfg.quarantine_dir:
                fname = f"nack_{int(time.time()*1000)}_{os.getpid()}.log"
                qpath = self.cfg.quarantine_dir / fname
                body = record.payload
                meta = {
                    "reason": reason,
                    "headers": record.headers,
                    "ts_ms": record.ts_ms,
                    "key": record.key,
                }
                with qpath.open("ab") as f:
                    f.write(json.dumps(meta, ensure_ascii=False).encode("utf-8"))
                    f.write(b"\n")
                    f.write(body if isinstance(body, (bytes, bytearray)) else bytes(body))
                    f.write(b"\n")
        finally:
            # не продвигаем оффсет; запись будет переотдана
            rid = id(record)
            if rid in self._pendings:
                self._pendings.pop(rid, None)

    async def commit(self) -> None:
        if not self._cp:
            return
        data = {k: v.committed_offset for k, v in self._files.items()}
        await self._cp.save(self._cp_key(), data)
        await self._metric_inc("commit_total")

    # --------- Внутренняя логика ---------

    async def _drain_records(self) -> AsyncIterator[IngestRecord]:
        """
        Отдаём записи из файлов, которые имеют непрочитанную часть.
        """
        # итерация по стабильному списку, чтобы не зависеть от изменений словаря
        keys = list(self._files.keys())
        for k in keys:
            st = self._files.get(k)
            if not st or st.done:
                continue
            # файл мог измениться (рост/усечение/ротация)
            try:
                pst = st.path.stat()
            except FileNotFoundError:
                # файл исчез — считаем финализированным
                st.done = True
                continue
            new_size = pst.st_size
            if new_size < st.read_offset:
                # усечение/ротация — начнем заново
                st.read_offset = st.committed_offset
            # читаем доступный диапазон
            if st.read_offset < new_size:
                async for rec, end_off in self._read_from(st, start=st.read_offset, limit=new_size):
                    # регистрируем pending, чтобы ack продвигал committed_offset
                    self._pendings[id(rec)] = _Pending(file_key=k, end_offset=end_off)
                    st.read_offset = end_off
                    yield rec
            # пробуем финализировать (если всё подтверждено и файл не растёт)
            await self._try_finalize_file(st)

    async def _read_from(self, st: _FileState, start: int, limit: int) -> AsyncIterator[Tuple[IngestRecord, int]]:
        """
        Читает кусок файла [start, limit) и выдаёт записи согласно формату.
        Возвращает (record, end_offset) для отслеживания ack.
        """
        path = st.path
        fmt = self.cfg.file_format
        # Чтение в отдельном потоке (без aiofiles) для совместимости
        def _open_and_seek() -> io.BufferedReader:
            f = open(path, "rb", buffering=1024 * 64)
            f.seek(start)
            return f

        loop = asyncio.get_event_loop()
        f: io.BufferedReader = await loop.run_in_executor(None, _open_and_seek)
        try:
            if fmt == FileFormat.BYTES:
                while f.tell() < limit:
                    to_read = min(self.cfg.max_bytes_per_record, limit - f.tell())
                    chunk = f.read(to_read)
                    if not chunk:
                        break
                    end_off = f.tell()
                    headers = self._mk_headers(st, start_offset=end_off - len(chunk), end_offset=end_off)
                    rec = IngestRecord(
                        key=f"{st.inode}:{end_off}",
                        payload=chunk,
                        ts_ms=int(time.time() * 1000),
                        headers=headers,
                    )
                    yield rec, end_off

            else:
                # построчное чтение
                decoder = self.cfg.encoding
                newline = self.cfg.newline.encode(decoder) if self.cfg.newline else b"\n"
                buf = bytearray()
                base_pos = f.tell()
                while f.tell() < limit:
                    chunk = f.read(min(64 * 1024, limit - f.tell()))
                    if not chunk:
                        break
                    # разбиваем на строки
                    buf.extend(chunk)
                    while True:
                        idx = buf.find(newline)
                        if idx < 0:
                            break
                        line = bytes(buf[:idx])
                        del buf[: idx + len(newline)]
                        end_off = base_pos + (f.tell() - len(buf))
                        if len(line) == 0:
                            continue
                        if len(line) > self.cfg.max_bytes_per_record:
                            # слишком большая запись — отправим в nack/карантин через BYTES‑образную запись
                            payload = line[: self.cfg.max_bytes_per_record]
                        else:
                            payload = line
                        payload_str = payload.decode(decoder, errors="replace")
                        if fmt == FileFormat.NDJSON:
                            # валидируем JSON сразу, чтобы при ошибке запись ушла в карантин на nack
                            try:
                                json.loads(payload_str)
                            except Exception:
                                # всё равно отдаём как есть; трансформер/менеджер выполнит nack
                                pass

                        headers = self._mk_headers(st, start_offset=end_off - len(line), end_offset=end_off)
                        rec = IngestRecord(
                            key=f"{st.inode}:{end_off}",
                            payload=payload if fmt != FileFormat.NDJSON else payload_str.encode(decoder),
                            ts_ms=int(time.time() * 1000),
                            headers=headers,
                        )
                        yield rec, end_off

                # если остался хвост без перевода строки и файл достиг лимита — выдадим его
                if buf and not self.cfg.tail and f.tell() >= limit:
                    end_off = f.tell()
                    payload = bytes(buf)
                    if len(payload) > self.cfg.max_bytes_per_record:
                        payload = payload[: self.cfg.max_bytes_per_record]
                    headers = self._mk_headers(st, start_offset=end_off - len(payload), end_offset=end_off)
                    rec = IngestRecord(
                        key=f"{st.inode}:{end_off}",
                        payload=payload,
                        ts_ms=int(time.time() * 1000),
                        headers=headers,
                    )
                    yield rec, end_off

        finally:
            try:
                f.close()
            except Exception:
                pass

    async def _try_finalize_file(self, st: _FileState) -> None:
        # файл считается завершённым, если подтверждённый оффсет >= текущего размера и файл не растёт
        try:
            pst = st.path.stat()
        except FileNotFoundError:
            st.done = True
            return
        if st.committed_offset < pst.st_size:
            return
        # проверим, что недавно не изменялся (простая эвристика)
        if (time.time() - pst.st_mtime) < max(self.cfg.poll_interval_ms / 1000.0, 0.2) and self.cfg.tail:
            return
        # финализация
        if self.cfg.delete_after:
            try:
                st.path.unlink(missing_ok=True)  # Python 3.8+: ignore if absent
            except Exception:
                pass
        elif self.cfg.move_processed_to:
            try:
                target = self.cfg.move_processed_to / st.path.name
                # если занято — добавим суффикс времени
                if target.exists():
                    target = target.with_name(f"{target.stem}_{int(time.time()*1000)}{target.suffix}")
                st.path.replace(target)
            except Exception:
                pass
        st.done = True

    async def _scan_files(self, initial: bool) -> None:
        """
        Сканирует файловую систему, регистрирует новые файлы, обновляет размеры/mtime.
        """
        root = self.cfg.root_dir
        if not root.exists():
            return
        entries: List[Path] = []
        if self.cfg.recursive:
            for p in root.rglob("*"):
                if p.is_file():
                    entries.append(p)
        else:
            entries = [p for p in root.iterdir() if p.is_file()]
        for p in entries:
            rel = str(p.relative_to(root))
            if not _match_globs(rel, self.cfg.include_globs, self.cfg.exclude_globs):
                continue
            try:
                st = p.stat()
            except FileNotFoundError:
                continue
            inode = _get_inode(p) if self.cfg.track_by_inode else 0
            key = f"{inode}" if self.cfg.track_by_inode else str(p.resolve())
            known = self._files.get(key)
            if not known:
                # новый файл
                start_offset = 0
                if not self.cfg.start_from_beginning and initial:
                    start_offset = st.st_size
                self._files[key] = _FileState(
                    path=p.resolve(),
                    inode=inode,
                    size=st.st_size,
                    mtime=st.st_mtime,
                    committed_offset=start_offset,
                    read_offset=start_offset,
                    done=False,
                )
            else:
                # обновили размер/mtime; если inode сменился — это ротация
                if self.cfg.track_by_inode:
                    # inode — ключ; если файл переименовали, просто обновим путь
                    known.path = p.resolve()
                known.size = st.st_size
                known.mtime = st.st_mtime
                # если файл усекли — сбросить read_offset до committed
                if known.read_offset > st.st_size:
                    known.read_offset = known.committed_offset

    async def _load_checkpoint(self) -> None:
        if not self._cp:
            return
        data = await self._cp.load(self._cp_key())
        if not isinstance(data, dict):
            return
        # пока файлов нет — просто сохраним оффсеты в self._files позднее на сканировании
        # применим позже в _scan_files: как только появится файл с таким key, выставим committed_offset
        # здесь же сохраним временно карту
        self._restored_offsets = {str(k): int(v) for k, v in data.items() if isinstance(v, int)}
        # Попробуем применить сразу к уже найденным
        for key, state in self._files.items():
            if key in self._restored_offsets:
                off = self._restored_offsets[key]
                state.committed_offset = max(state.committed_offset, off)
                state.read_offset = max(state.read_offset, off)

    def _cp_key(self) -> str:
        return f"{self.cfg.checkpoint_key}:{self.cfg.root_dir}"

    def _mk_headers(self, st: _FileState, *, start_offset: int, end_offset: int) -> Dict[str, str]:
        return {
            "x-file-path": str(st.path),
            "x-file-inode": str(st.inode),
            "x-file-offset-start": str(start_offset),
            "x-file-offset-end": str(end_offset),
            "x-file-format": self.cfg.file_format,
        }

    # --------- Метрики/трейсинг (безопасные-нулевые) ---------

    async def _metric_inc(self, name: str, value: int = 1, **labels: str) -> None:
        if self._metrics:
            try:
                await self._metrics.inc(f"{self.cfg.metrics_prefix}_{name}", value=value, **labels)
            except Exception:
                pass

    def _span(self, name: str, **attrs: Any) -> Span:
        if self._tracer:
            try:
                return self._tracer.start_span(name, **attrs)
            except Exception:
                pass
        # нулевая реализация
        class _NullSpan:
            def set_attribute(self, key: str, value: Any) -> None:
                return
            def record_exception(self, exc: BaseException) -> None:
                return
            def end(self) -> None:
                return
        return _NullSpan()

    # --------- Управление жизненным циклом источника ---------

    def stop(self) -> None:
        self._stop = True
