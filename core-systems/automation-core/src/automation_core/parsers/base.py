# automation-core/src/automation_core/parsers/base.py
# -*- coding: utf-8 -*-
"""
Базовая инфраструктура парсеров для automation-core.

Особенности:
- Абстрактный BaseParser со строгим контрактом: parse()/apar se(), sniff(), supports_media_type().
- Единый входной интерфейс: str | bytes | pathlib.Path | файловые объекты | Iterable[str/bytes] | AsyncIterable[...].
- Ограничение размера входа (max_input_mb) и безопасное декодирование (utf-8 с fallback).
- Опциональная валидация результата по JSON Schema (если установлен пакет jsonschema).
- Метаданные и метрики парсинга; стабильные исключения.
- Реестр парсеров ParserRegistry (по имени и медиа-типу).
- Интеграция с OpenTelemetry (если доступен модуль automation_core.observability.tracing).

Зависимости: стандартная библиотека; jsonschema и OpenTelemetry — опциональны.

Как расширять:
- Наследуйте BaseParser и реализуйте _parse_core_text() и/или _parse_core_bytes().
- При желании переопределите schema() для выдачи JSON Schema результата.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import io
import json
import logging
import mimetypes
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import (
    Any,
    AsyncIterable,
    Awaitable,
    Dict,
    Iterable,
    IO,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
)

log = logging.getLogger(__name__)

# ---------------------------- Исключения --------------------------------------


class ParserError(Exception):
    """Базовая ошибка парсинга."""


class ParserTimeoutError(ParserError):
    """Истек таймаут парсинга."""


class ParserValidationError(ParserError):
    """Результат не прошел валидацию схемой."""


class ParserUnsupportedTypeError(ParserError):
    """Входной тип данных неподдерживаем."""


# ---------------------------- Типы и результаты --------------------------------

@dataclass(frozen=True)
class ParseIssue:
    code: str
    message: str
    severity: str = "warning"  # "info" | "warning" | "error"
    location: Optional[Mapping[str, Any]] = None  # например: {"line": 10, "column": 3}
    extra: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ParseMetadata:
    content_type: Optional[str]
    encoding: Optional[str]
    size_bytes: int
    duration_ms: float
    source_hint: Optional[str] = None  # например путь файла
    hash_sha256: Optional[str] = None
    parser_name: str = "base"
    parser_version: str = "0.0.0"


@dataclass(frozen=True)
class ParseResult:
    data: Any
    issues: Tuple[ParseIssue, ...] = field(default_factory=tuple)
    metadata: ParseMetadata = field(default_factory=lambda: ParseMetadata(None, None, 0, 0.0))


# ---------------------------- Трассировка (опционально) -----------------------

def _try_trace_decorator(span_name: str):
    """
    Возвращает декоратор трассировки, если доступен automation_core.observability.tracing; иначе no-op.
    """
    try:
        from automation_core.observability.tracing import trace_function  # type: ignore
        return trace_function(span_name, record_args=False)
    except Exception:
        def _noop(fn):
            return fn
        return _noop


# ---------------------------- Утилиты ввода -----------------------------------

_BytesLike = Union[bytes, bytearray, memoryview]
_TextLike = str
_InputLike = Union[
    _TextLike,
    _BytesLike,
    Path,
    IO[str],
    IO[bytes],
    Iterable[str],
    Iterable[bytes],
    AsyncIterable[str],
    AsyncIterable[bytes],
]


def _is_text_iterable(obj: Any) -> bool:
    return hasattr(obj, "__iter__") and not isinstance(obj, (bytes, bytearray, memoryview, str))


def _is_async_iterable(obj: Any) -> bool:
    return hasattr(obj, "__aiter__")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _guess_content_type(source_hint: Optional[str], default: Optional[str] = None) -> Optional[str]:
    if not source_hint:
        return default
    guess, _ = mimetypes.guess_type(source_hint)
    return guess or default


@dataclass(frozen=True)
class ParserContext:
    """
    Контекст исполнения парсера.
    """
    requested_content_type: Optional[str]
    requested_encoding: Optional[str]
    max_input_mb: int
    timeout_sec: Optional[float]
    extra: Mapping[str, Any] = field(default_factory=dict)

    @property
    def max_bytes(self) -> int:
        return self.max_input_mb * 1024 * 1024


# ---------------------------- Базовый парсер ----------------------------------

T = TypeVar("T", bound="BaseParser")


class BaseParser(ABC):
    """
    Базовый класс парсеров.

    Минимальные переопределения:
      - NAME, VERSION, MEDIA_TYPES
      - _parse_core_text() и/или _parse_core_bytes()
      - при необходимости schema()
    """

    NAME: str = "base"
    VERSION: str = "0.1.0"
    MEDIA_TYPES: Tuple[str, ...] = tuple()  # например: ("application/json",)
    DEFAULT_ENCODING: str = "utf-8"
    STRICT_DECODING: bool = False  # если True — ошибки декодирования приводят к исключению

    # -------- Публичный API --------

    @_try_trace_decorator("parser.parse")
    def parse(
        self,
        data: _InputLike,
        *,
        content_type: Optional[str] = None,
        encoding: Optional[str] = None,
        max_input_mb: int = 16,
        timeout_sec: Optional[float] = None,
        validate: bool = True,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> ParseResult:
        """
        Синхронный парсинг. При timeout_sec выполняет работу в пуле потоков.
        """
        ctx = ParserContext(
            requested_content_type=content_type,
            requested_encoding=encoding,
            max_input_mb=max(1, int(max_input_mb)),
            timeout_sec=timeout_sec,
            extra=MappingProxyType(dict(extra or {})),
        )

        if timeout_sec is not None and timeout_sec > 0:
            import concurrent.futures
            loop = asyncio.new_event_loop()
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    fut = ex.submit(self._parse_sync_impl, data, ctx, validate)
                    return fut.result(timeout=timeout_sec)
            except concurrent.futures.TimeoutError as e:  # pragma: no cover - время зависимо от среды
                raise ParserTimeoutError(f"Parsing timed out after {timeout_sec}s") from e
            finally:
                loop.close()
        else:
            return self._parse_sync_impl(data, ctx, validate)

    @_try_trace_decorator("parser.aparse")
    async def aparse(
        self,
        data: _InputLike,
        *,
        content_type: Optional[str] = None,
        encoding: Optional[str] = None,
        max_input_mb: int = 16,
        timeout_sec: Optional[float] = None,
        validate: bool = True,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> ParseResult:
        """
        Асинхронный парсинг. Если вход — AsyncIterable, читается без блокировки.
        Таймаут реализован через asyncio.wait_for.
        """
        ctx = ParserContext(
            requested_content_type=content_type,
            requested_encoding=encoding,
            max_input_mb=max(1, int(max_input_mb)),
            timeout_sec=timeout_sec,
            extra=MappingProxyType(dict(extra or {})),
        )
        if timeout_sec is not None and timeout_sec > 0:
            return await asyncio.wait_for(self._parse_async_impl(data, ctx, validate), timeout=timeout_sec)
        return await self._parse_async_impl(data, ctx, validate)

    # -------- Вспомогательные возможности --------

    def supports_media_type(self, content_type: Optional[str]) -> bool:
        if not self.MEDIA_TYPES or not content_type:
            return False
        ct = content_type.split(";")[0].strip().lower()
        return any(ct == m.lower() for m in self.MEDIA_TYPES)

    def sniff(self, blob: Union[str, bytes]) -> float:
        """
        Эвристическая оценка "уверенности", что данный blob подходит этому парсеру.
        По умолчанию: если объявлены MEDIA_TYPES, возвращает 0.0; переопределяйте при необходимости.
        Диапазон: 0.0..1.0
        """
        return 0.0

    # -------- Для наследников: схема результата --------

    def schema(self) -> Optional[Mapping[str, Any]]:
        """
        Возвращает JSON Schema результата (dict) или None.
        Переопределите в наследниках для включения валидации.
        """
        return None

    # -------- Абстрактное ядро --------

    @abstractmethod
    def _parse_core_text(self, text: str, ctx: ParserContext) -> Tuple[Any, List[ParseIssue]]:
        """
        Обязательный для переопределения метод: парсинг из текстового представления.
        Возвращает кортеж: (data, issues)
        """
        raise NotImplementedError

    def _parse_core_bytes(self, data: bytes, ctx: ParserContext) -> Tuple[Any, List[ParseIssue]]:
        """
        Необязательный метод: если реализация работает напрямую с байтами.
        По умолчанию декодирует и делегирует в _parse_core_text.
        """
        text, enc, issues = self._decode_bytes(data, ctx)
        data, issues2 = self._parse_core_text(text, ctx)
        return data, issues + issues2

    # ------------------- Реализация пайплайна ---------------------------------

    def _parse_sync_impl(self, data: _InputLike, ctx: ParserContext, validate: bool) -> ParseResult:
        started = time.perf_counter()
        raw_bytes, src_hint, content_type = self._ingest_all(data, ctx)
        sha = _sha256(raw_bytes) if raw_bytes is not None else None
        try:
            parsed, issues = self._dispatch_parse(raw_bytes, ctx)
            if validate:
                self._maybe_validate(parsed)
            duration = (time.perf_counter() - started) * 1000.0
            meta = ParseMetadata(
                content_type=content_type,
                encoding=ctx.requested_encoding or self.DEFAULT_ENCODING,
                size_bytes=len(raw_bytes) if raw_bytes is not None else 0,
                duration_ms=duration,
                source_hint=src_hint,
                hash_sha256=sha,
                parser_name=self.NAME,
                parser_version=self.VERSION,
            )
            return ParseResult(parsed, tuple(issues), meta)
        except ParserError:
            raise
        except Exception as e:
            raise ParserError(str(e)) from e

    async def _parse_async_impl(self, data: _InputLike, ctx: ParserContext, validate: bool) -> ParseResult:
        started = time.perf_counter()
        raw_bytes, src_hint, content_type = await self._aingest_all(data, ctx)
        sha = _sha256(raw_bytes) if raw_bytes is not None else None
        try:
            # Сам парсинг у нас синхронный по умолчанию; если нужен async — переопределяйте метод.
            parsed, issues = self._dispatch_parse(raw_bytes, ctx)
            if validate:
                self._maybe_validate(parsed)
            duration = (time.perf_counter() - started) * 1000.0
            meta = ParseMetadata(
                content_type=content_type,
                encoding=ctx.requested_encoding or self.DEFAULT_ENCODING,
                size_bytes=len(raw_bytes) if raw_bytes is not None else 0,
                duration_ms=duration,
                source_hint=src_hint,
                hash_sha256=sha,
                parser_name=self.NAME,
                parser_version=self.VERSION,
            )
            return ParseResult(parsed, tuple(issues), meta)
        except ParserError:
            raise
        except Exception as e:
            raise ParserError(str(e)) from e

    # ------------------- Валидация по JSON Schema (опц.) ----------------------

    def _maybe_validate(self, data: Any) -> None:
        schema = self.schema()
        if not schema:
            return
        try:
            import jsonschema  # type: ignore
        except Exception:
            # jsonschema не установлен — пропускаем валидацию
            log.debug("jsonschema not installed; skipping validation for %s", self.NAME)
            return
        try:
            jsonschema.validate(instance=data, schema=schema)  # type: ignore[attr-defined]
        except Exception as e:
            raise ParserValidationError(str(e)) from e

    # ------------------- Чтение и нормализация входа --------------------------

    def _check_limit_and_append(self, buf: bytearray, chunk: bytes, ctx: ParserContext) -> None:
        if len(buf) + len(chunk) > ctx.max_bytes:
            raise ParserError(f"Input exceeds limit of {ctx.max_input_mb} MiB")
        buf.extend(chunk)

    def _read_all_from_io(self, f: IO[bytes], ctx: ParserContext) -> bytes:
        buf = bytearray()
        while True:
            chunk = f.read(1 << 16)
            if not chunk:
                break
            if isinstance(chunk, str):  # текстовый файл открыт 'r'
                chunk = chunk.encode(ctx.requested_encoding or self.DEFAULT_ENCODING, errors="replace")
            elif not isinstance(chunk, (bytes, bytearray)):
                raise ParserUnsupportedTypeError("Unsupported chunk type from IO")
            self._check_limit_and_append(buf, bytes(chunk), ctx)
        return bytes(buf)

    def _ingest_all(self, data: _InputLike, ctx: ParserContext) -> Tuple[bytes, Optional[str], Optional[str]]:
        """
        Преобразует любое поддерживаемое представление входа к bytes.
        Возвращает: (raw_bytes, source_hint, content_type)
        """
        source_hint: Optional[str] = None
        content_type = ctx.requested_content_type

        if isinstance(data, (bytes, bytearray, memoryview)):
            raw = bytes(data)
            return raw, None, content_type

        if isinstance(data, str):
            # это может быть строка содержимого; не путать с путём
            raw = data.encode(ctx.requested_encoding or self.DEFAULT_ENCODING, errors="replace")
            return raw, None, content_type

        if isinstance(data, Path):
            p = data
            source_hint = str(p)
            content_type = content_type or _guess_content_type(source_hint)
            with p.open("rb") as f:
                raw = self._read_all_from_io(f, ctx)
            return raw, source_hint, content_type

        # Файлоподобные объекты
        if hasattr(data, "read"):
            raw = self._read_all_from_io(data, ctx)  # type: ignore[arg-type]
            return raw, None, content_type

        # Итераторы/генераторы
        if _is_text_iterable(data):
            buf = bytearray()
            first = True
            for chunk in data:  # type: ignore[assignment]
                if isinstance(chunk, str):
                    b = chunk.encode(ctx.requested_encoding or self.DEFAULT_ENCODING, errors="replace")
                elif isinstance(chunk, (bytes, bytearray, memoryview)):
                    b = bytes(chunk)
                else:
                    raise ParserUnsupportedTypeError("Unsupported chunk type in Iterable")
                if first and source_hint is None and isinstance(chunk, str) and len(chunk) < 260:
                    # иногда передают "путь"; но мы не гадаем — оставляем как есть
                    pass
                self._check_limit_and_append(buf, b, ctx)
                first = False
            return bytes(buf), None, content_type

        raise ParserUnsupportedTypeError(f"Unsupported input type: {type(data)!r}")

    async def _aingest_all(self, data: _InputLike, ctx: ParserContext) -> Tuple[bytes, Optional[str], Optional[str]]:
        if _is_async_iterable(data):
            buf = bytearray()
            async for chunk in data:  # type: ignore[attr-defined]
                if isinstance(chunk, str):
                    b = chunk.encode(ctx.requested_encoding or self.DEFAULT_ENCODING, errors="replace")
                elif isinstance(chunk, (bytes, bytearray, memoryview)):
                    b = bytes(chunk)
                else:
                    raise ParserUnsupportedTypeError("Unsupported chunk type in AsyncIterable")
                self._check_limit_and_append(buf, b, ctx)
            return bytes(buf), None, ctx.requested_content_type
        # не async — используем синхронный путь
        return self._ingest_all(data, ctx)

    # ------------------- Декодирование и диспетчеризация ----------------------

    def _decode_bytes(self, data: bytes, ctx: ParserContext) -> Tuple[str, Optional[str], List[ParseIssue]]:
        """
        Декодирование байтов -> текст с учетом STRICT_DECODING.
        Возвращает (text, used_encoding, issues)
        """
        issues: List[ParseIssue] = []
        enc = ctx.requested_encoding or self.DEFAULT_ENCODING
        try:
            text = data.decode(enc, errors="strict" if self.STRICT_DECODING else "replace")
            if not self.STRICT_DECODING and text.encode(enc, errors="replace") != data:
                issues.append(ParseIssue(code="decode-replacement", message=f"Decoding with {enc} used replacement characters"))
            return text, enc, issues
        except UnicodeDecodeError as e:
            # жесткий провал
            raise ParserError(f"Failed to decode input with encoding={enc}: {e}") from e

    def _dispatch_parse(self, raw: bytes, ctx: ParserContext) -> Tuple[Any, List[ParseIssue]]:
        """
        Вызывает соответствующую реализацию (_bytes или _text).
        По умолчанию делегирует в _parse_core_bytes (которая при необходимости декодирует и вызывает _parse_core_text).
        """
        return self._parse_core_bytes(raw, ctx)


# ---------------------------- Реестр парсеров ---------------------------------

class ParserRegistry:
    """
    Реестр парсеров. Потокобезопасность на уровне GIL достаточна для типичных кейсов.
    """

    def __init__(self) -> None:
        self._by_name: Dict[str, BaseParser] = {}
        self._all: List[BaseParser] = []

    def register(self, parser: BaseParser) -> None:
        name = parser.NAME.lower()
        if name in self._by_name:
            log.warning("Parser with name '%s' already registered; overriding.", name)
        self._by_name[name] = parser
        if parser not in self._all:
            self._all.append(parser)

    def get(self, name: str) -> Optional[BaseParser]:
        return self._by_name.get(name.lower())

    def all(self) -> Tuple[BaseParser, ...]:
        return tuple(self._all)

    def choose_for(self, *, content_type: Optional[str] = None, sample: Optional[Union[str, bytes]] = None) -> Optional[BaseParser]:
        """
        Выбор парсера по медиа-типу; при нескольких кандидатах — по наибольшей уверенности sniff().
        """
        candidates: List[BaseParser] = []
        if content_type:
            ct = content_type.split(";")[0].strip().lower()
            candidates = [p for p in self._all if p.supports_media_type(ct)]
        else:
            # нет content-type — попросим всех дать оценку
            candidates = list(self._all)

        if not candidates:
            return None

        if sample is None:
            return candidates[0]

        # Выбираем с максимальным score
        best: Tuple[float, Optional[BaseParser]] = (-1.0, None)
        sample_blob = sample if isinstance(sample, (str, bytes)) else str(sample)
        for p in candidates:
            try:
                score = p.sniff(sample_blob)  # type: ignore[arg-type]
            except Exception:
                score = 0.0
            if score > best[0]:
                best = (score, p)
        return best[1] or candidates[0]


# Глобальный реестр по умолчанию (можно не использовать, если хотите явные инстансы)
DEFAULT_REGISTRY = ParserRegistry()


def register_parser(parser: BaseParser) -> None:
    DEFAULT_REGISTRY.register(parser)


def get_parser(name: str) -> Optional[BaseParser]:
    return DEFAULT_REGISTRY.get(name)


def choose_parser(content_type: Optional[str] = None, sample: Optional[Union[str, bytes]] = None) -> Optional[BaseParser]:
    return DEFAULT_REGISTRY.choose_for(content_type=content_type, sample=sample)
