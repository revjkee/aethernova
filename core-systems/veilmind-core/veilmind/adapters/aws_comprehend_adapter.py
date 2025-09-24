# -*- coding: utf-8 -*-
"""
VeilMind Core — AWS Comprehend Adapter

Функциональность:
  - detect_pii(text, language_code?) -> PiiResult
  - detect_language(text) -> LanguageResult
  - detect_sentiment(text, language_code) -> SentimentResult
  - batch_* методы для списка входов
  - redact_text_by_pii(text, entities, strategy=mask, ...) — корректная маскировка по смещениям

Надёжность/безопасность:
  - boto3 клиент с настраиваемым Config (connect/read timeout, max_pool)
  - экспоненциальные ретраи с джиттером на сетевые/троттлинг‑ошибки
  - простой circuit‑breaker (open -> half‑open -> closed)
  - поддержка AssumeRole (sts:AssumeRole), endpoint_url (в т.ч. VPC endpoint)
  - потокобезопасное обновление клиентов и кэша языка
  - ограничение входного размера в байтах (конфигурируемое)
  - опциональные метрики Prometheus (мягкий импорт) и OpenTelemetry trace

Зависимости рантайма:
  - boto3 (обязательно)
  - botocore (идёт с boto3)
  - prometheus_client, opentelemetry (опционально, мягко)

Лицензия: Apache-2.0
Автор: VeilMind Team
"""

from __future__ import annotations

import concurrent.futures
import threading
import time
import math
import random
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union, Callable

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError, ConnectionClosedError

# Опциональные зависимости
try:
    from prometheus_client import Counter, Histogram  # type: ignore
    _PROM = True
    MET_CALLS = Counter("veilmind_comprehend_calls_total", "AWS Comprehend calls", ["op", "status"])
    MET_RETRIES = Counter("veilmind_comprehend_retries_total", "Retries on Comprehend calls", ["op", "reason"])
    MET_LAT = Histogram("veilmind_comprehend_call_seconds", "Latency of Comprehend calls", ["op"])
except Exception:  # pragma: no cover
    _PROM = False

try:
    from opentelemetry import trace  # type: ignore
    _TR = True
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _TR = False
    _tracer = None  # type: ignore

# ---------------------------
# Конфиг адаптера и модели
# ---------------------------

@dataclass(frozen=True)
class ComprehendAdapterConfig:
    region_name: str
    # Переопределяемый endpoint (например, для VPC endpoint/прокси)
    endpoint_url: Optional[str] = None
    # Тайм-ауты/пул соединений
    connect_timeout: float = 3.0
    read_timeout: float = 10.0
    max_pool_connections: int = 16
    # Поведение ретраев
    max_retries: int = 5
    base_backoff: float = 0.25
    max_backoff: float = 5.0
    # Circuit breaker
    cb_failure_threshold: int = 5
    cb_cooldown_seconds: float = 20.0
    # Ограничение размера входа (байты UTF-8)
    max_input_bytes: int = 8000
    # Пул для to_thread/блокирующих вызовов из async
    thread_pool_size: int = 8
    # Опциональный ARN роли для AssumeRole
    role_arn: Optional[str] = None
    role_session_name: str = "veilmind-comprehend"
    role_external_id: Optional[str] = None
    # Кэш языка (сек)
    language_cache_ttl: float = 300.0


@dataclass(frozen=True)
class PiiEntity:
    type: str
    score: float
    begin_offset: int   # байтовый offset в UTF-8 согласно ответу AWS
    end_offset: int     # байтовый offset (исключительно)


@dataclass(frozen=True)
class PiiResult:
    language_code: Optional[str]
    entities: List[PiiEntity]
    model_version: Optional[str] = None


@dataclass(frozen=True)
class LanguageCandidate:
    language_code: str
    score: float


@dataclass(frozen=True)
class LanguageResult:
    languages: List[LanguageCandidate]


@dataclass(frozen=True)
class SentimentScores:
    positive: float
    negative: float
    neutral: float
    mixed: float


@dataclass(frozen=True)
class SentimentResult:
    language_code: str
    sentiment: str
    scores: SentimentScores
    model_version: Optional[str] = None


# ---------------------------
# Вспомогательные утилиты
# ---------------------------

def _utf8_truncate(text: str, max_bytes: int) -> str:
    """
    Возвращает префикс строки, укладывающийся в max_bytes в UTF-8, без разрыва кодпоинтов.
    """
    if max_bytes <= 0:
        return ""
    b = text.encode("utf-8")
    if len(b) <= max_bytes:
        return text
    # бинарный поиск по длине символов
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(text[:mid].encode("utf-8")) <= max_bytes:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo]


def _exponential_backoff(retry: int, base: float, cap: float) -> float:
    """
    Вычисляет задержку с джиттером.
    """
    raw = min(cap, base * (2 ** retry))
    # full jitter
    return random.random() * raw


def _should_retry(exc: Exception) -> Tuple[bool, str]:
    """
    Решение о ретрае для типовых исключений AWS/сети.
    """
    if isinstance(exc, (EndpointConnectionError, ConnectionClosedError, BotoCoreError)):
        return True, exc.__class__.__name__
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        # типичные коды троттлинга/временных сбоев
        if code in {"ThrottlingException", "Throttling", "TooManyRequestsException",
                    "ProvisionedThroughputExceededException", "ServiceUnavailableException",
                    "RequestTimeout", "InternalServerException"}:
            return True, code
    return False, ""


class _CircuitBreaker:
    """
    Простой circuit breaker: после N последовательных ошибок открывается на cooldown,
    затем полупрозрачный (half-open) на одну попытку.
    """
    def __init__(self, threshold: int, cooldown: float) -> None:
        self._threshold = max(1, threshold)
        self._cooldown = cooldown
        self._lock = threading.Lock()
        self._failures = 0
        self._opened_until = 0.0
        self._half_open = False

    def allow(self) -> bool:
        with self._lock:
            now = time.monotonic()
            if now < self._opened_until:
                return False
            if self._opened_until != 0.0 and now >= self._opened_until:
                # выходим в half-open
                self._half_open = True
                self._opened_until = 0.0
            return True

    def on_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._half_open = False
            self._opened_until = 0.0

    def on_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self._threshold:
                self._opened_until = time.monotonic() + self._cooldown
                self._half_open = False
                self._failures = 0


# ---------------------------
# Основной адаптер
# ---------------------------

class AWSComprehendAdapter:
    """
    Потокобезопасный адаптер для AWS Comprehend.
    """

    def __init__(self, cfg: ComprehendAdapterConfig):
        self.cfg = cfg
        self._lock = threading.RLock()
        self._session = self._make_session()
        self._client = self._make_client(self._session)
        self._cb = _CircuitBreaker(cfg.cb_failure_threshold, cfg.cb_cooldown_seconds)
        self._lang_cache: Dict[int, Tuple[float, LanguageResult]] = {}
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=cfg.thread_pool_size)

    # ----------- публичные API (синхронные) -----------

    def detect_language(self, text: str) -> LanguageResult:
        text = _utf8_truncate(text or "", self.cfg.max_input_bytes)
        return self._call("DetectDominantLanguage", lambda c: c.detect_dominant_language(Text=text), self._parse_language)

    def detect_sentiment(self, text: str, language_code: str) -> SentimentResult:
        text = _utf8_truncate(text or "", self.cfg.max_input_bytes)
        return self._call("DetectSentiment",
                          lambda c: c.detect_sentiment(Text=text, LanguageCode=language_code),
                          lambda r: self._parse_sentiment(r, language_code))

    def detect_pii(self, text: str, language_code: Optional[str] = None) -> PiiResult:
        text = _utf8_truncate(text or "", self.cfg.max_input_bytes)
        lang = language_code or self._get_or_detect_language(text)
        return self._call("DetectPiiEntities",
                          lambda c: c.detect_pii_entities(Text=text, LanguageCode=lang) if lang else c.detect_pii_entities(Text=text),
                          lambda r: self._parse_pii(r, lang))

    # Батч‑варианты (синхронные)

    def batch_detect_language(self, texts: Sequence[str]) -> List[LanguageResult]:
        return [self.detect_language(t) for t in texts]

    def batch_detect_sentiment(self, pairs: Sequence[Tuple[str, str]]) -> List[SentimentResult]:
        return [self.detect_sentiment(t, lc) for t, lc in pairs]

    def batch_detect_pii(self, items: Sequence[Tuple[str, Optional[str]]]) -> List[PiiResult]:
        return [self.detect_pii(t, lc) for t, lc in items]

    # Редакция по найденным PII (маскирование/хеш/токенизация)

    def redact_text_by_pii(
        self,
        text: str,
        entities: Sequence[PiiEntity],
        *,
        mode: str = "mask",           # mask|remove
        mask_char: str = "*",
        keep_head: int = 2,
        keep_tail: int = 2,
        placeholder: str = "[REDACTED]",
    ) -> str:
        """
        Применяет простую редактирующую стратегию к тексту на основе диапазонов PII.
        Смещения в entities считаются байтовыми (как в AWS), функция аккуратно мапит их в индексы символов.
        """
        if not entities or not text:
            return text

        # Построим соответствие: byte_offset -> char_index
        b = text.encode("utf-8")
        byte_to_char: List[int] = [0] * (len(b) + 1)
        char_index = 0
        pos = 0
        for ch in text:
            enc = ch.encode("utf-8")
            for _ in range(len(enc)):
                byte_to_char[pos] = char_index
                pos += 1
            char_index += 1
        byte_to_char[len(b)] = len(text)

        # Объединим пересекающиеся диапазоны
        ranges: List[Tuple[int, int]] = []
        for e in entities:
            start_b = max(0, int(e.begin_offset))
            end_b = max(start_b, int(e.end_offset))
            ranges.append((start_b, end_b))
        ranges.sort()
        merged: List[Tuple[int, int]] = []
        for s, e in ranges:
            if not merged or s > merged[-1][1]:
                merged.append((s, e))
            else:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))

        # Применим стратегию
        res: List[str] = []
        last_char = 0
        for s_b, e_b in merged:
            s_c = byte_to_char[min(s_b, len(b))]
            e_c = byte_to_char[min(e_b, len(b))]
            # неизмененный фрагмент
            if s_c > last_char:
                res.append(text[last_char:s_c])
            sensitive = text[s_c:e_c]
            if mode == "remove":
                res.append(placeholder)
            else:
                # mask
                n = len(sensitive)
                if n <= keep_head + keep_tail:
                    res.append(mask_char * n)
                else:
                    res.append(sensitive[:keep_head] + mask_char * (n - keep_head - keep_tail) + sensitive[-keep_tail:])
            last_char = e_c
        # хвост
        res.append(text[last_char:])
        return "".join(res)

    # ----------- публичные API (асинхронные) -----------

    async def adetect_language(self, text: str) -> LanguageResult:
        return await self._to_thread(self.detect_language, text)

    async def adetect_sentiment(self, text: str, language_code: str) -> SentimentResult:
        return await self._to_thread(self.detect_sentiment, text, language_code)

    async def adetect_pii(self, text: str, language_code: Optional[str] = None) -> PiiResult:
        return await self._to_thread(self.detect_pii, text, language_code)

    async def abatch_detect_language(self, texts: Sequence[str]) -> List[LanguageResult]:
        return await self._to_thread(self.batch_detect_language, texts)

    async def abatch_detect_sentiment(self, pairs: Sequence[Tuple[str, str]]) -> List[SentimentResult]:
        return await self._to_thread(self.batch_detect_sentiment, pairs)

    async def abatch_detect_pii(self, items: Sequence[Tuple[str, Optional[str]]]) -> List[PiiResult]:
        return await self._to_thread(self.batch_detect_pii, items)

    # ----------- ресурсный менеджмент -----------

    def close(self) -> None:
        try:
            self._pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    # ------------------ внутреннее ------------------

    def _get_or_detect_language(self, text: str) -> Optional[str]:
        """
        Простой кэш по hash(text); для приватности кэшируем только hash и результат.
        """
        h = hash(text)
        now = time.monotonic()
        with self._lock:
            cached = self._lang_cache.get(h)
            if cached and (now - cached[0]) <= self.cfg.language_cache_ttl:
                return cached[1].languages[0].language_code if cached[1].languages else None
        res = self.detect_language(text)
        with self._lock:
            self._lang_cache[h] = (now, res)
        return res.languages[0].language_code if res.languages else None

    def _call(self, op: str, fn: Callable, parser: Callable[[Mapping[str, Any]], Any]) -> Any:
        """
        Унифицированный вызов AWS с ретраями, метриками и circuit breaker.
        """
        if not self._cb.allow():
            if _PROM:  # pragma: no cover
                MET_CALLS.labels(op=op, status="circuit_open").inc()
            raise RuntimeError("Circuit breaker is open for AWS Comprehend")

        start = time.perf_counter()
        last_exc: Optional[Exception] = None
        for attempt in range(self.cfg.max_retries + 1):
            try:
                if _PROM:  # pragma: no cover
                    t = MET_LAT.labels(op=op).time()
                else:
                    t = None
                if _TR:  # pragma: no cover
                    with _tracer.start_as_current_span(f"aws.comprehend.{op}"):
                        resp = fn(self._client)
                else:
                    resp = fn(self._client)
                if t:  # pragma: no cover
                    t.observe_duration()
                self._cb.on_success()
                if _PROM:  # pragma: no cover
                    MET_CALLS.labels(op=op, status="ok").inc()
                return parser(resp)
            except Exception as e:
                last_exc = e
                retry, reason = _should_retry(e)
                if not retry or attempt >= self.cfg.max_retries:
                    self._cb.on_failure()
                    if _PROM:  # pragma: no cover
                        MET_CALLS.labels(op=op, status="error").inc()
                    raise
                delay = _exponential_backoff(attempt + 1, self.cfg.base_backoff, self.cfg.max_backoff)
                if _PROM:  # pragma: no cover
                    MET_RETRIES.labels(op=op, reason=reason or e.__class__.__name__).inc()
                time.sleep(delay)
                # безопасное обновление клиента (на случай закрытия соединения)
                if isinstance(e, (EndpointConnectionError, ConnectionClosedError)):
                    with self._lock:
                        self._client = self._make_client(self._session)
        # если дошли сюда — поднимем последнее исключение
        if last_exc:
            raise last_exc
        raise RuntimeError("Unexpected state in AWSComprehendAdapter._call")

    def _parse_language(self, resp: Mapping[str, Any]) -> LanguageResult:
        langs = []
        for it in resp.get("Languages", []) or []:
            code = it.get("LanguageCode")
            score = float(it.get("Score") or 0.0)
            if code:
                langs.append(LanguageCandidate(language_code=code, score=score))
        langs.sort(key=lambda x: x.score, reverse=True)
        return LanguageResult(languages=langs)

    def _parse_sentiment(self, resp: Mapping[str, Any], lang: str) -> SentimentResult:
        sentiment = str(resp.get("Sentiment") or "")
        s = resp.get("SentimentScore") or {}
        scores = SentimentScores(
            positive=float(s.get("Positive") or 0.0),
            negative=float(s.get("Negative") or 0.0),
            neutral=float(s.get("Neutral") or 0.0),
            mixed=float(s.get("Mixed") or 0.0),
        )
        return SentimentResult(language_code=lang, sentiment=sentiment, scores=scores,
                               model_version=resp.get("ModelVersion"))

    def _parse_pii(self, resp: Mapping[str, Any], lang: Optional[str]) -> PiiResult:
        ents: List[PiiEntity] = []
        for it in resp.get("Entities", []) or []:
            try:
                ents.append(PiiEntity(
                    type=str(it.get("Type") or ""),
                    score=float(it.get("Score") or 0.0),
                    begin_offset=int(it.get("BeginOffset") or 0),
                    end_offset=int(it.get("EndOffset") or 0),
                ))
            except Exception:
                continue
        return PiiResult(language_code=lang, entities=ents, model_version=resp.get("ModelVersion"))

    def _to_thread(self, fn: Callable, *args, **kwargs):
        """
        Унифицированный вызов в thread pool для совместимости с async кодом.
        """
        fut = self._pool.submit(fn, *args, **kwargs)
        # Превратим в awaitable без зависимостей
        import asyncio
        return asyncio.wrap_future(fut)

    # ----------- создание клиентов/сессий -----------

    def _make_session(self):
        if not self.cfg.role_arn:
            return boto3.Session(region_name=self.cfg.region_name)
        # AssumeRole (ручной, потокобезопасный; boto3 сам рефрешит, но поддержим явное построение)
        sts = boto3.client("sts", region_name=self.cfg.region_name, config=self._boto_config())
        assume_args: Dict[str, Any] = {
            "RoleArn": self.cfg.role_arn,
            "RoleSessionName": self.cfg.role_session_name,
        }
        if self.cfg.role_external_id:
            assume_args["ExternalId"] = self.cfg.role_external_id
        creds = sts.assume_role(**assume_args)["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self.cfg.region_name,
        )

    def _boto_config(self) -> BotoConfig:
        return BotoConfig(
            connect_timeout=self.cfg.connect_timeout,
            read_timeout=self.cfg.read_timeout,
            max_pool_connections=self.cfg.max_pool_connections,
            retries={"max_attempts": 0, "mode": "standard"},  # ретраи делаем сами
        )

    def _make_client(self, session) -> Any:
        return session.client(
            "comprehend",
            region_name=self.cfg.region_name,
            endpoint_url=self.cfg.endpoint_url,
            config=self._boto_config(),
        )


# ---------------------------
# Пример использования (док‑комментарий)
# ---------------------------
"""
from veilmind.adapters.aws_comprehend_adapter import AWSComprehendAdapter, ComprehendAdapterConfig

cfg = ComprehendAdapterConfig(
    region_name="eu-west-1",
    endpoint_url=None,
    connect_timeout=2.0,
    read_timeout=8.0,
    max_retries=4,
    role_arn=None,  # или "arn:aws:iam::123456789012:role/VeilMindComprehend"
)

adapter = AWSComprehendAdapter(cfg)

text = "John's email is john.doe@example.com, phone +14155550123."
pii = adapter.detect_pii(text)
red = adapter.redact_text_by_pii(text, pii.entities, mode="mask", mask_char="*", keep_head=1, keep_tail=1)

lang = adapter.detect_language(text)
sent = adapter.detect_sentiment("I love this product, but delivery was slow.", language_code="en")

adapter.close()
"""
