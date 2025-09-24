# veilmind-core/veilmind/adapters/azure_pii_adapter.py
# -*- coding: utf-8 -*-
"""
Адаптер для обнаружения PII через Azure Language (Text Analytics) PII API.

Особенности:
- Безопасные логи (маскирование секретов), Content-SHA256
- Строгая конфигурация: endpoint, путь PII, аутентификация (key/Bearer), таймауты
- Экспоненциальный бэкофф с джиттером, ограничение батча и размеров
- Нормализация категорий и offsets, опциональная локальная редакция текста
- Синхронный и асинхронный клиенты (httpx)
- Без утечки исходных значений в логи

Примечание: конкретный путь и версия API задаются конфигом (pii_path). Не хардкодится.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union, Literal

try:
    import httpx  # runtime dependency
except Exception as e:  # pragma: no cover
    raise ImportError("azure_pii_adapter requires 'httpx' package") from e


# ----------------------------- Безопасные логи -----------------------------

_REDACT_MASK = "[REDACTED]"
_DENY_KEYS = {
    "authorization", "cookie", "set-cookie",
    "password", "passwd", "secret", "token", "access_token", "refresh_token", "id_token",
    "api_key", "apikey", "private_key", "client_secret", "db_password", "jwt", "otp", "session",
    "ocp-apim-subscription-key", "x-api-key",
}
_PATTERNS = [
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]+"),
    re.compile(r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b"),  # JWT
    re.compile(r"\b\d{13,19}\b"),  # PAN (широкий)
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),             # Email
    re.compile(r"(?i)\+?[0-9][0-9\-\s()]{7,}"),                                # Phone
    re.compile(r"(?i)\b(pwd|pass(word)?|secret|token|key)\b\s*[:=]\s*\S+"),    # k=v секрет
]


def _redact_text(s: str, max_len: int = 2048) -> str:
    out = s
    for rx in _PATTERNS:
        out = rx.sub(_REDACT_MASK, out)
    if len(out) > max_len:
        out = out[:max_len] + "...(truncated)"
    return out


def _redact_headers(h: Mapping[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in h.items():
        if k.lower() in _DENY_KEYS:
            out[k] = _REDACT_MASK
        else:
            out[k] = _redact_text(str(v), max_len=256)
    return out


def _safe_json_dump(data: Any, max_len: int = 4096) -> str:
    try:
        txt = json.dumps(data, ensure_ascii=False, sort_keys=True)
        return _redact_text(txt, max_len=max_len)
    except Exception:
        return "<unserializable>"


# ----------------------------- Исключения/модели -----------------------------

class AzurePIIError(Exception):
    """Базовая ошибка адаптера Azure PII."""


@dataclass
class PIIEntity:
    kind: str                      # нормализованный тип (EMAIL/PHONE/CREDIT_CARD/IBAN/SSN/ADDRESS/…)
    category: str                  # исходная категория Azure
    subcategory: Optional[str]
    offset: int                    # смещение в кодпоинтах
    length: int                    # длина в кодпоинтах
    confidence: float
    hashed_value: Optional[str] = None  # SHA-256 от исходного entity.text (не возвращаем исходник)


@dataclass
class PIIResult:
    redacted_text: Optional[str]   # если включено редактирование на стороне клиента
    entities: List[PIIEntity]
    raw_redacted_text_from_service: Optional[str] = None  # если сервис его вернул
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    warnings: List[str] = field(default_factory=list)


# ----------------------------- Конфигурация -----------------------------

@dataclass
class AzurePIIConfig:
    """
    Конфигурация адаптера Azure PII.
    """
    endpoint: str                                # пример: "https://<resource>.cognitiveservices.azure.com"
    pii_path: str                                # пример: "/text/analytics/v3.2/entities/recognition/pii" (указать свой путь/версию)
    # Аутентификация: укажите один из вариантов
    api_key: Optional[str] = None                # Ocp-Apim-Subscription-Key
    bearer_token: Optional[str] = None           # Authorization: Bearer <token>
    # Параметры запроса
    default_language: Optional[str] = None       # напр. "en"|"ru"|"sv"
    string_index_type: Optional[str] = None      # например "UnicodeCodePoint"; передаётся как опция, если указано
    domain_filter: Optional[str] = None          # опционально: azure-домены, если поддерживается (не обязательно)
    categories_allow: Optional[Sequence[str]] = None  # фильтр по категориям Azure (после ответа)
    # Лимиты/таймауты/ретраи
    timeout_s: float = 10.0
    connect_timeout_s: float = 5.0
    read_timeout_s: float = 5.0
    write_timeout_s: float = 5.0
    retries: int = 3
    backoff_base_s: float = 0.2
    backoff_max_s: float = 2.5
    retry_on_status: Tuple[int, ...] = (408, 425, 429, 500, 502, 503, 504)
    batch_size: int = 10                           # размер батча документов
    max_text_len: int = 200_000                    # ограничение длины текста
    # Локальное редактирование
    local_redact: bool = True
    mask_char: str = "*"
    keep_left: int = 1
    keep_right: int = 1
    # Логи
    logger: Optional[logging.Logger] = None
    log_requests: bool = False
    log_bodies: bool = False
    # Прочее
    headers: Dict[str, str] = field(default_factory=dict)
    verify: Union[bool, str] = True                # валидация TLS; путь к CA или True/False
    proxies: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.endpoint.startswith(("http://", "https://")):
            raise ValueError("endpoint must start with http:// or https://")
        self.endpoint = self.endpoint.rstrip("/")
        if not self.pii_path.startswith("/"):
            raise ValueError("pii_path must start with '/'")
        if self.api_key is None and self.bearer_token is None and not self.headers:
            raise ValueError("provide api_key or bearer_token or custom headers")
        if self.logger is None:
            lg = logging.getLogger("veilmind.azure_pii")
            if not lg.handlers:
                h = logging.StreamHandler()
                h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
                lg.addHandler(h)
            lg.setLevel(logging.INFO)
            self.logger = lg


# ----------------------------- Нормализация категорий -----------------------------

_NORMALIZE_MAP = {
    # Примеры маппинга Azure → внутренний kind
    "Email": "EMAIL",
    "PhoneNumber": "PHONE",
    "USSocialSecurityNumber": "SSN",
    "CreditCardNumber": "CREDIT_CARD",
    "EUDebitCardNumber": "CREDIT_CARD",
    "IBAN": "IBAN",
    "IPAddress": "IP_ADDRESS",
    "UKNationalInsuranceNumber": "NATIONAL_ID",
    "USDriverLicenseNumber": "DRIVER_LICENSE",
    "AadhaarNumber": "NATIONAL_ID",
    "BankAccountNumber": "BANK_ACCOUNT",
    "SWIFTCode": "BANK_CODE",
    "TaxID": "TAX_ID",
    "Person": "PERSON",
    "Organization": "ORG",
    "Location": "LOCATION",
}


def _normalize_kind(category: str) -> str:
    return _NORMALIZE_MAP.get(category, category.upper().replace(" ", "_"))


# ----------------------------- Вспомогательные функции -----------------------------

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _content_sha256(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _compute_backoff(attempt: int, base: float, cap: float) -> float:
    import os
    b = min(cap, base * (2 ** (attempt - 1)))
    # full-jitter
    return 0.5 * b + (os.urandom(1)[0] / 255.0) * 0.5 * b


def _mask_span(text: str, start: int, length: int, mask_char: str) -> str:
    end = min(len(text), start + length)
    if start >= end:
        return text
    return text[:start] + (mask_char * (end - start)) + text[end:]


def _mask_partial(s: str, keep_left: int, keep_right: int, mask_char: str) -> str:
    if len(s) <= keep_left + keep_right:
        return mask_char * len(s)
    return s[:keep_left] + mask_char * (len(s) - keep_left - keep_right) + s[-keep_right:]


# ----------------------------- Клиент -----------------------------

class AzurePIIAdapter:
    """
    Синхронный клиент.
    """
    def __init__(self, cfg: AzurePIIConfig):
        self.cfg = cfg
        self._timeout = httpx.Timeout(
            timeout=cfg.timeout_s,
            connect=cfg.connect_timeout_s,
            read=cfg.read_timeout_s,
            write=cfg.write_timeout_s,
        )
        self._client = httpx.Client(
            base_url=cfg.endpoint,
            timeout=self._timeout,
            headers=dict(cfg.headers),
            verify=cfg.verify,
            proxies=cfg.proxies,
        )
        if cfg.api_key:
            # Распространенный заголовок для ключа Azure когнитивных сервисов
            self._client.headers["Ocp-Apim-Subscription-Key"] = cfg.api_key
        if cfg.bearer_token:
            self._client.headers["Authorization"] = f"Bearer {cfg.bearer_token}"
        self._client.headers["Accept"] = "application/json"
        self._client.headers.setdefault("User-Agent", "veilmind-azure-pii/1.0")

    # -------------- Логирование --------------

    def _log_req(self, url: str, headers: Mapping[str, str], body: Optional[Mapping[str, Any]]) -> None:
        if not self.cfg.log_requests:
            return
        msg = f"POST {url}\nHeaders: {_redact_headers(headers)}"
        if self.cfg.log_bodies and body is not None:
            msg += f"\nBody: {_safe_json_dump(body)}"
        self.cfg.logger.info(msg)

    def _log_resp(self, url: str, resp: httpx.Response) -> None:
        if not self.cfg.log_requests:
            return
        line = f"Response {resp.status_code} for {url}\nHeaders: {_redact_headers(dict(resp.headers))}"
        if self.cfg.log_bodies:
            with contextlib.suppress(Exception):
                line += f"\nBody: {_redact_text(resp.text)}"
        self.cfg.logger.info(line)

    # -------------- Основной вызов --------------

    def _post_with_retries(self, path: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        url = f"{self.cfg.endpoint}{path}"
        headers = {"Content-Type": "application/json", "Content-SHA256": _content_sha256(payload)}
        self._log_req(url, {**self._client.headers, **headers}, payload)
        attempt = 0
        while True:
            attempt += 1
            try:
                r = self._client.post(path, json=payload, headers=headers)
                if r.status_code in self.cfg.retry_on_status and attempt <= self.cfg.retries:
                    delay = _compute_backoff(attempt, self.cfg.backoff_base_s, self.cfg.backoff_max_s)
                    self.cfg.logger.info(f"Retry in {delay:.2f}s (status={r.status_code})")
                    time.sleep(delay)
                    continue
                if r.status_code == 401:
                    raise AzurePIIError("unauthorized")
                if r.status_code >= 400:
                    raise AzurePIIError(f"http {r.status_code}: {_redact_text(r.text)}")
                return r.json()
            except httpx.TimeoutException as e:
                if attempt > self.cfg.retries:
                    raise AzurePIIError("timeout") from e
                delay = _compute_backoff(attempt, self.cfg.backoff_base_s, self.cfg.backoff_max_s)
                self.cfg.logger.info(f"Retry in {delay:.2f}s (timeout)")
                time.sleep(delay)
            except httpx.HTTPError as e:
                if attempt > self.cfg.retries:
                    raise AzurePIIError(f"http error: {e}") from e
                delay = _compute_backoff(attempt, self.cfg.backoff_base_s, self.cfg.backoff_max_s)
                self.cfg.logger.info(f"Retry in {delay:.2f}s (network)")
                time.sleep(delay)

    # -------------- Публичный API --------------

    def recognize_pii(
        self,
        text: str,
        *,
        language: Optional[str] = None,
    ) -> PIIResult:
        """
        Обнаружить PII в одном документе.
        """
        docs, warnings = _build_documents([(text, language or self.cfg.default_language)], max_len=self.cfg.max_text_len)
        payload = _build_request_payload(docs, self.cfg)
        data = self._post_with_retries(self.cfg.pii_path, payload)
        result = _parse_response_single(data, docs[0]["id"], self.cfg, warnings)
        if self.cfg.local_redact and result.redacted_text is None:
            # Локальная редакция, если сервис не вернул redactedText
            result.redacted_text = _apply_local_redaction(text, result.entities, self.cfg.mask_char, self.cfg.keep_left, self.cfg.keep_right)
        return result

    def batch_recognize_pii(
        self,
        items: Iterable[Union[str, Tuple[str, Optional[str]]]],
    ) -> List[PIIResult]:
        """
        Пакетная обработка. items: либо строки, либо кортежи (text, language).
        """
        pairs: List[Tuple[str, Optional[str]]] = []
        for it in items:
            if isinstance(it, str):
                pairs.append((it, self.cfg.default_language))
            else:
                pairs.append((it[0], it[1]))
        results: List[PIIResult] = []
        for chunk in _chunks(pairs, self.cfg.batch_size):
            docs, warnings = _build_documents(chunk, max_len=self.cfg.max_text_len)
            payload = _build_request_payload(docs, self.cfg)
            data = self._post_with_retries(self.cfg.pii_path, payload)
            res_map = _parse_response_batch(data, self.cfg)
            for d in docs:
                r = res_map.get(d["id"]) or PIIResult(redacted_text=None, entities=[], warnings=list(warnings))
                if self.cfg.local_redact and r.redacted_text is None:
                    r.redacted_text = _apply_local_redaction(d["text"], r.entities, self.cfg.mask_char, self.cfg.keep_left, self.cfg.keep_right)
                results.append(r)
        return results

    def close(self) -> None:
        self._client.close()


# ----------------------------- Асинхронный клиент -----------------------------

class AsyncAzurePIIAdapter:
    """
    Асинхронный клиент.
    """
    def __init__(self, cfg: AzurePIIConfig):
        self.cfg = cfg
        self._timeout = httpx.Timeout(
            timeout=cfg.timeout_s,
            connect=cfg.connect_timeout_s,
            read=cfg.read_timeout_s,
            write=cfg.write_timeout_s,
        )
        self._client = httpx.AsyncClient(
            base_url=cfg.endpoint,
            timeout=self._timeout,
            headers=dict(cfg.headers),
            verify=cfg.verify,
            proxies=cfg.proxies,
        )
        if cfg.api_key:
            self._client.headers["Ocp-Apim-Subscription-Key"] = cfg.api_key
        if cfg.bearer_token:
            self._client.headers["Authorization"] = f"Bearer {cfg.bearer_token}"
        self._client.headers["Accept"] = "application/json"
        self._client.headers.setdefault("User-Agent", "veilmind-azure-pii/1.0")

    async def _post_with_retries(self, path: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        headers = {"Content-Type": "application/json", "Content-SHA256": _content_sha256(payload)}
        attempt = 0
        while True:
            attempt += 1
            try:
                r = await self._client.post(path, json=payload, headers=headers)
                if r.status_code in self.cfg.retry_on_status and attempt <= self.cfg.retries:
                    delay = _compute_backoff(attempt, self.cfg.backoff_base_s, self.cfg.backoff_max_s)
                    self.cfg.logger.info(f"Retry in {delay:.2f}s (status={r.status_code})")
                    await _sleep(delay)
                    continue
                if r.status_code == 401:
                    raise AzurePIIError("unauthorized")
                if r.status_code >= 400:
                    raise AzurePIIError(f"http {r.status_code}: {_redact_text(r.text)}")
                return r.json()
            except httpx.TimeoutException as e:
                if attempt > self.cfg.retries:
                    raise AzurePIIError("timeout") from e
                delay = _compute_backoff(attempt, self.cfg.backoff_base_s, self.cfg.backoff_max_s)
                self.cfg.logger.info(f"Retry in {delay:.2f}s (timeout)")
                await _sleep(delay)
            except httpx.HTTPError as e:
                if attempt > self.cfg.retries:
                    raise AzurePIIError(f"http error: {e}") from e
                delay = _compute_backoff(attempt, self.cfg.backoff_base_s, self.cfg.backoff_max_s)
                self.cfg.logger.info(f"Retry in {delay:.2f}s (network)")
                await _sleep(delay)

    async def recognize_pii(self, text: str, *, language: Optional[str] = None) -> PIIResult:
        docs, warnings = _build_documents([(text, language or self.cfg.default_language)], max_len=self.cfg.max_text_len)
        payload = _build_request_payload(docs, self.cfg)
        data = await self._post_with_retries(self.cfg.pii_path, payload)
        result = _parse_response_single(data, docs[0]["id"], self.cfg, warnings)
        if self.cfg.local_redact and result.redacted_text is None:
            result.redacted_text = _apply_local_redaction(text, result.entities, self.cfg.mask_char, self.cfg.keep_left, self.cfg.keep_right)
        return result

    async def batch_recognize_pii(self, items: Iterable[Union[str, Tuple[str, Optional[str]]]]) -> List[PIIResult]:
        pairs: List[Tuple[str, Optional[str]]] = []
        for it in items:
            if isinstance(it, str):
                pairs.append((it, self.cfg.default_language))
            else:
                pairs.append((it[0], it[1]))
        results: List[PIIResult] = []
        for chunk in _chunks(pairs, self.cfg.batch_size):
            docs, warnings = _build_documents(chunk, max_len=self.cfg.max_text_len)
            payload = _build_request_payload(docs, self.cfg)
            data = await self._post_with_retries(self.cfg.pii_path, payload)
            res_map = _parse_response_batch(data, self.cfg)
            for d in docs:
                r = res_map.get(d["id"]) or PIIResult(redacted_text=None, entities=[], warnings=list(warnings))
                if self.cfg.local_redact and r.redacted_text is None:
                    r.redacted_text = _apply_local_redaction(d["text"], r.entities, self.cfg.mask_char, self.cfg.keep_left, self.cfg.keep_right)
                results.append(r)
        return results

    async def aclose(self) -> None:
        await self._client.aclose()


# ----------------------------- Постобработка ответа -----------------------------

def _parse_response_single(data: Mapping[str, Any], doc_id: str, cfg: AzurePIIConfig, warnings: List[str]) -> PIIResult:
    docs = data.get("documents") or []
    err = data.get("errors") or []
    if err:
        warnings.append("service returned errors")
    found = None
    for d in docs:
        if str(d.get("id")) == str(doc_id):
            found = d
            break
    if not found:
        return PIIResult(redacted_text=None, entities=[], warnings=warnings)

    ents: List[PIIEntity] = []
    for e in found.get("entities") or []:
        cat = str(e.get("category", ""))
        if cfg.categories_allow and cat not in cfg.categories_allow:
            continue
        text_val = str(e.get("text", "")) if "text" in e else ""
        ents.append(
            PIIEntity(
                kind=_normalize_kind(cat),
                category=cat,
                subcategory=(e.get("subcategory") if isinstance(e.get("subcategory"), str) else None),
                offset=int(e.get("offset", 0) or 0),
                length=int(e.get("length", 0) or 0),
                confidence=float(e.get("confidenceScore", 0.0) or 0.0),
                hashed_value=_sha256_hex(text_val) if text_val else None,
            )
        )
    red_text = found.get("redactedText")
    return PIIResult(
        redacted_text=None,  # локальная редакция ниже при необходимости
        raw_redacted_text_from_service=red_text if isinstance(red_text, str) else None,
        entities=ents,
        warnings=warnings,
    )


def _parse_response_batch(data: Mapping[str, Any], cfg: AzurePIIConfig) -> Dict[str, PIIResult]:
    docs = data.get("documents") or []
    res: Dict[str, PIIResult] = {}
    for d in docs:
        doc_id = str(d.get("id"))
        r = _parse_response_single({"documents": [d]}, doc_id, cfg, warnings=[])
        res[doc_id] = r
    return res


# ----------------------------- Формирование запроса -----------------------------

def _build_documents(pairs: Sequence[Tuple[str, Optional[str]]], *, max_len: int) -> Tuple[List[Dict[str, Any]], List[str]]:
    warnings: List[str] = []
    docs: List[Dict[str, Any]] = []
    for i, (text, lang) in enumerate(pairs, start=1):
        t = str(text or "")
        if len(t) > max_len:
            warnings.append(f"document {i} truncated from {len(t)} to {max_len}")
            t = t[:max_len]
        doc = {"id": str(i), "text": t}
        if lang:
            doc["language"] = lang
        docs.append(doc)
    return docs, warnings


def _build_request_payload(docs: List[Dict[str, Any]], cfg: AzurePIIConfig) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"documents": docs}
    # Дополнительные опции Azure передаем в секции "parameters"/"options", если сервис ожидает
    # Чтобы избежать предположений, включаем их только если заданы явно
    options: Dict[str, Any] = {}
    if cfg.string_index_type:
        options["stringIndexType"] = cfg.string_index_type
    if cfg.domain_filter:
        options["domain"] = cfg.domain_filter
    if options:
        payload["options"] = options
    return payload


# ----------------------------- Локальное редактирование -----------------------------

def _apply_local_redaction(text: str, entities: List[PIIEntity], mask_char: str, keep_left: int, keep_right: int) -> str:
    """
    Безопасная редакция текста на стороне клиента.
    Для сущностей, у которых неизвестно исходное значение, маскируем по span.
    Для email/phone/credit_card применяем частичную маску.
    """
    # Предпочтем маску по span; если span отсутствует, используем эвристику partial-mask на подстроке
    spans = sorted([(e.offset, e.length, e.kind) for e in entities if e.length > 0], key=lambda x: x[0])
    out = text
    shift = 0
    for start, length, kind in spans:
        s = start + shift
        segment = out[s:s + length]
        if kind in {"EMAIL", "PHONE", "CREDIT_CARD"} and segment:
            masked = _mask_partial(segment, keep_left, keep_right, mask_char)
        else:
            masked = mask_char * len(segment)
        out = out[:s] + masked + out[s + length:]
        shift += len(masked) - length
    return out


# ----------------------------- Утилиты -----------------------------

def _chunks(seq: Sequence[Tuple[str, Optional[str]]], n: int) -> Iterable[List[Tuple[str, Optional[str]]]]:
    for i in range(0, len(seq), n):
        yield list(seq[i:i + n])


# ----------------------------- Асинхронные утилиты -----------------------------

import asyncio
import contextlib

async def _sleep(sec: float) -> None:
    await asyncio.sleep(sec)


# ----------------------------- Пример использования -----------------------------
# cfg = AzurePIIConfig(
#     endpoint=os.environ["AZURE_LANG_ENDPOINT"],
#     pii_path=os.environ["AZURE_PII_PATH"],  # задайте путь вашей версии PII API
#     api_key=os.environ.get("AZURE_LANG_KEY"),  # или bearer_token=...
#     default_language="en",
#     string_index_type="UnicodeCodePoint",
#     local_redact=True,
#     log_requests=False,
# )
# client = AzurePIIAdapter(cfg)
# res = client.recognize_pii("My email is john.doe@example.org and card 4111 1111 1111 1111")
# print(res.redacted_text, [e.kind for e in res.entities])
# client.close()
