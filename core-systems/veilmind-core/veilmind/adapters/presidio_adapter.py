# -*- coding: utf-8 -*-
"""
veilmind-core: adapters.presidio_adapter
Промышленный адаптер к Microsoft Presidio с безопасными дефолтами и fallback-режимом.

Режимы работы:
  - auto   : попытка local, затем remote, затем fallback (regex_detectors)
  - local  : через библиотеки presidio_analyzer / presidio_anonymizer (если установлены)
  - remote : через HTTP API (URL задаются конфигом)
  - fallback: локальные детекторы veilmind.detect.regex_detectors

Зависимости (необязательные):
  - presidio-analyzer, presidio-anonymizer  (для режима local)
  - httpx (для режима remote; иначе используется urllib)

Нормализованный формат Finding согласован с veilmind.detect.regex_detectors.Finding.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import math
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Literal, Optional, Sequence, Tuple

# Опциональные импорты Presidio
try:  # pragma: no cover
    from presidio_analyzer import AnalyzerEngine, RecognizerResult
    from presidio_anonymizer import AnonymizerEngine
    _PRESIDIO_AVAILABLE = True
except Exception:  # pragma: no cover
    AnalyzerEngine = None  # type: ignore
    AnonymizerEngine = None  # type: ignore
    RecognizerResult = None  # type: ignore
    _PRESIDIO_AVAILABLE = False

# Опциональный httpx
try:  # pragma: no cover
    import httpx
    _HTTPX = True
except Exception:  # pragma: no cover
    httpx = None  # type: ignore
    _HTTPX = False

# Локальный fallback
try:
    from veilmind.detect.regex_detectors import (
        Finding as LocalFinding,
        ScanConfig,
        build_default_detectors,
        scan_text,
    )
except Exception as e:
    # Минимальная локальная модель Finding на случай отсутствия модуля
    @dataclass(frozen=True)
    class LocalFinding:
        detector: str
        category: str
        severity: str
        start: int
        end: int
        match: str
        redacted: str
        context: str
        extra: Dict[str, str] = field(default_factory=dict)

    def build_default_detectors():
        return []

    class ScanConfig:  # type: ignore
        def __init__(self, detectors=None, **kwargs):
            self.detectors = detectors or []
        def is_allowed(self, s: str) -> bool:
            return False

    def scan_text(text: str, config: Optional[ScanConfig] = None) -> List[LocalFinding]:
        return []


# --------------------------------------------------------------------------------------
# Конфигурация и типы
# --------------------------------------------------------------------------------------

Severity = Literal["low", "medium", "high", "critical"]
Mode = Literal["auto", "local", "remote", "fallback"]

DEFAULT_LANGS = ("en", "ru")

_PRESIDIO_TO_CATEGORY: Dict[str, str] = {
    # Базовые PII Presidio → домены veilmind
    "EMAIL_ADDRESS": "PII",
    "PHONE_NUMBER": "PII",
    "US_SSN": "PII",
    "PERSON": "PII",
    "LOCATION": "PII",
    "DATE_TIME": "PII",
    "CREDIT_CARD": "FINANCIAL",
    "IBAN_CODE": "FINANCIAL",
    "IP_ADDRESS": "NETWORK",
    "US_BANK_NUMBER": "FINANCIAL",
    "CRYPTO": "CREDENTIAL",
    "MEDICAL_LICENSE": "PII",
    "PASSPORT": "PII",
    "UK_NHS": "PII",
    # Можно расширять в конфиге
}

# Преобразование score→severity
def _severity(score: float) -> Severity:
    if score >= 0.90:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.50:
        return "medium"
    return "low"


@dataclass(frozen=True)
class RemoteAPI:
    analyze_url: Optional[str] = None
    anonymize_url: Optional[str] = None
    api_key: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_sec: float = 5.0
    connect_timeout_sec: float = 2.0
    retries: int = 1
    backoff_sec: float = 0.2


@dataclass
class AnonymizePolicy:
    # entity_type → оператор и параметры
    # Примеры операторов Presidio: "mask", "replace", "hash", "redact"
    # Для fallback используются те же имена.
    operators: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "EMAIL_ADDRESS": {"type": "hash", "hash_type": "sha256", "prefix": "h:"},
        "PHONE_NUMBER": {"type": "mask", "chars_to_mask": 6, "from_end": True, "masking_char": "*"},
        "CREDIT_CARD": {"type": "mask", "chars_to_mask": 12, "from_end": True, "masking_char": "*"},
        "IBAN_CODE": {"type": "mask", "chars_to_mask": 14, "from_end": True, "masking_char": "*"},
        "IP_ADDRESS": {"type": "replace", "new_value": "<ip/>"},
        "*": {"type": "redact"},
    })


@dataclass
class PresidioConfig:
    mode: Mode = "auto"
    languages: Tuple[str, ...] = DEFAULT_LANGS
    score_threshold: float = 0.5
    entities_allow: Tuple[str, ...] = ()
    entities_deny: Tuple[str, ...] = ()
    chunk_size: int = 256 * 1024
    chunk_overlap: int = 256
    remote: RemoteAPI = field(default_factory=RemoteAPI)
    anonymize_policy: AnonymizePolicy = field(default_factory=AnonymizePolicy)
    # Circuit breaker
    cb_failure_threshold: int = 5
    cb_cooldown_sec: float = 30.0
    # Логи
    log_level: int = logging.INFO

    def effective_mode(self) -> Mode:
        if self.mode != "auto":
            return self.mode
        if _PRESIDIO_AVAILABLE:
            return "local"
        if self.remote.analyze_url:
            return "remote"
        return "fallback"


@dataclass(frozen=True)
class Finding:
    detector: str
    category: str
    severity: Severity
    start: int
    end: int
    match: str
    redacted: str
    context: str
    extra: Dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), ensure_ascii=False)


# --------------------------------------------------------------------------------------
# Адаптер
# --------------------------------------------------------------------------------------

class PresidioAdapter:
    def __init__(self, config: Optional[PresidioConfig] = None, logger: Optional[logging.Logger] = None) -> None:
        self.cfg = config or PresidioConfig()
        self.log = logger or logging.getLogger("veilmind.presidio")
        self.log.setLevel(self.cfg.log_level)

        self._mode: Mode = self.cfg.effective_mode()
        self._analyzer = None
        self._anonymizer = None

        self._cb_failures = 0
        self._cb_opened_at = 0.0

        if self._mode == "local":
            self._init_local()

    # ------------------------ public API ------------------------

    def analyze(self, text: str, *, languages: Optional[Sequence[str]] = None) -> List[Finding]:
        """
        Выполняет анализ текста и возвращает нормализованные находки.
        """
        mode = self._current_mode()
        langs = tuple(languages or self.cfg.languages or DEFAULT_LANGS)

        if mode == "local":
            findings = self._analyze_local(text, langs)
        elif mode == "remote":
            findings = self._analyze_remote(text, langs)
        else:
            findings = self._analyze_fallback(text)

        # Фильтры allow/deny и пороги
        findings = [f for f in findings if self._entity_allowed(f.extra.get("entity_type"))]
        findings = [f for f in findings if float(f.extra.get("score", "0")) >= self.cfg.score_threshold]
        return findings

    def anonymize(self, text: str, findings: Optional[Sequence[Finding]] = None) -> str:
        """
        Анонимизация текста по политике. Если findings не переданы — выполняется анализ.
        """
        mode = self._current_mode()
        if findings is None:
            findings = self.analyze(text)

        if mode == "local":
            try:
                return self._anonymize_local(text, findings)
            except Exception as e:
                self.log.warning("local anonymize failed, falling back: %s", e)
                return self._anonymize_fallback(text, findings)
        elif mode == "remote":
            try:
                res = self._anonymize_remote(text, findings)
                if res is not None:
                    return res
            except Exception as e:
                self.log.warning("remote anonymize failed, falling back: %s", e)
            return self._anonymize_fallback(text, findings)
        else:
            return self._anonymize_fallback(text, findings)

    # ------------------------ mode management ------------------------

    def _init_local(self) -> None:
        if not _PRESIDIO_AVAILABLE:
            self._mode = "fallback"
            return
        try:
            self._analyzer = AnalyzerEngine()
            self._anonymizer = AnonymizerEngine()
            self.log.info("Presidio local engines initialized")
        except Exception as e:
            self.log.error("Failed to init Presidio local engines: %s", e)
            self._mode = "fallback"

    def _current_mode(self) -> Mode:
        # простой circuit breaker для remote
        if self._mode == "remote" and self._cb_failures >= self.cfg.cb_failure_threshold:
            if (time.time() - self._cb_opened_at) < self.cfg.cb_cooldown_sec:
                return "fallback"
            # полузакрытое состояние
        return self._mode

    # ------------------------ local implementation ------------------------

    def _analyze_local(self, text: str, langs: Tuple[str, ...]) -> List[Finding]:
        assert self._analyzer is not None
        results: List[Finding] = []
        for lang in langs:
            try:
                pres = self._analyzer.analyze(text=text, language=lang)
            except Exception as e:
                self.log.debug("Analyzer error lang=%s: %s", lang, e)
                continue
            for rr in pres:
                results.append(self._from_presidio_result(text, rr))
        return self._dedupe(results)

    def _anonymize_local(self, text: str, findings: Sequence[Finding]) -> str:
        assert self._anonymizer is not None
        # Переводим Findings в формат Presidio operators
        ops = self._build_operator_config()
        # Presidio Anonymizer ожидает список {start, end, entity_type}
        items = [
            {
                "start": f.start,
                "end": f.end,
                "entity_type": f.extra.get("entity_type", f.detector),
            }
            for f in findings
        ]
        # Формируем конфиг операторов
        return self._anonymizer.anonymize(text=text, analyzer_results=items, operators=ops).text  # type: ignore

    # ------------------------ remote implementation ------------------------

    def _analyze_remote(self, text: str, langs: Tuple[str, ...]) -> List[Finding]:
        api = self.cfg.remote
        if not api.analyze_url:
            self._record_failure()
            self.log.error("Remote analyze_url is not configured")
            return self._analyze_fallback(text)

        payload = {
            "text": text,
            "languages": list(langs),
            # Поля могут отличаться в конкретной реализации API — поэтому структура конфигурируема на стороне сервиса.
            # Мы не делаем жёстких предположений.
        }
        headers = dict(api.headers)
        if api.api_key:
            headers["Authorization"] = f"Bearer {api.api_key}"

        try:
            data = _http_post_json(
                url=api.analyze_url,
                json_body=payload,
                headers=headers,
                timeout=api.timeout_sec,
                connect_timeout=api.connect_timeout_sec,
                retries=api.retries,
                backoff=api.backoff_sec,
            )
        except Exception as e:
            self._record_failure()
            self.log.warning("Remote analyze request failed: %s", e)
            return self._analyze_fallback(text)

        self._reset_cb()

        # Ожидаем формат: [{"entity_type": "...", "start": 0, "end": 10, "score": 0.85}, ...]
        findings: List[Finding] = []
        if isinstance(data, list):
            for item in data:
                try:
                    et = str(item.get("entity_type"))
                    st = int(item.get("start"))
                    en = int(item.get("end"))
                    sc = float(item.get("score", 0.0))
                except Exception:
                    continue
                raw = text[st:en]
                findings.append(
                    Finding(
                        detector="presidio-remote",
                        category=_PRESIDIO_TO_CATEGORY.get(et, "OTHER"),
                        severity=_severity(sc),
                        start=st,
                        end=en,
                        match=raw,
                        redacted=self._preview_redaction(raw, et),
                        context=_context(text, st, en),
                        extra={"entity_type": et, "score": f"{sc:.3f}"},
                    )
                )
        else:
            self.log.debug("Unexpected remote response format")

        return self._dedupe(findings)

    def _anonymize_remote(self, text: str, findings: Sequence[Finding]) -> Optional[str]:
        api = self.cfg.remote
        if not api.anonymize_url or not api.analyze_url:
            return None

        headers = dict(api.headers)
        if api.api_key:
            headers["Authorization"] = f"Bearer {api.api_key}"

        body = {
            "text": text,
            "items": [
                {
                    "entity_type": f.extra.get("entity_type", f.detector),
                    "start": f.start,
                    "end": f.end,
                }
                for f in findings
            ],
            "operators": self._build_operator_config(),
        }

        try:
            data = _http_post_json(
                url=api.anonymize_url,
                json_body=body,
                headers=headers,
                timeout=api.timeout_sec,
                connect_timeout=api.connect_timeout_sec,
                retries=api.retries,
                backoff=api.backoff_sec,
            )
        except Exception as e:
            self._record_failure()
            self.log.warning("Remote anonymize request failed: %s", e)
            return None

        self._reset_cb()
        # Ожидаем формат {"text": "..."} или просто строку
        if isinstance(data, dict) and "text" in data:
            return str(data["text"])
        if isinstance(data, str):
            return data
        return None

    # ------------------------ fallback implementation ------------------------

    def _analyze_fallback(self, text: str) -> List[Finding]:
        cfg = ScanConfig(detectors=build_default_detectors())
        loc = scan_text(text, cfg)
        res: List[Finding] = []
        for f in loc:
            res.append(
                Finding(
                    detector=f.detector,
                    category=f.category,
                    severity=f.severity,  # type: ignore
                    start=f.start,
                    end=f.end,
                    match=f.match,
                    redacted=f.redacted,
                    context=f.context,
                    extra={"entity_type": f.detector, "score": "0.80"},
                )
            )
        return self._dedupe(res)

    def _anonymize_fallback(self, text: str, findings: Sequence[Finding]) -> str:
        # Непересекающееся применении замен слева-направо
        if not findings:
            return text
        buf = []
        last = 0
        for f in sorted(findings, key=lambda x: x.start):
            if f.start < last:  # перекрытие — пропустим
                continue
            buf.append(text[last:f.start])
            et = f.extra.get("entity_type", f.detector)
            buf.append(self._apply_operator(self.cfg.anonymize_policy.operators, et, f.match))
            last = f.end
        buf.append(text[last:])
        return "".join(buf)

    # ------------------------ helpers ------------------------

    def _from_presidio_result(self, text: str, rr: Any) -> Finding:
        et = getattr(rr, "entity_type", "UNKNOWN")
        st = int(getattr(rr, "start", 0))
        en = int(getattr(rr, "end", 0))
        sc = float(getattr(rr, "score", 0.0))
        raw = text[st:en]
        return Finding(
            detector="presidio-local",
            category=_PRESIDIO_TO_CATEGORY.get(et, "OTHER"),
            severity=_severity(sc),
            start=st,
            end=en,
            match=raw,
            redacted=self._preview_redaction(raw, et),
            context=_context(text, st, en),
            extra={"entity_type": et, "score": f"{sc:.3f}"},
        )

    def _entity_allowed(self, entity_type: Optional[str]) -> bool:
        if not entity_type:
            return False
        if self.cfg.entities_allow and entity_type not in self.cfg.entities_allow:
            return False
        if self.cfg.entities_deny and entity_type in self.cfg.entities_deny:
            return False
        return True

    def _build_operator_config(self) -> Dict[str, Dict[str, Any]]:
        # Возвращаем копию, чтобы не мутировать исходный конфиг
        return json.loads(json.dumps(self.cfg.anonymize_policy.operators))

    def _apply_operator(self, ops: Dict[str, Dict[str, Any]], entity_type: str, value: str) -> str:
        op = ops.get(entity_type) or ops.get("*") or {"type": "redact"}
        kind = op.get("type")
        if kind == "mask":
            # параметры: chars_to_mask, from_end, masking_char
            n = int(op.get("chars_to_mask", 6))
            from_end = bool(op.get("from_end", True))
            ch = str(op.get("masking_char", "*"))[:1]
            if n <= 0:
                return value
            if from_end:
                return value[:-n] + ch * min(n, len(value))
            return ch * min(n, len(value)) + value[n:]
        if kind == "replace":
            return str(op.get("new_value", "<redacted/>"))
        if kind == "hash":
            algo = str(op.get("hash_type", "sha256")).lower()
            prefix = str(op.get("prefix", "h:"))
            try:
                h = hashlib.new(algo)
            except Exception:
                h = hashlib.sha256()
            h.update(value.strip().lower().encode("utf-8"))
            return f"{prefix}{h.hexdigest()}"
        # redact (по умолчанию)
        return "<redacted/>"

    def _dedupe(self, items: Sequence[Finding]) -> List[Finding]:
        # Дедуп по координатам и типу
        seen = set()
        out: List[Finding] = []
        for f in items:
            key = (f.start, f.end, f.extra.get("entity_type", f.detector))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    def _preview_redaction(self, raw: str, entity_type: str) -> str:
        try:
            return self._apply_operator(self.cfg.anonymize_policy.operators, entity_type, raw)
        except Exception:
            return "<redacted/>"

    def _record_failure(self) -> None:
        self._cb_failures += 1
        if self._cb_failures >= self.cfg.cb_failure_threshold:
            self._cb_opened_at = time.time()

    def _reset_cb(self) -> None:
        self._cb_failures = 0
        self._cb_opened_at = 0.0


# --------------------------------------------------------------------------------------
# Вспомогательные HTTP-функции (с httpx или stdlib)
# --------------------------------------------------------------------------------------

def _http_post_json(
    url: str,
    json_body: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 5.0,
    connect_timeout: float = 2.0,
    retries: int = 1,
    backoff: float = 0.2,
) -> Any:
    if _HTTPX:
        t = httpx.Timeout(timeout, connect=connect_timeout)
        attempt = 0
        while True:
            try:
                with httpx.Client(timeout=t) as client:
                    resp = client.post(url, json=json_body, headers=headers or {})
                    resp.raise_for_status()
                    return resp.json()
            except Exception:
                attempt += 1
                if attempt > max(0, retries):
                    raise
                time.sleep(backoff * attempt)
    else:
        import urllib.request
        import urllib.error
        import socket
        payload = json.dumps(json_body).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json", **(headers or {})}, method="POST")
        attempt = 0
        while True:
            try:
                with urllib.request.urlopen(req, timeout=timeout) as f:
                    data = f.read().decode("utf-8")
                    try:
                        return json.loads(data)
                    except Exception:
                        return data
            except (urllib.error.URLError, socket.timeout):
                attempt += 1
                if attempt > max(0, retries):
                    raise
                time.sleep(backoff * attempt)


def _context(text: str, start: int, end: int, radius: int = 30) -> str:
    a = max(0, start - radius)
    b = min(len(text), end + radius)
    return text[a:b].replace("\n", " ")


# --------------------------------------------------------------------------------------
# CLI утилита (одиночные файлы/STDIN)
# --------------------------------------------------------------------------------------

def _load_text(path: Optional[str]) -> str:
    if not path or path == "-":
        import sys
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(description="veilmind-core Presidio adapter")
    p.add_argument("--mode", default="auto", choices=["auto","local","remote","fallback"])
    p.add_argument("--analyze-url", default=os.getenv("PRESIDIO_ANALYZE_URL"))
    p.add_argument("--anonymize-url", default=os.getenv("PRESIDIO_ANONYMIZE_URL"))
    p.add_argument("--api-key", default=os.getenv("PRESIDIO_API_KEY"))
    p.add_argument("--langs", default="en,ru")
    p.add_argument("--score", type=float, default=0.5)
    p.add_argument("--file", default="-", help="Файл для анализа (или - для STDIN)")
    p.add_argument("--anonymize", action="store_true")
    args = p.parse_args(argv)

    cfg = PresidioConfig(
        mode=args.mode, score_threshold=args.score,
        languages=tuple(x.strip() for x in args.langs.split(",") if x.strip()),
        remote=RemoteAPI(analyze_url=args.analyze_url, anonymize_url=args.anonymize_url, api_key=args.api_key),
    )
    adapter = PresidioAdapter(cfg)

    text = _load_text(args.file)
    fins = adapter.analyze(text)
    print(json.dumps([dataclasses.asdict(f) for f in fins], ensure_ascii=False, indent=2))
    if args.anonymize:
        print("\n---- ANONYMIZED ----\n")
        print(adapter.anonymize(text, fins))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
