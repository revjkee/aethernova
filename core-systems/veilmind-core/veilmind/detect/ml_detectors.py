# veilmind-core/veilmind/detect/ml_detectors.py
from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import itertools
import json
import logging
import math
import os
import random
import re
import string
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from statistics import mean
from typing import Any, AsyncIterator, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

# ====== optional deps: numpy / onnxruntime / prometheus_client (safe fallback) ======
try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover
    np = None  # type: ignore

try:
    import onnxruntime as ort  # type: ignore
except Exception:  # pragma: no cover
    ort = None  # type: ignore

try:
    from prometheus_client import Counter, Histogram, Gauge, REGISTRY  # type: ignore
    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False

    class _NoopMetric:
        def labels(self, *_, **__):  # type: ignore
            return self
        def inc(self, *_: Any, **__: Any) -> None:  # type: ignore
            pass
        def dec(self, *_: Any, **__: Any) -> None:  # type: ignore
            pass
        def observe(self, *_: Any, **__: Any) -> None:  # type: ignore
            pass

    class Counter(_NoopMetric):  # type: ignore
        def __init__(self, *_, **__): pass
    class Histogram(_NoopMetric):  # type: ignore
        def __init__(self, *_, **__): pass
    class Gauge(_NoopMetric):  # type: ignore
        def __init__(self, *_, **__): pass
    REGISTRY = None  # type: ignore

# ====== logging ======
logger = logging.getLogger("veilmind.detect")
DEBUG = os.getenv("VMC_DEBUG", "").lower() in ("1", "true", "yes")

# ====== metrics ======
_LAT_BUCKETS = (0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2)
_SZ_BUCKETS = (16, 64, 256, 1024, 4096, 16384, 65536)

_DET_NS = "veilmind_detectors"
m_calls = Counter(f"{_DET_NS}_calls_total", "Detector calls", ["detector", "tenant_id"], registry=REGISTRY)
m_items = Counter(f"{_DET_NS}_items_total", "Items processed", ["detector", "tenant_id"], registry=REGISTRY)
m_hits = Counter(f"{_DET_NS}_hits_total", "Detections produced", ["detector", "tenant_id", "label"], registry=REGISTRY)
m_latency = Histogram(f"{_DET_NS}_latency_seconds", "Per-call latency", ["detector", "tenant_id"], buckets=_LAT_BUCKETS, registry=REGISTRY)
m_size = Histogram(f"{_DET_NS}_input_size_bytes", "Input size (bytes)", ["detector", "tenant_id"], buckets=_SZ_BUCKETS, registry=REGISTRY)
m_errors = Counter(f"{_DET_NS}_errors_total", "Unhandled errors", ["detector", "tenant_id"], registry=REGISTRY)
g_inflight = Gauge(f"{_DET_NS}_inflight", "In-flight calls", ["detector", "tenant_id"], registry=REGISTRY)

# ====== core structures ======
@dataclass(frozen=True)
class Span:
    start: int
    end: int

@dataclass
class Detection:
    detector: str
    label: str
    score: float
    span: Optional[Span] = None
    context: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tenant_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector": self.detector,
            "label": self.label,
            "score": float(self.score),
            "span": {"start": self.span.start, "end": self.span.end} if self.span else None,
            "context": self.context,
            "metadata": self.metadata,
            "tenant_id": self.tenant_id,
        }

class DetectorError(RuntimeError):
    pass

class BaseDetector:
    """
    Базовый протокол детектора.
    """
    name: str = "base"
    version: str = "1.0"
    default_threshold: float = 0.5

    def __init__(self, *, threshold: Optional[float] = None, tenant_id: Optional[str] = None) -> None:
        self.threshold = self.default_threshold if threshold is None else float(threshold)
        self.tenant_id = tenant_id

    def detect(self, text: str, *, attrs: Optional[Mapping[str, Any]] = None) -> List[Detection]:
        raise NotImplementedError

    async def detect_async(self, text: str, *, attrs: Optional[Mapping[str, Any]] = None) -> List[Detection]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.detect, text)

    def detect_batch(self, items: Sequence[str], *, attrs: Optional[Sequence[Optional[Mapping[str, Any]]]] = None) -> List[List[Detection]]:
        # По умолчанию — последовательная обработка. Детекторы могут переопределить.
        out: List[List[Detection]] = []
        for i, x in enumerate(items):
            out.append(self.detect(x, attrs=attrs[i] if attrs and i < len(attrs) else None))
        return out

    async def detect_batch_async(self, items: Sequence[str], *, attrs: Optional[Sequence[Optional[Mapping[str, Any]]]] = None) -> List[List[Detection]]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.detect_batch, items, attrs)

# ====== utilities ======
def _now() -> float:
    return time.perf_counter()

def _with_metrics(fn):
    @functools.wraps(fn)
    def wrapper(self: BaseDetector, *args, **kwargs):
        tenant = (self.tenant_id or "na")[:64]
        det = getattr(self, "name", self.__class__.__name__)[:64]
        start = _now()
        g_inflight.labels(detector=det, tenant_id=tenant).inc()
        m_calls.labels(detector=det, tenant_id=tenant).inc()
        try:
            # try to measure size if first arg resembles text or list of text
            if args:
                first = args[0]
                if isinstance(first, str):
                    m_size.labels(detector=det, tenant_id=tenant).observe(len(first.encode("utf-8", "ignore")))
                elif isinstance(first, (list, tuple)) and first and isinstance(first[0], str):
                    m_items.labels(detector=det, tenant_id=tenant).inc(len(first))
                    m_size.labels(detector=det, tenant_id=tenant).observe(sum(len(s.encode("utf-8", "ignore")) for s in first))
            res = fn(self, *args, **kwargs)
            # count hits
            def _count(dets: List[Detection]) -> None:
                for d in dets:
                    m_hits.labels(detector=det, tenant_id=tenant, label=(d.label[:64] if d.label else "na")).inc()
            if isinstance(res, list) and res and isinstance(res[0], list):
                for dets in res:
                    _count(dets)
            elif isinstance(res, list):
                _count(res)
            return res
        except Exception as e:  # pragma: no cover
            m_errors.labels(detector=det, tenant_id=tenant).inc()
            if DEBUG:
                logger.exception("Detector error: %s", det)
            else:
                logger.error("Detector error: %s: %s", det, type(e).__name__)
            raise
        finally:
            m_latency.labels(detector=det, tenant_id=tenant).observe(max(0.0, _now() - start))
            g_inflight.labels(detector=det, tenant_id=tenant).dec()
    return wrapper

def _clip01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))

def _entropy_bits(s: str) -> float:
    if not s:
        return 0.0
    # Шеннон на символах
    freqs: Dict[str, int] = {}
    for ch in s:
        freqs[ch] = freqs.get(ch, 0) + 1
    probs = [c / len(s) for c in freqs.values()]
    return -sum(p * math.log2(p) for p in probs)

def _luhn_ok(number: str) -> bool:
    try:
        digits = [int(ch) for ch in re.sub(r"\D", "", number)]
        checksum = 0
        oddeven = len(digits) & 1
        for i, d in enumerate(digits):
            if not ((i & 1) ^ oddeven):
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return (checksum % 10) == 0
    except Exception:
        return False

def _context_window(text: str, span: Span, *, size: int = 16) -> str:
    left = max(0, span.start - size)
    right = min(len(text), span.end + size)
    return text[left:right]

# ====== LRU cache for heavy detectors ======
class _LRU:
    def __init__(self, max_items: int = 1024) -> None:
        self.max_items = max_items
        self._data: OrderedDict[str, Any] = OrderedDict()

    def get(self, key: str) -> Optional[Any]:
        v = self._data.get(key)
        if v is not None:
            self._data.move_to_end(key)
        return v

    def put(self, key: str, value: Any) -> None:
        self._data[key] = value
        self._data.move_to_end(key)
        if len(self._data) > self.max_items:
            self._data.popitem(last=False)

# ====== Concrete detectors ======

class RegexPIIDetector(BaseDetector):
    """
    Детектор PII/перс.данных на основе регулярных выражений + Luhn.
    Лейблы: email, phone, ipv4, ipv6, credit_card, passport_generic, iban.
    """
    name = "pii_regex"
    default_threshold = 0.5  # применяется к эвристическому скору

    # Компилируем паттерны один раз
    _RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
    _RE_PHONE = re.compile(r"(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d{3}[\s-]?\d{2,4}[\s-]?\d{2,4}")
    _RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _RE_IPV6 = re.compile(r"\b(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}\b")
    _RE_CCARD = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
    _RE_IBAN  = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
    # Паспорт: общий шаблон (осознанно общий)
    _RE_PASSPORT = re.compile(r"\b[A-Z0-9]{5,15}\b")

    @_with_metrics
    def detect(self, text: str, *, attrs: Optional[Mapping[str, Any]] = None) -> List[Detection]:
        if not text:
            return []
        out: List[Detection] = []
        # email
        for m in self._RE_EMAIL.finditer(text):
            span = Span(m.start(), m.end())
            score = 0.95
            out.append(Detection(self.name, "email", score, span, _context_window(text, span), {"value": m.group(0)}, self.tenant_id))
        # phone
        for m in self._RE_PHONE.finditer(text):
            ph = re.sub(r"\D", "", m.group(0))
            if len(ph) < 7:
                continue
            span = Span(m.start(), m.end())
            score = _clip01(0.6 + 0.02 * min(len(ph), 12))
            out.append(Detection(self.name, "phone", score, span, _context_window(text, span), {"digits": len(ph)}, self.tenant_id))
        # IPv4
        for m in self._RE_IPV4.finditer(text):
            parts = list(map(int, m.group(0).split(".")))
            if any(p > 255 for p in parts):
                continue
            span = Span(m.start(), m.end())
            out.append(Detection(self.name, "ipv4", 0.9, span, _context_window(text, span), {}, self.tenant_id))
        # IPv6
        for m in self._RE_IPV6.finditer(text):
            span = Span(m.start(), m.end())
            out.append(Detection(self.name, "ipv6", 0.9, span, _context_window(text, span), {}, self.tenant_id))
        # Credit card
        for m in self._RE_CCARD.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                span = Span(m.start(), m.end())
                out.append(Detection(self.name, "credit_card", 0.98, span, _context_window(text, span), {"digits": len(digits)}, self.tenant_id))
        # IBAN
        for m in self._RE_IBAN.finditer(text):
            span = Span(m.start(), m.end())
            out.append(Detection(self.name, "iban", 0.9, span, _context_window(text, span), {}, self.tenant_id))
        # Passport generic (низкая уверенность, фильтруется порогом)
        for m in self._RE_PASSPORT.finditer(text):
            val = m.group(0)
            if val.isdigit():
                continue
            span = Span(m.start(), m.end())
            out.append(Detection(self.name, "passport_generic", 0.55, span, _context_window(text, span), {}, self.tenant_id))
        # Порог
        return [d for d in out if d.score >= self.threshold]

class SecretLeakDetector(BaseDetector):
    """
    Детектор секретов/токенов: AWS, JWT, generic high-entropy, base64-ключи.
    Лейблы: aws_access_key, aws_secret_key, jwt, generic_secret.
    """
    name = "secrets"
    default_threshold = 0.6

    _RE_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
    _RE_AWS_SECRET_KEY = re.compile(r"(?i)\b(?:aws_)?secret(?:_access)?_key\s*[:=]\s*([A-Za-z0-9/+=]{35,45})")
    _RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")
    _RE_GENERIC = re.compile(r"(?i)\b(?:token|api[_-]?key|secret|password)\b[:= ]{0,3}([A-Za-z0-9/\+_\-=]{12,})")

    @_with_metrics
    def detect(self, text: str, *, attrs: Optional[Mapping[str, Any]] = None) -> List[Detection]:
        if not text:
            return []
        out: List[Detection] = []
        # AWS Access Key
        for m in self._RE_AWS_ACCESS_KEY.finditer(text):
            span = Span(m.start(), m.end())
            out.append(Detection(self.name, "aws_access_key", 0.95, span, _context_window(text, span), {}, self.tenant_id))
        # AWS Secret
        for m in self._RE_AWS_SECRET_KEY.finditer(text):
            secret = m.group(1)
            score = _clip01(0.7 + 0.03 * min(len(secret), 20) + 0.02 * (_entropy_bits(secret) / 5.0))
            span = Span(m.start(1), m.end(1))
            out.append(Detection(self.name, "aws_secret_key", score, span, _context_window(text, span), {}, self.tenant_id))
        # JWT
        for m in self._RE_JWT.finditer(text):
            span = Span(m.start(), m.end())
            out.append(Detection(self.name, "jwt", 0.9, span, _context_window(text, span), {}, self.tenant_id))
        # Generic secrets
        for m in self._RE_GENERIC.finditer(text):
            val = m.group(1)
            ent = _entropy_bits(val)
            score = _clip01(0.5 + 0.03 * min(len(val), 30) + 0.02 * (ent / 5.0))
            span = Span(m.start(1), m.end(1))
            out.append(Detection(self.name, "generic_secret", score, span, _context_window(text, span), {"entropy": ent}, self.tenant_id))
        return [d for d in out if d.score >= self.threshold]

class ToxicityDetector(BaseDetector):
    """
    Детектор токсичности/бранной лексики (упрощённый эвристический, пороговый).
    При наличии ONNX-классификатора (binary) использует его, иначе — словарь/эвристики.
    Лейбл: toxicity.
    """
    name = "toxicity"
    default_threshold = 0.7

    def __init__(self, *, threshold: Optional[float] = None, tenant_id: Optional[str] = None,
                 onnx_path: Optional[str] = None, label_index: int = 1) -> None:
        super().__init__(threshold=threshold, tenant_id=tenant_id)
        self.onnx_path = onnx_path
        self.label_index = label_index
        self._sess = None
        if onnx_path and ort is not None:
            try:
                self._sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])  # type: ignore
            except Exception:  # pragma: no cover
                logger.warning("ONNX session failed, falling back to heuristics")

        # примитивные эвристики
        self._bad_words = {
            "idiot", "stupid", "moron", "hate", "kill", "trash",
            "дурак", "тупой", "ненавижу", "убью"
        }

    def _heuristic_score(self, text: str) -> float:
        if not text:
            return 0.0
        tokens = re.findall(r"\w+", text.lower(), flags=re.UNICODE)
        if not tokens:
            return 0.0
        bad = sum(1 for t in tokens if t in self._bad_words)
        exclam = text.count("!") + text.count("?")
        caps = sum(1 for ch in text if ch.isupper())
        base = bad / max(1, len(tokens))
        extra = 0.1 * min(5, exclam) + 0.05 * min(20, caps)
        return _clip01(base + extra)

    def _onnx_score(self, text: str) -> Optional[float]:
        if not self._sess or np is None:
            return None
        # очень простой токенайзер: отсечка/хеш‑мешок символов (замена реального токенайзера)
        # цель — безопасный фолбэк без внешних зависимостей
        vec = np.zeros((1, 256), dtype=np.float32)  # type: ignore
        for ch in text[:1024]:
            vec[0, ord(ch) % 256] += 1.0
        vec = vec / (np.linalg.norm(vec) + 1e-6)
        try:
            outputs = self._sess.run(None, {"input": vec})  # type: ignore
            logits = outputs[0].reshape(-1)  # type: ignore
            # softmax
            exps = np.exp(logits - np.max(logits))
            probs = exps / (np.sum(exps) + 1e-6)
            return float(probs[self.label_index] if 0 <= self.label_index < len(probs) else probs[-1])
        except Exception:  # pragma: no cover
            return None

    @_with_metrics
    def detect(self, text: str, *, attrs: Optional[Mapping[str, Any]] = None) -> List[Detection]:
        if not text:
            return []
        score = self._onnx_score(text)
        if score is None:
            score = self._heuristic_score(text)
        if score >= self.threshold:
            return [Detection(self.name, "toxicity", score, None, None, {}, self.tenant_id)]
        return []

class OnnxAnomalyDetector(BaseDetector):
    """
    Детектор аномалий на основе реконструкции автоэнкодера (ONNX).
    Вход — строка; простая числовая проекция (hash‑скетч) -> модель; score = normalized recon error.
    """
    name = "anomaly_ae"
    default_threshold = 0.8

    def __init__(self, *, threshold: Optional[float] = None, tenant_id: Optional[str] = None,
                 onnx_path: Optional[str] = None) -> None:
        super().__init__(threshold=threshold, tenant_id=tenant_id)
        self.onnx_path = onnx_path
        self._sess = None
        if onnx_path and ort is not None:
            try:
                self._sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])  # type: ignore
            except Exception:  # pragma: no cover
                logger.warning("ONNX session failed, anomaly detector is heuristic")

    def _embed(self, text: str) -> Optional["np.ndarray"]:
        if np is None:
            return None
        v = np.zeros((1, 256), dtype=np.float32)  # type: ignore
        for ch in text[:2048]:
            v[0, (ord(ch) * 131) % 256] += 1.0
        v = v / (np.linalg.norm(v) + 1e-6)
        return v

    def _heuristic(self, text: str) -> float:
        # простая эвристика: «аномально длинная» или «много необычных символов»
        if not text:
            return 0.0
        rare = sum(1 for ch in text if ch not in (string.ascii_letters + string.digits + " _-.,:;!?@/\\"))
        ratio = rare / max(1, len(text))
        ln = len(text)
        base = 0.2 * min(5, ln / 2000) + 0.8 * min(1.0, ratio * 5)
        return _clip01(base)

    @_with_metrics
    def detect(self, text: str, *, attrs: Optional[Mapping[str, Any]] = None) -> List[Detection]:
        if not text:
            return []
        if self._sess is None or np is None:
            score = self._heuristic(text)
        else:
            emb = self._embed(text)
            if emb is None:
                score = self._heuristic(text)
            else:
                try:
                    recon = self._sess.run(None, {"input": emb})[0]  # type: ignore
                    err = float(np.linalg.norm(emb - recon) / (np.linalg.norm(emb) + 1e-6))
                    # нормируем в 0..1 через тангенту
                    score = _clip01(math.tanh(err))
                except Exception:  # pragma: no cover
                    score = self._heuristic(text)
        if score >= self.threshold:
            return [Detection(self.name, "anomaly", score, None, None, {}, self.tenant_id)]
        return []

# ====== Composite pipeline ======
class CompositeDetector(BaseDetector):
    """
    Композитный детектор, объединяющий несколько.
    Поддерживает батчи и параллелизм потоков.
    """
    name = "composite"
    default_threshold = 0.0  # не используется

    def __init__(self, detectors: Sequence[BaseDetector], *, max_workers: int = 4, tenant_id: Optional[str] = None) -> None:
        super().__init__(tenant_id=tenant_id)
        self.detectors = list(detectors)
        self.pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="vm-det")

    @_with_metrics
    def detect(self, text: str, *, attrs: Optional[Mapping[str, Any]] = None) -> List[Detection]:
        if not text:
            return []
        futures = []
        for d in self.detectors:
            futures.append(self.pool.submit(d.detect, text, attrs=attrs))
        out: List[Detection] = []
        for f in futures:
            try:
                out.extend(f.result())
            except Exception as e:  # pragma: no cover
                logger.error("Subdetector error (%s): %s", type(e).__name__, e)
        return out

    @_with_metrics
    def detect_batch(self, items: Sequence[str], *, attrs: Optional[Sequence[Optional[Mapping[str, Any]]]] = None) -> List[List[Detection]]:
        if not items:
            return []
        # стратегия: параллелим по детекторам, внутри они уже могут батчить
        results: List[List[Detection]] = [[] for _ in range(len(items))]
        for d in self.detectors:
            part = d.detect_batch(items, attrs=attrs)
            for i, dets in enumerate(part):
                results[i].extend(dets)
        return results

# ====== Builder / defaults ======
def build_default_pipeline(
    *,
    tenant_id: Optional[str] = None,
    enable_toxicity: bool = True,
    enable_anomaly: bool = True,
    toxicity_onnx: Optional[str] = None,
    anomaly_onnx: Optional[str] = None,
    threads: int = 4,
) -> CompositeDetector:
    dets: List[BaseDetector] = [
        RegexPIIDetector(tenant_id=tenant_id, threshold=0.5),
        SecretLeakDetector(tenant_id=tenant_id, threshold=0.65),
    ]
    if enable_toxicity:
        dets.append(ToxicityDetector(tenant_id=tenant_id, threshold=0.75, onnx_path=toxicity_onnx))
    if enable_anomaly:
        dets.append(OnnxAnomalyDetector(tenant_id=tenant_id, threshold=0.8, onnx_path=anomaly_onnx))
    return CompositeDetector(dets, max_workers=threads, tenant_id=tenant_id)

# ====== simple CLI (optional for local runs) ======
if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO if not DEBUG else logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description="VeilMind detectors CLI")
    ap.add_argument("--tox", help="toxicity onnx model path", default=None)
    ap.add_argument("--ae", help="anomaly autoencoder onnx model path", default=None)
    ap.add_argument("--tenant", help="tenant id", default="local")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("text", nargs="+", help="text to scan")
    args = ap.parse_args()

    pipe = build_default_pipeline(
        tenant_id=args.tenant,
        toxicity_onnx=args.tox,
        anomaly_onnx=args.ae,
        threads=args.threads,
    )
    res = pipe.detect_batch(args.text)
    if args.json:
        print(json.dumps([[d.to_dict() for d in ds] for ds in res], ensure_ascii=False, indent=2))
    else:
        for i, ds in enumerate(res):
            print(f"--- item {i} ---")
            for d in ds:
                print(d.to_dict())
