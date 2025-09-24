# -*- coding: utf-8 -*-
"""
policy_core.audit.trail
Промышленный асинхронный аудит-трейл с батчингом, ротацией и тампер-очевидной цепочкой.

Особенности:
- Асинхронная очередь (asyncio.Queue) + бэкграунд-воркер
- Батчинг по размеру и интервалу, backpressure (maxsize)
- Семплинг событий (probabilistic), счётчики дропа
- Редакция секретов/PII, лимиты размеров полей
- Тампер-очевидная хеш-цепочка (prev_hash + hash), опционально HMAC(secret)
- Синкы: Console, JSONL с ротацией по размеру/дате, HTTP (NDJSON)
- Резервный аварийный JSONL при сбое всех синков
- Интеграция с ABACInput и EvaluationResult

Зависимости:
- pydantic>=1
- httpx (для HTTP sink; опционально)

Автор: policy-core
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import functools
import hashlib
import hmac
import io
import json
import logging
import os
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

try:
    from pydantic import BaseModel, Field, validator
except Exception as e:  # pragma: no cover
    raise ImportError("pydantic>=1 is required for policy_core.audit.trail") from e

try:
    import httpx  # optional for HttpSink
    _HTTPX_OK = True
except Exception:
    _HTTPX_OK = False

# Для типизации без хард-зависимости во время импорта
from typing import TYPE_CHECKING
if TYPE_CHECKING:  # pragma: no cover
    from policy_core.models.attributes import ABACInput
    from policy_core.pdp.evaluator_rego import EvaluationResult


# ---------------------------------------------------------------------------
# Константы и утилиты
# ---------------------------------------------------------------------------

SENSITIVE_KEYS = {
    "authorization", "token", "access_token", "id_token", "refresh_token",
    "password", "secret", "api_key", "x-api-key", "x-auth-token", "cookie"
}

MAX_LABELS = 2048
MAX_STR = 10_000
MAX_LIST = 1024

def _now_ms() -> int:
    return int(time.time() * 1000)

def _ts_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _stable_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def _limit_str(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    return s if len(s) <= MAX_STR else s[:MAX_STR]

def _limit_labels(labels: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not labels:
        return {}
    out: Dict[str, Any] = {}
    for i, (k, v) in enumerate(labels.items()):
        if i >= MAX_LABELS:
            break
        key = str(k)[:128]
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[key] = v if not isinstance(v, str) else _limit_str(v)
        else:
            out[key] = _limit_str(_stable_dumps(v))
    return out

def _mask_secrets(data: Any) -> Any:
    if isinstance(data, dict):
        res = {}
        for k, v in data.items():
            if k.lower() in SENSITIVE_KEYS:
                res[k] = "***"
            else:
                res[k] = _mask_secrets(v)
        return res
    if isinstance(data, list):
        return [_mask_secrets(v) for v in data[:MAX_LIST]]
    if isinstance(data, str):
        return _limit_str(data)
    return data

def _hsha256(payload: str, secret: Optional[bytes] = None) -> str:
    if secret:
        return hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    h = hashlib.sha256()
    h.update(payload.encode("utf-8"))
    return h.hexdigest()

_HOSTNAME = socket.gethostname()


# ---------------------------------------------------------------------------
# Конфигурация и перечисления
# ---------------------------------------------------------------------------

class DecisionEffect(str, Enum):
    Permit = "permit"
    Deny = "deny"
    Indeterminate = "indeterminate"
    NotApplicable = "not_applicable"

@dataclass(frozen=True)
class AuditConfig:
    # Очередь/батч
    queue_maxsize: int = 10000
    batch_size: int = 200
    flush_interval_ms: int = 1500

    # Семплинг (0.0..1.0). 1.0 = писать все
    sampling_rate: float = 1.0

    # Редакция и лимиты
    redact: bool = True

    # Тампер-цепочка
    enable_chain: bool = True
    hmac_secret: Optional[bytes] = None  # b"..." для HMAC; None -> просто SHA-256

    # Синкы
    console_enabled: bool = True

    jsonl_path: Optional[str] = "./logs/audit-%Y%m%d.jsonl"
    jsonl_rotate_bytes: int = 128 * 1024 * 1024  # 128 MiB
    jsonl_dir_create: bool = True

    http_endpoint: Optional[str] = None  # POST NDJSON
    http_headers: Optional[Dict[str, str]] = None
    http_timeout_s: float = 3.0

    # Аварийный слив
    emergency_path: str = "./logs/audit_emergency.jsonl"

    # Неймспейс и узел
    namespace: str = "policy-core"


# ---------------------------------------------------------------------------
# Модель события аудита
# ---------------------------------------------------------------------------

class AuditEvent(BaseModel):
    # Обязательные
    ts_ms: int = Field(default_factory=_now_ms, description="Время события ms")
    event_id: str = Field(..., description="Уникальный ID события")
    request_id: Optional[str] = Field(None, description="ID запроса/корреляции")
    namespace: str = Field(..., description="Логический неймспейс")
    node: str = Field(default=_HOSTNAME, description="Имя хоста")

    # Контекст арендатора/субъекта
    tenant_id: Optional[str] = None
    subject_id: Optional[str] = None
    subject_type: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)

    # Ресурс и действие
    action: str
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None

    # Политики и решение
    policy_path: Optional[str] = None
    decision_effect: DecisionEffect
    decision_bool: Optional[bool] = None
    decision_latency_ms: Optional[float] = None
    obligations: Dict[str, Any] = Field(default_factory=dict)
    reason: Optional[str] = None

    # Риски/аутентификация
    risk_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    auth_strength: Optional[int] = Field(None, ge=0, le=10)
    mfa: Optional[bool] = None

    # Окружение
    channel: Optional[str] = None
    env_ip: Optional[str] = None
    env_country: Optional[str] = None
    app_version: Optional[str] = None
    labels: Dict[str, Any] = Field(default_factory=dict)

    # Хеш-цепочка
    prev_hash: Optional[str] = None
    hash: Optional[str] = None
    signer: Optional[str] = None  # algo: sha256 | hmac-sha256

    @validator("labels", pre=True)
    def v_labels(cls, v):
        return _limit_labels(v)

    def canonical_payload(self) -> Dict[str, Any]:
        """Поля, входящие в вычисление hash/подписи (маскировка не применяется)."""
        return {
            "ts_ms": self.ts_ms,
            "event_id": self.event_id,
            "request_id": self.request_id,
            "namespace": self.namespace,
            "node": self.node,
            "tenant_id": self.tenant_id,
            "subject_id": self.subject_id,
            "subject_type": self.subject_type,
            "roles": self.roles,
            "groups": self.groups,
            "scopes": self.scopes,
            "action": self.action,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "policy_path": self.policy_path,
            "decision_effect": self.decision_effect.value,
            "decision_bool": self.decision_bool,
            "decision_latency_ms": self.decision_latency_ms,
            "obligations": self.obligations,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "auth_strength": self.auth_strength,
            "mfa": self.mfa,
            "channel": self.channel,
            "env_ip": self.env_ip,
            "env_country": self.env_country,
            "app_version": self.app_version,
            "labels": self.labels,
            "prev_hash": self.prev_hash,
        }

    def to_jsonl(self, redact: bool) -> str:
        data = self.dict()
        if redact:
            data = _mask_secrets(data)
        return _stable_dumps(data)


# ---------------------------------------------------------------------------
# Синковая абстракция и реализации
# ---------------------------------------------------------------------------

class AsyncAuditSink:
    async def start(self) -> None:
        return None
    async def aclose(self) -> None:
        return None
    async def write_batch(self, lines: Sequence[str]) -> None:
        raise NotImplementedError

class ConsoleSink(AsyncAuditSink):
    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    async def write_batch(self, lines: Sequence[str]) -> None:
        for ln in lines:
            self._logger.info(ln)

class JsonlRotatingSink(AsyncAuditSink):
    """Ротация по дате (%Y%m%d в пути) и по размеру файла."""
    def __init__(self, path_pattern: str, rotate_bytes: int, create_dir: bool = True) -> None:
        self._pattern = path_pattern
        self._rotate_bytes = rotate_bytes
        self._create_dir = create_dir
        self._fh: Optional[io.TextIOBase] = None
        self._current_path: Optional[Path] = None
        self._bytes_written = 0
        self._loop = asyncio.get_event_loop()

    def _target_path(self) -> Path:
        p = datetime.now(timezone.utc).strftime(self._pattern)
        path = Path(p)
        if self._create_dir:
            path.parent.mkdir(parents=True, exist_ok=True)
        return path

    async def start(self) -> None:
        await self._rollover(force=True)

    async def aclose(self) -> None:
        if self._fh:
            await self._run_blocking(self._fh.flush)
            self._fh.close()
            self._fh = None

    async def write_batch(self, lines: Sequence[str]) -> None:
        await self._maybe_rollover()
        if not self._fh:
            await self._rollover(force=True)
        buf = "".join(l + "\n" for l in lines)
        await self._run_blocking(self._fh.write, buf)  # type: ignore
        self._bytes_written += len(buf)

    async def _maybe_rollover(self) -> None:
        target = self._target_path()
        if self._current_path != target or (self._bytes_written >= self._rotate_bytes):
            await self._rollover(force=True)

    async def _rollover(self, force: bool = False) -> None:
        if self._fh:
            await self._run_blocking(self._fh.flush)
            self._fh.close()
            self._fh = None

        path = self._target_path()
        # Доп. суффиксы при достижении лимита размера
        if path.exists() and path.stat().st_size >= self._rotate_bytes:
            idx = 1
            while True:
                candidate = path.with_suffix(path.suffix + f".{idx}")
                if not candidate.exists() or candidate.stat().st_size < self._rotate_bytes:
                    path = candidate
                    break
                idx += 1

        self._fh = open(path, "a", encoding="utf-8", buffering=1)
        self._current_path = path
        self._bytes_written = self._fh.tell()

    async def _run_blocking(self, fn, *args, **kwargs):
        return await self._loop.run_in_executor(None, functools.partial(fn, *args, **kwargs))

class HttpSink(AsyncAuditSink):
    """POST NDJSON батча событий на http_endpoint."""
    def __init__(self, endpoint: str, headers: Optional[Dict[str, str]], timeout_s: float) -> None:
        if not _HTTPX_OK:
            raise RuntimeError("httpx is required for HttpSink")
        self._endpoint = endpoint
        self._headers = headers or {}
        self._timeout = timeout_s
        self._client: Optional[httpx.AsyncClient] = None

    async def start(self) -> None:
        self._client = httpx.AsyncClient(timeout=self._timeout, headers=self._headers)

    async def aclose(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def write_batch(self, lines: Sequence[str]) -> None:
        assert self._client is not None
        ndjson = "".join(l + "\n" for l in lines)
        resp = await self._client.post(self._endpoint, content=ndjson, headers={"Content-Type": "application/x-ndjson"})
        if resp.status_code >= 300:
            raise RuntimeError(f"HttpSink failed: {resp.status_code} {resp.text}")


# ---------------------------------------------------------------------------
# Основной аудитор: очередь, батчинг, семплинг, цепочка
# ---------------------------------------------------------------------------

class AuditTrail:
    def __init__(self, cfg: AuditConfig, logger: Optional[logging.Logger] = None) -> None:
        self._cfg = cfg
        self._logger = logger or logging.getLogger("policy_core.audit.trail")
        self._logger.setLevel(logging.INFO)
        self._queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=cfg.queue_maxsize)
        self._worker_task: Optional[asyncio.Task] = None

        # цепочка целостности
        self._last_hash: Optional[str] = None

        # метрики
        self._metric_in_total = 0
        self._metric_dropped = 0
        self._metric_written = 0
        self._metric_batches = 0
        self._metric_failures = 0

        # синки
        self._sinks: List[AsyncAuditSink] = []
        if cfg.console_enabled:
            self._sinks.append(ConsoleSink(self._logger))
        if cfg.jsonl_path:
            self._sinks.append(JsonlRotatingSink(cfg.jsonl_path, cfg.jsonl_rotate_bytes, cfg.jsonl_dir_create))
        if cfg.http_endpoint:
            self._sinks.append(HttpSink(cfg.http_endpoint, cfg.http_headers, cfg.http_timeout_s))

    # ---------- lifecycle ----------

    async def start(self) -> None:
        for s in self._sinks:
            with contextlib.suppress(Exception):
                await s.start()
        self._worker_task = asyncio.create_task(self._worker(), name="audit-trail-worker")

    async def aclose(self) -> None:
        if self._worker_task:
            self._worker_task.cancel()
            with contextlib.suppress(Exception):
                await self._worker_task
            self._worker_task = None
        for s in self._sinks:
            with contextlib.suppress(Exception):
                await s.aclose()

    # ---------- публичные методы ----------

    async def submit(self, event: AuditEvent) -> None:
        """Отправить событие в очередь с семплингом и цепочкой."""
        if self._cfg.sampling_rate < 1.0:
            # простейший семплинг на основе hash(event_id)
            hv = int(hashlib.sha256(event.event_id.encode("utf-8")).hexdigest(), 16)
            if (hv % 10_000) / 10_000.0 > self._cfg.sampling_rate:
                self._metric_dropped += 1
                return

        # обновление цепочки
        if self._cfg.enable_chain:
            event.prev_hash = self._last_hash
            payload = _stable_dumps(event.canonical_payload())
            digest = _hsha256(payload, self._cfg.hmac_secret)
            event.hash = digest
            event.signer = "hmac-sha256" if self._cfg.hmac_secret else "sha256"
            self._last_hash = digest

        try:
            self._queue.put_nowait(event)
            self._metric_in_total += 1
        except asyncio.QueueFull:
            # стратегия: drop-старые (очередь уже переполнена, вытесним 1)
            with contextlib.suppress(Exception):
                _ = self._queue.get_nowait()
            with contextlib.suppress(Exception):
                self._queue.task_done()
            try:
                self._queue.put_nowait(event)
                self._metric_dropped += 1  # считаем вытеснение как дроп
            except Exception:
                self._metric_dropped += 1

    async def audit_decision(
        self,
        *,
        abac: "ABACInput",
        eval_result: "EvaluationResult",
        decision_effect: DecisionEffect,
        obligations: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
    ) -> None:
        """Формирует AuditEvent из ABACInput + EvaluationResult."""
        inp = abac.to_opa_input()
        principal = inp.get("principal", {})
        resource = inp.get("resource", {})
        action = inp.get("action", {})
        env = inp.get("env", {})

        event = AuditEvent(
            ts_ms=_now_ms(),
            event_id=eval_result.request_id,
            request_id=eval_result.request_id,
            namespace=self._cfg.namespace,
            tenant_id=principal.get("tenant_id"),
            subject_id=principal.get("subject_id"),
            subject_type=principal.get("subject_type"),
            roles=principal.get("roles", []),
            groups=principal.get("groups", []),
            scopes=principal.get("scopes", []),
            action=action.get("action", "unknown"),
            resource_id=resource.get("resource_id"),
            resource_type=resource.get("resource_type"),
            policy_path=eval_result.policy_path,
            decision_effect=decision_effect,
            decision_bool=eval_result.decision,
            decision_latency_ms=eval_result.latency_ms,
            obligations=obligations or {},
            reason=reason,
            risk_score=principal.get("risk_score"),
            auth_strength=principal.get("auth_strength"),
            mfa=principal.get("mfa"),
            channel=env.get("channel"),
            env_ip=env.get("ip"),
            env_country=env.get("country"),
            app_version=env.get("app_version"),
            labels=_limit_labels({"explain": eval_result.explain, **(resource.get("labels") or {})}),
        )

        await self.submit(event)

    def snapshot_metrics(self) -> Dict[str, Union[int, float]]:
        qsize = self._queue.qsize()
        return {
            "in_total": self._metric_in_total,
            "dropped": self._metric_dropped,
            "written": self._metric_written,
            "batches": self._metric_batches,
            "failures": self._metric_failures,
            "queue_size": qsize,
            "batch_size": self._cfg.batch_size,
        }

    # ---------- приватные методы ----------

    async def _worker(self) -> None:
        buf: List[AuditEvent] = []
        last_flush = time.monotonic()
        interval_s = self._cfg.flush_interval_ms / 1000.0

        try:
            while True:
                timeout = max(0.0, interval_s - (time.monotonic() - last_flush))
                try:
                    evt = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                    buf.append(evt)
                    self._queue.task_done()
                except asyncio.TimeoutError:
                    pass

                if len(buf) >= self._cfg.batch_size or (time.monotonic() - last_flush) >= interval_s:
                    if buf:
                        await self._flush(buf)
                        buf = []
                        last_flush = time.monotonic()
        except asyncio.CancelledError:  # мягкая остановка
            if buf:
                with contextlib.suppress(Exception):
                    await self._flush(buf)
            raise

    async def _flush(self, events: List[AuditEvent]) -> None:
        # сериализуем заранее, чтобы одинаково отправлять всем синкам
        lines = [e.to_jsonl(self._cfg.redact) for e in events]
        wrote_any = False
        for sink in self._sinks:
            try:
                await sink.write_batch(lines)
                wrote_any = True
            except Exception as e:
                self._metric_failures += 1
                self._logger.error("Audit sink error: %s", str(e))
        if not wrote_any:
            # аварийный слив
            try:
                Path(self._cfg.emergency_path).parent.mkdir(parents=True, exist_ok=True)
                with open(self._cfg.emergency_path, "a", encoding="utf-8") as f:
                    for ln in lines:
                        f.write(ln + "\n")
            except Exception as e:
                self._logger.critical("Emergency write failed: %s", str(e))
        else:
            self._metric_written += len(events)

    # ---------- Верификация цепочки для JSONL ----------

    @staticmethod
    def verify_jsonl_chain(path: str, hmac_secret: Optional[bytes] = None) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Проверяет целостность цепочки в JSONL-файле.
        Возвращает (ok, line_number_of_failure, reason).
        """
        prev_hash = None
        try:
            with open(path, "r", encoding="utf-8") as f:
                for i, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    expected_prev = data.get("prev_hash")
                    if expected_prev != prev_hash:
                        return (False, i, "prev_hash mismatch")
                    # Восстановить канонический payload
                    event = AuditEvent(**{k: v for k, v in data.items() if k != "hash"})
                    payload = _stable_dumps(event.canonical_payload())
                    calc = _hsha256(payload, hmac_secret)
                    if data.get("hash") != calc:
                        return (False, i, "hash mismatch")
                    prev_hash = calc
            return (True, None, None)
        except Exception as e:
            return (False, None, f"verification error: {e}")


# ---------------------------------------------------------------------------
# Утилита построения по окружению
# ---------------------------------------------------------------------------

def build_default_audit() -> AuditTrail:
    """
    Конструктор по переменным окружения:
      AUDIT_NS, AUDIT_JSONL, AUDIT_HTTP_ENDPOINT, AUDIT_SAMPLING, AUDIT_CHAIN(0/1)
    """
    ns = os.getenv("AUDIT_NS", "policy-core")
    jsonl = os.getenv("AUDIT_JSONL", "./logs/audit-%Y%m%d.jsonl")
    endpoint = os.getenv("AUDIT_HTTP_ENDPOINT") or None
    sampling = float(os.getenv("AUDIT_SAMPLING", "1.0"))
    chain = os.getenv("AUDIT_CHAIN", "1") != "0"
    secret_b64 = os.getenv("AUDIT_HMAC_SECRET_BASE64")
    secret = None
    if secret_b64:
        try:
            import base64
            secret = base64.b64decode(secret_b64)
        except Exception:
            secret = None

    cfg = AuditConfig(
        namespace=ns,
        jsonl_path=jsonl,
        http_endpoint=endpoint,
        sampling_rate=sampling,
        enable_chain=chain,
        hmac_secret=secret
    )
    return AuditTrail(cfg)


# ---------------------------------------------------------------------------
# Пример smoke-теста (не выполняется в проде)
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    async def _demo():
        logging.basicConfig(stream=sys.stdout, level=logging.INFO)
        audit = build_default_audit()
        await audit.start()
        try:
            # Мини-событие
            evt = AuditEvent(
                ts_ms=_now_ms(),
                event_id="evt-001",
                request_id="req-001",
                namespace=audit._cfg.namespace,
                action="read",
                decision_effect=DecisionEffect.Permit,
                decision_bool=True,
                decision_latency_ms=12.3,
                labels={"authorization": "Bearer secret", "note": "demo"},
            )
            await audit.submit(evt)
            await asyncio.sleep(2.0)
            print("Metrics:", audit.snapshot_metrics())
        finally:
            await audit.aclose()

    asyncio.run(_demo())
