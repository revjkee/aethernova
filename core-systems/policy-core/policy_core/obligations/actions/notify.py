# policy_core/obligations/actions/notify.py
# Industrial-grade Notification Obligation Executor
# License: Apache-2.0 (align with project)
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import email.message
import hashlib
import hmac
import json
import logging
import os
import smtplib
import string
import time
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# Optional async libs
try:
    import aiosmtplib  # type: ignore
    _HAS_AIOSMTP = True
except Exception:
    _HAS_AIOSMTP = False

try:
    import aiohttp  # type: ignore
    _HAS_AIOHTTP = True
except Exception:
    _HAS_AIOHTTP = False

# OpenTelemetry (optional)
try:
    from opentelemetry import trace  # type: ignore
    _otel_tracer = trace.get_tracer("policy_core.obligations.notify")
except Exception:
    _otel_tracer = None

# Policy core models
from ...context import (
    PolicyDecision,
    EnforcementMode,
    RequestContext,
    EvaluationResult,
    PolicyContext,
)

__all__ = [
    "NotifyChannelKind",
    "NotifySeverity",
    "NotifySpec",
    "EmailSettings",
    "WebhookSettings",
    "NotificationExecutor",
    "apply_notify_obligations",
]

log = logging.getLogger("policy_core.obligations.notify")


# -----------------------------
# Enums & Settings dataclasses
# -----------------------------
class NotifyChannelKind(str, Enum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    LOGGER = "logger"


class NotifySeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class EmailSettings:
    host: str
    port: int = 587
    username: Optional[str] = None
    password: Optional[str] = None
    starttls: bool = True
    from_addr: str = "no-reply@localhost"
    timeout_s: float = 5.0


@dataclass(frozen=True)
class WebhookSettings:
    url: str
    method: str = "POST"
    headers: Mapping[str, str] = field(default_factory=dict)
    timeout_s: float = 4.0
    # Optional HMAC signing of raw body
    hmac_secret_env: Optional[str] = None
    hmac_header: str = "X-Signature"
    hmac_algo: str = "sha256"


@dataclass(frozen=True)
class NotifySpec:
    """
    Declarative spec of one notify action.
    """
    channel: NotifyChannelKind
    severity: NotifySeverity = NotifySeverity.MEDIUM
    # Conditions
    only_if_decision_in: Tuple[PolicyDecision, ...] = field(
        default_factory=lambda: (PolicyDecision.DENY, PolicyDecision.CHALLENGE)
    )
    skip_in_enforcement_modes: Tuple[EnforcementMode, ...] = field(default_factory=tuple)
    # Throttle / dedup
    throttle_s: float = 0.0                # suppress repeated sends for same key within this window
    dedupe_key_template: Optional[str] = None  # template for dedup key; defaults to message fingerprint
    # Rendering
    subject_template: Optional[str] = None
    body_template: Optional[str] = None
    json_template: Optional[Mapping[str, Any]] = None  # for webhook payloads
    # Channel settings
    email: Optional[EmailSettings] = None
    to: Tuple[str, ...] = field(default_factory=tuple)  # email recipients
    webhook: Optional[WebhookSettings] = None
    logger_name: Optional[str] = None                  # for LOGGER


# -----------------------------
# Template & redaction utils
# -----------------------------
class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def _flatten(prefix: str, obj: Any, out: Dict[str, Any]) -> None:
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            nk = f"{prefix}.{k}" if prefix else str(k)
            _flatten(nk, v, out)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            nk = f"{prefix}.{i}" if prefix else str(i)
            _flatten(nk, v, out)
    else:
        out[prefix] = obj


def _build_template_ctx(req: RequestContext, res: EvaluationResult, ctx: PolicyContext) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "decision": res.decision.value,
        "reasons": list(res.reasons or []),
        "latency_ms": res.latency_ms,
        "source": req.source,
        "action": req.action,
        "timestamp": req.timestamp.isoformat(),
        "enforcement": str(getattr(ctx, "_enforcement", None)),
    }
    # Flatten nested
    _flatten("actor", {
        "subject_id": req.actor.subject_id,
        "tenant_id": req.actor.tenant_id,
        "roles": list(req.actor.roles),
        "scopes": list(req.actor.scopes),
        "attributes": dict(req.actor.attributes or {}),
    }, base)
    _flatten("resource", {
        "type": req.resource.type,
        "id": req.resource.id,
        "owner": req.resource.owner,
        "labels": list(req.resource.labels),
        "security_label": req.resource.security_label.value,
        "attributes": dict(req.resource.attributes or {}),
    }, base)
    _flatten("environment", dataclasses.asdict(req.environment), base)
    # obligations may include hints (mask fields, etc.)
    _flatten("obligations", dict(res.obligations or {}), base)
    return base


def _render_template(template: Optional[str], mapping: Mapping[str, Any]) -> Optional[str]:
    if not template:
        return None
    # Support {dot.path} placeholders by passing flattened map
    try:
        return str(template).format_map(_SafeDict(mapping))
    except Exception:
        # Fallback to string.Template
        try:
            return string.Template(template).safe_substitute(mapping)
        except Exception:
            return template  # last resort, return raw


def _render_json_template(tpl: Optional[Mapping[str, Any]], mapping: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    if tpl is None:
        return None

    def _walk(x: Any) -> Any:
        if isinstance(x, str):
            return _render_template(x, mapping)
        if isinstance(x, Mapping):
            return {k: _walk(v) for k, v in x.items()}
        if isinstance(x, list):
            return [_walk(v) for v in x]
        if isinstance(x, tuple):
            return tuple(_walk(v) for v in x)
        return x

    return _walk(tpl)


def _fingerprint(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode("utf-8"))
        h.update(b"|")
    return h.hexdigest()


# -----------------------------
# In-memory throttle/dedup store
# -----------------------------
class _ThrottleStore:
    def __init__(self):
        self._last: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def should_send(self, key: str, throttle_s: float) -> bool:
        if throttle_s <= 0:
            return True
        now = time.monotonic()
        async with self._lock:
            last = self._last.get(key, 0.0)
            if now - last >= throttle_s:
                self._last[key] = now
                return True
            return False


_THROTTLE = _ThrottleStore()


# -----------------------------
# Channels
# -----------------------------
class _Channel(ABC):
    @abstractmethod
    async def send(self, spec: NotifySpec, subject: Optional[str], body: Optional[str], payload: Optional[Mapping[str, Any]]) -> None:
        ...


class LoggerChannel(_Channel):
    def __init__(self, logger: Optional[logging.Logger] = None):
        self._logger = logger or logging.getLogger("policy_core.notify")

    async def send(self, spec: NotifySpec, subject: Optional[str], body: Optional[str], payload: Optional[Mapping[str, Any]]) -> None:
        data = {
            "severity": spec.severity.value,
            "subject": subject,
            "body": body,
            "payload": payload,
        }
        # Use info for <= HIGH, error for CRITICAL
        if spec.severity in (NotifySeverity.CRITICAL,):
            self._logger.error(json.dumps(data, ensure_ascii=False))
        else:
            self._logger.info(json.dumps(data, ensure_ascii=False))


class EmailChannel(_Channel):
    def __init__(self):
        self._pool_lock = asyncio.Lock()

    async def _send_aiosmtp(self, spec: NotifySpec, subject: Optional[str], body: Optional[str]) -> None:
        assert spec.email is not None
        msg = email.message.EmailMessage()
        msg["From"] = spec.email.from_addr
        msg["To"] = ", ".join(spec.to)
        msg["Subject"] = subject or "(no subject)"
        msg.set_content(body or "")

        # aiosmtplib send
        await aiosmtplib.send(
            msg,
            hostname=spec.email.host,
            port=spec.email.port,
            username=spec.email.username,
            password=spec.email.password,
            start_tls=spec.email.starttls,
            timeout=spec.email.timeout_s,
        )

    def _send_smtplib_blocking(self, spec: NotifySpec, subject: Optional[str], body: Optional[str]) -> None:
        assert spec.email is not None
        msg = email.message.EmailMessage()
        msg["From"] = spec.email.from_addr
        msg["To"] = ", ".join(spec.to)
        msg["Subject"] = subject or "(no subject)"
        msg.set_content(body or "")

        server: Optional[smtplib.SMTP] = None
        try:
            server = smtplib.SMTP(spec.email.host, spec.email.port, timeout=spec.email.timeout_s)
            if spec.email.starttls:
                server.starttls()
            if spec.email.username and spec.email.password:
                server.login(spec.email.username, spec.email.password)
            server.send_message(msg)
        finally:
            try:
                if server:
                    server.quit()
            except Exception:
                pass

    async def send(self, spec: NotifySpec, subject: Optional[str], body: Optional[str], payload: Optional[Mapping[str, Any]]) -> None:
        if not spec.email or not spec.to:
            raise ValueError("Email channel requires EmailSettings and at least one recipient")
        if _HAS_AIOSMTP:
            await self._send_aiosmtp(spec, subject, body)
        else:
            await asyncio.to_thread(self._send_smtplib_blocking, spec, subject, body)


class WebhookChannel(_Channel):
    async def _send_aiohttp(self, spec: NotifySpec, payload_bytes: bytes, headers: Mapping[str, str]) -> None:
        assert spec.webhook is not None
        timeout = aiohttp.ClientTimeout(total=spec.webhook.timeout_s)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.request(
                spec.webhook.method.upper(),
                spec.webhook.url,
                data=payload_bytes,
                headers=dict(headers),
            ) as resp:
                # Read body to avoid resource warnings
                await resp.read()
                if resp.status >= 400:
                    raise RuntimeError(f"Webhook HTTP {resp.status}")

    def _send_urllib_blocking(self, spec: NotifySpec, payload_bytes: bytes, headers: Mapping[str, str]) -> None:
        assert spec.webhook is not None
        req = urllib.request.Request(
            spec.webhook.url,
            data=payload_bytes,
            method=spec.webhook.method.upper(),
            headers=dict(headers),
        )
        with urllib.request.urlopen(req, timeout=spec.webhook.timeout_s) as resp:
            if resp.status >= 400:
                raise RuntimeError(f"Webhook HTTP {resp.status}")

    async def send(self, spec: NotifySpec, subject: Optional[str], body: Optional[str], payload: Optional[Mapping[str, Any]]) -> None:
        if not spec.webhook:
            raise ValueError("Webhook channel requires WebhookSettings")
        # Build default payload: JSON with subject/body if none provided
        json_payload = payload or {"subject": subject, "body": body, "severity": spec.severity.value}
        payload_bytes = json.dumps(json_payload, ensure_ascii=False).encode("utf-8")

        # Build headers (Content-Type + HMAC if configured)
        headers = dict(spec.webhook.headers or {})
        if "content-type" not in {k.lower() for k in headers.keys()}:
            headers["Content-Type"] = "application/json"

        if spec.webhook.hmac_secret_env:
            secret = os.getenv(spec.webhook.hmac_secret_env, "")
            if not secret:
                log.warning("HMAC secret env %s not set; sending without signature", spec.webhook.hmac_secret_env)
            else:
                algo = spec.webhook.hmac_algo.lower()
                if algo not in ("sha256", "sha1", "md5"):
                    raise ValueError("Unsupported HMAC algo")
                digestmod = getattr(hashlib, algo)
                signature = hmac.new(secret.encode("utf-8"), payload_bytes, digestmod).hexdigest()
                headers[spec.webhook.hmac_header] = signature

        if _HAS_AIOHTTP:
            await self._send_aiohttp(spec, payload_bytes, headers)
        else:
            await asyncio.to_thread(self._send_urllib_blocking, spec, payload_bytes, headers)


# -----------------------------
# Notification executor
# -----------------------------
class NotificationExecutor:
    """
    Executes notify obligations defined in EvaluationResult.obligations["notify"].
    Spec schema (example):

    obligations:
      notify:
        - channel: "email"
          to: ["secops@example.com"]
          severity: "high"
          only_if_decision_in: ["deny","challenge"]
          throttle_s: 60
          subject_template: "Policy {decision} for {resource.type}/{resource.id}"
          body_template: "Actor={actor.subject_id}; Action={action}; Reasons={reasons}"
          email:
            host: "smtp.example.com"
            port: 587
            username: "bot"
            password: "****"
            starttls: true
            from_addr: "no-reply@example.com"

        - channel: "webhook"
          webhook:
            url: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
            headers: {"X-App": "policy-core"}
            timeout_s: 4.0
            hmac_secret_env: "SLACK_HMAC"
            hmac_header: "X-Signature"
            hmac_algo: "sha256"
          json_template:
            text: "[{severity}] {decision} {action} {resource.type}/{resource.id} by {actor.subject_id}"
          throttle_s: 10

        - channel: "logger"
          severity: "low"
          subject_template: "AUDIT {decision}"
          body_template: "{action} {resource.type}/{resource.id}"
    """

    def __init__(self, *, default_logger: Optional[logging.Logger] = None):
        self._channels: Dict[NotifyChannelKind, _Channel] = {
            NotifyChannelKind.EMAIL: EmailChannel(),
            NotifyChannelKind.WEBHOOK: WebhookChannel(),
            NotifyChannelKind.LOGGER: LoggerChannel(default_logger),
        }

    def register_channel(self, kind: NotifyChannelKind, channel: _Channel) -> None:
        self._channels[kind] = channel

    async def execute(self, req: RequestContext, res: EvaluationResult, ctx: PolicyContext) -> None:
        specs = _parse_notify_specs(res.obligations.get("notify") if isinstance(res.obligations, Mapping) else None)
        if not specs:
            return

        mapping = _build_template_ctx(req, res, ctx)

        async def _run_one(spec: NotifySpec) -> None:
            # Conditions
            if res.decision not in spec.only_if_decision_in:
                return
            if getattr(ctx, "_enforcement", None) in spec.skip_in_enforcement_modes:
                return

            subject = _render_template(spec.subject_template, mapping)
            body = _render_template(spec.body_template, mapping)
            payload = _render_json_template(spec.json_template, mapping)

            # Dedup key (template -> string)
            dedup_base = spec.dedupe_key_template or (subject or "") + "|" + (body or json.dumps(payload or {}, ensure_ascii=False))
            dedup_key = _render_template(dedup_base, mapping) or dedup_base
            fp = _fingerprint(
                str(spec.channel.value),
                str(spec.severity.value),
                dedup_key,
            )

            # Throttle
            if not await _THROTTLE.should_send(fp, spec.throttle_s):
                return

            # Execute
            ch = self._channels.get(spec.channel)
            if not ch:
                raise KeyError(f"No channel registered for {spec.channel}")
            if _otel_tracer is not None:
                with _otel_tracer.start_as_current_span("notify.send") as span:
                    span.set_attribute("notify.channel", spec.channel.value)
                    span.set_attribute("notify.severity", spec.severity.value)
                    await ch.send(spec, subject, body, payload)
            else:
                await ch.send(spec, subject, body, payload)

        # Fire all notify specs concurrently with isolation
        await asyncio.gather(*(_run_one(s) for s in specs), return_exceptions=True)


# -----------------------------
# Parsing helpers
# -----------------------------
def _as_bool(x: Any, default: bool = False) -> bool:
    if isinstance(x, bool):
        return x
    if x is None:
        return default
    s = str(x).strip().lower()
    return s in ("1", "true", "yes", "y", "on")


def _parse_email_settings(node: Mapping[str, Any]) -> EmailSettings:
    return EmailSettings(
        host=str(node.get("host")),
        port=int(node.get("port", 587)),
        username=node.get("username"),
        password=node.get("password"),
        starttls=_as_bool(node.get("starttls", True)),
        from_addr=str(node.get("from_addr", "no-reply@localhost")),
        timeout_s=float(node.get("timeout_s", 5.0)),
    )


def _parse_webhook_settings(node: Mapping[str, Any]) -> WebhookSettings:
    return WebhookSettings(
        url=str(node.get("url")),
        method=str(node.get("method", "POST")),
        headers=dict(node.get("headers", {})),
        timeout_s=float(node.get("timeout_s", 4.0)),
        hmac_secret_env=node.get("hmac_secret_env"),
        hmac_header=str(node.get("hmac_header", "X-Signature")),
        hmac_algo=str(node.get("hmac_algo", "sha256")),
    )


def _parse_notify_specs(node: Any) -> List[NotifySpec]:
    specs: List[NotifySpec] = []
    if node is None:
        return specs
    if isinstance(node, Mapping):
        node = [node]  # allow single object

    if not isinstance(node, (list, tuple)):
        return specs

    for item in node:
        if not isinstance(item, Mapping):
            continue
        channel = NotifyChannelKind(str(item.get("channel", "logger")).lower())
        severity = NotifySeverity(str(item.get("severity", "medium")).lower())
        only_if = tuple(
            PolicyDecision(str(x).lower())
            for x in (item.get("only_if_decision_in") or ["deny", "challenge"])
        )
        skip_modes = tuple(
            EnforcementMode(str(x).lower())
            for x in (item.get("skip_in_enforcement_modes") or [])
        )
        throttle_s = float(item.get("throttle_s", 0.0))
        dedupe_tpl = item.get("dedupe_key_template")

        subject_tpl = item.get("subject_template")
        body_tpl = item.get("body_template")
        json_tpl = item.get("json_template")

        email_settings = None
        recipients: Tuple[str, ...] = tuple(item.get("to") or ())
        if channel == NotifyChannelKind.EMAIL:
            if "email" not in item:
                raise ValueError("Email notify requires 'email' settings")
            email_settings = _parse_email_settings(item["email"])

        webhook_settings = None
        if channel == NotifyChannelKind.WEBHOOK:
            if "webhook" not in item:
                raise ValueError("Webhook notify requires 'webhook' settings")
            webhook_settings = _parse_webhook_settings(item["webhook"])

        logger_name = item.get("logger_name")

        specs.append(NotifySpec(
            channel=channel,
            severity=severity,
            only_if_decision_in=only_if,
            skip_in_enforcement_modes=skip_modes,
            throttle_s=throttle_s,
            dedupe_key_template=dedupe_tpl,
            subject_template=subject_tpl,
            body_template=body_tpl,
            json_template=json_tpl if isinstance(json_tpl, Mapping) else None,
            email=email_settings,
            to=recipients,
            webhook=webhook_settings,
            logger_name=logger_name,
        ))
    return specs


# -----------------------------
# Public entrypoint for obligations pipeline
# -----------------------------
async def apply_notify_obligations(req: RequestContext, res: EvaluationResult, ctx: PolicyContext) -> None:
    """
    Execute notify obligations from res.obligations (if any). Intended to be
    called immediately after policy evaluation, regardless of enforcement mode.
    """
    executor = NotificationExecutor()
    try:
        await executor.execute(req, res, ctx)
    except Exception as e:
        # Never propagate notification failures to the caller path; just log
        log.exception("Notification execution failed: %s", e)


# -----------------------------
# Inline usage reference (non-executable)
# -----------------------------
"""
Example integration:

from policy_core.obligations.actions.notify import apply_notify_obligations

# After you got (res = await ctx.evaluate(...)):
await apply_notify_obligations(req, res, ctx)

# Example obligations from evaluator:
result = EvaluationResult(
    decision=PolicyDecision.DENY,
    obligations={
        "notify": [
            {
                "channel": "logger",
                "severity": "high",
                "subject_template": "Denied {action} on {resource.type}/{resource.id}",
                "body_template": "Actor={actor.subject_id}, Reasons={reasons}",
                "throttle_s": 10
            },
            {
                "channel": "webhook",
                "webhook": {
                    "url": "https://example.net/hook",
                    "headers": {"X-App": "policy-core"},
                    "timeout_s": 3.0,
                    "hmac_secret_env": "WEBHOOK_SECRET",
                    "hmac_header": "X-Signature",
                    "hmac_algo": "sha256"
                },
                "json_template": {
                    "text": "[{severity}] {decision} {action} {resource.type}/{resource.id} by {actor.subject_id}",
                    "extra": {"latency_ms": "{latency_ms}"}
                },
                "throttle_s": 30
            }
        ]
    }
)
"""
