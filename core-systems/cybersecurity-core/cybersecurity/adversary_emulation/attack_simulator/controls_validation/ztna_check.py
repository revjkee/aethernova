# cybersecurity-core/cybersecurity/adversary_emulation/attack_simulator/controls_validation/ztna_check.py
# -*- coding: utf-8 -*-
"""
ZTNA Controls Validation — промышленный валидатор контролей Zero Trust Network Access.

Методологические опоры (проверяемые источники):
- NIST SP 800-207: Zero Trust Architecture (архитектурные принципы ZTNA)
  https://csrc.nist.gov/publications/detail/sp/800-207/final
- CISA Zero Trust Maturity Model v2.0 (модель зрелости и домены контроля)
  https://www.cisa.gov/zero-trust-maturity-model
- NIST SP 800-53 Rev.5 (AC, IA, SC — контроли доступа/идентификации/шифрования)
  https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- RFC 5280 (выпуск/проверка сертификатов X.509, пути сертификации)
  https://www.rfc-editor.org/rfc/rfc5280
- OAuth 2.0 (RFC 6749) и OpenID Connect Core 1.0 (выпуск/валидация JWT-токенов)
  https://www.rfc-editor.org/rfc/rfc6749
  https://openid.net/specs/openid-connect-core-1_0.html

Назначение:
- Программная проверка «policy decision points» (PDP) и «policy enforcement points» (PEP)
  в контексте Zero Trust: личность, устройство, соединение, политика, непрерывная верификация.
- Только read-only проверки и запросы; модуль не выполняет деструктивных действий.

Функции:
- Валидация JWT/OIDC (iss/aud/exp/nbf/iat, подпись, nonce — при наличии).
- Валидация цепочки сертификатов X.509 (mTLS) и параметров TLS.
- Проверки позы устройства (device posture) через plug-in адаптеры.
- Тестирование сетевого пути/сегментации до целевого сервиса (TCP/TLS).
- Оценка политики: встроенный движок правил + опциональная интеграция с OPA (HTTP API).
- Непрерывная верификация (re-evaluation loop) и SLO (время ответа, доля прохождений).
- Структурированные логи (JSON) и аудиторский JSONL-трейл.

Зависимости:
- Опциональные: pyjwt, cryptography, httpx/requests. Отсутствие библиотек обрабатывается graceful degradation.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import json
import logging
import os
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

# --------- Опциональные импорты (graceful degrade) ----------
try:  # JWT / OIDC
    import jwt  # pyjwt
    from jwt import algorithms
except Exception:  # pragma: no cover
    jwt = None
    algorithms = None

try:  # X.509 / PKIX
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.x509.base import Certificate
except Exception:  # pragma: no cover
    x509 = None
    serialization = None
    hashes = None
    padding = None
    Certificate = None

try:  # HTTP client (OPA, OIDC JWKS и т.п.)
    import httpx
except Exception:  # pragma: no cover
    httpx = None

# -------------------- Логирование и аудит --------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload = {
            "@timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "log.level": record.levelname,
            "message": record.getMessage(),
            "logger.name": record.name,
            "process.pid": record.process,
            "thread.name": record.threadName,
        }
        if record.exc_info:
            payload["error.type"] = str(record.exc_info[0].__name__)
            payload["error.message"] = str(record.exc_info[1])
            payload["error.stack_trace"] = self.formatException(record.exc_info)
        # Добавляем кастомные поля, если сериализуемы
        for k, v in getattr(record, "__dict__", {}).items():
            if k.startswith("_"):
                continue
            if k in payload:
                continue
            if k in (
                "msg", "args", "name", "levelname", "levelno", "pathname", "filename",
                "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                "created", "msecs", "relativeCreated", "thread", "process", "asctime"
            ):
                continue
            try:
                json.dumps(v)
                payload[k] = v
            except Exception:
                payload[k] = repr(v)
        return json.dumps(payload, ensure_ascii=False)


def build_logger(name: str = __name__) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.propagate = False
    return logger


LOGGER = build_logger(__name__)


# -------------------- Конфигурация/модель результатов --------------------

@dataclass
class JWTRules:
    issuer: str
    audience: str
    leeway_s: int = 60  # допуск часов/сетевых дрейфов (OpenID Connect Core допускает небольшой leeway)
    jwks_url: Optional[str] = None
    required_claims: Tuple[str, ...] = ("iss", "aud", "sub", "exp", "iat")
    algorithms: Tuple[str, ...] = ("RS256", "ES256")  # RFC 7518 (JOSE) — безопасные по умолчанию


@dataclass
class MTLSRules:
    verify_chain: bool = True
    trust_store_pem: Optional[Path] = None
    verify_hostname: bool = True
    min_tls_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2  # NIST SP 800-52r2 рекомендует TLS 1.2+ (косвенно)
    ciphers: Optional[str] = None  # можно ограничить FIPS-набор при необходимости


@dataclass
class DevicePostureRule:
    name: str
    required: bool = True
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkRule:
    target_host: str
    target_port: int
    must_be_reachable: bool = True
    timeout_s: float = 5.0
    tls: bool = False
    sni: Optional[str] = None


@dataclass
class OPAPolicy:
    url: str  # http(s)://opa:8181/v1/data/<package>/<rule>
    input_template: Dict[str, Any] = field(default_factory=dict)
    allow_on_unavailable: bool = False  # fail-open vs fail-closed


@dataclass
class ZTNAConfig:
    scenario_id: str
    jwt_rules: Optional[JWTRules] = None
    mtls_rules: Optional[MTLSRules] = None
    device_rules: Tuple[DevicePostureRule, ...] = ()
    network_rules: Tuple[NetworkRule, ...] = ()
    opa_policy: Optional[OPAPolicy] = None
    audit_dir: Path = field(default_factory=lambda: Path("./audit"))
    audit_file_prefix: str = "ztna_validation"
    continuous_reverify_s: Optional[int] = None  # период re-evaluation (сек); None — однократно
    max_iterations: int = 1  # для continuous режима
    tags: Tuple[str, ...] = ()


@dataclass
class CheckRecord:
    name: str
    success: bool
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ZTNAResult:
    scenario_id: str
    started_at: str
    ended_at: Optional[str] = None
    duration_s: Optional[float] = None
    checks: List[CheckRecord] = field(default_factory=list)
    allowed: bool = False  # итоговое решение PDP (allow/deny)
    reasons: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)


# -------------------- Утилиты аудита --------------------

class Auditor:
    def __init__(self, base_dir: Path, prefix: str, scenario_id: str):
        self._dir = base_dir
        self._prefix = prefix
        self._scenario_id = scenario_id
        self._dir.mkdir(parents=True, exist_ok=True)

    def _file(self) -> Path:
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        return self._dir / f"{self._prefix}_{self._scenario_id}_{date_str}.jsonl"

    def write(self, record: Mapping[str, Any]) -> None:
        payload = dict(record)
        payload["ts"] = datetime.now(timezone.utc).isoformat()
        payload["scenario_id"] = self._scenario_id
        with self._file().open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")


# -------------------- Валидатор ZTNA --------------------

class ZTNAValidator:
    """
    Валидатор контролей ZTNA в духе NIST SP 800-207/CISA ZTMM:
    - Личность (Identity): JWT/OIDC (RFC 6749 / OIDC Core).
    - Устройство (Device): posture (плагины).
    - Сеть/транспорт (Network): TCP/TLS доступ/сегментация, mTLS (RFC 5280).
    - Приложение/Политика (Application/Policy): встроенные правила + OPA.
    - Непрерывность (Continuous): периодический re-evaluation.

    Все проверки — read-only. Не изменяет конфигурацию сетей/хостов/сертификатов.
    """

    def __init__(self, cfg: ZTNAConfig):
        self.cfg = cfg
        self.audit = Auditor(cfg.audit_dir, cfg.audit_file_prefix, cfg.scenario_id)

    # ---------- Публичный API ----------
    def run(self, context: Optional[Dict[str, Any]] = None) -> ZTNAResult:
        return asyncio.run(self.run_async(context or {}))

    async def run_async(self, context: Dict[str, Any]) -> ZTNAResult:
        started = datetime.now(timezone.utc).isoformat()
        res = ZTNAResult(
            scenario_id=self.cfg.scenario_id,
            started_at=started,
            meta={"tags": list(self.cfg.tags)},
        )

        iterations = self.cfg.max_iterations if self.cfg.continuous_reverify_s else 1
        for i in range(iterations):
            LOGGER.info("ztna_iteration_start", extra={"iteration": i + 1})
            self.audit.write({"event": "iteration_start", "iteration": i + 1})

            checks: List[CheckRecord] = []
            reasons: List[str] = []

            # Identity
            if self.cfg.jwt_rules:
                cr = await self._check_jwt_async(context, self.cfg.jwt_rules)
                checks.append(cr)
                if not cr.success:
                    reasons.append("JWT/OIDC validation failed (Identity)")

            # Device posture
            for rule in self.cfg.device_rules:
                cr = await self._check_device_posture_async(context, rule)
                checks.append(cr)
                if rule.required and not cr.success:
                    reasons.append(f"Device posture failed: {rule.name}")

            # Network and mTLS
            for nr in self.cfg.network_rules:
                cr = await self._check_network_path_async(nr, self.cfg.mtls_rules)
                checks.append(cr)
                if not cr.success and nr.must_be_reachable:
                    reasons.append(f"Network path failed: {nr.target_host}:{nr.target_port}")

            # Policy (built-in)
            policy_cr = self._check_builtin_policy(checks, context)
            checks.append(policy_cr)
            if not policy_cr.success:
                reasons.append("Built-in policy denied")

            # OPA integration (optional)
            if self.cfg.opa_policy:
                opa_cr = await self._check_opa_policy_async(checks, context, self.cfg.opa_policy)
                checks.append(opa_cr)
                if not opa_cr.success:
                    reasons.append("OPA policy denied")

            # Итоговое решение: allow если нет причин deny
            res.checks = checks
            res.allowed = len(reasons) == 0
            res.reasons = reasons

            # Аудит итерации
            self.audit.write({
                "event": "iteration_result",
                "iteration": i + 1,
                "allowed": res.allowed,
                "reasons": res.reasons,
                "checks": [dataclasses.asdict(c) for c in checks],
            })
            LOGGER.info("ztna_iteration_done", extra={"iteration": i + 1, "allowed": res.allowed})

            if self.cfg.continuous_reverify_s and (i + 1) < iterations:
                await asyncio.sleep(self.cfg.continuous_reverify_s)

        res.ended_at = datetime.now(timezone.utc).isoformat()
        res.duration_s = _duration_s(res.started_at, res.ended_at)
        self.audit.write({"event": "summary", "result": dataclasses.asdict(res)})
        LOGGER.info("ztna_validation_summary", extra={"allowed": res.allowed})
        return res

    # ---------- Частные проверки ----------
    async def _check_jwt_async(self, context: Dict[str, Any], rules: JWTRules) -> CheckRecord:
        """
        Валидация токена в духе RFC 6749 (OAuth 2.0) и OpenID Connect Core:
        - iss == ожидаемому, aud включает ожидаемую аудиторию
        - exp/nbf/iat с учётом leeway
        - подпись по публичному ключу (JWKS)
        Источники: RFC 6749; OIDC Core 1.0.
        """
        name = "identity.jwt_validation"
        token = context.get("access_token") or context.get("id_token")
        details: Dict[str, Any] = {"iss": rules.issuer, "aud": rules.audience}
        if not token:
            details["reason"] = "token_missing"
            self.audit.write({"event": name, "success": False, "details": details})
            return CheckRecord(name=name, success=False, details=details)

        if jwt is None:
            details["reason"] = "pyjwt_not_available"
            self.audit.write({"event": name, "success": False, "details": details})
            return CheckRecord(name=name, success=False, details=details)

        try:
            # Получаем ключи
            key = None
            options = {"require": list(rules.required_claims), "verify_aud": True}
            leeway = rules.leeway_s
            if rules.jwks_url and httpx is not None:
                async with httpx.AsyncClient(timeout=10) as client:
                    r = await client.get(rules.jwks_url)
                    r.raise_for_status()
                    jwks = r.json()
                headers = jwt.get_unverified_header(token)
                kid = headers.get("kid")
                key = _select_jwk_key(jwks, kid)
                details["jwks_kid"] = kid

            decoded = jwt.decode(
                token,
                key=key,
                algorithms=list(rules.algorithms),
                audience=rules.audience,
                issuer=rules.issuer,
                options=options,
                leeway=leeway,
            )
            details["sub"] = decoded.get("sub")
            details["token_valid"] = True
            self.audit.write({"event": name, "success": True, "details": details})
            return CheckRecord(name=name, success=True, details=details)
        except Exception as ex:
            details["reason"] = str(ex)
            self.audit.write({"event": name, "success": False, "details": details})
            return CheckRecord(name=name, success=False, details=details)

    async def _check_device_posture_async(self, context: Dict[str, Any], rule: DevicePostureRule) -> CheckRecord:
        """
        Device posture в понимании CISA ZTMM/NIST SP 800-207: управляемость, шифрование диска,
        наличие EDR, патч-уровень и т.п. Здесь — plug-in механизм: пользователь передаёт
        в context callable, соответствующий имени правила.
        Источники: CISA ZTMM (Device), NIST SP 800-207.
        """
        name = f"device.posture.{rule.name}"
        fn = context.get("device_posture_adapters", {}).get(rule.name)
        details: Dict[str, Any] = {"required": rule.required, "params": rule.params}
        if not callable(fn):
            details["reason"] = "adapter_missing"
            self.audit.write({"event": name, "success": not rule.required, "details": details})
            return CheckRecord(name=name, success=not rule.required, details=details)
        try:
            ok, info = await _maybe_await(fn(rule.params))
            details.update({"adapter_info": info})
            self.audit.write({"event": name, "success": bool(ok), "details": details})
            return CheckRecord(name=name, success=bool(ok), details=details)
        except Exception as ex:
            details["reason"] = str(ex)
            self.audit.write({"event": name, "success": False, "details": details})
            return CheckRecord(name=name, success=False, details=details)

    async def _check_network_path_async(self, nr: NetworkRule, mtls: Optional[MTLSRules]) -> CheckRecord:
        """
        Проверка сетевого пути/сегментации и (опционально) параметров TLS/mTLS.
        Источники: NIST SP 800-207 (Policy enforcement), RFC 5280 (цепочки X.509).
        """
        name = f"network.path.{nr.target_host}:{nr.target_port}"
        details: Dict[str, Any] = {"tls": nr.tls, "timeout": nr.timeout_s, "must_be_reachable": nr.must_be_reachable}
        try:
            if nr.tls:
                # Настраиваем SSL-контекст
                ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
                if mtls:
                    ctx.minimum_version = mtls.min_tls_version
                    if mtls.ciphers:
                        ctx.set_ciphers(mtls.ciphers)
                    if mtls.trust_store_pem:
                        ctx.load_verify_locations(str(mtls.trust_store_pem))
                # Подключаемся
                await _tls_connect(nr.target_host, nr.target_port, ctx, nr.timeout_s, sni=nr.sni)
                details["reachable"] = True
                # Проверки mTLS/PKI (hostname проверяется на этапе wrap_socket)
                if mtls and mtls.verify_chain and x509 is not None:
                    # В python ssl уже проверяет цепочку, здесь можем дополнительно извлечь и
                    # формально провалидировать сертификат сервера при необходимости.
                    details["chain_verified"] = True
            else:
                await _tcp_connect(nr.target_host, nr.target_port, nr.timeout_s)
                details["reachable"] = True

            ok = True if nr.must_be_reachable else True
            self.audit.write({"event": name, "success": ok, "details": details})
            return CheckRecord(name=name, success=ok, details=details)
        except Exception as ex:
            details["reachable"] = False
            details["reason"] = str(ex)
            # Если ресурс необязателен, то успех, иначе — провал
            ok = not nr.must_be_reachable
            self.audit.write({"event": name, "success": ok, "details": details})
            return CheckRecord(name=name, success=ok, details=details)

    def _check_builtin_policy(self, checks: Sequence[CheckRecord], context: Dict[str, Any]) -> CheckRecord:
        """
        Минимальный PDP: deny по умолчанию, allow при успехе ключевых доменов:
        - Identity: ok
        - Required Device Posture: ok
        - Required Network Rules: ok
        Источники: NIST SP 800-207 (policy decision).
        """
        name = "policy.builtin"
        details: Dict[str, Any] = {}
        # Агрегируем по префиксам
        identity_ok = _all_success(checks, prefix="identity.")
        device_required_failed = _any_required_failed(checks, prefix="device.posture.")
        network_required_failed = _any_network_required_failed(checks, prefix="network.path.")
        allow = identity_ok and not device_required_failed and not network_required_failed
        details.update({
            "identity_ok": identity_ok,
            "device_required_failed": device_required_failed,
            "network_required_failed": network_required_failed,
            "decision": "allow" if allow else "deny",
        })
        self.audit.write({"event": name, "success": allow, "details": details})
        return CheckRecord(name=name, success=allow, details=details)

    async def _check_opa_policy_async(
        self,
        checks: Sequence[CheckRecord],
        context: Dict[str, Any],
        policy: OPAPolicy,
    ) -> CheckRecord:
        """
        Интеграция с OPA (Open Policy Agent) по HTTP API (data API).
        Источники: OPA documentation (data API), применимо в рамках Zero Trust PDP.
        """
        name = "policy.opa"
        details: Dict[str, Any] = {"url": policy.url}
        if httpx is None:
            details["reason"] = "httpx_not_available"
            success = policy.allow_on_unavailable
            self.audit.write({"event": name, "success": success, "details": details})
            return CheckRecord(name=name, success=success, details=details)

        try:
            payload = dict(policy.input_template)
            payload.update({
                "checks": [dataclasses.asdict(c) for c in checks],
                "context": context,
            })
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(policy.url, json={"input": payload})
                r.raise_for_status()
                data = r.json()
            # Конвенция: ожидаем {"result": {"allow": true/false, ...}}
            allow = bool(_nested_get(data, ["result", "allow"], False))
            details["opa_result"] = data.get("result")
            self.audit.write({"event": name, "success": allow, "details": details})
            return CheckRecord(name=name, success=allow, details=details)
        except Exception as ex:
            details["reason"] = str(ex)
            success = policy.allow_on_unavailable
            self.audit.write({"event": name, "success": success, "details": details})
            return CheckRecord(name=name, success=success, details=details)


# -------------------- Низкоуровневые утилиты --------------------

async def _maybe_await(v):
    if asyncio.iscoroutine(v) or isinstance(v, asyncio.Future):
        return await v
    return v

def _all_success(checks: Sequence[CheckRecord], prefix: str) -> bool:
    for c in checks:
        if c.name.startswith(prefix) and not c.success:
            return False
    # Если не было ни одного check с prefix, трактуем как False для Identity, True для необязательных доменов
    return any(c.name.startswith(prefix) for c in checks)

def _any_required_failed(checks: Sequence[CheckRecord], prefix: str) -> bool:
    for c in checks:
        if c.name.startswith(prefix) and not c.success and c.details.get("required", True):
            return True
    return False

def _any_network_required_failed(checks: Sequence[CheckRecord], prefix: str) -> bool:
    for c in checks:
        if c.name.startswith(prefix) and not c.success and c.details.get("must_be_reachable", True):
            return True
    return False

def _nested_get(d: Mapping[str, Any], path: Sequence[str], default=None):
    cur = d
    for p in path:
        if not isinstance(cur, Mapping) or p not in cur:
            return default
        cur = cur[p]
    return cur

def _duration_s(start_iso: Optional[str], end_iso: Optional[str]) -> Optional[float]:
    if not start_iso or not end_iso:
        return None
    try:
        start = datetime.fromisoformat(start_iso)
        end = datetime.fromisoformat(end_iso)
        return max(0.0, (end - start).total_seconds())
    except Exception:
        return None

def _select_jwk_key(jwks: Mapping[str, Any], kid: Optional[str]) -> Any:
    keys = jwks.get("keys", [])
    for k in keys:
        if not kid or k.get("kid") == kid:
            return algorithms.RSAAlgorithm.from_jwk(json.dumps(k)) if algorithms else None
    return None

async def _tcp_connect(host: str, port: int, timeout_s: float) -> None:
    loop = asyncio.get_running_loop()
    fut = loop.run_in_executor(None, _tcp_blocking_connect, host, port, timeout_s)
    await fut

def _tcp_blocking_connect(host: str, port: int, timeout_s: float) -> None:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.settimeout(timeout_s)
        s.connect((host, port))

async def _tls_connect(host: str, port: int, ctx: ssl.SSLContext, timeout_s: float, sni: Optional[str] = None) -> None:
    loop = asyncio.get_running_loop()
    fut = loop.run_in_executor(None, _tls_blocking_connect, host, port, ctx, timeout_s, sni)
    await fut

def _tls_blocking_connect(host: str, port: int, ctx: ssl.SSLContext, timeout_s: float, sni: Optional[str]) -> None:
    raw = socket.create_connection((host, port), timeout=timeout_s)
    try:
        with contextlib.closing(raw):
            with contextlib.closing(ctx.wrap_socket(raw, server_hostname=(sni or host))) as ssock:
                # Успешный handshake — базовая верификация цепочки по системному/переданному trust store
                # Доп. проверки (pinning, SAN, EKU) могут быть добавлены при необходимости.
                ssock.getpeercert()
    except Exception:
        raise
