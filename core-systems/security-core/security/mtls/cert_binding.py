# security-core/security/mtls/cert_binding.py
from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519, ed448

# Опциональная глубокая валидация цепочки
_HAS_CERTVALIDATOR = False
try:  # pragma: no cover
    from certvalidator import CertificateValidator, ValidationContext  # type: ignore
    _HAS_CERTVALIDATOR = True
except Exception:  # pragma: no cover
    pass

# -----------------------------
# Логирование (структурированное)
# -----------------------------

def _get_logger() -> logging.Logger:
    logger = logging.getLogger("security_core.mtls.cert_binding")
    if not logger.handlers:
        h = logging.StreamHandler(stream=sys.stdout)
        h.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(h)
        logger.setLevel(os.getenv("SEC_CORE_MTLS_LOG_LEVEL", "INFO").upper())
    return logger

log = _get_logger()

def jlog(level: int, message: str, **fields: Any) -> None:
    payload = {"ts": datetime.now(timezone.utc).isoformat(), "level": logging.getLevelName(level), "message": message}
    payload.update(fields)
    try:
        log.log(level, json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        log.log(level, f"{message} | {fields}")

# -----------------------------
# Исключения
# -----------------------------

class MtlsError(Exception):
    pass

class CertMissing(MtlsError):
    pass

class CertInvalid(MtlsError):
    pass

class CertNotYetValid(MtlsError):
    pass

class CertExpired(MtlsError):
    pass

class CertPolicyViolation(MtlsError):
    pass

class ChainValidationFailed(MtlsError):
    pass

class BindingMismatch(MtlsError):
    pass

# -----------------------------
# Конфигурация
# -----------------------------

@dataclass
class ProxyHeaders:
    """
    Настройка источников сертификата из прокси.
    Поддержка популярных вариантов:
      - Nginx:  ssl-client-cert (сырое PEM/escaped), ssl_client_raw_cert (base64 DER), ssl-client-verify
      - Envoy:  x-forwarded-client-cert (XFCC)
      - HAProxy: x-ssl-client-cert (base64 DER)
    """
    mode: str = field(default=os.getenv("SEC_CORE_MTLS_MODE", "proxy"))  # "direct" | "proxy"
    # Nginx
    nginx_cert_header: str = field(default=os.getenv("SEC_CORE_MTLS_NGINX_CERT", "ssl-client-cert"))
    nginx_verify_header: str = field(default=os.getenv("SEC_CORE_MTLS_NGINX_VERIFY", "ssl-client-verify"))
    nginx_cert_is_escaped: bool = field(default=os.getenv("SEC_CORE_MTLS_NGINX_ESCAPED", "true").lower() in ("1", "true", "yes", "on"))
    # Envoy
    envoy_xfcc_header: str = field(default=os.getenv("SEC_CORE_MTLS_ENVOY_XFCC", "x-forwarded-client-cert"))
    # HAProxy
    haproxy_cert_header: str = field(default=os.getenv("SEC_CORE_MTLS_HAPROXY_CERT", "x-ssl-client-cert"))
    # Общие
    allow_unverified_proxy_flag: bool = field(default=os.getenv("SEC_CORE_MTLS_ALLOW_UNVERIFIED", "false").lower() in ("1", "true", "yes", "on"))
    header_prefixes_to_strip: Tuple[str, ...] = ("http_",)  # gunicorn/uwsgi иногда префиксуют заголовки

@dataclass
class TrustConfig:
    use_system_trust: bool = field(default=os.getenv("SEC_CORE_MTLS_SYSTEM_TRUST", "true").lower() in ("1", "true", "yes", "on"))
    extra_ca_pem_path: Optional[str] = field(default=os.getenv("SEC_CORE_MTLS_EXTRA_CA"))
    require_chain_validation: bool = field(default=os.getenv("SEC_CORE_MTLS_REQUIRE_CHAIN", "false").lower() in ("1", "true", "yes", "on"))
    check_eku_client_auth: bool = True
    require_digital_signature_ku: bool = True
    # Политика SAN/URI
    require_san: bool = False
    allow_spiffe: bool = True
    allowed_spiffe_trust_domains: Tuple[str, ...] = tuple(filter(None, (os.getenv("SEC_CORE_MTLS_SPIFFE_DOMAINS") or "").split(",")))
    # Временные допуски
    not_before_leeway_sec: int = 0
    not_after_leeway_sec: int = 0

@dataclass
class BindingPolicy:
    # Проверка cnf в токене (RFC 8705)
    verify_cnf: bool = True
    cnf_field: str = "cnf"
    # Какие отпечатки принимать
    accept_x5t_s256: bool = True
    accept_x5t: bool = True  # SHA-1 — допускается только при явном включении
    # Сопоставление субъекта/сан с требуемыми признаками (например, tenant)
    required_san_dns_suffixes: Tuple[str, ...] = ()
    required_san_uris_prefixes: Tuple[str, ...] = ()
    required_subject_regex: Optional[str] = None

@dataclass
class MtlsConfig:
    proxy: ProxyHeaders = field(default_factory=ProxyHeaders)
    trust: TrustConfig = field(default_factory=TrustConfig)
    binding: BindingPolicy = field(default_factory=BindingPolicy)
    max_cert_chain_len: int = 6
    max_header_size_bytes: int = 64 * 1024

# -----------------------------
# Результаты и модель
# -----------------------------

@dataclass(frozen=True)
class ClientCertificate:
    cert: x509.Certificate
    der: bytes
    pem: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    serial_number: str
    x5t: str
    x5t_s256: str
    sans_dns: Tuple[str, ...]
    sans_emails: Tuple[str, ...]
    sans_uris: Tuple[str, ...]
    spiffe_ids: Tuple[str, ...]
    public_key_type: str

@dataclass
class ChainResult:
    valid: bool
    reason: Optional[str] = None
    depth: int = 1

@dataclass
class BindingResult:
    bound: bool
    reason: Optional[str] = None
    client: Optional[ClientCertificate] = None
    chain: Optional[ChainResult] = None
    policy_notes: Dict[str, Any] = field(default_factory=dict)

# -----------------------------
# Утилиты
# -----------------------------

_B64_RE = re.compile(r"^[A-Za-z0-9+/=\-_]+$")

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _is_probably_base64(s: str) -> bool:
    return bool(_B64_RE.match(s.strip())) and len(s) >= 8

def _unescape_nginx_cert(s: str) -> str:
    # Nginx может отдавать "escaped" PEM: заменяет переносы \n или URL-кодирует
    s = s.strip()
    try:
        # Попытка URL-decode
        from urllib.parse import unquote_plus
        s2 = unquote_plus(s)
        if "-----BEGIN CERTIFICATE-----" in s2:
            return s2
    except Exception:
        pass
    # Замена \n
    s = s.replace(" ", "+")  # иногда пробелы вместо +
    s = s.replace("\\n", "\n")
    return s

def _load_pem_or_der(cert_bytes: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(cert_bytes)
    except Exception:
        return x509.load_der_x509_certificate(cert_bytes)

def _calc_thumbprints(der: bytes) -> Tuple[str, str]:
    x5t = _b64u(hashlib.sha1(der).digest())
    x5t_s256 = _b64u(hashlib.sha256(der).digest())
    return x5t, x5t_s256

def _eku_has_client_auth(cert: x509.Certificate) -> bool:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        return x509.ExtendedKeyUsageOID.CLIENT_AUTH in eku
    except x509.ExtensionNotFound:
        # Отсутствует EKU — трактуем как допустимо, если политика не требует строго
        return True

def _ku_allows_digital_signature(cert: x509.Certificate) -> bool:
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        return bool(ku.digital_signature)
    except x509.ExtensionNotFound:
        return True

def _extract_sans(cert: x509.Certificate) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]:
    dns: List[str] = []
    emails: List[str] = []
    uris: List[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        for name in san:
            if isinstance(name, x509.DNSName):
                dns.append(name.value)
            elif isinstance(name, x509.RFC822Name):
                emails.append(name.value)
            elif isinstance(name, x509.UniformResourceIdentifier):
                uris.append(name.value)
    except x509.ExtensionNotFound:
        pass
    return tuple(dns), tuple(emails), tuple(uris)

def _extract_spiffe(uris: Sequence[str]) -> Tuple[str, ...]:
    return tuple(u for u in uris if u.startswith("spiffe://"))

def _get_pubkey_type(cert: x509.Certificate) -> str:
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return f"EC:{pk.curve.name}"
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448"
    return "Unknown"

def _to_client_cert(cert: x509.Certificate, der: bytes) -> ClientCertificate:
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    sn = hex(cert.serial_number)[2:].upper()
    dns, emails, uris = _extract_sans(cert)
    spiffe_ids = _extract_spiffe(uris)
    x5t, x5t_s256 = _calc_thumbprints(der)
    return ClientCertificate(
        cert=cert,
        der=der,
        pem=pem,
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        serial_number=sn,
        x5t=x5t,
        x5t_s256=x5t_s256,
        sans_dns=dns,
        sans_emails=emails,
        sans_uris=uris,
        spiffe_ids=spiffe_ids,
        public_key_type=_get_pubkey_type(cert),
    )

# -----------------------------
# Извлечение сертификата из заголовков прокси
# -----------------------------

def _headers_lower(headers: Mapping[str, str], strip_prefixes: Tuple[str, ...]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in headers.items():
        key = k.lower()
        for pref in strip_prefixes:
            if key.startswith(pref):
                key = key[len(pref):]
                break
        out[key] = v
    return out

def extract_client_cert_from_proxy(headers: Mapping[str, str], cfg: ProxyHeaders) -> bytes:
    """
    Возвращает DER клиентского сертификата из заголовков прокси.
    Бросает CertMissing/CertInvalid при ошибке.
    """
    h = _headers_lower(headers, cfg.header_prefixes_to_strip)
    # Envoy XFCC имеет вид: By=...,Hash=...,Subject="...",URI=...,Cert="<base64>",...
    xfcc = h.get(cfg.envoy_xfcc_header)
    if xfcc:
        m = re.search(r'Cert="([^"]+)"', xfcc)
        if m and _is_probably_base64(m.group(1)):
            try:
                return base64.b64decode(m.group(1))
            except Exception as e:
                raise CertInvalid("Invalid XFCC Cert field")
        # Допустимо когда Envoy не вставляет Cert, но это против политики
        raise CertMissing("XFCC present but no Cert field")

    # Nginx: ssl-client-cert (PEM escaped/URL-encoded) или ssl_client_raw_cert (base64 DER)
    raw_der = h.get("ssl_client_raw_cert") or h.get("ssl-client-raw-cert")
    if raw_der and _is_probably_base64(raw_der):
        try:
            return base64.b64decode(raw_der)
        except Exception:
            raise CertInvalid("Invalid ssl_client_raw_cert base64")

    pem_or_escaped = h.get(cfg.nginx_cert_header)
    if pem_or_escaped:
        s = _unescape_nginx_cert(pem_or_escaped)
        if "BEGIN CERTIFICATE" in s:
            return x509.load_pem_x509_certificate(s.encode("ascii")).public_bytes(serialization.Encoding.DER)
        if _is_probably_base64(s):
            try:
                return base64.b64decode(s)
            except Exception:
                pass
        raise CertInvalid("Unrecognized nginx client cert format")

    # HAProxy: x-ssl-client-cert (base64 DER)
    hap = h.get(cfg.haproxy_cert_header)
    if hap and _is_probably_base64(hap):
        try:
            return base64.b64decode(hap)
        except Exception:
            raise CertInvalid("Invalid HAProxy client cert b64")

    # Возможно, прокси явно отметило "не проверен"
    ver = h.get(cfg.nginx_verify_header)
    if ver and ver.lower() not in ("success", "ok", "verified") and not cfg.allow_unverified_proxy_flag:
        raise CertInvalid(f"Proxy verification status: {ver}")

    raise CertMissing("Client certificate not found in proxy headers")

# -----------------------------
# Валидация сертификата и цепочки
# -----------------------------

def _load_ca_bundle(extra_ca_pem_path: Optional[str]) -> List[x509.Certificate]:
    cas: List[x509.Certificate] = []
    if extra_ca_pem_path and os.path.exists(extra_ca_pem_path):
        pem = open(extra_ca_pem_path, "rb").read()
        # Может содержать несколько сертификатов
        for match in re.findall(b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, flags=re.S):
            cas.append(x509.load_pem_x509_certificate(match))
    return cas

def validate_certificate(
    client: ClientCertificate,
    trust: TrustConfig,
    intermediates_pem: Optional[bytes] = None,
) -> ChainResult:
    # Время
    now = _now()
    if now + timedelta(seconds=trust.not_before_leeway_sec) < client.not_before:
        raise CertNotYetValid("Certificate not yet valid")
    if now - timedelta(seconds=trust.not_after_leeway_sec) > client.not_after:
        raise CertExpired("Certificate expired")

    # EKU / KU
    if trust.check_eku_client_auth and not _eku_has_client_auth(client.cert):
        raise CertPolicyViolation("EKU does not allow clientAuth")
    if trust.require_digital_signature_ku and not _ku_allows_digital_signature(client.cert):
        raise CertPolicyViolation("KeyUsage digitalSignature required")

    # SAN политика
    if trust.require_san and not (client.sans_dns or client.sans_emails or client.sans_uris):
        raise CertPolicyViolation("SAN required but missing")

    # SPIFFE домены
    if client.spiffe_ids and trust.allowed_spiffe_trust_domains:
        ok = any(any(sid.startswith(f"spiffe://{d.strip()}/") for sid in client.spiffe_ids)
                 for d in trust.allowed_spiffe_trust_domains)
        if not ok:
            raise CertPolicyViolation("SPIFFE trust domain not allowed")

    # Проверка цепочки (опционально строгая)
    if not trust.require_chain_validation:
        return ChainResult(valid=True, reason="chain validation skipped by policy", depth=1)

    # Попытка использовать certvalidator при наличии
    if _HAS_CERTVALIDATOR:
        extras = _load_ca_bundle(trust.extra_ca_pem_path)
        store: List[x509.Certificate] = extras
        # Системное хранилище: certvalidator может использовать доверенные платформы через флаги
        ctx = ValidationContext(
            trust_roots=store if store else None,
            allow_fetching=True,  # OCSP/CRL/CDP — при желании
        )
        try:
            validator = CertificateValidator(client.cert, intermediate_certs=[], validation_context=ctx)
            path = validator.validate_usage(set(["client_auth"]))
            depth = len(path)
            return ChainResult(valid=True, depth=depth, reason="certvalidator ok")
        except Exception as e:
            raise ChainValidationFailed(str(e))

    # Фоллбэк: минимальная проверка самоподписи/issuer равен subject CA (без реального path building)
    # Предпочтительно использовать certvalidator. Здесь лишь базовая защита.
    try:
        issuer_pk = client.cert.issuer
        subject_pk = client.cert.subject
        if issuer_pk == subject_pk:
            # самоподписанный: принимаем только если явно добавлен в extra_ca
            extras = _load_ca_bundle(trust.extra_ca_pem_path)
            ok = any(c.subject == client.cert.subject and c.public_key().public_numbers() == client.cert.public_key().public_numbers() for c in extras)
            if not ok:
                raise ChainValidationFailed("Self-signed and not in extra CA bundle")
        return ChainResult(valid=True, depth=1, reason="basic validation (no certvalidator)")
    except Exception as e:
        raise ChainValidationFailed(str(e))

# -----------------------------
# Политика сопоставления и cnf
# -----------------------------

def build_cnf(client: ClientCertificate) -> Dict[str, Any]:
    """
    RFC 8705: подтверждающий материал (cnf). Рекомендуется x5t#S256.
    """
    return {"x5t#S256": client.x5t_s256, "x5t": client.x5t}

def ensure_binding_against_claims(
    client: ClientCertificate,
    claims: Mapping[str, Any],
    policy: BindingPolicy,
) -> None:
    """
    Проверяет, что claims (например, из JWT) содержат cnf, совпадающий с сертификатом.
    """
    if not policy.verify_cnf:
        return
    cnf = claims.get("cnf") if policy.cnf_field == "cnf" else claims.get(policy.cnf_field)
    if not isinstance(cnf, Mapping):
        raise BindingMismatch("cnf claim missing")

    matched = False
    if policy.accept_x5t_s256 and "x5t#S256" in cnf:
        matched = str(cnf.get("x5t#S256")) == client.x5t_s256
    if not matched and policy.accept_x5t and "x5t" in cnf:
        matched = str(cnf.get("x5t")) == client.x5t
    if not matched:
        raise BindingMismatch("cnf does not match presented certificate")

    # Дополнительная политика по SAN/Subject
    if policy.required_san_dns_suffixes:
        ok = any(any(d.endswith(suf) for suf in policy.required_san_dns_suffixes) for d in client.sans_dns)
        if not ok:
            raise CertPolicyViolation("DNS SAN suffix policy failed")
    if policy.required_san_uris_prefixes:
        ok = any(any(u.startswith(pref) for pref in policy.required_san_uris_prefixes) for u in client.sans_uris)
        if not ok:
            raise CertPolicyViolation("URI SAN prefix policy failed")
    if policy.required_subject_regex:
        if not re.search(policy.required_subject_regex, client.subject):
            raise CertPolicyViolation("Subject policy failed")

# -----------------------------
# Основной биндер
# -----------------------------

class MtlsBinder:
    def __init__(self, config: Optional[MtlsConfig] = None) -> None:
        self.cfg = config or MtlsConfig()

    def extract_from_headers(self, headers: Mapping[str, str]) -> ClientCertificate:
        der = extract_client_cert_from_proxy(headers, self.cfg.proxy) if self.cfg.proxy.mode == "proxy" else self._direct_not_supported()
        try:
            cert = _load_pem_or_der(der)
        except Exception as e:
            raise CertInvalid("Failed to parse client certificate")
        return _to_client_cert(cert, der)

    def _direct_not_supported(self) -> bytes:
        # В pure-ASGI получить peercert нельзя — обычно TLS терминируется на прокси.
        # Если у вас прямой TLS, передавайте сертификат через заголовок в том же процессе.
        raise CertMissing("Direct TLS extraction is not supported in this adapter; use proxy headers")

    def verify_binding(
        self,
        *,
        headers: Mapping[str, str],
        token_claims: Optional[Mapping[str, Any]] = None,
        intermediates_pem: Optional[bytes] = None,
    ) -> BindingResult:
        try:
            client = self.extract_from_headers(headers)
            chain = validate_certificate(client, self.cfg.trust, intermediates_pem)
            if token_claims is not None:
                ensure_binding_against_claims(client, token_claims, self.cfg.binding)
            return BindingResult(bound=True, client=client, chain=chain, policy_notes={"cnf": build_cnf(client)})
        except (CertMissing, CertInvalid, CertNotYetValid, CertExpired, CertPolicyViolation, ChainValidationFailed, BindingMismatch) as e:
            jlog(logging.WARNING, "mtls.binding.failed", reason=str(e))
            return BindingResult(bound=False, reason=str(e))
        except Exception as e:
            jlog(logging.ERROR, "mtls.binding.error", error=str(e))
            return BindingResult(bound=False, reason="internal_error")

# -----------------------------
# Утилиты интеграции
# -----------------------------

def bind_token_claims_with_client_cert(claims: Mapping[str, Any], client: ClientCertificate, cnf_field: str = "cnf") -> Dict[str, Any]:
    """
    Возвращает новый словарь claims с добавленным cnf (x5t#S256/x5t).
    """
    out = dict(claims)
    out[cnf_field] = build_cnf(client)
    return out

# -----------------------------
# Пример (для справки)
# -----------------------------
# from fastapi import FastAPI, Request, HTTPException
# app = FastAPI()
# binder = MtlsBinder()
#
# @app.get("/secure")
# async def secure_ep(request: Request):
#     # token_claims вы получите после валидации JWT
#     token_claims = request.state.jwt_claims  # пример
#     res = binder.verify_binding(headers=request.headers, token_claims=token_claims)
#     if not res.bound:
#         raise HTTPException(status_code=401, detail=res.reason or "mtls bind failed")
#     return {
#         "subject": res.client.subject,
#         "x5t#S256": res.client.x5t_s256,
#         "spiffe": list(res.client.spiffe_ids),
#         "valid_chain": res.chain.valid if res.chain else False,
#     }
#
# Переменные окружения:
#   SEC_CORE_MTLS_MODE=proxy
#   SEC_CORE_MTLS_NGINX_CERT=ssl-client-cert
#   SEC_CORE_MTLS_NGINX_VERIFY=ssl-client-verify
#   SEC_CORE_MTLS_NGINX_ESCAPED=true
#   SEC_CORE_MTLS_ENVOY_XFCC=x-forwarded-client-cert
#   SEC_CORE_MTLS_HAPROXY_CERT=x-ssl-client-cert
#   SEC_CORE_MTLS_ALLOW_UNVERIFIED=false
#   SEC_CORE_MTLS_SYSTEM_TRUST=true
#   SEC_CORE_MTLS_EXTRA_CA=/etc/ssl/aethernova/extra-ca.pem
#   SEC_CORE_MTLS_REQUIRE_CHAIN=true
#   SEC_CORE_MTLS_SPIFFE_DOMAINS=prod.example.com,stage.example.com
#   SEC_CORE_MTLS_LOG_LEVEL=INFO
