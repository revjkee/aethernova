# File: zero-trust-core/zero_trust/settings.py
# Purpose: Industrial, type-safe settings for Zero Trust core (no heavy deps required).
# Python: 3.10+
from __future__ import annotations

import json
import os
import re
import socket
from dataclasses import dataclass, field, asdict
from datetime import timedelta
from ipaddress import ip_network
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

# Optional, soft-deps
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

__all__ = [
    "Settings",
    "SecretProvider",
    "EnvSecretProvider",
    "FileSecretProvider",
]

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

_DUR_RX = re.compile(
    r"""
    ^(?:
        P(?:(?P<days>\d+)D)?
        (?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?
      |
        (?:(?P<d>\d+)d)?\s*(?:(?P<h>\d+)h)?\s*(?:(?P<m>\d+)m)?\s*(?:(?P<s>\d+)s)?
    )$
    """,
    re.IGNORECASE | re.VERBOSE,
)

def _as_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    s = str(v).strip().lower()
    return s in ("1", "true", "yes", "y", "on")

def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default

def _as_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(str(v).strip())
    except Exception:
        return default

def _as_list(v: Any, sep: str = ",") -> List[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [s for s in (str(v).split(sep)) if s.strip()]

def _as_set(v: Any, sep: str = ",") -> List[str]:
    return list(dict.fromkeys(_as_list(v, sep=sep)))  # preserve order, remove dups

def _as_map(v: Any) -> Dict[str, str]:
    if v is None or v == "":
        return {}
    if isinstance(v, Mapping):
        return {str(k): str(v) for k, v in v.items()}  # type: ignore
    # Try JSON
    try:
        obj = json.loads(str(v))
        if isinstance(obj, Mapping):
            return {str(k): str(v) for k, v in obj.items()}  # type: ignore
    except Exception:
        pass
    # Fallback: k1=v1,k2=v2
    out: Dict[str, str] = {}
    for part in str(v).split(","):
        if "=" in part:
            k, vv = part.split("=", 1)
            out[k.strip()] = vv.strip()
    return out

def _parse_duration(v: Any, default: timedelta = timedelta(0)) -> timedelta:
    if v is None or v == "":
        return default
    if isinstance(v, timedelta):
        return v
    s = str(v).strip()
    m = _DUR_RX.match(s)
    if not m:
        return default
    gd = m.groupdict()
    days = _as_int(gd.get("days") or gd.get("d"), 0)
    hours = _as_int(gd.get("hours") or gd.get("h"), 0)
    minutes = _as_int(gd.get("minutes") or gd.get("m"), 0)
    seconds = _as_int(gd.get("seconds") or gd.get("s"), 0)
    return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)

def _env(name: str, default: Any = None) -> Optional[str]:
    return os.getenv(name, default if default is not None else None)

def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "localhost"

def _mask_secret(v: Optional[str]) -> Optional[str]:
    if not v:
        return v
    if len(v) <= 8:
        return "*" * len(v)
    return v[:2] + "…" + v[-2:]

# -----------------------------------------------------------------------------
# Secret providers (pluggable)
# -----------------------------------------------------------------------------

class SecretProvider:
    """
    Abstract secret provider. Implement resolve("sm://path") -> str
    """
    def resolve(self, ref: str) -> Optional[str]:
        raise NotImplementedError

class EnvSecretProvider(SecretProvider):
    """
    Resolve env://VAR_NAME -> $VAR_NAME. For plain values returns as-is.
    """
    def resolve(self, ref: str) -> Optional[str]:
        if ref.startswith("env://"):
            return os.getenv(ref[6:])
        return ref

class FileSecretProvider(SecretProvider):
    """
    Resolve file:///abs/path or file://relative -> file contents (stripped).
    """
    def resolve(self, ref: str) -> Optional[str]:
        if ref.startswith("file://"):
            path = ref[7:]
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return f.read().strip()
            except Exception:
                return None
        return ref

# -----------------------------------------------------------------------------
# Settings sections
# -----------------------------------------------------------------------------

@dataclass
class AppSettings:
    env: str = "prod"             # prod|staging|dev|test
    region: str = "eu-central-1"
    tenant_mode: str = "multi"    # single|multi
    service_name: str = "zero-trust-core"
    instance_id: str = field(default_factory=_hostname)

    def __post_init__(self) -> None:
        if self.tenant_mode not in ("single", "multi"):
            raise ValueError("tenant_mode must be single|multi")

@dataclass
class HttpSettings:
    host: str = "0.0.0.0"
    port: int = 8080
    root_path: str = ""
    workers: int = 0                            # 0 -> auto
    request_timeout: timedelta = timedelta(seconds=30)
    idle_timeout: timedelta = timedelta(seconds=60)
    allowed_hosts: List[str] = field(default_factory=lambda: ["*"])
    cors_allow_origins: List[str] = field(default_factory=lambda: [])
    cors_allow_headers: List[str] = field(default_factory=lambda: ["authorization", "content-type", "x-request-id"])
    cors_allow_methods: List[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "PATCH"])
    cors_allow_credentials: bool = False
    tls_cert_file: str = ""
    tls_key_file: str = ""
    secure_headers: Dict[str, str] = field(default_factory=lambda: {
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none';",
        "referrer-policy": "no-referrer",
        "x-content-type-options": "nosniff",
        "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    })

    def __post_init__(self) -> None:
        if not (0 <= self.port <= 65535):
            raise ValueError("HTTP port out of range")

@dataclass
class GrpcSettings:
    host: str = "0.0.0.0"
    port: int = 9090
    max_concurrent_streams: int = 1024
    require_binding_for_methods: List[str] = field(default_factory=lambda: ["/zero.trust.v1.Admin/*", "/zero.trust.v1.Secrets/*"])
    allow_unauthenticated_methods: List[str] = field(default_factory=lambda: ["/grpc.health.v1.Health/Check", "/grpc.health.v1.Health/Watch"])
    request_id_header: str = "x-request-id"

    def __post_init__(self) -> None:
        if not (0 <= self.port <= 65535):
            raise ValueError("gRPC port out of range")

@dataclass
class JwtSettings:
    issuer: str = "https://auth.example.com"
    default_audience: str = "api://default"
    signing_alg: str = "ES256"           # ES256|EdDSA|RS256
    jwks_path: str = "/etc/security/jwks.json"
    jwks_url: str = ""
    accept_retiring_kids_for: timedelta = timedelta(hours=24)
    # JWE
    jwe_enabled: bool = True
    jwe_alg: str = "ECDH-ES+A256KW"
    jwe_enc: str = "A256GCM"

    def __post_init__(self) -> None:
        if self.signing_alg not in ("ES256", "EdDSA", "RS256"):
            raise ValueError("Unsupported signing_alg")
        if self.jwe_enabled and self.jwe_enc not in ("A256GCM", "A128GCM"):
            raise ValueError("Unsupported jwe enc")

@dataclass
class CookieSettings:
    enabled: bool = True
    name: str = "zt_sid"
    domain: str = ""
    path: str = "/"
    http_only: bool = True
    secure: bool = True
    same_site: str = "strict"  # strict|lax|none
    partitioned: bool = True

    def __post_init__(self) -> None:
        if self.same_site not in ("strict", "lax", "none"):
            raise ValueError("same_site must be strict|lax|none")

@dataclass
class CsrfSettings:
    enabled: bool = True
    header_name: str = "x-csrf-token"
    cookie_name: str = "zt_csrf"

@dataclass
class RedisSettings:
    urls: List[str] = field(default_factory=lambda: ["redis+tls://redis-1:6379", "redis+tls://redis-2:6379", "redis+tls://redis-3:6379"])
    db: int = 0
    tls: bool = True
    pool_max: int = 256
    min_idle: int = 16
    socket_timeout_ms: int = 50
    key_prefix: str = "zt:sess:"
    password_ref: str = "env://REDIS_PASSWORD"  # secret ref, resolve via SecretProvider

@dataclass
class PostgresSettings:
    dsn: str = "postgresql://user:pass@localhost:5432/zt_core"
    app_tenant_setting: str = "app.tenant_id"
    statement_timeout_ms: int = 60000

@dataclass
class KafkaSettings:
    brokers: List[str] = field(default_factory=lambda: ["broker-1:9092", "broker-2:9092"])
    acks: str = "all"
    compression: str = "zstd"
    # Topics
    topic_audit: str = "zt.audit"
    topic_logout: str = "zt.logout"

@dataclass
class OTelSettings:
    enabled: bool = True
    exporter_otlp_endpoint: str = "http://otel-collector:4317"
    service_name: str = "zero-trust-core"
    resource_attrs: Dict[str, str] = field(default_factory=lambda: {})

@dataclass
class MTLSSettings:
    required_for_admin: bool = True
    ca_bundle_ref: str = "file:///etc/pki/mtls/ca_bundle.pem"  # secret ref or file ref
    subject_dn_pattern: str = "OU=CorpVPN, O=Example Inc, CN=*"
    pin_spki_hashes: List[str] = field(default_factory=list)

@dataclass
class BindingPolicies:
    dpop_required_percent: int = 0              # 0..100 rollout
    require_binding_paths: List[str] = field(default_factory=lambda: ["POST:/admin/*", "GET:/internal/keys/*"])

    def __post_init__(self) -> None:
        if not (0 <= self.dpop_required_percent <= 100):
            raise ValueError("dpop_required_percent must be 0..100")

@dataclass
class RiskSettings:
    allow_max: int = 29
    step_up_min: int = 30
    deny_min: int = 70

    def __post_init__(self) -> None:
        if not (0 <= self.allow_max < self.step_up_min <= self.deny_min <= 100):
            raise ValueError("Risk thresholds must satisfy: 0<=allow<step_up<=deny<=100")

@dataclass
class RateLimitSettings:
    login_limit: int = 10
    login_window: timedelta = timedelta(minutes=5)
    refresh_limit: int = 60
    refresh_window: timedelta = timedelta(minutes=1)

@dataclass
class CORSSettings:
    allow_origins: List[str] = field(default_factory=list)
    allow_methods: List[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "PATCH"])
    allow_headers: List[str] = field(default_factory=lambda: ["authorization", "content-type", "x-request-id"])
    allow_credentials: bool = False

@dataclass
class LoggingSettings:
    http_logger: str = "zt.http"
    grpc_logger: str = "zt.grpc.auth"
    level: str = "info"            # debug|info|warning|error
    sample_req_body: bool = True
    sample_res_body: bool = False
    sample_max_bytes: int = 2048

@dataclass
class ComplianceSettings:
    gdpr_retention_days: int = 90
    soc2_access_review_days: int = 90
    hipaa_enabled: bool = False

# -----------------------------------------------------------------------------
# Root settings
# -----------------------------------------------------------------------------

@dataclass
class Settings:
    app: AppSettings = field(default_factory=AppSettings)
    http: HttpSettings = field(default_factory=HttpSettings)
    grpc: GrpcSettings = field(default_factory=GrpcSettings)
    jwt: JwtSettings = field(default_factory=JwtSettings)
    cookies: CookieSettings = field(default_factory=CookieSettings)
    csrf: CsrfSettings = field(default_factory=CsrfSettings)
    redis: RedisSettings = field(default_factory=RedisSettings)
    postgres: PostgresSettings = field(default_factory=PostgresSettings)
    kafka: KafkaSettings = field(default_factory=KafkaSettings)
    otel: OTelSettings = field(default_factory=OTelSettings)
    mtls: MTLSSettings = field(default_factory=MTLSSettings)
    binding: BindingPolicies = field(default_factory=BindingPolicies)
    risk: RiskSettings = field(default_factory=RiskSettings)
    ratelimit: RateLimitSettings = field(default_factory=RateLimitSettings)
    cors: CORSSettings = field(default_factory=CORSSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)

    # -------------------------
    # Loaders
    # -------------------------
    @classmethod
    def load(
        cls,
        *,
        env: Mapping[str, str] | None = None,
        config_file: str | None = None,
        secret_provider: SecretProvider | None = None,
    ) -> "Settings":
        """
        Load settings from optional config file and environment (ZT_*).
        Precedence: defaults < file < environment.
        """
        env = dict(os.environ if env is None else env)
        cfg: Dict[str, Any] = {}
        if config_file:
            cfg = _load_config_file(config_file)
        s = cls()  # with defaults
        # overlay file
        if cfg:
            _overlay_dataclass(s, cfg)
        # overlay env
        _apply_env_overrides(s, env)
        # resolve secrets if provider is given
        if secret_provider:
            _resolve_secrets(s, secret_provider)
        return s

    # -------------------------
    # Validation and helpers
    # -------------------------
    def validate(self) -> None:
        # Trigger sub-dataclass validations
        self.app.__post_init__(); self.http.__post_init__(); self.grpc.__post_init__()
        self.jwt.__post_init__(); self.cookies.__post_init__(); self.binding.__post_init__()
        self.risk.__post_init__()
        # Additional cross-section checks
        if self.cookies.enabled and not self.cookies.secure:
            raise ValueError("cookies.secure must be true in Zero Trust")
        if self.jwt.jwe_enabled and not self.jwt.jwks_path and not self.jwt.jwks_url:
            raise ValueError("JWKS must be provided for JWT/JWE (jwks_path or jwks_url)")
        if self.grpc.request_id_header.lower() not in ("x-request-id", "x-correlation-id"):
            raise ValueError("grpc.request_id_header should be x-request-id or x-correlation-id")

    def to_dict(self, redact_secrets: bool = True) -> Dict[str, Any]:
        d = asdict(self)
        if redact_secrets:
            # mask known secret refs/fields
            _mask_inplace(d, keys=["password_ref", "dsn", "ca_bundle_ref", "jwks_path"])
        return d

# -----------------------------------------------------------------------------
# Internal loaders/overlays
# -----------------------------------------------------------------------------

def _load_config_file(path: str) -> Dict[str, Any]:
    if path.lower().endswith(
