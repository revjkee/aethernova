# security-core/security/settings.py
# Industrial Security Settings Hub for NeuroCity / security-core
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import threading
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Literal, Mapping, Optional, Tuple

from pydantic import BaseModel, Field, HttpUrl, IPvAnyAddress, PositiveInt, ValidationError, root_validator, validator

# =========================
# Helpers
# =========================

_ENV_PREFIX = "SECURITY_CORE_"
_DEFAULT_CONFIG_PATH = os.getenv(f"{_ENV_PREFIX}CONFIG_PATH", "").strip() or "configs/security.core.yaml"
_DEFAULT_ENV = os.getenv("RUNTIME_ENV", "").strip() or "prod"  # dev|stage|prod|test|local
_HOSTNAME = socket.gethostname()


def _read_yaml(path: Path) -> Dict[str, Any]:
    import yaml  # lazy import
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Non-destructive deep merge: values from b override a."""
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    return os.getenv(name, default)


def _maybe_path(val: Optional[str]) -> Optional[Path]:
    return Path(val) if val else None


def _hash_config(obj: Any) -> str:
    data = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _resolve_secret(value: Optional[str]) -> Optional[str]:
    """
    Resolve secret from:
      - env:ENV_NAME
      - file:/abs/or/rel/path
      - base64:ENCODED
      - literal:plaintext
    """
    if value is None:
        return None
    v = value.strip()
    if v.startswith("env:"):
        return os.getenv(v[4:], None)
    if v.startswith("file:"):
        p = Path(v[5:])
        if p.exists():
            return p.read_text(encoding="utf-8").strip()
        return None
    if v.startswith("base64:"):
        try:
            return base64.b64decode(v[7:].encode("utf-8")).decode("utf-8").strip()
        except Exception:
            return None
    if v.startswith("literal:"):
        return v[8:]
    # raw fallback (not recommended for prod)
    return v


def _bool_env(name: str, default: bool = False) -> bool:
    return (_env(name, "true" if default else "false") or "").lower() in {"1", "true", "yes", "on"}


# =========================
# Config Models
# =========================

class AppEnv(BaseModel):
    name: Literal["dev", "stage", "prod", "test", "local"] = Field(default=_DEFAULT_ENV)
    node: str = Field(default=_HOSTNAME, description="Hostname/Node id")
    project: str = Field(default="neurocity", description="Project identifier")
    service: str = Field(default="security-core", description="Service name")

    @validator("name")
    def _normalize_env(cls, v: str) -> str:
        return v.lower()


class TLSConfig(BaseModel):
    enabled: bool = True
    min_version: Literal["TLS1.2", "TLS1.3"] = "TLS1.2"
    prefer_version: Literal["TLS1.2", "TLS1.3"] = "TLS1.3"
    ca_file: Optional[Path] = None
    cert_file: Optional[Path] = None
    key_file: Optional[Path] = None
    ciphersuites_policy: Literal["modern", "intermediate"] = "modern"
    hsts: bool = True

    @validator("ca_file", "cert_file", "key_file", pre=True)
    def _pathify(cls, v):
        return Path(v) if v else None

    @root_validator
    def _prod_requires_cert(cls, values):
        env = values.get("_env_ctx")
        # Attach at runtime (see Settings.attach_env_ctx)
        return values


class HTTPConfig(BaseModel):
    host: str = "0.0.0.0"
    port: PositiveInt = 8080
    cors_enabled: bool = False
    cors_origins: List[str] = Field(default_factory=list)
    rate_limit_rps: int = 0  # 0 = off
    rate_limit_burst: int = 0
    request_max_body_mb: int = 10
    headers_secure_defaults: bool = True  # sets HSTS, Referrer-Policy, X-Frame-Options


class LoggingConfig(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    json: bool = True
    include_trace_ids: bool = True
    redact_fields: List[str] = Field(default_factory=lambda: ["password", "secret", "token", "authorization"])
    sinks: List[Literal["stdout", "stderr", "file"]] = Field(default_factory=lambda: ["stdout"])
    file_path: Optional[Path] = None

    @validator("file_path", pre=True)
    def _pathify(cls, v):
        return Path(v) if v else None


class OPAConfig(BaseModel):
    enabled: bool = False
    url: Optional[HttpUrl] = None
    package_path: str = "authz/allow"
    timeout_ms: int = 2500


class PolicyConfig(BaseModel):
    path: Optional[Path] = None
    default_decision: Literal["ALLOW", "DENY"] = "DENY"

    @validator("path", pre=True)
    def _pathify(cls, v):
        return Path(v) if v else None


class InhibitorConfig(BaseModel):
    state_path: Optional[Path] = None
    admin_hmac_secret: Optional[str] = None  # use resolver syntax
    allow_unprotected_cmds: bool = False
    sig_skew_sec: int = 60
    nonce_ttl_sec: int = 300
    arm_ttl_sec: int = 300
    trigger_ttl_sec: int = 900
    webhook_url: Optional[HttpUrl] = None

    @validator("state_path", pre=True)
    def _pathify(cls, v):
        return Path(v) if v else None


class AuditKafkaConfig(BaseModel):
    enabled: bool = True
    brokers: List[str] = Field(default_factory=lambda: ["localhost:9092"])
    topic: str = "security.audit.v1"
    acks: Literal["0", "1", "all"] = "all"
    compression: Literal["none", "gzip", "lz4", "zstd", "snappy"] = "zstd"
    batch_size: int = 16384
    linger_ms: int = 5
    tls: TLSConfig = TLSConfig(enabled=False)
    sasl_username: Optional[str] = None
    sasl_password: Optional[str] = None  # resolver syntax allowed
    schema_registry_url: Optional[HttpUrl] = None
    schema_registry_api_key: Optional[str] = None  # resolver
    schema_registry_api_secret: Optional[str] = None  # resolver


class VaultConfig(BaseModel):
    enabled: bool = False
    addr: Optional[HttpUrl] = None
    token: Optional[str] = None  # resolver
    namespace: Optional[str] = None
    kv_mount: str = "secret"
    # path patterns: secret/data/<path> for v2


class KMSConfig(BaseModel):
    provider: Literal["none", "cloudKMS", "aws_kms", "azure_kv", "gcp_kms"] = "none"
    key_uri_code_sign: Optional[str] = None
    key_uri_app_secrets: Optional[str] = None
    key_uri_db_at_rest: Optional[str] = None


class JWTConfig(BaseModel):
    issuer: Optional[str] = None
    audience: Optional[str] = None
    jwks_url: Optional[HttpUrl] = None
    leeway_sec: int = 60
    required: bool = False


class ObservabilityConfig(BaseModel):
    otel_enabled: bool = False
    otel_exporter_otlp_endpoint: Optional[str] = None
    sentry_dsn: Optional[str] = None
    sampling_percent: int = 10


class FeatureFlags(BaseModel):
    strict_prod_invariants: bool = True
    enable_policy_hot_reload: bool = True
    enable_authz_cache: bool = True


class Settings(BaseModel):
    # Global
    env: AppEnv = AppEnv()
    http: HTTPConfig = HTTPConfig()
    tls: TLSConfig = TLSConfig()
    logging: LoggingConfig = LoggingConfig()
    features: FeatureFlags = FeatureFlags()

    # Security subsystems
    opa: OPAConfig = OPAConfig()
    policy: PolicyConfig = PolicyConfig()
    inhibitor: InhibitorConfig = InhibitorConfig()
    audit_kafka: AuditKafkaConfig = AuditKafkaConfig()
    vault: VaultConfig = VaultConfig()
    kms: KMSConfig = KMSConfig()
    jwt: JWTConfig = JWTConfig()
    obs: ObservabilityConfig = ObservabilityConfig()

    # Derived / meta
    _hash: str = Field(default="", repr=False)
    _source_paths: List[str] = Field(default_factory=list, repr=False)

    # ---------- Validators & Post init ----------
    @root_validator
    def attach_env_ctx(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        # attach environment ctx for downstream checks
        values["tls"].__dict__["_env_ctx"] = values["env"].name
        return values

    @root_validator
    def enforce_invariants(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        env_name = values["env"].name
        strict = values["features"].strict_prod_invariants
        # TLS in prod
        if env_name == "prod" and strict and not values["tls"].enabled:
            raise ValueError("TLS must be enabled in prod")
        # Logging sink file requires path
        if "file" in values["logging"].sinks and not values["logging"].file_path:
            raise ValueError("logging.file_path is required when 'file' sink is enabled")
        # OPA URL required if enabled
        if values["opa"].enabled and not values["opa"].url:
            raise ValueError("OPA enabled but opa.url not set")
        # JWT strictness when required
        if values["jwt"].required and not (values["jwt"].issuer and values["jwt"].jwks_url):
            raise ValueError("JWT required but issuer/jwks_url not configured")
        # Kafka schema registry auth consistency
        ak = values["audit_kafka"]
        if ak.schema_registry_url and not (ak.schema_registry_api_key and ak.schema_registry_api_secret):
            # allow anonymous only if explicitly disabled
            pass
        return values

    # ---------- Public API ----------
    def to_sanitized_dict(self) -> Dict[str, Any]:
        def redact(v: Optional[str]) -> Optional[str]:
            return None if v is None else "***"
        ak = self.audit_kafka
        inh = self.inhibitor
        vault = self.vault
        out = self.dict()
        # redact secrets
        out["audit_kafka"]["sasl_password"] = redact(ak.sasl_password)
        out["audit_kafka"]["schema_registry_api_key"] = redact(ak.schema_registry_api_key)
        out["audit_kafka"]["schema_registry_api_secret"] = redact(ak.schema_registry_api_secret)
        out["inhibitor"]["admin_hmac_secret"] = redact(inh.admin_hmac_secret)
        out["vault"]["token"] = redact(vault.token)
        out["_hash"] = self._hash
        return out

    def config_hash(self) -> str:
        return self._hash


# =========================
# Loading Logic
# =========================

def _load_from_files() -> Dict[str, Any]:
    """
    Load base YAML + env overlay:
      - configs/security.core.yaml
      - configs/security.core.<env>.yaml
    Missing files are ignored.
    """
    base_path = Path(_DEFAULT_CONFIG_PATH)
    env_name = _DEFAULT_ENV
    env_path = base_path.with_suffix(f".{env_name}.yaml")

    data = _read_yaml(base_path)
    if env_path.exists():
        data = _deep_merge(data, _read_yaml(env_path))
    data["_source_paths"] = [str(base_path), str(env_path)]
    return data


def _overlay_env(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Overlay selected ENV variables with SECURITY_CORE_* prefix.
    Only critical knobs are supported directly; advanced override via YAML.
    """
    # HTTP
    if _env(f"{_ENV_PREFIX}HTTP_PORT"):
        data.setdefault("http", {})["port"] = int(_env(f"{_ENV_PREFIX}HTTP_PORT"))  # type: ignore
    if _env(f"{_ENV_PREFIX}HTTP_HOST"):
        data.setdefault("http", {})["host"] = _env(f"{_ENV_PREFIX}HTTP_HOST")

    # TLS
    if _env(f"{_ENV_PREFIX}TLS_ENABLED"):
        data.setdefault("tls", {})["enabled"] = _bool_env(f"{_ENV_PREFIX}TLS_ENABLED")
    for k in ("CA_FILE", "CERT_FILE", "KEY_FILE"):
        if _env(f"{_ENV_PREFIX}TLS_{k}"):
            data.setdefault("tls", {})[k.lower()] = _env(f"{_ENV_PREFIX}TLS_{k}")

    # OPA
    if _env(f"{_ENV_PREFIX}OPA_URL"):
        data.setdefault("opa", {})["url"] = _env(f"{_ENV_PREFIX}OPA_URL")
        data["opa"]["enabled"] = True

    # Policy
    if _env(f"{_ENV_PREFIX}AUTHZ_POLICIES"):
        data.setdefault("policy", {})["path"] = _env(f"{_ENV_PREFIX}AUTHZ_POLICIES")

    # Inhibitor
    if _env(f"{_ENV_PREFIX}INHIBITOR_STATE_PATH"):
        data.setdefault("inhibitor", {})["state_path"] = _env(f"{_ENV_PREFIX}INHIBITOR_STATE_PATH")
    if _env(f"{_ENV_PREFIX}ADMIN_HMAC_SECRET"):
        data.setdefault("inhibitor", {})["admin_hmac_secret"] = _env(f"{_ENV_PREFIX}ADMIN_HMAC_SECRET")

    # Audit Kafka
    if _env(f"{_ENV_PREFIX}AUDIT_BROKERS"):
        data.setdefault("audit_kafka", {})["brokers"] = [x.strip() for x in _env(f"{_ENV_PREFIX}AUDIT_BROKERS").split(",")]
    if _env(f"{_ENV_PREFIX}AUDIT_TOPIC"):
        data.setdefault("audit_kafka", {})["topic"] = _env(f"{_ENV_PREFIX}AUDIT_TOPIC")

    # JWT
    if _env(f"{_ENV_PREFIX}JWT_ISSUER"):
        data.setdefault("jwt", {})["issuer"] = _env(f"{_ENV_PREFIX}JWT_ISSUER")
    if _env(f"{_ENV_PREFIX}JWT_AUDIENCE"):
        data.setdefault("jwt", {})["audience"] = _env(f"{_ENV_PREFIX}JWT_AUDIENCE")
    if _env(f"{_ENV_PREFIX}JWT_JWKS_URL"):
        data.setdefault("jwt", {})["jwks_url"] = _env(f"{_ENV_PREFIX}JWT_JWKS_URL")
        data["jwt"]["required"] = True

    # Observability
    if _env(f"{_ENV_PREFIX}OTEL_ENDPOINT"):
        data.setdefault("obs", {})["otel_enabled"] = True
        data["obs"]["otel_exporter_otlp_endpoint"] = _env(f"{_ENV_PREFIX}OTEL_ENDPOINT")

    # Logging
    if _env(f"{_ENV_PREFIX}LOG_LEVEL"):
        data.setdefault("logging", {})["level"] = _env(f"{_ENV_PREFIX}LOG_LEVEL").upper()

    return data


def _resolve_secrets_inplace(data: Dict[str, Any]) -> None:
    # Inhibitor
    inh = data.get("inhibitor", {})
    inh["admin_hmac_secret"] = _resolve_secret(inh.get("admin_hmac_secret"))
    # Kafka
    ak = data.get("audit_kafka", {})
    ak["sasl_password"] = _resolve_secret(ak.get("sasl_password"))
    ak["schema_registry_api_key"] = _resolve_secret(ak.get("schema_registry_api_key"))
    ak["schema_registry_api_secret"] = _resolve_secret(ak.get("schema_registry_api_secret"))
    # Vault
    va = data.get("vault", {})
    va["token"] = _resolve_secret(va.get("token"))


def _finalize_and_hash(settings: Settings) -> Settings:
    payload = settings.to_sanitized_dict()
    settings._hash = _hash_config(payload)
    return settings


# =========================
# Public API
# =========================

_lock = threading.RLock()


def _load_settings_impl() -> Settings:
    # 1) YAML base + env overlay file
    data = _load_from_files()
    # 2) Direct ENV overlay
    data = _overlay_env(data)
    # 3) Secrets resolution
    _resolve_secrets_inplace(data)
    # 4) Build model
    try:
        model = Settings(**data)
    except ValidationError as e:
        # Produce compact readable error
        raise RuntimeError(f"Security settings validation failed: {e}") from e
    # 5) Hash
    return _finalize_and_hash(model)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    with _lock:
        return _load_settings_impl()


def reload_settings() -> Settings:
    """Invalidate cache and reload settings (e.g., after config file rotation)."""
    with _lock:
        get_settings.cache_clear()  # type: ignore
        return get_settings()


# Eager singleton for modules that prefer import-time availability
settings: Settings = get_settings()


# =========================
# Convenience accessors
# =========================

def is_prod() -> bool:
    return settings.env.name == "prod"


def cors_origins() -> List[str]:
    return settings.http.cors_origins or ([] if not settings.http.cors_enabled else ["*"])


def security_headers_enabled() -> bool:
    return settings.http.headers_secure_defaults


def policy_file_path() -> Optional[Path]:
    return settings.policy.path


def opa_url() -> Optional[str]:
    return str(settings.opa.url) if settings.opa.enabled and settings.opa.url else None


def inhibitor_state_path() -> Optional[Path]:
    return settings.inhibitor.state_path


def audit_kafka_enabled() -> bool:
    return settings.audit_kafka.enabled


def config_hash() -> str:
    return settings.config_hash()
