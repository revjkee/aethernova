# mythos-core/mythos/settings.py
# Industrial settings loader for Mythos: typed, nested, ENV-first, secrets-aware, no external deps.
from __future__ import annotations

import dataclasses
import json
import logging
import os
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple, Type, Union, get_args, get_origin

# =========================
# Utilities: parsing & casting
# =========================

_BOOL_TRUE = {"1", "true", "yes", "y", "on", "t"}
_BOOL_FALSE = {"0", "false", "no", "n", "off", "f"}

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)([smhd]?)\s*$", re.IGNORECASE)

def parse_bool(val: Union[str, bool, int, None], default: bool = False) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return default
    s = str(val).strip().lower()
    if s in _BOOL_TRUE:
        return True
    if s in _BOOL_FALSE:
        return False
    return default

def parse_int(val: Union[str, int, float, None], default: int = 0) -> int:
    if val is None:
        return default
    try:
        return int(str(val).strip().replace("_", ""))
    except Exception:
        return default

def parse_float(val: Union[str, int, float, None], default: float = 0.0) -> float:
    if val is None:
        return default
    try:
        return float(str(val).strip().replace("_", ""))
    except Exception:
        return default

def parse_list(val: Union[str, Iterable[str], None], subtype: Type = str) -> List:
    if val is None:
        return []
    if isinstance(val, str):
        parts = [p.strip() for p in val.split(",") if p.strip() != ""]
    else:
        parts = list(val)
    if subtype is int:
        return [parse_int(p) for p in parts]
    if subtype is float:
        return [parse_float(p) for p in parts]
    return parts

def parse_duration_seconds(val: Union[str, int, float, None], default: float = 0.0) -> float:
    """
    Supports: 10, 2.5, 500ms (rounded), 10s, 5m, 2h, 1d
    Returns seconds (float).
    """
    if val is None:
        return default
    if isinstance(val, (int, float)):
        return float(val)
    m = _DURATION_RE.match(val)
    if not m:
        return default
    q, unit = m.groups()
    q = float(q)
    unit = unit.lower()
    if unit == "s" or unit == "":
        return q
    if unit == "m":
        return q * 60.0
    if unit == "h":
        return q * 3600.0
    if unit == "d":
        return q * 86400.0
    return default

def read_first_existing_text_file(paths: Iterable[str]) -> Optional[str]:
    for p in paths:
        if not p:
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                return f.read().strip()
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return None

def _secret_from_env(name: str, default: str = "") -> str:
    """
    Convention: NAME or NAME_FILE. NAME takes priority; otherwise try file.
    """
    val = os.getenv(name)
    if val:
        return val
    file_path = os.getenv(f"{name}_FILE")
    if file_path:
        content = read_first_existing_text_file([file_path])
        if content is not None:
            return content
    return default

# =========================
# Data classes (typed settings)
# =========================

@dataclass
class GeneralSettings:
    app_name: str = "mythos-core"
    environment: str = os.getenv("MYTHOS_ENV", "dev")  # dev|stage|prod
    timezone: str = os.getenv("MYTHOS_TIMEZONE", "Europe/Stockholm")
    version: str = os.getenv("MYTHOS_VERSION", "0.0.0")
    build_sha: str = os.getenv("MYTHOS_BUILD_SHA", "")
    instance_id: str = os.getenv("MYTHOS_INSTANCE_ID", f"{socket.gethostname()}-{int(time.time())}")
    debug: bool = parse_bool(os.getenv("MYTHOS_DEBUG", "false"))
    k8s: bool = bool(os.getenv("KUBERNETES_SERVICE_HOST"))
    compose: bool = parse_bool(os.getenv("COMPOSE", "false"))

@dataclass
class HTTPSettings:
    host: str = os.getenv("MYTHOS_HTTP__HOST", "0.0.0.0")
    port: int = parse_int(os.getenv("MYTHOS_HTTP__PORT", "8090"), 8090)
    workers: int = parse_int(os.getenv("MYTHOS_HTTP__WORKERS", "1"), 1)
    cors_origins: List[str] = field(default_factory=lambda: parse_list(os.getenv("MYTHOS_HTTP__CORS_ORIGINS", "*")))
    cors_allow_headers: List[str] = field(default_factory=lambda: parse_list(os.getenv("MYTHOS_HTTP__CORS_ALLOW_HEADERS", "Content-Type,Authorization")))
    request_timeout_s: float = parse_duration_seconds(os.getenv("MYTHOS_HTTP__REQUEST_TIMEOUT", "30s"), 30.0)
    rate_limit_rps: float = parse_float(os.getenv("MYTHOS_HTTP__RATE_LIMIT_RPS", "20"), 20.0)
    rate_limit_burst: float = parse_float(os.getenv("MYTHOS_HTTP__RATE_LIMIT_BURST", "60"), 60.0)

@dataclass
class SecuritySettings:
    api_token: str = _secret_from_env("MYTHOS_API_TOKEN", "")
    jwt_secret: str = _secret_from_env("MYTHOS_JWT_SECRET", "")
    allowed_hosts: List[str] = field(default_factory=lambda: parse_list(os.getenv("MYTHOS_ALLOWED_HOSTS", "")))
    allow_insecure_http: bool = parse_bool(os.getenv("MYTHOS_ALLOW_INSECURE_HTTP", "false"))

@dataclass
class ObservabilitySettings:
    log_level: str = os.getenv("MYTHOS_LOG_LEVEL", "INFO")
    log_json: bool = parse_bool(os.getenv("MYTHOS_LOG_JSON", "true"))
    log_sample_rate: float = parse_float(os.getenv("MYTHOS_LOG_SAMPLE_RATE", "0.1"), 0.1)
    metrics_enabled: bool = parse_bool(os.getenv("MYTHOS_METRICS_ENABLED", "true"))
    metrics_port: int = parse_int(os.getenv("MYTHOS_METRICS_PORT", "9100"), 9100)
    sentry_dsn: str = _secret_from_env("SENTRY_DSN", "")
    traces_sample_rate: float = parse_float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0.0"), 0.0)

@dataclass
class ServeLocalSettings:
    root: str = os.getenv("MYTHOS_SERVE__ROOT", "/data/artifacts")
    readonly: bool = parse_bool(os.getenv("MYTHOS_SERVE__READONLY", "false"))
    max_upload_mb: int = parse_int(os.getenv("MYTHOS_SERVE__MAX_UPLOAD_MB", "2048"), 2048)
    rl_rate: float = parse_float(os.getenv("MYTHOS_SERVE__RL_RATE", "50"), 50.0)
    rl_burst: float = parse_float(os.getenv("MYTHOS_SERVE__RL_BURST", "200"), 200.0)
    cors: str = os.getenv("MYTHOS_SERVE__CORS", "*")
    tls_cert_file: str = os.getenv("MYTHOS_SERVE__TLS_CERT_FILE", "")
    tls_key_file: str = os.getenv("MYTHOS_SERVE__TLS_KEY_FILE", "")

@dataclass
class LLMSettings:
    provider: str = os.getenv("MYTHOS_LLM__PROVIDER", "mock")  # mock|openai
    openai_base_url: str = os.getenv("MYTHOS_LLM__OPENAI_BASE_URL", "https://api.openai.com/v1")
    openai_model: str = os.getenv("MYTHOS_LLM__OPENAI_MODEL", "gpt-4o-mini")
    openai_api_key: str = field(default_factory=lambda: _secret_from_env("OPENAI_API_KEY", ""))
    request_timeout_s: float = parse_duration_seconds(os.getenv("MYTHOS_LLM__TIMEOUT", "30s"), 30.0)
    max_retries: int = parse_int(os.getenv("MYTHOS_LLM__MAX_RETRIES", "2"), 2)

@dataclass
class ModerationSettings:
    require_token: bool = parse_bool(os.getenv("MODERATION_REQUIRE_TOKEN", "false"))
    api_token: str = field(default_factory=lambda: _secret_from_env("MODERATION_API_TOKEN", ""))
    max_items: int = parse_int(os.getenv("MODERATION_MAX_ITEMS", "16"), 16)
    max_text_bytes: int = parse_int(os.getenv("MODERATION_MAX_TEXT_BYTES", "200_000"), 200_000)
    max_total_bytes: int = parse_int(os.getenv("MODERATION_MAX_TOTAL_BYTES", "2_000_000"), 2_000_000)

@dataclass
class WorkerSettings:
    jobs_root: str = os.getenv("MYTHOS_WORKER__JOBS_ROOT", "/data/jobs")
    log_dir: str = os.getenv("MYTHOS_WORKER__LOG_DIR", "/var/log/mythos/worker")
    http_host: str = os.getenv("MYTHOS_WORKER__HTTP_HOST", "0.0.0.0")
    http_port: int = parse_int(os.getenv("MYTHOS_WORKER__HTTP_PORT", "8080"), 8080)
    concurrency: int = parse_int(os.getenv("MYTHOS_WORKER__CONCURRENCY", "2"), 2)
    poll_interval_s: float = parse_duration_seconds(os.getenv("MYTHOS_WORKER__POLL_INTERVAL", "1s"), 1.0)
    stale_reclaim_s: float = parse_duration_seconds(os.getenv("MYTHOS_WORKER__STALE_RECLAIM", "900s"), 900.0)
    log_level: str = os.getenv("MYTHOS_WORKER__LOG_LEVEL", "INFO")

@dataclass
class PathsSettings:
    data_root: str = os.getenv("MYTHOS_PATHS__DATA_ROOT", "/data")
    logs_root: str = os.getenv("MYTHOS_PATHS__LOGS_ROOT", "/var/log/mythos")

@dataclass
class Settings:
    general: GeneralSettings = field(default_factory=GeneralSettings)
    http: HTTPSettings = field(default_factory=HTTPSettings)
    security: SecuritySettings = field(default_factory=SecuritySettings)
    observability: ObservabilitySettings = field(default_factory=ObservabilitySettings)
    serve_local: ServeLocalSettings = field(default_factory=ServeLocalSettings)
    llm: LLMSettings = field(default_factory=LLMSettings)
    moderation: ModerationSettings = field(default_factory=ModerationSettings)
    worker: WorkerSettings = field(default_factory=WorkerSettings)
    paths: PathsSettings = field(default_factory=PathsSettings)

    # -------------------------
    # Loading & validation
    # -------------------------

    @staticmethod
    def _coerce(value: str, target_type: Type) -> Any:
        """
        Cast string ENV value to target type based on annotation.
        Supports Optional, List[T], basic primitives, durations for *seconds fields.
        """
        origin = get_origin(target_type)
        args = get_args(target_type)

        # Optional[T] or Union[T, None]
        if origin is Union and len(args) == 2 and type(None) in args:
            inner = args[0] if args[1] is type(None) else args[1]
            return Settings._coerce(value, inner)

        # List[T]
        if origin in (list, List):
            subtype = args[0] if args else str
            return parse_list(value, subtype=subtype if isinstance(subtype, type) else str)

        # Primitives
        if target_type in (str, Optional[str]):
            return value
        if target_type in (int, Optional[int]):
            return parse_int(value, None)  # type: ignore[arg-type]
        if target_type in (float, Optional[float]):
            # special-case fields ending with *_s as seconds
            return parse_float(value, None)  # type: ignore[arg-type]
        if target_type in (bool, Optional[bool]):
            return parse_bool(value, None)  # type: ignore[arg-type]

        # Fallback to JSON parse for complex types
        try:
            return json.loads(value)
        except Exception:
            return value

    @classmethod
    def _apply_env_overrides(cls, obj: Any, prefix: str = "MYTHOS_") -> None:
        """
        Apply ENV variables to nested dataclasses using convention:
        MYTHOS_<SECTION>__<FIELD>=value
        e.g., MYTHOS_HTTP__PORT=8081
        """
        for key, val in os.environ.items():
            if not key.startswith(prefix):
                continue
            path = key[len(prefix):]
            # Ignore if it's a known global var we've already handled via default constructors
            # We still allow nested overrides
            parts = [p for p in path.split("__") if p]
            if not parts:
                continue

            # Walk nested dataclasses
            cur = obj
            parent = None
            fld_name = None
            for p in parts[:-1]:
                p_attr = p.lower()
                if not hasattr(cur, p_attr):
                    # unknown path; skip
                    cur = None
                    break
                parent = cur
                cur = getattr(cur, p_attr)
            if cur is None:
                continue

            fld_name = parts[-1].lower()
            if not hasattr(cur, fld_name):
                continue

            # Get type annotation if available
            target_type = None
            try:
                for f in dataclasses.fields(cur):
                    if f.name == fld_name:
                        target_type = f.type
                        break
            except Exception:
                pass

            casted = cls._coerce(val, target_type or str)
            try:
                setattr(cur, fld_name, casted)
            except Exception:
                # Best effort: ignore invalid assignment
                continue

    @classmethod
    def load(cls) -> "Settings":
        """
        Build settings from defaults -> config file -> ENV overrides -> computed -> validate.
        """
        settings = cls()

        # 1) Optional JSON config file overlay
        cfg_path = os.getenv("MYTHOS_CONFIG_FILE", "")
        if cfg_path and os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                _overlay_dict(settings, data)
            except Exception:
                # Ignore malformed external file (do not crash app)
                pass

        # 2) ENV overrides (nested)
        cls._apply_env_overrides(settings, prefix="MYTHOS_")

        # 3) Common alias secrets (OPENAI_API_KEY/_FILE already handled in LLMSettings factory)

        # 4) Computed fixes/normalization
        if settings.http.port <= 0:
            settings.http.port = 8090
        if settings.general.environment not in ("dev", "stage", "prod"):
            settings.general.environment = "dev"

        # 5) Validation (raise ValueError for fatal misconfigurations)
        settings.validate()

        return settings

    def validate(self) -> None:
        # If moderation requires token — ensure present
        if self.moderation.require_token and not self.moderation.api_token:
            raise ValueError("MODERATION_REQUIRE_TOKEN is true, but MODERATION_API_TOKEN is empty")
        # If LLM provider is openai — ensure API key
        if self.llm.provider.lower() == "openai" and not self.llm.openai_api_key:
            raise ValueError("LLM provider 'openai' requires OPENAI_API_KEY or OPENAI_API_KEY_FILE")
        # Ports sanity
        for p in (self.http.port, self.worker.http_port, self.observability.metrics_port):
            if not (0 < int(p) < 65536):
                raise ValueError(f"Invalid TCP port: {p}")

    # -------------------------
    # Introspection
    # -------------------------

    def as_dict(self, redact: bool = True) -> Dict[str, Any]:
        """
        Convert settings to dict. If redact=True, hide secrets.
        """
        data = dataclasses.asdict(self)

        def _redact(d: Any, path: Tuple[str, ...] = ()) -> Any:
            if isinstance(d, dict):
                out = {}
                for k, v in d.items():
                    kp = (*path, str(k))
                    key_l = str(k).lower()
                    if redact and key_l in {"api_key", "api_token", "jwt_secret", "sentry_dsn", "openai_api_key"}:
                        out[k] = "[redacted]"
                    else:
                        out[k] = _redact(v, kp)
                return out
            if isinstance(d, list):
                return [_redact(x, path) for x in d]
            return d

        return _redact(data)

# -------------------------
# Dict overlay helper
# -------------------------

def _overlay_dict(obj: Any, data: Dict[str, Any]) -> None:
    """
    Overlay a dict onto nested dataclasses (keys case-insensitive).
    """
    for k, v in data.items():
        k_attr = k.lower()
        if not hasattr(obj, k_attr):
            continue
        cur = getattr(obj, k_attr)
        if dataclasses.is_dataclass(cur) and isinstance(v, dict):
            _overlay_dict(cur, v)
        else:
            try:
                setattr(obj, k_attr, v)
            except Exception:
                pass

# =========================
# Singleton accessors
# =========================

_LOCK = threading.RLock()
_SETTINGS: Optional[Settings] = None

def get_settings() -> Settings:
    global _SETTINGS
    with _LOCK:
        if _SETTINGS is None:
            _SETTINGS = Settings.load()
        return _SETTINGS

def reload_settings() -> Settings:
    global _SETTINGS
    with _LOCK:
        _SETTINGS = Settings.load()
        return _SETTINGS

# =========================
# Logging configuration
# =========================

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "lvl": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # Merge 'extra' dict if provided
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            payload.update(extra)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def configure_logging() -> None:
    """
    Configure root logger according to settings (JSON/plain).
    Idempotent. Does not remove existing handlers.
    """
    s = get_settings()
    level = getattr(logging, s.observability.log_level.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    has_stream = any(isinstance(h, logging.StreamHandler) for h in root.handlers)
    if not has_stream:
        handler = logging.StreamHandler(stream=sys.stdout)
        if s.observability.log_json:
            handler.setFormatter(_JsonFormatter())
        else:
            fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
            handler.setFormatter(logging.Formatter(fmt))
        root.addHandler(handler)

    # Reduce noise from uvicorn/access if needed
    logging.getLogger("uvicorn").setLevel(level)
    logging.getLogger("uvicorn.access").setLevel(level)

# Eager logging setup if requested
if parse_bool(os.getenv("MYTHOS_CONFIGURE_LOGGING", "true")):
    try:
        configure_logging()
    except Exception:
        # Do not fail app on logging init issues
        pass
