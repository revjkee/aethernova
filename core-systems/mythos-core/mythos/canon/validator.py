from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import sys
import typing as t
from pathlib import Path

try:
    import yaml  # PyYAML
except Exception as e:  # pragma: no cover
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    raise

# jsonschema опционален: если есть — выполним структурную валидацию
try:
    import jsonschema  # type: ignore
except Exception:
    jsonschema = None  # type: ignore


# =========================
# Модель результата
# =========================

Severity = t.Literal["ERROR", "WARNING", "INFO"]


@dataclasses.dataclass
class Issue:
    code: str
    message: str
    path: str
    severity: Severity = "ERROR"
    hint: t.Optional[str] = None

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Report:
    issues: list[Issue]
    fingerprint: str
    profile: str
    elapsed_ms: int

    @property
    def has_errors(self) -> bool:
        return any(i.severity == "ERROR" for i in self.issues)

    @property
    def has_warnings(self) -> bool:
        return any(i.severity == "WARNING" for i in self.issues)

    def to_json(self) -> str:
        return json.dumps(
            {
                "profile": self.profile,
                "fingerprint": self.fingerprint,
                "elapsed_ms": self.elapsed_ms,
                "issues": [i.as_dict() for i in self.issues],
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def to_text(self) -> str:
        lines = [f"profile={self.profile} fingerprint={self.fingerprint} elapsed_ms={self.elapsed_ms}ms"]
        for it in self.issues:
            hint = f" | hint: {it.hint}" if it.hint else ""
            lines.append(f"[{it.severity}] {it.code} @ {it.path}: {it.message}{hint}")
        if not self.issues:
            lines.append("OK: no issues found")
        return "\n".join(lines)

    def to_sarif(self) -> str:
        # Минимальный SARIF 2.1.0 для CI (GitHub Actions и пр.)
        rules = {}
        results = []
        for it in self.issues:
            rules[it.code] = {"id": it.code, "name": it.code, "shortDescription": {"text": it.message[:80]}}
            results.append(
                {
                    "ruleId": it.code,
                    "level": "error" if it.severity == "ERROR" else ("warning" if it.severity == "WARNING" else "note"),
                    "message": {"text": it.message + (f" | {it.hint}" if it.hint else "")},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": it.path}}}],
                }
            )
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "mythos-canon-validator", "rules": list(rules.values())}},
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, ensure_ascii=False)


# =========================
# Утилиты
# =========================

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
DURATION_RE = re.compile(r"^(?:\d+)(?:ms|s|m|h|d)$")
URL_RE = re.compile(r"^(https?)://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
HOST_RE = re.compile(r"^[a-z0-9.-]+$", re.IGNORECASE)
MIME_RE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$", re.I)
CRON_5F_RE = re.compile(
    r"^([0-5]?\d|\*)\s+([01]?\d|2[0-3]|\*)\s+([01]?\d|2[0-9]|3[01]|\*)\s+(1[0-2]|0?[1-9]|\*)\s+([0-6]|\*)$"
)

def is_duration(v: str) -> bool:
    return bool(DURATION_RE.match(str(v)))

def is_url(v: str) -> bool:
    return bool(URL_RE.match(str(v)))

def is_cidr(v: str) -> bool:
    try:
        ipaddress.ip_network(v, strict=False)
        return True
    except Exception:
        return False

def is_port(n: int) -> bool:
    return isinstance(n, int) and 0 < n < 65536

def is_mime(v: str) -> bool:
    return bool(MIME_RE.match(str(v)))

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def deep_get(d: dict, path: str, default=None):
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur

def deep_merge(base: dict, overlay: dict) -> dict:
    out = dict(base)
    for k, v in overlay.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out

def as_path(rootfile: Path, jsonpath: str) -> str:
    # Для SARIF/читаемости привязываем путь к файлу конфигурации
    return f"{rootfile}:{jsonpath or '/'}"


# =========================
# Пример укороченной JSON Schema (опциональная)
# =========================

# Схема не отражает всех полей canon.yaml (иначе файл станет чрезмерно большим),
# но позволяет поймать типовые ошибки и неизвестные ключи в основных узлах.
JSON_SCHEMA_MIN = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["schemaVersion", "metadata", "environment", "server", "security", "database", "observability"],
    "properties": {
        "schemaVersion": {"type": "string"},
        "metadata": {
            "type": "object",
            "additionalProperties": False,
            "required": ["service", "version", "owner"],
            "properties": {
                "service": {"type": "string"},
                "version": {"type": "string"},
                "owner": {"type": "string"},
                "labels": {"type": "object", "additionalProperties": {"type": "string"}},
            },
        },
        "environment": {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "region", "timezone"],
            "properties": {
                "name": {"type": "string", "enum": ["dev", "staging", "prod"]},
                "region": {"type": "string"},
                "timezone": {"type": "string"},
            },
        },
        "server": {
            "type": "object",
            "additionalProperties": True,
            "properties": {
                "http": {
                    "type": "object",
                    "additionalProperties": True,
                    "properties": {
                        "host": {"type": "string"},
                        "port": {"type": "integer"},
                        "basePath": {"type": "string"},
                        "cors": {"type": "object"},
                        "securityHeaders": {"type": "object"},
                    },
                }
            },
        },
        "security": {"type": "object"},
        "database": {"type": "object"},
        "cache": {"type": "object"},
        "queue": {"type": "object"},
        "storage": {"type": "object"},
        "observability": {"type": "object"},
        "features": {"type": "object"},
        "limits": {"type": "object"},
        "quotas": {"type": "object"},
        "validation": {"type": "object"},
        "webhooks": {"type": "object"},
        "scheduler": {"type": "object"},
        "migrations": {"type": "object"},
        "slo": {"type": "object"},
        "api": {"type": "object"},
        "profiles": {"type": "object"},
    },
}


# =========================
# Основной валидатор
# =========================

class CanonValidator:
    def __init__(self, cfg: dict, source: Path, profile: str = "dev", strict: bool = False) -> None:
        self.cfg = cfg
        self.source = source
        self.profile = profile
        self.strict = strict
        self.issues: list[Issue] = []

    # --------- публичное API ---------

    def validate(self) -> Report:
        start = dt.datetime.now()
        merged = self._materialize_profile(self.cfg, self.profile)

        # 1) JSON Schema (если доступна библиотека)
        if jsonschema is not None:
            try:
                jsonschema.validate(self.cfg, JSON_SCHEMA_MIN)  # базовая структурная проверка
            except Exception as e:
                self._err("SCHEMA", f"JSON Schema validation failed: {e}", "root")

        # 2) Семантика
        self._check_env_name(merged)
        self._check_server(merged)
        self._check_security(merged)
        self._check_database(merged)
        self._check_cache_queue(merged)
        self._check_storage(merged)
        self._check_observability(merged)
        self._check_limits_quotas(merged)
        self._check_scheduler(merged)
        self._check_api(merged)
        self._check_profiles_overlay(self.cfg)

        # 3) Строгий режим: запрет плэйнтекст-секретов
        self._check_plaintext_secrets(merged)

        # 4) Фингерпринт
        fp = sha256_hex(json.dumps(merged, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        elapsed = int((dt.datetime.now() - start).total_seconds() * 1000)
        return Report(self.issues, fp, self.profile, elapsed)

    # --------- helpers / rules ---------

    def _materialize_profile(self, cfg: dict, profile: str) -> dict:
        base = {k: v for k, v in cfg.items() if k != "profiles"}
        overlay = (cfg.get("profiles") or {}).get(profile) or {}
        merged = deep_merge(base, overlay)
        return merged

    def _err(self, code: str, msg: str, path: str, hint: str | None = None) -> None:
        self.issues.append(Issue(code=code, message=msg, path=as_path(self.source, path), severity="ERROR", hint=hint))

    def _warn(self, code: str, msg: str, path: str, hint: str | None = None) -> None:
        self.issues.append(Issue(code=code, message=msg, path=as_path(self.source, path), severity="WARNING", hint=hint))

    def _info(self, code: str, msg: str, path: str) -> None:
        self.issues.append(Issue(code=code, message=msg, path=as_path(self.source, path), severity="INFO"))

    # ---- rules ----

    def _check_env_name(self, cfg: dict) -> None:
        env = cfg.get("environment") or {}
        name = env.get("name")
        if name not in {"dev", "staging", "prod"}:
            self._err("ENV_NAME", f"environment.name must be one of dev|staging|prod, got {name}", "environment.name")

    def _check_server(self, cfg: dict) -> None:
        http = deep_get(cfg, "server.http") or {}
        host = http.get("host")
        port = http.get("port")
        if host and not HOST_RE.match(host):
            self._err("HTTP_HOST", f"Invalid host '{host}'", "server.http.host")
        if port is not None and not is_port(port):
            self._err("HTTP_PORT", f"Invalid port '{port}'", "server.http.port")

        # CORS
        cors = http.get("cors") or {}
        if cors.get("enabled") is True:
            origins = cors.get("allowOrigins")
            if not isinstance(origins, list) or not origins:
                self._err("CORS_EMPTY", "CORS enabled but allowOrigins is empty", "server.http.cors.allowOrigins")
            if "*" in origins and self.strict:
                self._err("CORS_STAR", "Wildcard '*' is forbidden in strict mode", "server.http.cors.allowOrigins")

        # Security headers
        sh = http.get("securityHeaders") or {}
        if sh.get("hsts", {}).get("enabled") and sh.get("hsts", {}).get("maxAgeSeconds", 0) < 31536000:
            self._warn("HSTS_SHORT", "HSTS maxAgeSeconds is less than 1 year", "server.http.securityHeaders.hsts.maxAgeSeconds")

        csp = sh.get("csp")
        if csp is None or not isinstance(csp, str) or not csp.strip():
            self._warn("CSP_MISSING", "Content-Security-Policy is missing or empty", "server.http.securityHeaders.csp")

        # Admin interface checks
        admin = deep_get(cfg, "server.admin") or {}
        a_port = admin.get("port")
        if a_port is not None and not is_port(a_port):
            self._err("ADMIN_PORT", f"Invalid admin port '{a_port}'", "server.admin.port")
        allowlist = admin.get("ipAllowList") or []
        for i, cidr in enumerate(allowlist):
            if not is_cidr(cidr):
                self._err("ADMIN_IP", f"Invalid CIDR '{cidr}'", f"server.admin.ipAllowList[{i}]")
        if (cfg.get("environment") or {}).get("name") == "prod" and allowlist == ["0.0.0.0/0"]:
            self._err("ADMIN_OPEN", "Admin ipAllowList must not be 0.0.0.0/0 in prod", "server.admin.ipAllowList")

    def _check_security(self, cfg: dict) -> None:
        sec = cfg.get("security") or {}
        tls = sec.get("tls") or {}
        if tls.get("enforceHttps") is not True:
            self._warn("TLS_WEAK", "TLS enforceHttps should be true", "security.tls.enforceHttps")

        auth = sec.get("auth") or {}
        mode = auth.get("mode")
        if mode not in {"oidc", "jwt"}:
            self._err("AUTH_MODE", f"Invalid auth.mode '{mode}'", "security.auth.mode")

        if mode == "oidc":
            oidc = auth.get("oidc") or {}
            for key in ("issuer", "clientId", "clientSecretEnv"):
                if not oidc.get(key):
                    self._err("OIDC_CFG", f"security.auth.oidc.{key} must be set", f"security.auth.oidc.{key}")
            if self.strict and oidc.get("issuer") and not is_url(oidc.get("issuer")):
                self._err("OIDC_ISSUER_URL", "OIDC issuer must be valid URL", "security.auth.oidc.issuer")

        if mode == "jwt":
            jwt = auth.get("jwt") or {}
            if not jwt.get("secretEnv"):
                self._err("JWT_SECRET_ENV", "security.auth.jwt.secretEnv must be set", "security.auth.jwt.secretEnv")

        # Tokens TTLs
        tokens = (auth.get("tokens") or {})
        for fld in ("accessTtl", "refreshTtl"):
            if fld in tokens and not is_duration(tokens[fld]):
                self._err("TOKENS_TTL", f"security.auth.tokens.{fld} must be duration (e.g. 15m)", f"security.auth.tokens.{fld}")

        # CSRF cookie flags
        csrf = sec.get("csrf") or {}
        if csrf.get("enabled"):
            if csrf.get("cookieSecure") is not True:
                self._warn("CSRF_INSECURE", "csrf.cookieSecure should be true", "security.csrf.cookieSecure")
            if csrf.get("cookieSameSite") not in {"Lax", "Strict"}:
                self._warn("CSRF_SAMESITE", "csrf.cookieSameSite should be Lax or Strict", "security.csrf.cookieSameSite")

    def _check_database(self, cfg: dict) -> None:
        db = cfg.get("database") or {}
        url = db.get("url")
        if not url or not isinstance(url, str) or not url.startswith("postgres"):
            self._err("DB_URL", "database.url must be a Postgres URL", "database.url")
        pool = db.get("pool") or {}
        for fld in ("maxOpen", "maxIdle"):
            if fld in pool and (not isinstance(pool[fld], int) or pool[fld] <= 0):
                self._err("DB_POOL", f"database.pool.{fld} must be positive int", f"database.pool.{fld}")
        for fld in ("connMaxLifetime", "connMaxIdleTime"):
            if fld in pool and not is_duration(pool[fld]):
                self._err("DB_POOL_DUR", f"database.pool.{fld} must be duration", f"database.pool.{fld}")

    def _check_cache_queue(self, cfg: dict) -> None:
        # Redis
        r = deep_get(cfg, "cache.redis") or {}
        if r:
            if not isinstance(r.get("url"), str) or not (r["url"].startswith("redis://") or r["url"].startswith("rediss://")):
                self._err("REDIS_URL", "cache.redis.url must be redis:// or rediss://", "cache.redis.url")
            for fld in ("poolSize", "minIdleConns"):
                if fld in r and (not isinstance(r[fld], int) or r[fld] <= 0):
                    self._err("REDIS_POOL", f"cache.redis.{fld} must be positive int", f"cache.redis.{fld}")
        # Queue provider
        q = cfg.get("queue") or {}
        prov = q.get("provider")
        if prov not in {"sqs", "rabbit", "memory"}:
            self._err("QUEUE_PROVIDER", f"Invalid queue.provider '{prov}'", "queue.provider")
        if prov == "sqs":
            sqs = q.get("sqs") or {}
            if not sqs.get("queueUrl"):
                self._err("SQS_URL", "queue.sqs.queueUrl must be set", "queue.sqs.queueUrl")
        if prov == "rabbit":
            rabbit = q.get("rabbit") or {}
            if not rabbit.get("url", "").startswith("amqp://") and not rabbit.get("url", "").startswith("amqps://"):
                self._err("RABBIT_URL", "queue.rabbit.url must be amqp(s)://", "queue.rabbit.url")

    def _check_storage(self, cfg: dict) -> None:
        storage = cfg.get("storage") or {}
        reg = storage.get("registry") or {}
        backend = reg.get("backend")
        if backend not in {"s3", "local"}:
            self._err("REG_BACKEND", f"storage.registry.backend must be s3|local, got {backend}", "storage.registry.backend")
        if backend == "s3":
            s3 = reg.get("s3") or {}
            if not s3.get("bucket"):
                self._err("REG_S3_BUCKET", "storage.registry.s3.bucket must be set", "storage.registry.s3.bucket")
            if not s3.get("region"):
                self._warn("REG_S3_REGION", "storage.registry.s3.region is empty", "storage.registry.s3.region")
        uploads = storage.get("uploads") or {}
        up_backend = uploads.get("backend")
        if up_backend not in {"s3", "local"}:
            self._err("UP_BACKEND", f"storage.uploads.backend must be s3|local, got {up_backend}", "storage.uploads.backend")
        # CAC
        cac = storage.get("cac") or {}
        if cac.get("enabled") and (not isinstance(cac.get("maxSizeBytes"), int) or cac["maxSizeBytes"] <= 0):
            self._err("CAC_MAXSIZE", "storage.cac.maxSizeBytes must be positive int", "storage.cac.maxSizeBytes")

    def _check_observability(self, cfg: dict) -> None:
        obs = cfg.get("observability") or {}
        log = obs.get("logging") or {}
        level = (log.get("level") or "").upper()
        if level not in {"DEBUG", "INFO", "WARN", "WARNING", "ERROR"}:
            self._err("LOG_LEVEL", f"Invalid logging.level '{level}'", "observability.logging.level")
        tracing = obs.get("tracing") or {}
        if tracing.get("enabled"):
            exporter = tracing.get("exporter")
            if exporter not in {"otlp", "jaeger", "none"}:
                self._err("TRACE_EXPORTER", f"Unsupported tracing.exporter '{exporter}'", "observability.tracing.exporter")
            if exporter == "otlp" and not tracing.get("endpoint"):
                self._err("TRACE_ENDPOINT", "tracing.endpoint must be set for OTLP", "observability.tracing.endpoint")
        metrics = deep_get(cfg, "observability.metrics.prometheus") or {}
        if metrics.get("enabled") and not is_port(metrics.get("port", 0)):
            self._err("METRICS_PORT", "metrics.prometheus.port must be valid TCP port", "observability.metrics.prometheus.port")

    def _check_limits_quotas(self, cfg: dict) -> None:
        limits = cfg.get("limits") or {}
        rl = (limits.get("rateLimits") or {}).get("default") or {}
        for fld in ("rps", "burst", "windowSec"):
            if fld in rl and (not isinstance(rl[fld], int) or rl[fld] <= 0):
                self._err("RATE_LIMIT", f"limits.rateLimits.default.{fld} must be positive int", f"limits.rateLimits.default.{fld}")
        quotas = cfg.get("quotas") or {}
        if quotas.get("enabled"):
            defs = (quotas.get("defaults") or {})
            if "storageBytes" in defs and (not isinstance(defs["storageBytes"], int) or defs["storageBytes"] <= 0):
                self._err("QUOTA_BYTES", "quotas.defaults.storageBytes must be positive int", "quotas.defaults.storageBytes")

    def _check_scheduler(self, cfg: dict) -> None:
        sch = cfg.get("scheduler") or {}
        if sch.get("enabled"):
            jobs = sch.get("jobs") or []
            if not isinstance(jobs, list):
                self._err("SCH_JOBS", "scheduler.jobs must be an array", "scheduler.jobs")
                return
            for i, job in enumerate(jobs):
                name = job.get("name")
                cron = job.get("cron")
                task = job.get("task")
                if not name or not isinstance(name, str):
                    self._err("SCH_NAME", "job.name must be non-empty", f"scheduler.jobs[{i}].name")
                if not task or not isinstance(task, str):
                    self._err("SCH_TASK", "job.task must be non-empty", f"scheduler.jobs[{i}].task")
                if not cron or not isinstance(cron, str) or not CRON_5F_RE.match(cron.strip()):
                    self._err("SCH_CRON", "job.cron must be a valid 5-field cron", f"scheduler.jobs[{i}].cron")
                if "timeoutSec" in job and (not isinstance(job["timeoutSec"], int) or job["timeoutSec"] <= 0):
                    self._err("SCH_TIMEOUT", "job.timeoutSec must be positive int", f"scheduler.jobs[{i}].timeoutSec")

    def _check_api(self, cfg: dict) -> None:
        api = cfg.get("api") or {}
        if "majorVersion" in api and api["majorVersion"] not in (1, 2, 3):
            self._warn("API_MAJOR", "api.majorVersion unusual (expected 1..3)", "api.majorVersion")
        depr = api.get("deprecations") or []
        if not isinstance(depr, list):
            self._err("API_DEPRECATIONS", "api.deprecations must be an array", "api.deprecations")

    def _check_profiles_overlay(self, raw_cfg: dict) -> None:
        profiles = raw_cfg.get("profiles") or {}
        if not profiles:
            self._warn("PROFILES_MISSING", "profiles.* overlays are missing", "profiles")
            return
        for name, overlay in profiles.items():
            if name not in {"dev", "staging", "prod"}:
                self._warn("PROFILE_NAME", f"Unknown profile '{name}'", f"profiles.{name}")
            if not isinstance(overlay, dict):
                self._err("PROFILE_TYPE", f"profiles.{name} must be an object", f"profiles.{name}")
            # Базовая проверка на ключи серверной части
            if "server" in overlay and not isinstance(overlay["server"], dict):
                self._err("PROFILE_SERVER", f"profiles.{name}.server must be an object", f"profiles.{name}.server")

    def _check_plaintext_secrets(self, cfg: dict) -> None:
        """
        Запрещаем секреты в явном виде; допускаем только ссылки на ENV:
        поля вида *.secret, *.clientSecret, *.password, *.accessKey, *.token.
        """
        SUSPICIOUS_KEYS = re.compile(r"(secret|password|access[_-]?key|token)$", re.I)

        def walk(node: t.Any, jpath: str) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    path = f"{jpath}.{k}" if jpath else k
                    if isinstance(v, (dict, list)):
                        walk(v, path)
                    else:
                        if SUSPICIOUS_KEYS.search(k):
                            if isinstance(v, str) and not v.startswith("${") and self.strict:
                                self._err(
                                    "PLAINTEXT_SECRET",
                                    f"Plaintext secret found at {path}. Use environment variable indirection.",
                                    path,
                                )

        walk(cfg, "")

        # Дополнительно: проверим, что указанные *Env переменные существуют в окружении (строгий режим)
        if self.strict:
            env_refs = [
                ("security.auth.oidc.clientSecretEnv", deep_get(cfg, "security.auth.oidc.clientSecretEnv")),
                ("security.auth.jwt.secretEnv", deep_get(cfg, "security.auth.jwt.secretEnv")),
                ("storage.registry.s3.kmsKeyId", deep_get(cfg, "storage.registry.s3.kmsKeyId")),
            ]
            for p, var in env_refs:
                if isinstance(var, str) and var and var.isupper():
                    if os.environ.get(var) in (None, ""):
                        self._warn("ENV_MISSING", f"Environment variable '{var}' for {p} is not set", p)


# =========================
# CLI
# =========================

def load_config(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    # Поддержка JSON для удобства
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return yaml.safe_load(text)

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Mythos Canon Config Validator")
    p.add_argument("--file", "-f", required=True, help="Path to canon.yaml")
    p.add_argument("--profile", "-p", default=os.getenv("ENVIRONMENT", "dev"), help="Profile: dev|staging|prod")
    p.add_argument("--format", "-o", choices=["text", "json", "sarif"], default="text", help="Output format")
    p.add_argument("--strict", action="store_true", help="Enable strict mode (for CI/prod)")
    p.add_argument("--fail-on-warn", action="store_true", help="Exit non-zero when warnings exist")
    args = p.parse_args(argv)

    src = Path(args.file)
    try:
        cfg = load_config(src)
    except Exception as e:
        print(f"ERROR: cannot load config: {e}", file=sys.stderr)
        return 2

    validator = CanonValidator(cfg, src, profile=args.profile, strict=args.strict)
    rep = validator.validate()

    if args.format == "json":
        print(rep.to_json())
    elif args.format == "sarif":
        print(rep.to_sarif())
    else:
        print(rep.to_text())

    if rep.has_errors:
        return 1
    if args.fail_on_warn and rep.has_warnings:
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
