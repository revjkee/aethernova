# zero-trust-core/zero_trust/bootstrap.py
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

# ----------------------- Опциональные зависимости -----------------------
try:
    import yaml  # type: ignore
    _HAVE_YAML = True
except Exception:
    _HAVE_YAML = False

try:
    from jsonschema import Draft202012Validator, RefResolver  # type: ignore
    _HAVE_JSONSCHEMA = True
except Exception:
    _HAVE_JSONSCHEMA = False

try:
    from prometheus_fastapi_instrumentator import Instrumentator  # type: ignore
    _HAVE_PROM = True
except Exception:
    _HAVE_PROM = False

from fastapi import FastAPI
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware

# Двунаправленный импорт для совместимости с layoutами zero_trust_core и zero_trust
try:
    from zero_trust_core.api.http.middleware.auth import (
        AuthMiddleware,
        AuthConfig,
        TokenBindingConfig,
    )
    from zero_trust_core.api.http.routers.v1.enforce import (
        router as enforce_router,
        set_policy_engine,
    )
except Exception:
    from zero_trust.api.http.middleware.auth import (  # type: ignore
        AuthMiddleware,
        AuthConfig,
        TokenBindingConfig,
    )
    from zero_trust.api.http.routers.v1.enforce import (  # type: ignore
        router as enforce_router,
        set_policy_engine,
    )


# ============================= Настройки приложения =============================

@dataclass
class Settings:
    app_name: str = "zero-trust-core"
    env: str = os.getenv("ZT_ENV", "prod")
    base_dir: Path = field(default_factory=lambda: Path(os.getenv("ZT_BASE_DIR", ".")))

    # Конфиги
    features_file: Path = None  # type: ignore
    env_override_file: Path = None  # type: ignore
    session_policy_schema: Path = None  # type: ignore
    session_policies_dir: Optional[Path] = None

    # Auth/JWT/JWKS
    issuer: str = os.getenv("ZT_ISSUER", "https://idp.corp/")
    audience: str = os.getenv("ZT_AUDIENCE", "zero-trust-core")
    jwks_url: Optional[str] = os.getenv("ZT_JWKS_URL") or None
    require_mtls: bool = os.getenv("ZT_REQUIRE_MTLS", "true").lower() == "true"
    client_cert_header: Optional[str] = os.getenv("ZT_CLIENT_CERT_HEADER", "x-ssl-client-cert")
    token_binding_type: str = os.getenv("ZT_TOKEN_BINDING", "mtls")  # none|mtls|dpop
    shadow_mode: bool = os.getenv("ZT_SHADOW_MODE", "false").lower() == "true"
    decision_cache_ttl_s: int = int(os.getenv("ZT_DECISION_CACHE_TTL", "30"))

    # CORS/Network
    cors_allowed_origins: Tuple[str, ...] = tuple(
        x.strip() for x in os.getenv("ZT_CORS_ALLOWED_ORIGINS", "").split(",") if x.strip()
    )
    gzip_min_size: int = int(os.getenv("ZT_GZIP_MIN", "1024"))

    # Политика: модуль для загрузки PolicyEngine
    policy_engine_path: Optional[str] = os.getenv("ZT_POLICY_ENGINE") or None

    # Метрики
    enable_metrics: bool = os.getenv("ZT_ENABLE_METRICS", "true").lower() == "true"

    def finalize_paths(self) -> None:
        # Значения по умолчанию для путей
        self.features_file = self.features_file or (self.base_dir / "configs" / "features.yaml")
        self.env_override_file = self.env_override_file or (self.base_dir / "configs" / "env" / f"{self.env}.yaml")
        self.session_policy_schema = self.session_policy_schema or (
            self.base_dir / "schemas" / "jsonschema" / "v1" / "session_policy.schema.json"
        )
        # По желанию: директория JSON‑политик для валидации
        if not self.session_policies_dir:
            maybe_dir = self.base_dir / "configs" / "policies"
            self.session_policies_dir = maybe_dir if maybe_dir.exists() else None


# ============================= Утилиты загрузки/мерджа =============================

def _load_yaml(path: Path) -> Dict[str, Any]:
    if not _HAVE_YAML:
        return {}
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def _deep_merge(dst: Dict[str, Any], src: Mapping[str, Any]) -> Dict[str, Any]:
    for k, v in src.items():
        if isinstance(v, Mapping) and isinstance(dst.get(k), Mapping):
            dst[k] = _deep_merge(dict(dst[k]), v)  # type: ignore
        else:
            dst[k] = v  # overwrite
    return dst

def load_features(settings: Settings) -> Dict[str, Any]:
    base = _load_yaml(settings.features_file)
    env = _load_yaml(settings.env_override_file)
    if env:
        # Ожидаем структуру вида {flags: {...}} и др.
        base = _deep_merge(base, env)
    return base


# ============================= Валидация JSON‑политик (опционально) =============================

def validate_session_policies(settings: Settings, logger: logging.Logger) -> None:
    if not _HAVE_JSONSCHEMA or not settings.session_policies_dir or not settings.session_policy_schema.exists():
        return
    with settings.session_policy_schema.open("r", encoding="utf-8") as f:
        schema = json.load(f)
    validator = Draft202012Validator(schema)
    ok = True
    for path in sorted(settings.session_policies_dir.glob("*.json")):
        try:
            with path.open("r", encoding="utf-8") as pf:
                doc = json.load(pf)
            errors = sorted(validator.iter_errors(doc), key=lambda e: e.path)
            if errors:
                ok = False
                for e in errors:
                    logger.error("policy.validation_error", extra={"policy": str(path), "msg": e.message, "path": list(e.path)})
        except Exception as ex:
            ok = False
            logger.error("policy.load_error", extra={"policy": str(path), "err": type(ex).__name__})
    if not ok:
        logger.error("policy.validation_failed_hard_deny")


# ============================= Логирование =============================

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(time.time()),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if hasattr(record, "extra"):
            try:
                payload.update(record.extra)  # type: ignore
            except Exception:
                pass
        return json.dumps(payload, ensure_ascii=False)

def setup_logging(app_name: str) -> logging.Logger:
    logger = logging.getLogger(app_name)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.handlers = [handler]
    logger.propagate = False
    return logger


# ============================= Загрузка PolicyEngine плагина =============================

def load_policy_engine(policy_engine_path: Optional[str], logger: logging.Logger):
    if not policy_engine_path:
        return None
    try:
        mod_name, cls_name = policy_engine_path.split(":")
        mod = __import__(mod_name, fromlist=[cls_name])
        cls = getattr(mod, cls_name)
        inst = cls()  # ожидаем пустой конструктор; при необходимости расширьте
        logger.info(f"policy.engine_loaded {policy_engine_path}")
        return inst
    except Exception as ex:
        logger.error("policy.engine_load_failed", extra={"extra": {"path": policy_engine_path, "err": type(ex).__name__}})
        return None


# ============================= JWKS прогрев (опционально) =============================

def start_jwks_warmer(jwks_url: Optional[str], logger: logging.Logger, interval_s: int = 300) -> Optional[threading.Thread]:
    if not jwks_url:
        return None

    def _worker() -> None:
        import urllib.request  # stdlib
        while True:
            try:
                with urllib.request.urlopen(jwks_url, timeout=5) as resp:
                    _ = resp.read()  # контент кэшируется в SimpleJWKSVerifier при первом запросе
                logger.info(f"jwks.warm_ok url={jwks_url}")
            except Exception as ex:
                logger.error("jwks.warm_failed", extra={"extra": {"err": type(ex).__name__}})
            time.sleep(max(60, int(interval_s)))

    t = threading.Thread(target=_worker, name="jwks-warmer", daemon=True)
    t.start()
    return t


# ============================= Создание FastAPI приложения =============================

def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or Settings()
    settings.finalize_paths()

    logger = setup_logging(settings.app_name)
    logger.info(f"bootstrap.start env={settings.env}")

    # Загрузка/мердж фич (необязательная, но полезная для дальнейших зависимостей)
    features = load_features(settings)
    # Здесь можно использовать features для тонкой настройки, если требуется

    # Валидация JSON‑политик (если есть)
    validate_session_policies(settings, logger)

    # Политический движок (плагин) — опционально
    engine = load_policy_engine(settings.policy_engine_path, logger)
    if engine is not None:
        set_policy_engine(engine)

    # CORS
    middlewares = [
        Middleware(GZipMiddleware, minimum_size=settings.gzip_min_size),
    ]
    if settings.cors_allowed_origins:
        middlewares.append(
            Middleware(
                CORSMiddleware,
                allow_origins=list(settings.cors_allowed_origins),
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
        )

    app = FastAPI(title=settings.app_name, version="1.0.0", middleware=middlewares)

    # Метрики Prometheus (если библиотека доступна)
    if _HAVE_PROM and settings.enable_metrics:
        Instrumentator().instrument(app).expose(app, include_in_schema=False)

    # AuthMiddleware (Zero Trust)
    auth_cfg = AuthConfig(
        issuer=settings.issuer,
        audience=settings.audience,
        jwks_url=settings.jwks_url,
        require_mtls=settings.require_mtls,
        accepted_client_cert_header=settings.client_cert_header,
        token_binding=TokenBindingConfig(type=settings.token_binding_type, required=settings.token_binding_type != "none"),
        shadow_mode=settings.shadow_mode,
        decision_cache_ttl_s=settings.decision_cache_ttl_s,
    )

    def _logger_hook(name: str, fields: Mapping[str, Any]) -> None:
        logger.info(name, extra={"extra": dict(fields)})

    app.add_middleware(
        AuthMiddleware,
        config=auth_cfg,
        logger=_logger_hook,
    )

    # Роуты API v1
    app.include_router(enforce_router)

    # Health/ready
    @app.get("/live", include_in_schema=False)
    def live() -> Dict[str, str]:
        return {"status": "live"}

    @app.get("/ready", include_in_schema=False)
    def ready() -> Dict[str, str]:
        return {"status": "ready"}

    # Лайфспан: прогрев JWKS, graceful‑shutdown
    jwks_thread_holder: Dict[str, Any] = {}

    @app.on_event("startup")
    async def _startup() -> None:
        t = start_jwks_warmer(settings.jwks_url, logger, interval_s=300)
        jwks_thread_holder["t"] = t
        logger.info("bootstrap.started")

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        logger.info("bootstrap.stopping")
        # Поток‑демон завершится сам
        logger.info("bootstrap.stopped")

    # Graceful по сигналам (если процесс позволяет)
    def _graceful_exit(signum, frame):  # type: ignore[no-untyped-def]
        logger.info(f"signal.received {signum}")
        # UVicorn сам корректно останавливается по SIGTERM/SIGINT
    try:
        signal.signal(signal.SIGTERM, _graceful_exit)
        signal.signal(signal.SIGINT, _graceful_exit)
    except Exception:
        pass

    return app


# ============================= Локальный запуск (опционально) =============================

def main() -> None:
    """
    Локальный запуск: python -m zero_trust.bootstrap
    Переменные окружения управляют конфигурацией (см. Settings).
    """
    try:
        import uvicorn  # type: ignore
    except Exception:
        print("uvicorn not installed", file=sys.stderr)
        sys.exit(2)

    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")), lifespan="on")


if __name__ == "__main__":
    main()
