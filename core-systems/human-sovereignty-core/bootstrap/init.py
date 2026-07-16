# human-sovereignty-core/bootstrap/init.py
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping

import yaml

try:
    import structlog
except Exception as exc:  # pragma: no cover
    raise RuntimeError("structlog is required but not installed") from exc


_ENV_TRUE = {"1", "true", "yes", "y", "on"}
_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,128}$")


class BootstrapError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class BootstrapConfig:
    project_name: str = "human-sovereignty-core"
    env: str = "prod"  # prod|dev|test
    strict: bool = True
    config_dir: Path = field(default_factory=lambda: _default_config_dir())
    max_yaml_bytes: int = 512 * 1024
    max_yaml_depth: int = 64
    log_level: str = "INFO"
    log_json: bool = True
    log_timestamps_utc: bool = True

    @staticmethod
    def from_env() -> "BootstrapConfig":
        env = os.environ.get("HSC_ENV", "prod").strip().lower()
        strict = os.environ.get("HSC_STRICT", "1").strip().lower() in _ENV_TRUE

        config_dir_raw = os.environ.get("HSC_CONFIG_DIR", "").strip()
        config_dir = Path(config_dir_raw).resolve() if config_dir_raw else _default_config_dir()

        max_yaml_bytes = _parse_int(os.environ.get("HSC_MAX_YAML_BYTES"), 512 * 1024, 64 * 1024, 10 * 1024 * 1024)
        max_yaml_depth = _parse_int(os.environ.get("HSC_MAX_YAML_DEPTH"), 64, 16, 256)

        log_level = os.environ.get("HSC_LOG_LEVEL", "INFO").strip().upper()
        log_json = os.environ.get("HSC_LOG_JSON", "1").strip().lower() in _ENV_TRUE
        log_timestamps_utc = os.environ.get("HSC_LOG_UTC", "1").strip().lower() in _ENV_TRUE

        return BootstrapConfig(
            env=env,
            strict=strict,
            config_dir=config_dir,
            max_yaml_bytes=max_yaml_bytes,
            max_yaml_depth=max_yaml_depth,
            log_level=log_level,
            log_json=log_json,
            log_timestamps_utc=log_timestamps_utc,
        )


@dataclass(slots=True)
class BootstrapState:
    config: BootstrapConfig
    started_at_unix: float
    duration_ms: int
    configs: dict[str, Any]
    config_files: dict[str, Path]
    checks: dict[str, Any]


def _default_project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _default_config_dir() -> Path:
    return _default_project_root() / "config"


def _parse_int(raw: str | None, default: int, min_v: int, max_v: int) -> int:
    if raw is None or raw.strip() == "":
        return default
    try:
        v = int(raw.strip(), 10)
    except Exception as exc:
        raise BootstrapError(f"Invalid integer value: {raw!r}") from exc
    if v < min_v or v > max_v:
        raise BootstrapError(f"Integer out of bounds [{min_v}, {max_v}]: {v}")
    return v


def _require_safe_key(name: str) -> str:
    if not _SAFE_NAME_RE.match(name):
        raise BootstrapError(f"Unsafe config key name: {name!r}")
    return name


def _read_limited_bytes(path: Path, max_bytes: int) -> bytes:
    try:
        st = path.stat()
    except FileNotFoundError as exc:
        raise BootstrapError(f"Config file not found: {str(path)}") from exc
    except Exception as exc:
        raise BootstrapError(f"Cannot stat config file: {str(path)}") from exc

    if st.st_size <= 0:
        raise BootstrapError(f"Empty config file: {str(path)}")
    if st.st_size > max_bytes:
        raise BootstrapError(f"Config file too large ({st.st_size} bytes): {str(path)}")

    try:
        return path.read_bytes()
    except Exception as exc:
        raise BootstrapError(f"Cannot read config file: {str(path)}") from exc


def _yaml_safe_load_limited(payload: bytes, max_depth: int) -> Any:
    # PyYAML itself does not expose a hard depth limit; we enforce via post-parse traversal.
    try:
        obj = yaml.safe_load(payload)
    except Exception as exc:
        raise BootstrapError("Invalid YAML") from exc

    _enforce_depth(obj, max_depth)
    return obj


def _enforce_depth(obj: Any, max_depth: int) -> None:
    def walk(node: Any, depth: int) -> None:
        if depth > max_depth:
            raise BootstrapError(f"YAML exceeds max depth: {max_depth}")
        if isinstance(node, dict):
            for k, v in node.items():
                walk(k, depth + 1)
                walk(v, depth + 1)
        elif isinstance(node, (list, tuple)):
            for v in node:
                walk(v, depth + 1)

    walk(obj, 1)


def _init_std_logging(level: str) -> None:
    root = logging.getLogger()
    if root.handlers:
        return

    lvl = getattr(logging, level, None)
    if not isinstance(lvl, int):
        raise BootstrapError(f"Invalid log level: {level!r}")

    handler = logging.StreamHandler(stream=sys.stdout)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)

    root.setLevel(lvl)
    root.addHandler(handler)


def _init_structlog(cfg: BootstrapConfig) -> structlog.BoundLogger:
    _init_std_logging(cfg.log_level)

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=cfg.log_timestamps_utc)

    shared_processors: list[Callable[..., Any]] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        timestamper,
    ]

    if cfg.log_json:
        renderer: Callable[..., Any] = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.UnicodeDecoder(),
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLogger().level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    return structlog.get_logger(cfg.project_name).bind(component="bootstrap", env=cfg.env)


def _expected_config_files(config_dir: Path) -> dict[str, Path]:
    expected = {
        "red_domains": config_dir / "red_domains.yaml",
        "approval_rules": config_dir / "approval_rules.yaml",
        "escalation_policy": config_dir / "escalation_policy.yaml",
        "ttl_policy": config_dir / "ttl_policy.yaml",
        "veto_policy": config_dir / "veto_policy.yaml",
        "limits": config_dir / "limits.yaml",
        "webui_security": config_dir / "webui_security.yaml",
        "webui_bindings": config_dir / "webui_bindings.yaml",
        "trust_anchors": config_dir / "trust_anchors.yaml",
    }
    return {_require_safe_key(k): v for k, v in expected.items()}


def _load_configs(cfg: BootstrapConfig, log: structlog.BoundLogger) -> tuple[dict[str, Any], dict[str, Path]]:
    config_dir = cfg.config_dir
    if not config_dir.exists() or not config_dir.is_dir():
        raise BootstrapError(f"Config directory missing or not a directory: {str(config_dir)}")

    files = _expected_config_files(config_dir)
    loaded: dict[str, Any] = {}

    for key, path in files.items():
        if not path.exists():
            if cfg.strict:
                raise BootstrapError(f"Missing required config: {key} at {str(path)}")
            log.warning("config_missing", key=key, path=str(path))
            continue

        payload = _read_limited_bytes(path, cfg.max_yaml_bytes)
        obj = _yaml_safe_load_limited(payload, cfg.max_yaml_depth)

        loaded[key] = obj
        log.info("config_loaded", key=key, path=str(path), bytes=len(payload))

    return loaded, files


async def _maybe_call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    try:
        res = fn(*args, **kwargs)
    except Exception:
        raise
    if inspect.isawaitable(res):
        return await res
    return res


def _safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
    except Exception:
        return '"<unserializable>"'


async def bootstrap(config: BootstrapConfig | None = None) -> BootstrapState:
    start = time.time()
    cfg = config or BootstrapConfig.from_env()
    log = _init_structlog(cfg)

    log.info("bootstrap_start", config_dir=str(cfg.config_dir), strict=cfg.strict, log_json=cfg.log_json)

    configs, config_files = _load_configs(cfg, log)

    checks: dict[str, Any] = {}

    try:
        from .invariants import assert_invariants  # type: ignore
    except Exception as exc:
        raise BootstrapError("bootstrap/invariants.py must expose assert_invariants") from exc

    try:
        from .self_check import run_self_check  # type: ignore
    except Exception as exc:
        raise BootstrapError("bootstrap/self_check.py must expose run_self_check") from exc

    try:
        from .hardening_check import run_hardening_check  # type: ignore
    except Exception as exc:
        raise BootstrapError("bootstrap/hardening_check.py must expose run_hardening_check") from exc

    checks["invariants"] = await _maybe_call(assert_invariants, cfg=cfg, configs=configs, logger=log)
    log.info("bootstrap_invariants_ok", result=_safe_json(checks["invariants"]))

    checks["self_check"] = await _maybe_call(run_self_check, cfg=cfg, configs=configs, logger=log)
    log.info("bootstrap_self_check_ok", result=_safe_json(checks["self_check"]))

    checks["hardening_check"] = await _maybe_call(run_hardening_check, cfg=cfg, configs=configs, logger=log)
    log.info("bootstrap_hardening_check_ok", result=_safe_json(checks["hardening_check"]))

    dur_ms = int((time.time() - start) * 1000)
    log.info("bootstrap_ok", duration_ms=dur_ms)

    return BootstrapState(
        config=cfg,
        started_at_unix=start,
        duration_ms=dur_ms,
        configs=configs,
        config_files=config_files,
        checks=checks,
    )


def bootstrap_sync(config: BootstrapConfig | None = None) -> BootstrapState:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        raise BootstrapError("bootstrap_sync() cannot run inside an active event loop; use await bootstrap().")

    return asyncio.run(bootstrap(config=config))


__all__ = [
    "BootstrapConfig",
    "BootstrapState",
    "BootstrapError",
    "bootstrap",
    "bootstrap_sync",
]
