# agent_mash/legacy/scripts_archive/auth/deprecated_login_flow.py
"""
DEPRECATED LOGIN FLOW (ARCHIVE SCRIPT)

Назначение:
- Архивный скрипт для воспроизведения устаревшего login-flow
- Полезен для диагностики старых интеграций и регрессий
- Не является частью актуального продукта

Ключевые свойства промышленного уровня:
- Безопасен по умолчанию: не делает сетевых запросов без явного флага
- Строгая обработка ошибок, таймауты, детерминированное логирование
- Редактирование чувствительных полей в логах
- Поддержка чтения payload из файла (например tests/test_data)

Важно:
- Фактический контракт вашего API я не могу подтвердить без спецификации.
- Скрипт использует типовой формат payload (username, password, grant_type, client_id),
  который должен быть синхронизирован с вашим API, если вы захотите его реально использовать.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


LOGGER = logging.getLogger("deprecated_login_flow")


SENSITIVE_KEYS = {
    "password",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "api_key",
    "private_key",
    "authorization",
}


def _now_monotonic_ms() -> int:
    return int(time.monotonic() * 1000)


def _configure_logging(level: str) -> None:
    numeric = getattr(logging, level.upper(), None)
    if not isinstance(numeric, int):
        raise ValueError(f"Invalid log level: {level}")

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d %(levelname)s %(name)s:%(lineno)d %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(numeric)


def _redact(obj: Any) -> Any:
    """
    Редактирует чувствительные поля для безопасного логирования.
    """
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in SENSITIVE_KEYS:
                out[k] = "***REDACTED***"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    return obj


def _read_json_file(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"JSON file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Payload JSON must be an object at top level")

    return data


def _validate_payload_minimal(payload: Dict[str, Any]) -> None:
    """
    Минимальная валидация структуры payload.
    Не заменяет серверную валидацию.
    """
    required = ("username", "password")
    missing = [k for k in required if k not in payload]
    if missing:
        raise ValueError(f"Missing required fields: {missing}")

    if not isinstance(payload.get("username"), str) or not payload["username"].strip():
        raise ValueError("Field 'username' must be a non-empty string")

    if not isinstance(payload.get("password"), str) or not payload["password"]:
        raise ValueError("Field 'password' must be a non-empty string")

    # Эти поля опциональны, но если есть, должны быть корректного типа.
    optional_string_fields = ("grant_type", "client_id")
    for key in optional_string_fields:
        if key in payload and payload[key] is not None:
            if not isinstance(payload[key], str) or not payload[key].strip():
                raise ValueError(f"Field '{key}' must be a non-empty string when provided")


@dataclass(frozen=True)
class HttpResult:
    ok: bool
    status_code: int
    elapsed_ms: int
    json_body: Optional[Dict[str, Any]]
    text_body: Optional[str]


class DeprecatedLoginFlowClient:
    """
    Клиент архивного login-flow.

    По умолчанию предназначен для dry-run.
    Реальные HTTP вызовы допускаются только при allow_network=True.
    """

    def __init__(
        self,
        base_url: str,
        timeout_seconds: float,
        allow_network: bool,
        user_agent: str = "agent_mash-deprecated-login-flow/1.0",
    ) -> None:
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("base_url must be a non-empty string")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")

        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._allow_network = allow_network
        self._user_agent = user_agent

    def post_login(self, endpoint_path: str, payload: Dict[str, Any]) -> HttpResult:
        if not isinstance(endpoint_path, str) or not endpoint_path.strip():
            raise ValueError("endpoint_path must be a non-empty string")

        _validate_payload_minimal(payload)

        url = f"{self._base_url}/{endpoint_path.lstrip('/')}"
        start = _now_monotonic_ms()

        LOGGER.info("Prepared request url=%s payload=%s", url, _redact(payload))

        if not self._allow_network:
            elapsed = _now_monotonic_ms() - start
            LOGGER.warning("Network is disabled. Dry-run mode. No request sent.")
            return HttpResult(
                ok=False,
                status_code=0,
                elapsed_ms=elapsed,
                json_body=None,
                text_body="DRY_RUN_NETWORK_DISABLED",
            )

        try:
            import requests  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "The 'requests' package is required for network mode but is not available"
            ) from exc

        headers = {
            "User-Agent": self._user_agent,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            resp = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            elapsed = _now_monotonic_ms() - start
            LOGGER.error("HTTP request failed elapsed_ms=%d error=%s", elapsed, str(exc))
            return HttpResult(
                ok=False,
                status_code=0,
                elapsed_ms=elapsed,
                json_body=None,
                text_body=str(exc),
            )

        elapsed = _now_monotonic_ms() - start
        status_code = int(getattr(resp, "status_code", 0))

        body_json: Optional[Dict[str, Any]] = None
        body_text: Optional[str] = None

        content_type = (resp.headers.get("Content-Type") or "").lower()
        if "application/json" in content_type:
            try:
                parsed = resp.json()
                if isinstance(parsed, dict):
                    body_json = parsed
                else:
                    body_text = resp.text
            except Exception:
                body_text = resp.text
        else:
            body_text = resp.text

        ok = 200 <= status_code <= 299
        LOGGER.info(
            "Response received ok=%s status_code=%d elapsed_ms=%d body=%s",
            ok,
            status_code,
            elapsed,
            _redact(body_json) if body_json is not None else (body_text[:500] if body_text else None),
        )

        return HttpResult(
            ok=ok,
            status_code=status_code,
            elapsed_ms=elapsed,
            json_body=body_json,
            text_body=body_text,
        )


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="deprecated_login_flow",
        description="Archive script for deprecated login flow (safe by default).",
    )

    p.add_argument(
        "--base-url",
        required=True,
        help="Base URL, e.g. https://localhost:8443",
    )
    p.add_argument(
        "--endpoint",
        default="/auth/login",
        help="Login endpoint path (default: /auth/login)",
    )
    p.add_argument(
        "--payload-json",
        required=True,
        help="Path to JSON payload file (top-level object).",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout seconds (default: 10.0)",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (DEBUG, INFO, WARNING, ERROR). Default: INFO",
    )
    p.add_argument(
        "--allow-network",
        action="store_true",
        help="Enable real network requests (DANGEROUS). Default is dry-run.",
    )
    p.add_argument(
        "--i-know-this-is-deprecated",
        action="store_true",
        help="Required confirmation flag to run the script.",
    )

    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    _configure_logging(args.log_level)

    if not args.i_know_this_is_deprecated:
        LOGGER.error("Refusing to run: confirmation flag is missing.")
        LOGGER.error("Provide --i-know-this-is-deprecated to proceed.")
        return 2

    try:
        payload = _read_json_file(args.payload_json)
        _validate_payload_minimal(payload)
    except Exception as exc:
        LOGGER.error("Invalid payload file: %s", str(exc))
        return 3

    client = DeprecatedLoginFlowClient(
        base_url=args.base_url,
        timeout_seconds=float(args.timeout),
        allow_network=bool(args.allow_network),
    )

    result = client.post_login(args.endpoint, payload)

    # Стандартизированный итог для CI или ручной диагностики.
    summary = {
        "ok": result.ok,
        "status_code": result.status_code,
        "elapsed_ms": result.elapsed_ms,
        "mode": "network" if args.allow_network else "dry_run",
    }
    print(json.dumps(summary, ensure_ascii=False))

    if not args.allow_network:
        return 4  # dry-run intentional non-success

    return 0 if result.ok else 5


if __name__ == "__main__":
    raise SystemExit(main())
