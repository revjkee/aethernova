# agent_mash/tests/e2e/scenarios/test_failure_recovery.py
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import pytest

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore


@dataclass(frozen=True)
class E2EFailureRecoveryConfig:
    """
    Конфигурация e2e-теста через переменные окружения.

    Все значения по умолчанию безопасные: если базовый URL не задан, тест пропускается.

    Требуемый минимум:
      - E2E_BASE_URL

    Рекомендуемые endpoint-ы (контракт):
      - E2E_HEALTH_PATH (по умолчанию /health)
      - E2E_READY_PATH  (по умолчанию /ready)  (если отсутствует, можно оставить как /health)
      - E2E_PROBE_PATH  (по умолчанию /probe)  (любой "лёгкий" endpoint, который должен работать стабильно)
      - E2E_CHAOS_PATH  (по умолчанию /_test/chaos/fail)  (endpoint, инициирующий сбой)
      - E2E_RECOVERY_PATH (по умолчанию /_test/chaos/status) (endpoint статуса восстановления)

    Варианты авторизации:
      - E2E_AUTH_BEARER  (Bearer token)
      - E2E_AUTH_HEADER  (произвольный заголовок вида "X-Api-Key: value")
    """

    base_url: str
    health_path: str
    ready_path: str
    probe_path: str
    chaos_path: str
    recovery_path: str

    connect_timeout_s: float
    read_timeout_s: float

    warmup_deadline_s: float
    degrade_deadline_s: float
    recovery_deadline_s: float

    poll_interval_s: float
    request_retries: int
    retry_backoff_base_s: float

    auth_bearer: Optional[str]
    auth_header: Optional[Tuple[str, str]]

    @staticmethod
    def from_env() -> "E2EFailureRecoveryConfig":
        base_url = os.getenv("E2E_BASE_URL", "").strip().rstrip("/")

        health_path = os.getenv("E2E_HEALTH_PATH", "/health").strip()
        ready_path = os.getenv("E2E_READY_PATH", "/ready").strip()
        probe_path = os.getenv("E2E_PROBE_PATH", "/probe").strip()

        chaos_path = os.getenv("E2E_CHAOS_PATH", "/_test/chaos/fail").strip()
        recovery_path = os.getenv("E2E_RECOVERY_PATH", "/_test/chaos/status").strip()

        connect_timeout_s = float(os.getenv("E2E_CONNECT_TIMEOUT_S", "5"))
        read_timeout_s = float(os.getenv("E2E_READ_TIMEOUT_S", "10"))

        warmup_deadline_s = float(os.getenv("E2E_WARMUP_DEADLINE_S", "60"))
        degrade_deadline_s = float(os.getenv("E2E_DEGRADE_DEADLINE_S", "30"))
        recovery_deadline_s = float(os.getenv("E2E_RECOVERY_DEADLINE_S", "180"))

        poll_interval_s = float(os.getenv("E2E_POLL_INTERVAL_S", "1.0"))
        request_retries = int(os.getenv("E2E_REQUEST_RETRIES", "2"))
        retry_backoff_base_s = float(os.getenv("E2E_RETRY_BACKOFF_BASE_S", "0.3"))

        auth_bearer = os.getenv("E2E_AUTH_BEARER", "").strip() or None
        auth_header_raw = os.getenv("E2E_AUTH_HEADER", "").strip() or None
        auth_header = _parse_header_kv(auth_header_raw) if auth_header_raw else None

        return E2EFailureRecoveryConfig(
            base_url=base_url,
            health_path=health_path,
            ready_path=ready_path,
            probe_path=probe_path,
            chaos_path=chaos_path,
            recovery_path=recovery_path,
            connect_timeout_s=connect_timeout_s,
            read_timeout_s=read_timeout_s,
            warmup_deadline_s=warmup_deadline_s,
            degrade_deadline_s=degrade_deadline_s,
            recovery_deadline_s=recovery_deadline_s,
            poll_interval_s=poll_interval_s,
            request_retries=request_retries,
            retry_backoff_base_s=retry_backoff_base_s,
            auth_bearer=auth_bearer,
            auth_header=auth_header,
        )


def _parse_header_kv(raw: str) -> Tuple[str, str]:
    # Ожидаем формат: "Header-Name: value"
    parts = raw.split(":", 1)
    if len(parts) != 2:
        raise ValueError("E2E_AUTH_HEADER must be in format 'Header-Name: value'")
    name = parts[0].strip()
    value = parts[1].strip()
    if not name:
        raise ValueError("E2E_AUTH_HEADER header name is empty")
    return name, value


def _require_httpx() -> None:
    if httpx is None:
        pytest.skip("httpx is not installed; install httpx to run e2e HTTP scenarios")


def _build_headers(cfg: E2EFailureRecoveryConfig) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if cfg.auth_bearer:
        headers["Authorization"] = f"Bearer {cfg.auth_bearer}"
    if cfg.auth_header:
        k, v = cfg.auth_header
        headers[k] = v
    return headers


def _full_url(cfg: E2EFailureRecoveryConfig, path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return f"{cfg.base_url}{path}"


def _sleep(backoff_s: float) -> None:
    if backoff_s > 0:
        time.sleep(backoff_s)


def _request_with_retries(
    client: "httpx.Client",
    method: str,
    url: str,
    *,
    retries: int,
    backoff_base_s: float,
    timeout: "httpx.Timeout",
    json: Optional[Dict[str, Any]] = None,
) -> "httpx.Response":
    last_exc: Optional[BaseException] = None
    for attempt in range(retries + 1):
        try:
            return client.request(method, url, json=json, timeout=timeout)
        except Exception as exc:
            last_exc = exc
            if attempt >= retries:
                raise
            _sleep(backoff_base_s * (2**attempt))
    raise RuntimeError(f"unreachable; last exception: {last_exc!r}")


def _is_ok_status(resp: "httpx.Response") -> bool:
    return 200 <= resp.status_code < 300


def _safe_json(resp: "httpx.Response") -> Optional[Dict[str, Any]]:
    try:
        data = resp.json()
        if isinstance(data, dict):
            return data
        return None
    except Exception:
        return None


def _wait_until(
    *,
    name: str,
    deadline_s: float,
    poll_interval_s: float,
    condition,
) -> None:
    start = time.monotonic()
    last_error: Optional[str] = None
    while True:
        elapsed = time.monotonic() - start
        if elapsed > deadline_s:
            details = f"{name} timeout after {deadline_s:.2f}s"
            if last_error:
                details += f"; last_error={last_error}"
            raise AssertionError(details)

        try:
            ok, msg = condition()
            if ok:
                return
            last_error = msg
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        time.sleep(poll_interval_s)


@pytest.mark.e2e
@pytest.mark.recovery
def test_failure_recovery_end_to_end() -> None:
    """
    Промышленный e2e сценарий восстановления после сбоя.

    Контракт:
      1) /health и /ready возвращают 2xx когда система готова
      2) /probe (или иной лёгкий endpoint) возвращает 2xx в норме
      3) /_test/chaos/fail инициирует сбой (может вернуть 2xx или 202)
      4) /_test/chaos/status возвращает JSON со статусом восстановления

    Если контрактные endpoint-ы отсутствуют, тест корректно пропускается
    при помощи переменных окружения (см. E2EFailureRecoveryConfig).
    """
    _require_httpx()

    cfg = E2EFailureRecoveryConfig.from_env()
    if not cfg.base_url:
        pytest.skip("E2E_BASE_URL is not set; skipping failure recovery e2e test")

    headers = _build_headers(cfg)
    timeout = httpx.Timeout(cfg.read_timeout_s, connect=cfg.connect_timeout_s)

    with httpx.Client(headers=headers, follow_redirects=True) as client:
        health_url = _full_url(cfg, cfg.health_path)
        ready_url = _full_url(cfg, cfg.ready_path)
        probe_url = _full_url(cfg, cfg.probe_path)
        chaos_url = _full_url(cfg, cfg.chaos_path)
        recovery_url = _full_url(cfg, cfg.recovery_path)

        # 1) Прогрев и ожидание готовности
        _wait_until(
            name="warmup: health endpoint",
            deadline_s=cfg.warmup_deadline_s,
            poll_interval_s=cfg.poll_interval_s,
            condition=lambda: _check_simple_ok(
                client, "GET", health_url, timeout, cfg.request_retries, cfg.retry_backoff_base_s
            ),
        )

        _wait_until(
            name="warmup: ready endpoint",
            deadline_s=cfg.warmup_deadline_s,
            poll_interval_s=cfg.poll_interval_s,
            condition=lambda: _check_simple_ok(
                client, "GET", ready_url, timeout, cfg.request_retries, cfg.retry_backoff_base_s
            ),
        )

        # Пробный запрос должен быть стабильно успешным до инъекции сбоя
        _wait_until(
            name="warmup: probe endpoint",
            deadline_s=cfg.warmup_deadline_s,
            poll_interval_s=cfg.poll_interval_s,
            condition=lambda: _check_simple_ok(
                client, "GET", probe_url, timeout, cfg.request_retries, cfg.retry_backoff_base_s
            ),
        )

        # 2) Инъекция сбоя
        chaos_resp = _request_with_retries(
            client,
            "POST",
            chaos_url,
            retries=cfg.request_retries,
            backoff_base_s=cfg.retry_backoff_base_s,
            timeout=timeout,
            json={"scenario": "failure_recovery", "ts": time.time()},
        )

        # Если chaos endpoint не существует, лучше честно пропустить, чем фейлить на инфраструктуре
        if chaos_resp.status_code == 404:
            pytest.skip("chaos endpoint returned 404; configure E2E_CHAOS_PATH or expose test-only chaos API")

        assert chaos_resp.status_code in (200, 202, 204), (
            f"unexpected chaos response status: {chaos_resp.status_code}; "
            f"body_snippet={chaos_resp.text[:300]!r}"
        )

        # 3) Ожидаем деградацию (не обязана случиться как 5xx; допускаем timeouts/ошибки/не-2xx)
        # Если деградация не проявилась, это тоже допустимо (например, система перезапускает только воркер без простоя).
        degradation_observed = _try_observe_degradation(
            client=client,
            url=probe_url,
            timeout=timeout,
            deadline_s=cfg.degrade_deadline_s,
            poll_interval_s=cfg.poll_interval_s,
            retries=cfg.request_retries,
            backoff_base_s=cfg.retry_backoff_base_s,
        )

        # 4) Ожидаем восстановления: probe снова 2xx и recovery/status сообщает recovered (если endpoint есть)
        _wait_until(
            name="recovery: probe endpoint becomes ok",
            deadline_s=cfg.recovery_deadline_s,
            poll_interval_s=cfg.poll_interval_s,
            condition=lambda: _check_simple_ok(
                client, "GET", probe_url, timeout, cfg.request_retries, cfg.retry_backoff_base_s
            ),
        )

        # 5) Проверка статуса восстановления (если endpoint существует)
        rec = _request_with_retries(
            client,
            "GET",
            recovery_url,
            retries=cfg.request_retries,
            backoff_base_s=cfg.retry_backoff_base_s,
            timeout=timeout,
        )

        if rec.status_code == 404:
            # Это не ошибка теста: статусный endpoint может отсутствовать.
            # В таком случае достаточно факта, что probe/ready восстановились.
            return

        assert _is_ok_status(rec), (
            f"recovery status endpoint not ok: {rec.status_code}; body_snippet={rec.text[:300]!r}"
        )

        data = _safe_json(rec)
        if data is None:
            raise AssertionError("recovery status endpoint must return JSON object")

        # Контрактный формат статуса: хотя бы один из ключей должен указывать на восстановление
        # Примеры допустимых полей: {"status":"recovered"} или {"recovered":true} или {"state":"ready"}
        if _json_indicates_recovered(data):
            return

        # Если JSON не содержит признаков восстановления, это реальная ошибка контракта
        raise AssertionError(
            "recovery status JSON does not indicate recovered state; "
            f"json={data!r}; degradation_observed={degradation_observed}"
        )


def _check_simple_ok(
    client: "httpx.Client",
    method: str,
    url: str,
    timeout: "httpx.Timeout",
    retries: int,
    backoff_base_s: float,
) -> Tuple[bool, str]:
    try:
        resp = _request_with_retries(
            client,
            method,
            url,
            retries=retries,
            backoff_base_s=backoff_base_s,
            timeout=timeout,
        )
        if _is_ok_status(resp):
            return True, "ok"
        return False, f"status={resp.status_code}; body_snippet={resp.text[:200]!r}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _try_observe_degradation(
    *,
    client: "httpx.Client",
    url: str,
    timeout: "httpx.Timeout",
    deadline_s: float,
    poll_interval_s: float,
    retries: int,
    backoff_base_s: float,
) -> bool:
    start = time.monotonic()
    while (time.monotonic() - start) <= deadline_s:
        ok, _ = _check_simple_ok(client, "GET", url, timeout, retries, backoff_base_s)
        if not ok:
            return True
        time.sleep(poll_interval_s)
    return False


def _json_indicates_recovered(data: Dict[str, Any]) -> bool:
    # Без предположений о точном формате: проверяем несколько распространённых вариантов.
    def norm(v: Any) -> str:
        return str(v).strip().lower()

    if "recovered" in data and isinstance(data["recovered"], bool):
        return data["recovered"] is True

    if "status" in data and norm(data["status"]) in ("recovered", "ok", "ready", "healthy"):
        return True

    if "state" in data and norm(data["state"]) in ("recovered", "ok", "ready", "healthy"):
        return True

    if "phase" in data and norm(data["phase"]) in ("ready", "healthy", "serving"):
        return True

    return False
