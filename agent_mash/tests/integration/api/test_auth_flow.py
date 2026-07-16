from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import pytest

try:
    import httpx
except Exception as exc:  # pragma: no cover
    raise RuntimeError("Missing dependency: httpx") from exc


@dataclass(frozen=True, slots=True)
class AuthApiConfig:
    base_url: str
    login_path: str
    register_path: str
    me_path: str
    timeout_seconds: float
    verify_tls: bool

    username: str
    password: str

    token_field_candidates: Tuple[str, ...]
    access_token_cookie_candidates: Tuple[str, ...]
    auth_header_prefix: str

    @staticmethod
    def from_env() -> "AuthApiConfig":
        base_url = (os.getenv("AETH_TEST_BASE_URL") or "").strip()
        if not base_url:
            raise ValueError("AETH_TEST_BASE_URL is required for integration API tests")

        login_path = (os.getenv("AETH_TEST_LOGIN_PATH") or "/auth/login").strip()
        register_path = (os.getenv("AETH_TEST_REGISTER_PATH") or "/auth/register").strip()
        me_path = (os.getenv("AETH_TEST_ME_PATH") or "/auth/me").strip()

        username = (os.getenv("AETH_TEST_USERNAME") or "").strip()
        password = (os.getenv("AETH_TEST_PASSWORD") or "").strip()
        if not username or not password:
            raise ValueError("AETH_TEST_USERNAME and AETH_TEST_PASSWORD are required for integration API tests")

        timeout_seconds_raw = (os.getenv("AETH_TEST_TIMEOUT_SECONDS") or "15").strip()
        try:
            timeout_seconds = float(timeout_seconds_raw)
        except ValueError as exc:
            raise ValueError("AETH_TEST_TIMEOUT_SECONDS must be a number") from exc

        verify_tls_raw = (os.getenv("AETH_TEST_VERIFY_TLS") or "true").strip().lower()
        verify_tls = verify_tls_raw not in ("0", "false", "no")

        token_fields_raw = (os.getenv("AETH_TEST_TOKEN_FIELDS") or "access_token,token,jwt").strip()
        token_field_candidates = tuple([x.strip() for x in token_fields_raw.split(",") if x.strip()])

        cookie_names_raw = (os.getenv("AETH_TEST_TOKEN_COOKIES") or "access_token,session,token").strip()
        access_token_cookie_candidates = tuple([x.strip() for x in cookie_names_raw.split(",") if x.strip()])

        auth_header_prefix = (os.getenv("AETH_TEST_AUTH_HEADER_PREFIX") or "Bearer").strip()
        if not auth_header_prefix:
            auth_header_prefix = "Bearer"

        return AuthApiConfig(
            base_url=base_url.rstrip("/"),
            login_path=login_path if login_path.startswith("/") else f"/{login_path}",
            register_path=register_path if register_path.startswith("/") else f"/{register_path}",
            me_path=me_path if me_path.startswith("/") else f"/{me_path}",
            timeout_seconds=timeout_seconds,
            verify_tls=verify_tls,
            username=username,
            password=password,
            token_field_candidates=token_field_candidates,
            access_token_cookie_candidates=access_token_cookie_candidates,
            auth_header_prefix=auth_header_prefix,
        )


def _skip_if_no_env() -> Optional[str]:
    base_url = (os.getenv("AETH_TEST_BASE_URL") or "").strip()
    username = (os.getenv("AETH_TEST_USERNAME") or "").strip()
    password = (os.getenv("AETH_TEST_PASSWORD") or "").strip()
    if not base_url:
        return "AETH_TEST_BASE_URL is not set"
    if not username or not password:
        return "AETH_TEST_USERNAME or AETH_TEST_PASSWORD is not set"
    return None


def _json(obj: Any) -> Dict[str, Any]:
    if isinstance(obj, dict):
        return obj
    raise AssertionError("Response JSON is not an object")


def _extract_token(data: Dict[str, Any], fields: Tuple[str, ...]) -> Optional[str]:
    for key in fields:
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _extract_cookie_token(cookies: httpx.Cookies, names: Tuple[str, ...]) -> Optional[str]:
    for name in names:
        val = cookies.get(name)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _retryable_status(code: int) -> bool:
    return code in (408, 429, 500, 502, 503, 504)


def _request_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    max_attempts: int = 3,
    base_backoff_seconds: float = 0.4,
) -> httpx.Response:
    last_exc: Optional[BaseException] = None
    for attempt in range(1, max_attempts + 1):
        try:
            resp = client.request(method, url, headers=headers, json=json_body)
            if _retryable_status(resp.status_code) and attempt < max_attempts:
                time.sleep(base_backoff_seconds * attempt)
                continue
            return resp
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            last_exc = exc
            if attempt < max_attempts:
                time.sleep(base_backoff_seconds * attempt)
                continue
            raise
    if last_exc:
        raise last_exc
    raise RuntimeError("Unreachable")


@pytest.fixture(scope="session")
def auth_api_config() -> AuthApiConfig:
    reason = _skip_if_no_env()
    if reason:
        pytest.skip(reason)
    try:
        return AuthApiConfig.from_env()
    except ValueError as exc:
        pytest.skip(str(exc))


@pytest.fixture(scope="session")
def http_client(auth_api_config: AuthApiConfig) -> httpx.Client:
    timeout = httpx.Timeout(auth_api_config.timeout_seconds)
    client = httpx.Client(
        base_url=auth_api_config.base_url,
        timeout=timeout,
        verify=auth_api_config.verify_tls,
        headers={"Accept": "application/json"},
        follow_redirects=False,
    )
    yield client
    client.close()


def _login_payload(cfg: AuthApiConfig) -> Dict[str, Any]:
    return {"username": cfg.username, "password": cfg.password}


def _register_payload(cfg: AuthApiConfig) -> Dict[str, Any]:
    uname = f"{cfg.username}+it_{secrets.token_hex(4)}"
    return {"username": uname, "password": cfg.password}


def _is_auth_failure(status_code: int, data: Optional[Dict[str, Any]]) -> bool:
    if status_code in (401, 403):
        return True
    if status_code == 400 and isinstance(data, dict):
        msg = data.get("detail") or data.get("message")
        if isinstance(msg, str) and msg.strip():
            return True
    return False


def _maybe_register_then_login(
    client: httpx.Client,
    cfg: AuthApiConfig,
) -> Tuple[Optional[str], Optional[str]]:
    login_resp = _request_with_retry(
        client,
        "POST",
        cfg.login_path,
        json_body=_login_payload(cfg),
        max_attempts=3,
    )

    login_data: Optional[Dict[str, Any]] = None
    try:
        login_data = _json(login_resp.json())
    except Exception:
        login_data = None

    if _is_auth_failure(login_resp.status_code, login_data):
        reg_resp = _request_with_retry(
            client,
            "POST",
            cfg.register_path,
            json_body=_register_payload(cfg),
            max_attempts=3,
        )
        if reg_resp.status_code not in (200, 201, 204):
            raise AssertionError(f"Register failed: status={reg_resp.status_code} body={reg_resp.text[:500]}")

        login_resp = _request_with_retry(
            client,
            "POST",
            cfg.login_path,
            json_body=_login_payload(cfg),
            max_attempts=3,
        )
        try:
            login_data = _json(login_resp.json())
        except Exception:
            login_data = None

    if login_resp.status_code not in (200, 201):
        raise AssertionError(f"Login failed: status={login_resp.status_code} body={login_resp.text[:500]}")

    token: Optional[str] = None
    if isinstance(login_data, dict):
        token = _extract_token(login_data, cfg.token_field_candidates)

    cookie_token = _extract_cookie_token(login_resp.cookies, cfg.access_token_cookie_candidates)
    return token, cookie_token


@pytest.mark.integration
@pytest.mark.api
def test_auth_flow_login_and_access_protected_endpoint(http_client: httpx.Client, auth_api_config: AuthApiConfig) -> None:
    cfg = auth_api_config
    client = http_client

    token, cookie_token = _maybe_register_then_login(client, cfg)

    if not token and not cookie_token:
        raise AssertionError(
            "No token found in response JSON or cookies. "
            "Configure AETH_TEST_TOKEN_FIELDS or AETH_TEST_TOKEN_COOKIES to match API contract."
        )

    headers: Dict[str, str] = {}
    if token:
        headers["Authorization"] = f"{cfg.auth_header_prefix} {token}"

    me_resp = _request_with_retry(
        client,
        "GET",
        cfg.me_path,
        headers=headers if headers else None,
        max_attempts=3,
    )

    if me_resp.status_code == 401 and not token and cookie_token:
        me_resp = _request_with_retry(
            client,
            "GET",
            cfg.me_path,
            headers=None,
            max_attempts=3,
        )

    if me_resp.status_code != 200:
        raise AssertionError(f"Protected endpoint failed: status={me_resp.status_code} body={me_resp.text[:500]}")

    data = _json(me_resp.json())
    if "id" not in data and "user" not in data and "username" not in data:
        raise AssertionError("Protected endpoint JSON does not contain expected identity fields (id/user/username)")


@pytest.mark.integration
@pytest.mark.api
def test_auth_flow_rejects_invalid_credentials(http_client: httpx.Client, auth_api_config: AuthApiConfig) -> None:
    cfg = auth_api_config
    client = http_client

    bad_payload = {"username": cfg.username, "password": "invalid_password_for_test_only"}
    resp = _request_with_retry(client, "POST", cfg.login_path, json_body=bad_payload, max_attempts=3)

    if resp.status_code not in (400, 401, 403):
        raise AssertionError(f"Expected auth failure status. Got status={resp.status_code} body={resp.text[:500]}")
