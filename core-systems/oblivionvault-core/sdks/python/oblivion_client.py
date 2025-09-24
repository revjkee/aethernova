# -*- coding: utf-8 -*-
"""
OblivionVault Core Python SDK (industrial-grade, single-file)
- Safe defaults, TLS/mTLS
- Auth strategies (Bearer, API Key, NoAuth)
- Retries with exponential backoff + jitter
- Idempotency keys for unsafe methods
- Token-bucket rate limiter
- Strong exceptions mapping
- Context manager support
- Optional requests; built-in urllib fallback

Compatibility: Python 3.9+
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Union

SDK_VERSION = "1.0.0"
DEFAULT_TIMEOUT = 30.0  # seconds
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_BACKOFF_BASE = 0.2
DEFAULT_BACKOFF_FACTOR = 2.0
DEFAULT_BACKOFF_MAX = 5.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_RATE_LIMIT_RPS = 0  # 0 = disabled

# Optional dependency: requests
try:
    import requests  # type: ignore
    _HAS_REQUESTS = True
except Exception:  # pragma: no cover
    requests = None
    _HAS_REQUESTS = False

# ---------------------------
# Exceptions
# ---------------------------

class OblivionError(Exception):
    """Base SDK error."""

class ConfigError(OblivionError):
    """Configuration-related error."""

class AuthError(OblivionError):
    """Authentication/authorization failure."""

class RateLimitError(OblivionError):
    """Local client-side rate limiting triggered."""

class RetryError(OblivionError):
    """Exhausted retries."""

class APIError(OblivionError):
    """HTTP error with payload."""

    def __init__(self, status_code: int, message: str, payload: Optional[dict] = None):
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.payload = payload or {}

class NotFound(APIError):
    pass

class Conflict(APIError):
    pass

class ValidationError(APIError):
    pass

class ServerError(APIError):
    pass


# ---------------------------
# Auth strategies
# ---------------------------

class AuthStrategy:
    """Base class for auth strategies."""

    def apply(self, headers: MutableMapping[str, str]) -> None:
        """Mutate headers in-place."""
        raise NotImplementedError

class BearerTokenAuth(AuthStrategy):
    def __init__(self, token: str):
        if not token:
            raise ConfigError("Bearer token is empty")
        self._token = token

    def apply(self, headers: MutableMapping[str, str]) -> None:
        headers["Authorization"] = f"Bearer {self._token}"

class ApiKeyAuth(AuthStrategy):
    def __init__(self, api_key: str, header_name: str = "X-API-Key"):
        if not api_key:
            raise ConfigError("API key is empty")
        self._api_key = api_key
        self._header_name = header_name

    def apply(self, headers: MutableMapping[str, str]) -> None:
        headers[self._header_name] = self._api_key

class NoAuth(AuthStrategy):
    def apply(self, headers: MutableMapping[str, str]) -> None:
        # intentionally no-op
        return


# ---------------------------
# Rate limiter (token bucket)
# ---------------------------

class TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: Optional[int] = None):
        self.rate = max(0.0, float(rate_per_sec))
        self.capacity = int(capacity if capacity is not None else max(1.0, self.rate * 2.0))
        self.tokens = self.capacity
        self.lock = threading.Lock()
        self.updated_at = time.monotonic()

    def take(self, tokens: int = 1, timeout: float = 0.0) -> None:
        if self.rate <= 0.0:
            return  # disabled

        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.updated_at
                refill = elapsed * self.rate
                if refill > 0:
                    self.tokens = min(self.capacity, self.tokens + refill)
                    self.updated_at = now
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
            if time.monotonic() >= deadline:
                raise RateLimitError("Rate limit exceeded (local token bucket)")
            # sleep a small slice
            time.sleep(0.005)


# ---------------------------
# Config
# ---------------------------

@dataclass
class ClientConfig:
    base_url: str
    timeout: float = DEFAULT_TIMEOUT
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    tenant_id: Optional[str] = None

    # TLS/mTLS
    verify: Union[bool, str] = True  # True/False or CA bundle path
    client_cert: Optional[str] = None  # path to cert pem
    client_key: Optional[str] = None   # path to key pem

    # Retries
    max_retries: int = DEFAULT_MAX_RETRIES
    backoff_base: float = DEFAULT_BACKOFF_BASE
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR
    backoff_max: float = DEFAULT_BACKOFF_MAX
    retry_on_status: Tuple[int, ...] = (408, 425, 429, 500, 502, 503, 504)

    # Local rate limiting
    rate_limit_rps: float = DEFAULT_RATE_LIMIT_RPS
    rate_capacity: Optional[int] = None

    # Proxies
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None

    # Extra headers
    default_headers: Dict[str, str] = field(default_factory=dict)

    # Idempotency
    enable_idempotency: bool = True

    @classmethod
    def from_env(cls, prefix: str = "OV_") -> "ClientConfig":
        def _get(name: str, default: Optional[str] = None) -> Optional[str]:
            return os.getenv(prefix + name, default)

        base_url = _get("BASE_URL")
        if not base_url:
            raise ConfigError(f"{prefix}BASE_URL is required")

        def _float(name: str, default: float) -> float:
            try:
                return float(_get(name, str(default)))  # type: ignore
            except Exception:
                return default

        def _int(name: str, default: int) -> int:
            try:
                return int(_get(name, str(default)))  # type: ignore
            except Exception:
                return default

        verify_env = _get("TLS_VERIFY", "true").lower()
        verify: Union[bool, str]
        if verify_env in ("true", "1", "yes"):
            verify = True
        elif verify_env in ("false", "0", "no"):
            verify = False
        else:
            verify = verify_env  # path

        return cls(
            base_url=base_url.rstrip("/"),
            timeout=_float("TIMEOUT", DEFAULT_TIMEOUT),
            connect_timeout=_float("CONNECT_TIMEOUT", DEFAULT_CONNECT_TIMEOUT),
            tenant_id=_get("TENANT_ID"),
            verify=verify,
            client_cert=_get("CLIENT_CERT"),
            client_key=_get("CLIENT_KEY"),
            max_retries=_int("MAX_RETRIES", DEFAULT_MAX_RETRIES),
            backoff_base=_float("BACKOFF_BASE", DEFAULT_BACKOFF_BASE),
            backoff_factor=_float("BACKOFF_FACTOR", DEFAULT_BACKOFF_FACTOR),
            backoff_max=_float("BACKOFF_MAX", DEFAULT_BACKOFF_MAX),
            rate_limit_rps=_float("RATE_LIMIT_RPS", DEFAULT_RATE_LIMIT_RPS),
            rate_capacity=int(_get("RATE_CAPACITY", "0")) or None,
            http_proxy=_get("HTTP_PROXY"),
            https_proxy=_get("HTTPS_PROXY"),
        )


# ---------------------------
# HTTP layer (requests or urllib)
# ---------------------------

class _HttpClient:
    def __init__(self, cfg: ClientConfig):
        self.cfg = cfg
        self._session = None
        self._proxies = {}
        if cfg.http_proxy:
            self._proxies["http"] = cfg.http_proxy
        if cfghttps := cfg.https_proxy:
            self._proxies["https"] = cfghttps

        if _HAS_REQUESTS:
            self._session = requests.Session()  # type: ignore
            self._session.headers.update({"User-Agent": f"OblivionVaultPythonSDK/{SDK_VERSION}"})
            if cfg.default_headers:
                self._session.headers.update(cfg.default_headers)

    def close(self) -> None:
        if _HAS_REQUESTS and self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        json_body: Optional[dict],
        timeout: float,
        verify: Union[bool, str],
        cert: Optional[Tuple[str, str]],
    ) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        if _HAS_REQUESTS:
            resp = self._session.request(  # type: ignore
                method=method,
                url=url,
                headers=dict(headers),
                json=json_body,
                timeout=(self.cfg.connect_timeout, timeout),
                verify=verify,
                cert=cert,
                proxies=self._proxies or None,
            )
            status = resp.status_code
            text = resp.text or ""
            try:
                payload = resp.json() if text else {}
            except Exception:
                payload = {"raw": text}
            return status, payload, dict(resp.headers)
        # Fallback to urllib
        import urllib.request
        import ssl

        req = urllib.request.Request(url=url, method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            req.add_header("Content-Type", "application/json")

        context = None
        if isinstance(verify, bool):
            context = ssl.create_default_context()
            if not verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        else:
            context = ssl.create_default_context(cafile=verify)

        if cert:
            context.load_cert_chain(certfile=cert[0], keyfile=cert[1])

        opener = urllib.request.build_opener()
        if self._proxies:
            proxy_handler = urllib.request.ProxyHandler(self._proxies)
            opener.add_handler(proxy_handler)

        try:
            with opener.open(req, data=data, timeout=timeout) as resp:  # type: ignore
                status = resp.getcode()
                body = resp.read().decode("utf-8") if resp.length is None or resp.length > 0 else ""
                headers_out = {k: v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:  # type: ignore
            status = e.code
            body = e.read().decode("utf-8")
            headers_out = dict(e.headers.items())
        except Exception as e:
            raise APIError(0, f"Network error: {e}") from e

        try:
            payload = json.loads(body) if body else {}
        except Exception:
            payload = {"raw": body}
        return status, payload, headers_out


# ---------------------------
# Utilities
# ---------------------------

def _rm_none(d: Any) -> Any:
    """Recursively drop None values."""
    if isinstance(d, dict):
        return {k: _rm_none(v) for k, v in d.items() if v is not None}
    if isinstance(d, list):
        return [_rm_none(x) for x in d if x is not None]
    return d

def _gen_request_id() -> str:
    return str(uuid.uuid4())

def _gen_idempotency_key() -> str:
    # 16 bytes base64url
    return base64.urlsafe_b64encode(uuid.uuid4().bytes).decode("ascii").rstrip("=")


# ---------------------------
# Main client
# ---------------------------

class OblivionClient:
    """
    OblivionVault Core API v1 client.

    Notes:
      - base_path: /api/v1
      - All methods accept optional headers override.
    """

    def __init__(
        self,
        config: ClientConfig,
        auth: Optional[AuthStrategy] = None,
        base_path: str = "/api/v1",
    ):
        if not config.base_url.startswith("http"):
            raise ConfigError("base_url must start with http:// or https://")
        self.cfg = config
        self.base_path = base_path.rstrip("/")
        self.auth = auth or NoAuth()
        self.http = _HttpClient(config)
        self._rate = TokenBucket(config.rate_limit_rps, config.rate_capacity)
        self._closed = False

    # ------------- Lifecycle -------------

    def close(self) -> None:
        if not self._closed:
            self.http.close()
            self._closed = True

    def __enter__(self) -> "OblivionClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------- Core HTTP -------------

    def _do_request(
        self,
        method: str,
        path: str,
        json_body: Optional[dict] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotent: Optional[bool] = None,
    ) -> Dict[str, Any]:
        if self._closed:
            raise OblivionError("Client is closed")

        self._rate.take(1)  # may raise RateLimitError

        url = f"{self.cfg.base_url}{self.base_path}{path}"
        hdrs: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": f"OblivionVaultPythonSDK/{SDK_VERSION}",
            "X-Request-Id": _gen_request_id(),
        }
        if self.cfg.tenant_id:
            hdrs["X-Tenant-Id"] = self.cfg.tenant_id
        if headers:
            hdrs.update(headers)
        # Apply auth
        self.auth.apply(hdrs)

        # Idempotency for unsafe methods
        if self.cfg.enable_idempotency and (idempotent if idempotent is not None else method.upper() in ("POST", "PUT", "PATCH", "DELETE")):
            hdrs.setdefault("Idempotency-Key", _gen_idempotency_key())

        # Cert tuple if both provided
        cert_tuple = (self.cfg.client_cert, self.cfg.client_key) if (self.cfg.client_cert and self.cfg.client_key) else None

        # Retries
        attempt = 0
        last_exc: Optional[Exception] = None
        while attempt <= self.cfg.max_retries:
            status, payload, resp_headers = self.http.request(
                method=method.upper(),
                url=url,
                headers=hdrs,
                json_body=_rm_none(json_body) if json_body is not None else None,
                timeout=self.cfg.timeout,
                verify=self.cfg.verify,
                cert=cert_tuple,
            )
            if status and status < 400:
                return payload or {}
            # Decide retry
            retryable = status in self.cfg.retry_on_status or status == 0
            if attempt < self.cfg.max_retries and retryable:
                delay = min(self.cfg.backoff_max, self.cfg.backoff_base * (self.cfg.backoff_factor ** attempt))
                # add equal-jitter
                delay = 0.5 * delay + (0.5 * delay * (uuid.uuid4().int % 1000) / 1000.0)
                time.sleep(delay)
                attempt += 1
                continue

            # No more retries -> raise mapped error
            message = ""
            if isinstance(payload, dict):
                message = payload.get("message") or payload.get("error") or json.dumps(payload)[:400]
            if status == 401 or status == 403:
                raise AuthError(f"Auth failed: {message}")
            if status == 404:
                raise NotFound(status, message or "Not found", payload)
            if status == 409:
                raise Conflict(status, message or "Conflict", payload)
            if status == 400 or status == 422:
                raise ValidationError(status, message or "Validation error", payload)
            if status >= 500:
                raise ServerError(status, message or "Server error", payload)
            raise APIError(status, message or "HTTP error", payload)

        raise RetryError(f"Exhausted retries: {last_exc}")

    # ------------- API: Secrets -------------

    def create_secret(
        self,
        name: str,
        payload_value_b64: str,
        namespace: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
        tags: Optional[List[str]] = None,
        type_: Optional[str] = None,  # GENERIC|CREDENTIAL|BINARY|CERTIFICATE
        compression: Optional[str] = None,  # NONE|GZIP|ZSTD
        client_encrypted: Optional[bool] = None,
        encryption_context: Optional[Dict[str, str]] = None,
        delete_protection: Optional[bool] = None,
        ttl_seconds: Optional[int] = None,
        new_version: Optional[bool] = None,
        upsert: bool = False,
        reason: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        body = {
            "meta": {},  # server can fill request metadata
            "name": name,
            "namespace": namespace,
            "payload": {
                "value": base64.urlsafe_b64decode(payload_value_b64.encode("ascii")).decode("latin1") if False else payload_value_b64,
                "metadata": {"items": metadata or {}},
                "type": type_,
                "compression": compression,
                "client_encrypted": client_encrypted,
                "encryption_context": {"items": encryption_context or {}},
            },
            "policy": {
                "delete_protection": delete_protection,
                "ttl": f"{ttl_seconds}s" if ttl_seconds is not None else None,
                "new_version": new_version,
                "reason": reason,
            },
            "tags": tags or [],
            "labels": {"items": {}},
            "upsert": upsert,
        }
        return self._do_request("POST", "/secrets", json_body=body, headers=headers)

    def update_secret(
        self,
        selector: Dict[str, str],
        update_mask: List[str],
        payload_value_b64: Optional[str] = None,
        labels: Optional[Dict[str, str]] = None,
        tags: Optional[List[str]] = None,
        delete_protection: Optional[bool] = None,
        ttl_seconds: Optional[int] = None,
        new_version: Optional[bool] = None,
        reason: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        body = {
            "meta": {},
            "target": {"id": selector.get("id"), "name": selector.get("name"), "alias": selector.get("alias")},
            "update_mask": {"paths": update_mask},
            "payload": {
                "value": payload_value_b64,
            } if payload_value_b64 is not None else None,
            "labels": {"items": labels or {}} if labels is not None else None,
            "tags": tags if tags is not None else None,
            "policy": {
                "delete_protection": delete_protection,
                "ttl": f"{ttl_seconds}s" if ttl_seconds is not None else None,
                "new_version": new_version,
                "reason": reason,
            },
        }
        return self._do_request("PATCH", "/secrets", json_body=body, headers=headers)

    def get_secret(
        self,
        selector: Dict[str, str],
        version: Optional[int] = None,
        include_metadata: Optional[bool] = None,
        include_history: Optional[bool] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        body = {
            "meta": {},
            "target": {"id": selector.get("id"), "name": selector.get("name"), "alias": selector.get("alias")},
            "version": version,
            "include_metadata": include_metadata,
            "include_history": include_history,
        }
        return self._do_request("POST", "/secrets:get", json_body=body, headers=headers)

    def list_secrets(
        self,
        namespace: Optional[str] = None,
        name_prefix: Optional[List[str]] = None,
        tags_any: Optional[List[str]] = None,
        labels_equals: Optional[Dict[str, str]] = None,
        include_deleted: Optional[bool] = None,
        page_size: int = 100,
        page_token: Optional[str] = None,
        sort_field: Optional[str] = None,
        sort_desc: bool = False,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        body = {
            "meta": {},
            "namespace": namespace,
            "name_prefix": name_prefix or [],
            "tags": {"any": tags_any or []} if tags_any else None,
            "labels": {"equals": labels_equals} if labels_equals else None,
            "page": {"page_size": page_size, "page_token": page_token},
            "sort": {"field": sort_field, "direction": "DESC" if sort_desc else "ASC"} if sort_field else None,
            "include_deleted": include_deleted,
        }
        return self._do_request("POST", "/secrets:list", json_body=body, headers=headers)

    def list_secrets_iter(
        self,
        **kwargs: Any,
    ) -> Generator[Dict[str, Any], None, None]:
        """Yield secrets across all pages."""
        token = None
        while True:
            resp = self.list_secrets(page_token=token, **kwargs)
            items = resp.get("items") or resp.get("secrets") or []
            for it in items:
                yield it
            token = resp.get("next_page_token")
            if not token:
                break

    def delete_secret(
        self,
        selector: Dict[str, str],
        soft_delete: bool = True,
        reason: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        body = {
            "meta": {},
            "target": {"id": selector.get("id"), "name": selector.get("name"), "alias": selector.get("alias")},
            "soft_delete": soft_delete,
            "reason": reason,
        }
        return self._do_request("POST", "/secrets:delete", json_body=body, headers=headers)

    def restore_secret(
        self,
        selector: Dict[str, str],
        version: Optional[int] = None,
        reason: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        body = {
            "meta": {},
            "target": {"id": selector.get("id"), "name": selector.get("name"), "alias": selector.get("alias")},
            "version": version,
            "reason": reason,
        }
        return self._do_request("POST", "/secrets:restore", json_body=body, headers=headers)

    # ------------- API: Rotation -------------

    def rotate_key(
        self,
        namespace: Optional[str] = None,
        target_selector: Optional[Dict[str, str]] = None,
        reencrypt_existing: bool = True,
        batch_size: Optional[int] = None,
        deadline_seconds: Optional[int] = None,
        kms_key_id: Optional[str] = None,
        kms_profile: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"meta": {}}
        if namespace is not None:
            body["namespace"] = namespace
        elif target_selector is not None:
            body["target"] = {
                "id": target_selector.get("id"),
                "name": target_selector.get("name"),
                "alias": target_selector.get("alias"),
            }
        else:
            raise ValidationError(400, "Either namespace or target_selector must be provided")
        body.update(
            {
                "reencrypt_existing": reencrypt_existing,
                "batch_size": batch_size,
                "deadline": f"{deadline_seconds}s" if deadline_seconds is not None else None,
                "kms_key_id": kms_key_id,
                "kms_profile": kms_profile,
            }
        )
        return self._do_request("POST", "/secrets:rotateKey", json_body=body, headers=headers)

    # ------------- API: Ops -------------

    def health_check(self, probe: str = "LIVENESS", headers: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
        body = {"meta": {}, "probe": probe}
        return self._do_request("POST", "/health:check", json_body=body, headers=headers)

    def status(
        self,
        include_storage: Optional[bool] = None,
        include_kms: Optional[bool] = None,
        include_cache: Optional[bool] = None,
        include_metrics: Optional[bool] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        body = {
            "meta": {},
            "include_storage": include_storage,
            "include_kms": include_kms,
            "include_cache": include_cache,
            "include_metrics": include_metrics,
        }
        return self._do_request("POST", "/system:status", json_body=body, headers=headers)

    def backup(
        self,
        verify: Optional[bool] = True,
        snapshot_id: Optional[str] = None,
        incremental: Optional[bool] = None,
        destination: Optional[Dict[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        body = {
            "meta": {},
            "verify": verify,
            "snapshot_id": snapshot_id,
            "incremental": incremental,
        }
        if destination:
            if "file" in destination:
                body["file"] = destination["file"]
            if "s3" in destination:
                body["s3"] = destination["s3"]
        return self._do_request("POST", "/ops:backup", json_body=body, headers=headers)

    def restore_backup(
        self,
        backup_uri: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        dry_run: Optional[bool] = None,
        overwrite: Optional[bool] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        if not backup_uri and not snapshot_id:
            raise ValidationError(400, "Either backup_uri or snapshot_id must be provided")
        body = {
            "meta": {},
            "backup_uri": backup_uri,
            "snapshot_id": snapshot_id,
            "dry_run": dry_run,
            "overwrite": overwrite,
        }
        return self._do_request("POST", "/ops:restore", json_body=body, headers=headers)


__all__ = [
    "OblivionClient",
    "ClientConfig",
    "AuthStrategy",
    "BearerTokenAuth",
    "ApiKeyAuth",
    "NoAuth",
    "OblivionError",
    "ConfigError",
    "AuthError",
    "RateLimitError",
    "RetryError",
    "APIError",
    "NotFound",
    "Conflict",
    "ValidationError",
    "ServerError",
]
