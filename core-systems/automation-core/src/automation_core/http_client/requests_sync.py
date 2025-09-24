# -*- coding: utf-8 -*-
"""
Synchronous industrial HTTP client built on top of requests.

Verified references used to design this module:
- Session objects reuse connections (connection pooling) and persist settings/cookies.  # :contentReference[oaicite:4]{index=4}
- TLS verification is enabled by default; disabling verify is insecure and only for testing. # :contentReference[oaicite:5]{index=5}
- Timeouts must be explicitly set (connect/read); production code should use them.         # :contentReference[oaicite:6]{index=6}
- Streaming downloads and uploads via stream=True and iter_content()/file-like objects.    # :contentReference[oaicite:7]{index=7}
- Proxies are supported via per-request 'proxies' or session-level proxies.               # :contentReference[oaicite:8]{index=8}
- Automatic retries via HTTPAdapter(max_retries=urllib3.util.Retry).                      # :contentReference[oaicite:9]{index=9}
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Tuple, Union
from urllib.parse import urljoin

import requests
from requests import Response, Session
from requests.adapters import HTTPAdapter
from urllib3.util import Retry  # type: ignore  # provided by urllib3 vendored in requests

__all__ = [
    "RetryConfig",
    "Timeouts",
    "HttpClientConfig",
    "HttpClient",
    "HttpClientError",
]

# --------------------------- configuration ---------------------------

@dataclass(frozen=True)
class RetryConfig:
    total: int = 3
    backoff_factor: float = 0.3
    status_forcelist: Iterable[int] = (429, 500, 502, 503, 504)
    allowed_methods: Iterable[str] = frozenset({"HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"})
    respect_retry_after_header: bool = True

    def to_retry(self) -> Retry:
        # urllib3 Retry parameters and behavior reference.  # :contentReference[oaicite:10]{index=10}
        return Retry(
            total=self.total,
            backoff_factor=self.backoff_factor,
            status_forcelist=tuple(self.status_forcelist),
            allowed_methods=frozenset(m.upper() for m in self.allowed_methods),
            respect_retry_after_header=self.respect_retry_after_header,
        )


@dataclass(frozen=True)
class Timeouts:
    # (connect, read) timeouts as recommended by Requests docs.  # :contentReference[oaicite:11]{index=11}
    connect: float = 3.05
    read: float = 27.0

    @property
    def as_tuple(self) -> Tuple[float, float]:
        return (self.connect, self.read)


@dataclass
class HttpClientConfig:
    base_url: Optional[str] = None
    headers: MutableMapping[str, str] = field(default_factory=dict)
    timeouts: Timeouts = field(default_factory=Timeouts)
    retry: RetryConfig = field(default_factory=RetryConfig)
    # Pool sizes are adapter-level knobs provided by Requests' HTTPAdapter.
    pool_connections: int = 10
    pool_maxsize: int = 10
    # TLS
    verify: Union[bool, str] = True  # True or path to CA bundle (REQUESTS_CA_BUNDLE supported)  # :contentReference[oaicite:12]{index=12}
    cert: Optional[Union[str, Tuple[str, str]]] = None  # client cert or (cert,key)  # :contentReference[oaicite:13]{index=13}
    # Proxies mapping like {'http': 'http://...', 'https': 'http://...'}  # :contentReference[oaicite:14]{index=14}
    proxies: Optional[Mapping[str, str]] = None
    # Auth object implementing requests' AuthBase or tuple
    auth: Optional[Any] = None
    # Redirects
    allow_redirects: bool = True
    # User-Agent override
    user_agent: Optional[str] = None
    # Redacted headers in logs
    redact_headers: Iterable[str] = field(default_factory=lambda: ("authorization", "cookie", "set-cookie"))


# --------------------------- exceptions ---------------------------

class HttpClientError(RuntimeError):
    """Error wrapper that includes HTTP context."""

    def __init__(
        self,
        message: str,
        *,
        response: Optional[Response] = None,
        request_kwargs: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.response = response
        self.request_kwargs = request_kwargs or {}

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"message": str(self)}
        if self.response is not None:
            data.update(
                {
                    "status_code": self.response.status_code,
                    "url": self.response.url,
                    "headers": dict(self.response.headers),
                    "text_preview": self.response.text[:2048] if self.response.text else "",
                }
            )
        if self.request_kwargs:
            data["request"] = {k: v for k, v in self.request_kwargs.items() if k != "data"}
        return data


# --------------------------- client ---------------------------

class HttpClient:
    """
    Synchronous HTTP client with safe defaults:
    - Pooled Session, TLS verify on, explicit timeouts, retries, proxies, streaming helpers.
    """

    def __init__(self, config: Optional[HttpClientConfig] = None, logger: Optional[logging.Logger] = None) -> None:
        self.config = config or HttpClientConfig()
        self.log = logger or logging.getLogger(__name__)
        self.session = self._build_session(self.config)

    # ---- session lifecycle ----

    def _build_session(self, cfg: HttpClientConfig) -> Session:
        s = requests.Session()  # connection pooling + persisted settings  # :contentReference[oaicite:15]{index=15}

        # Default headers
        s.headers.update({"Accept": "*/*"})
        if cfg.user_agent:
            s.headers["User-Agent"] = cfg.user_agent
        s.headers.update(cfg.headers or {})

        # TLS / auth / proxies
        s.verify = cfg.verify  # True or path to CA bundle  # :contentReference[oaicite:16]{index=16}
        if cfg.cert:
            s.cert = cfg.cert   # client-side certificate(s)                    # :contentReference[oaicite:17]{index=17}
        if cfg.proxies:
            s.proxies.update(dict(cfg.proxies))                                 # :contentReference[oaicite:18]{index=18}
        if cfg.auth:
            s.auth = cfg.auth

        # Mount adapters with retries and pool sizes
        adapter = HTTPAdapter(
            max_retries=cfg.retry.to_retry(),
            pool_connections=cfg.pool_connections,
            pool_maxsize=cfg.pool_maxsize,
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)

        return s

    # Context manager support
    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:  # pragma: no cover
            self.log.exception("Session close failed")

    # ---- core request ----

    def _build_url(self, url_or_path: str) -> str:
        if self.config.base_url and not url_or_path.lower().startswith(("http://", "https://")):
            return urljoin(self.config.base_url.rstrip("/") + "/", url_or_path.lstrip("/"))
        return url_or_path

    def _redact(self, headers: Mapping[str, str]) -> Dict[str, str]:
        redacted = {}
        red_set = {h.lower() for h in self.config.redact_headers}
        for k, v in headers.items():
            redacted[k] = "***REDACTED***" if k.lower() in red_set else v
        return redacted

    def request(
        self,
        method: str,
        url_or_path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        json_body: Optional[Any] = None,
        data: Optional[Union[bytes, Mapping[str, Any]]] = None,
        files: Optional[Mapping[str, Any]] = None,
        timeout: Optional[Tuple[float, float]] = None,
        allow_redirects: Optional[bool] = None,
        stream: bool = False,
        proxies: Optional[Mapping[str, str]] = None,
        auth: Optional[Any] = None,
    ) -> Response:
        """
        Perform a request with safe defaults.
        - JSON is sent via 'json=' to auto-encode per docs.            # :contentReference[oaicite:19]{index=19}
        - Timeouts default to (connect, read).                         # :contentReference[oaicite:20]{index=20}
        - TLS verify uses session default (True unless overridden).    # :contentReference[oaicite:21]{index=21}
        """
        url = self._build_url(url_or_path)
        req_headers = {}
        if headers:
            req_headers.update(headers)

        # Log request (with redaction)
        self.log.debug(
            "HTTP %s %s params=%s headers=%s",
            method, url, params, self._redact(req_headers),
        )

        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                headers=req_headers,
                json=json_body,
                data=data if json_body is None else None,  # json takes precedence  # :contentReference[oaicite:22]{index=22}
                files=files,
                timeout=timeout or self.config.timeouts.as_tuple,
                allow_redirects=self.config.allow_redirects if allow_redirects is None else allow_redirects,
                stream=stream,
                proxies=proxies,  # per-request proxy override                        # :contentReference[oaicite:23]{index=23}
                auth=auth or self.config.auth,
            )
        except requests.Timeout as e:
            raise HttpClientError("HTTP timeout") from e
        except requests.RequestException as e:
            raise HttpClientError("HTTP request failed") from e

        # Basic audit log
        self.log.debug(
            "HTTP %s <- %s status=%s len=%s",
            method, url, resp.status_code, resp.headers.get("Content-Length"),
        )
        return resp

    # ---- convenience methods ----

    def get_json(
        self,
        url_or_path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[Tuple[float, float]] = None,
    ) -> Any:
        r = self.request("GET", url_or_path, params=params, headers=headers, timeout=timeout)
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            raise HttpClientError("Non-2xx response", response=r) from e
        try:
            return r.json()  # Response.json is callable; raises on decode error.  # :contentReference[oaicite:24]{index=24}
        except ValueError as e:
            raise HttpClientError("Failed to decode JSON", response=r) from e

    def post_json(
        self,
        url_or_path: str,
        *,
        json_body: Any,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[Tuple[float, float]] = None,
    ) -> Any:
        r = self.request("POST", url_or_path, json_body=json_body, headers=headers, timeout=timeout)
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            raise HttpClientError("Non-2xx response", response=r) from e
        try:
            return r.json()
        except ValueError as e:
            raise HttpClientError("Failed to decode JSON", response=r) from e

    # ---- file transfer helpers ----

    def download(
        self,
        url_or_path: str,
        *,
        dest: Union[str, Path],
        chunk_size: int = 1024 * 1024,
        checksum: Optional[Tuple[str, str]] = None,  # ("sha256", "hex")
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[Tuple[float, float]] = None,
    ) -> Path:
        """
        Stream download to file with optional checksum verification.
        Uses iter_content() as recommended for streaming.  # :contentReference[oaicite:25]{index=25}
        """
        r = self.request("GET", url_or_path, headers=headers, timeout=timeout, stream=True)
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            # ensure release of connection if error
            r.close()
            raise HttpClientError("Non-2xx response", response=r) from e

        algo = None
        h = None
        if checksum:
            algo, expected = checksum
            h = hashlib.new(algo)

        path = Path(dest)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            for chunk in r.iter_content(chunk_size=chunk_size):
                if not chunk:
                    continue
                f.write(chunk)
                if h:
                    h.update(chunk)
        r.close()

        if h:
            digest = h.hexdigest()
            if digest.lower() != expected.lower():
                raise HttpClientError(f"Checksum mismatch: got {digest}, expected {expected}")

        return path

    def upload_multipart(
        self,
        url_or_path: str,
        *,
        files: Mapping[str, Any],
        data: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[Tuple[float, float]] = None,
    ) -> Response:
        """
        Multipart upload helper; pass open binary file handles for streaming.
        Requests supports streaming uploads via file-like objects.          # :contentReference[oaicite:26]{index=26}
        """
        r = self.request("POST", url_or_path, files=files, data=data, headers=headers, timeout=timeout)
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            raise HttpClientError("Non-2xx response", response=r) from e
        return r
