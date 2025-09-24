# cybersecurity-core/cybersecurity/vuln/connectors/nessus.py
from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple, Union

import httpx
from pydantic import BaseModel, Field, validator

__all__ = [
    "NessusError",
    "NessusAuthError",
    "NessusRateLimitError",
    "NessusPermissionError",
    "NessusNotFoundError",
    "ScanSummary",
    "ScanDetails",
    "VulnerabilityRecord",
    "NessusClient",
]

logger = logging.getLogger(__name__)


# ============================== Exceptions ===================================

class NessusError(Exception):
    """Generic connector error."""


class NessusAuthError(NessusError):
    """Authentication/authorization error."""


class NessusRateLimitError(NessusError):
    """HTTP 429 with Retry-After."""


class NessusPermissionError(NessusError):
    """HTTP 403 Forbidden."""


class NessusNotFoundError(NessusError):
    """HTTP 404 Not Found."""


# ================================ Models =====================================

class ScanSummary(BaseModel):
    id: int
    name: str
    status: Optional[str] = None
    folder_id: Optional[int] = Field(default=None, alias="folder_id")
    last_modification_date: Optional[int] = None
    owner: Optional[str] = None

    class Config:
        allow_population_by_field_name = True


class ScanHistory(BaseModel):
    history_id: Optional[int] = Field(default=None, alias="history_id")
    status: Optional[str] = None
    last_modification_date: Optional[int] = None

    class Config:
        allow_population_by_field_name = True


class ScanDetails(BaseModel):
    id: int
    name: str
    status: Optional[str] = None
    history: List[ScanHistory] = Field(default_factory=list)
    targets: Optional[str] = None  # Nessus often returns comma-separated
    policy: Optional[str] = None
    owner: Optional[str] = None

    @validator("history", pre=True)
    def _coerce_history(cls, v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return []


Severity = Literal["info", "low", "medium", "high", "critical"]


class VulnerabilityRecord(BaseModel):
    plugin_id: Optional[int] = None
    plugin_name: Optional[str] = None
    family: Optional[str] = None
    severity: Optional[Severity] = None
    severity_id: Optional[int] = None
    cve: List[str] = Field(default_factory=list)
    cvss_base_score: Optional[float] = None
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    synopsis: Optional[str] = None
    description: Optional[str] = None
    solution: Optional[str] = None
    references: Dict[str, List[str]] = Field(default_factory=dict)


# ============================== Helper utils =================================

def _join_url(base: str, path: str) -> str:
    base = base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _default_user_agent() -> str:
    return "Aethernova-NessusClient/1.0 (+https://aethernova.internal)"


def _is_cloud(base_url: str) -> bool:
    return "cloud.tenable.com" in base_url.lower()


def _mask(s: Optional[str]) -> str:
    if not s:
        return ""
    if len(s) <= 6:
        return "***"
    return s[:3] + "***" + s[-3:]


# ============================== Main Client ==================================

@dataclass
class _RetryCfg:
    max_retries: int = 4
    backoff_factor: float = 0.8
    jitter: float = 0.2
    retry_on_status: Tuple[int, ...] = (429, 500, 502, 503, 504)


class NessusClient:
    """
    Async client for Tenable Nessus / Tenable.io.

    Authentication:
      - Tenable.io: X-ApiKeys: accessKey=...; secretKey=...
      - Nessus local (https://host:8834): session cookie token via POST /session, or API keys if enabled.

    Key capabilities:
      - List scans, get scan details, launch scans
      - Export and download scan results
      - Tenable.io: list vulnerabilities via Workbenches
      - Robust retries with Retry-After, connection and read timeouts
    """

    def __init__(
        self,
        base_url: str,
        *,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Union[bool, str] = True,
        timeout: float = 30.0,
        retry: _RetryCfg = _RetryCfg(),
        proxies: Optional[Dict[str, str]] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.retry = retry
        self.proxies = proxies
        self.user_agent = user_agent or _default_user_agent()
        self._session_token: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    # --------------- lifecycle ---------------

    async def __aenter__(self) -> "NessusClient":
        await self._ensure_client()
        if not self.access_key and not self.secret_key and (self.username and self.password):
            await self.login()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def _ensure_client(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
                proxies=self.proxies,
                headers={"User-Agent": self.user_agent, "Accept": "application/json"},
                http2=True,
            )

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # --------------- auth ---------------

    async def login(self) -> None:
        """
        Obtain session token for local Nessus via POST /session.
        """
        await self._ensure_client()
        if not (self.username and self.password):
            raise NessusAuthError("Username/password required for session login")
        url = _join_url(self.base_url, "/session")
        payload = {"username": self.username, "password": self.password}
        resp = await self._client.post(url, json=payload)
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("token")
            if not token:
                raise NessusAuthError("No token in /session response")
            self._session_token = token
            logger.info("Nessus session established for %s", self.username)
        elif resp.status_code in (401, 403):
            raise NessusAuthError(f"Login failed: {resp.text}")
        else:
            raise NessusError(f"Unexpected /session response: {resp.status_code} {resp.text}")

    def _auth_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.access_key and self.secret_key:
            headers["X-ApiKeys"] = f"accessKey={self.access_key}; secretKey={self.secret_key}"
        elif self._session_token:
            headers["X-Cookie"] = f"token={self._session_token}"
        return headers

    # --------------- request core ---------------

    async def _request(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE"],
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        stream: bool = False,
        expected: Tuple[int, ...] = (200,),
    ) -> httpx.Response:
        await self._ensure_client()
        assert self._client is not None

        url = _join_url(self.base_url, path)
        attempt = 0
        last_exc: Optional[Exception] = None

        while True:
            attempt += 1
            headers = self._auth_headers()
            try:
                resp = await self._client.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=headers,
                    timeout=self.timeout,
                    follow_redirects=False,
                )
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.PoolTimeout) as e:
                last_exc = e
                if attempt <= self.retry.max_retries:
                    await asyncio.sleep(self._sleep_for(attempt))
                    continue
                raise NessusError(f"Connection error: {e}") from e

            if resp.status_code in expected:
                return resp

            # Auth errors
            if resp.status_code in (401, 403):
                # Try to login once if using username/password and not yet logged in
                if resp.status_code == 401 and self.username and self.password and not self._session_token:
                    await self.login()
                    if attempt <= self.retry.max_retries:
                        await asyncio.sleep(self._sleep_for(attempt))
                        continue
                if resp.status_code == 403:
                    raise NessusPermissionError(f"Forbidden: {resp.text}")
                raise NessusAuthError(f"Unauthorized: {resp.text}")

            if resp.status_code == 404:
                raise NessusNotFoundError(f"Not found: {method} {path}")

            if resp.status_code == 429 or resp.status_code in self.retry.retry_on_status:
                if attempt <= self.retry.max_retries:
                    delay = self._retry_after(resp) or self._sleep_for(attempt)
                    await asyncio.sleep(delay)
                    continue
                if resp.status_code == 429:
                    raise NessusRateLimitError(f"Rate limited after {attempt} attempts")
                raise NessusError(f"Server error {resp.status_code}: {resp.text}")

            # Other client error
            if 400 <= resp.status_code < 500:
                raise NessusError(f"Client error {resp.status_code}: {resp.text}")

            # Other server error
            if 500 <= resp.status_code < 600:
                if attempt <= self.retry.max_retries:
                    await asyncio.sleep(self._sleep_for(attempt))
                    continue
                raise NessusError(f"Server error {resp.status_code}: {resp.text}")

    def _retry_after(self, resp: httpx.Response) -> Optional[float]:
        ra = resp.headers.get("Retry-After")
        if not ra:
            return None
        try:
            return max(0.0, float(ra))
        except ValueError:
            return None

    def _sleep_for(self, attempt: int) -> float:
        base = self.retry.backoff_factor * (2 ** (attempt - 1))
        return base + (self.retry.jitter * (0.5 - (time.time() % 1)))

    # --------------- Scans ---------------

    async def list_scans(self) -> List[ScanSummary]:
        """
        GET /scans
        """
        resp = await self._request("GET", "/scans")
        data = resp.json() or {}
        items = data.get("scans", [])
        # some Nessus builds wrap content under "folders" -> "scans"
        if not items and "folders" in data:
            for f in data["folders"] or []:
                items.extend(f.get("scans", []))
        return [ScanSummary(**_coerce_scan_summary(x)) for x in items]

    async def get_scan(self, scan_id: int) -> ScanDetails:
        """
        GET /scans/{scan_id}
        """
        resp = await self._request("GET", f"/scans/{scan_id}")
        data = resp.json() or {}
        info = data.get("info") or {}
        history = data.get("history") or []
        details = {
            "id": int(scan_id),
            "name": info.get("name") or data.get("name") or f"scan-{scan_id}",
            "status": info.get("status") or data.get("status"),
            "history": [{"history_id": h.get("history_id"), "status": h.get("status"), "last_modification_date": h.get("last_modification_date")} for h in history],
            "targets": (info.get("targets") or info.get("compliance") or None),
            "policy": info.get("policy"),
            "owner": info.get("owner"),
        }
        return ScanDetails(**details)

    async def launch_scan(self, scan_id: int, *, alt_targets: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        """
        POST /scans/{scan_id}/launch
        alt_targets: optional iterable of IPs/hosts, joined with comma for request body.
        """
        body: Dict[str, Any] = {}
        if alt_targets:
            body["alt_targets"] = ",".join([str(t) for t in alt_targets])
        resp = await self._request("POST", f"/scans/{scan_id}/launch", json_body=body, expected=(200, 202))
        return resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}

    # --------------- Export and Download ---------------

    async def export_scan(
        self,
        scan_id: int,
        *,
        fmt: Literal["nessus", "csv", "html", "pdf", "db"] = "csv",
        chapters: Optional[str] = None,
        password: Optional[str] = None,
        history_id: Optional[int] = None,
        filters: Optional[Dict[str, Any]] = None,
        poll_interval: float = 2.0,
        timeout_seconds: int = 900,
    ) -> Tuple[int, Dict[str, Any]]:
        """
        POST /scans/{scan_id}/export then poll /status until ready.
        Returns (file_id, original_export_response).
        """
        body: Dict[str, Any] = {"format": fmt}
        if chapters:
            body["chapters"] = chapters
        if password:
            body["password"] = password
        if history_id is not None:
            body["history_id"] = history_id
        if filters:
            body["filters"] = filters

        # request export
        resp = await self._request("POST", f"/scans/{scan_id}/export", json_body=body, expected=(200, 202))
        data = resp.json() or {}
        file_id = data.get("file") or data.get("file_id")
        if not file_id:
            raise NessusError(f"Export did not return file id: {data}")

        # poll status
        deadline = time.time() + timeout_seconds
        while True:
            st = await self._request("GET", f"/scans/{scan_id}/export/{file_id}/status")
            status = (st.json() or {}).get("status", "").lower()
            if status == "ready":
                break
            if status in {"error", "canceled", "cancelled"}:
                raise NessusError(f"Export failed with status={status}")
            if time.time() >= deadline:
                raise NessusError("Export polling timed out")
            await asyncio.sleep(poll_interval)

        return int(file_id), data

    async def download_export(self, scan_id: int, file_id: int, *, dest_path: str, chunk_size: int = 1 << 16) -> str:
        """
        GET /scans/{scan_id}/export/{file_id}/download streaming to file.
        Returns dest_path on success.
        """
        await self._ensure_client()
        assert self._client is not None
        resp = await self._request(
            "GET",
            f"/scans/{scan_id}/export/{file_id}/download",
            expected=(200,),
        )
        # If server sends JSON error by mistake, fail
        ctype = resp.headers.get("content-type", "")
        if "application/json" in ctype:
            raise NessusError(f"Unexpected JSON on download: {resp.text}")

        # stream content from a new request to avoid buffering in memory
        url = _join_url(self.base_url, f"/scans/{scan_id}/export/{file_id}/download")
        headers = self._auth_headers()
        async with self._client.stream("GET", url, headers=headers) as stream:
            with open(dest_path, "wb") as f:
                async for chunk in stream.aiter_bytes(chunk_size):
                    f.write(chunk)
        return dest_path

    # --------------- Tenable.io Workbenches (cloud) ---------------

    async def list_vulnerabilities_tio(
        self,
        *,
        severity: Optional[Iterable[str]] = None,
        cpe: Optional[str] = None,
        cve: Optional[str] = None,
        age: Optional[int] = None,
        plugin_id: Optional[int] = None,
        limit: Optional[int] = None,
        asset_uuid: Optional[str] = None,
        extra_params: Optional[Dict[str, Any]] = None,
    ) -> List[VulnerabilityRecord]:
        """
        GET /workbenches/vulnerabilities (Tenable.io only).
        """
        if not _is_cloud(self.base_url):
            raise NessusError("list_vulnerabilities_tio is available only against Tenable.io base_url")

        params: Dict[str, Any] = {}
        if severity:
            params["severity"] = ",".join(severity)
        if cpe:
            params["cpe"] = cpe
        if cve:
            params["cve"] = cve
        if age is not None:
            params["age"] = int(age)
        if plugin_id is not None:
            params["plugin.id"] = int(plugin_id)
        if limit is not None:
            params["limit"] = int(limit)
        if asset_uuid:
            params["asset.uuid"] = asset_uuid
        if extra_params:
            params.update(extra_params)

        resp = await self._request("GET", "/workbenches/vulnerabilities", params=params)
        data = resp.json() or {}
        items = data.get("vulnerabilities") or data.get("vulns") or []
        out: List[VulnerabilityRecord] = []
        for v in items:
            out.append(
                VulnerabilityRecord(
                    plugin_id=v.get("plugin_id") or v.get("pluginID"),
                    plugin_name=v.get("plugin_name"),
                    family=v.get("family"),
                    severity=_sev_str(v.get("severity") or v.get("severity_id")),
                    severity_id=v.get("severity_id") or _sev_id(v.get("severity")),
                    cve=_split_cves(v.get("cve")),
                    cvss_base_score=_safe_float(v.get("cvss_base_score") or v.get("cvss_v2_base_score")),
                    host=v.get("hostname") or v.get("host"),
                    port=_safe_int(v.get("port")),
                    protocol=v.get("protocol"),
                    first_seen=v.get("first_seen"),
                    last_seen=v.get("last_seen"),
                    synopsis=v.get("synopsis"),
                    description=v.get("description"),
                    solution=v.get("solution"),
                    references=_collect_refs(v),
                )
            )
        return out

    # ============================== helpers ===================================

def _coerce_scan_summary(x: Dict[str, Any]) -> Dict[str, Any]:
    # Nessus/Tenable may use different key casing
    return {
        "id": x.get("id"),
        "name": x.get("name") or x.get("uuid") or f"scan-{x.get('id')}",
        "status": x.get("status"),
        "folder_id": x.get("folder_id") or x.get("folder"),
        "last_modification_date": x.get("last_modification_date") or x.get("last_modification") or x.get("last_modification_time"),
        "owner": x.get("owner"),
    }


def _safe_int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except Exception:
        return None


def _safe_float(v: Any) -> Optional[float]:
    try:
        return float(v)
    except Exception:
        return None


def _sev_id(sev: Any) -> Optional[int]:
    if isinstance(sev, int):
        return sev
    m = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if isinstance(sev, str):
        return m.get(sev.lower())
    return None


def _sev_str(sev: Any) -> Optional[str]:
    if isinstance(sev, str):
        return sev.lower()
    if isinstance(sev, int):
        m = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
        return m.get(sev)
    return None


def _split_cves(v: Any) -> List[str]:
    if not v:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [s.strip() for s in str(v).replace(";", ",").split(",") if s.strip()]


def _collect_refs(v: Dict[str, Any]) -> Dict[str, List[str]]:
    refs: Dict[str, List[str]] = {}
    for key in ("see_also", "xref", "refs", "references"):
        val = v.get(key)
        if not val:
            continue
        if isinstance(val, list):
            refs[key] = [str(x) for x in val]
        else:
            refs[key] = [s.strip() for s in str(val).replace(";", ",").split(",") if s.strip()]
    return refs
