# oblivionvault-core/tests/contract/test_http_api_v1.py
"""
Contract tests for OblivionVault HTTP API v1.

Dependencies:
  - pytest

Environment:
  OBLIVIONVAULT_BASE_URL       e.g. "https://localhost:8443"
  OBLIVIONVAULT_BEARER         optional Bearer token (without "Bearer ")
  OBLIVIONVAULT_HEALTH_SLA_MS  optional SLA in ms for /v1/health (default: 1000)
  OBLIVIONVAULT_TEST_404       if "1", test 404 JSON error contract
  OBLIVIONVAULT_CONTRACT_PATH  optional path to JSON manifest with extra endpoints

Manifest format (JSON):
[
  {
    "name": "get-info",
    "method": "GET",
    "path": "/v1/info",
    "expected_status": 200,
    "schema": {
      "type": "object",
      "required": ["name", "version"],
      "properties": {
        "name": {"type": "string"},
        "version": {"type": "string"}
      }
    },
    "idempotent": true
  },
  ...
]
"""

from __future__ import annotations

import gzip
import io
import json
import os
import ssl
import time
import http.client
import urllib.parse as urlparse
from typing import Any, Dict, Optional, Tuple, List

import pytest


# -------------------------
# Module-level configuration
# -------------------------

BASE_URL = os.environ.get("OBLIVIONVAULT_BASE_URL", "").strip()
if not BASE_URL:
    pytest.skip("OBLIVIONVAULT_BASE_URL not set; skipping HTTP contract tests", allow_module_level=True)

BEARER = os.environ.get("OBLIVIONVAULT_BEARER", "").strip()
HEALTH_SLA_MS = int(os.environ.get("OBLIVIONVAULT_HEALTH_SLA_MS", "1000"))
TEST_404 = os.environ.get("OBLIVIONVAULT_TEST_404", "0") == "1"
MANIFEST_PATH = os.environ.get("OBLIVIONVAULT_CONTRACT_PATH", "").strip()


# -------------------------
# Minimal stdlib HTTP client
# -------------------------

class SimpleHttpClient:
    def __init__(self, base_url: str, *, connect_timeout: float = 5.0, read_timeout: float = 15.0, bearer: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.parsed = urlparse.urlparse(self.base_url)
        if self.parsed.scheme not in ("http", "https"):
            raise ValueError("Unsupported scheme")
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.bearer = bearer

    def _build_conn(self) -> http.client.HTTPConnection:
        host = self.parsed.hostname
        port = self.parsed.port
        timeout = self.connect_timeout
        if self.parsed.scheme == "https":
            context = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port=port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(host, port=port, timeout=timeout)
        return conn

    def _full_path(self, path: str, query: Optional[Dict[str, Any]] = None) -> str:
        p = path if path.startswith("/") else f"/{path}"
        base = self.parsed.path.rstrip("/")
        full = f"{base}{p}"
        if query:
            q = urlparse.urlencode(query, doseq=True)
            return f"{full}?{q}"
        return full

    @staticmethod
    def _decode_body(headers: Dict[str, str], raw: bytes) -> bytes:
        enc = headers.get("Content-Encoding", "").lower()
        if enc == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as f:
                return f.read()
        return raw

    def _default_headers(self) -> Dict[str, str]:
        h = {
            "Accept": "application/json",
            "User-Agent": "OV-Contract-Tester/1.0",
            "Accept-Encoding": "gzip",
        }
        if self.bearer:
            h["Authorization"] = f"Bearer {self.bearer}"
        return h

    def request_json(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, str], Any, float]:
        """
        Returns: (status, headers, decoded_json, elapsed_ms)
        Raises AssertionError if response is not JSON.
        """
        conn = self._build_conn()
        start = time.perf_counter()
        try:
            body_bytes = None
            h = self._default_headers()
            if headers:
                h.update(headers)
            if json_body is not None:
                raw = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                h["Content-Type"] = "application/json; charset=utf-8"
                h["Content-Length"] = str(len(raw))
                body_bytes = raw

            conn.putrequest(method.upper(), self._full_path(path, query))
            for k, v in h.items():
                conn.putheader(k, v)
            conn.endheaders()
            if body_bytes is not None:
                conn.send(body_bytes)
            conn.sock.settimeout(self.read_timeout)  # type: ignore[attr-defined]

            resp = conn.getresponse()
            status = resp.status
            hdrs = {k: v for k, v in resp.getheaders()}
            raw_data = resp.read()
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            data = self._decode_body(hdrs, raw_data)

            ctype = hdrs.get("Content-Type", "")
            if "application/json" in ctype:
                try:
                    parsed = json.loads(data.decode("utf-8"))
                except Exception as e:
                    raise AssertionError(f"Invalid JSON body: {e}") from e
            else:
                # Non-JSON response: pass through raw text for diagnostics
                parsed = data.decode("utf-8", errors="replace")

            return status, hdrs, parsed, elapsed_ms
        finally:
            try:
                conn.close()
            except Exception:
                pass


# -------------------------
# Lightweight schema checks
# -------------------------

def assert_json_schema(obj: Any, schema: Dict[str, Any], path: str = "$") -> None:
    """
    Minimal JSON schema validator supporting:
      - type: object/array/string/number/integer/boolean
      - required: [..]
      - properties: {name: {schema}}
      - items: {schema}
      - enum: [..]
    Raises AssertionError on mismatch.
    """
    t = schema.get("type")
    if t:
        if t == "object":
            assert isinstance(obj, dict), f"{path}: expected object, got {type(obj).__name__}"
            required = schema.get("required", [])
            for k in required:
                assert k in obj, f"{path}: missing required key '{k}'"
            props = schema.get("properties", {})
            for k, sub in props.items():
                if k in obj:
                    assert_json_schema(obj[k], sub, f"{path}.{k}")
        elif t == "array":
            assert isinstance(obj, list), f"{path}: expected array, got {type(obj).__name__}"
            items = schema.get("items")
            if items:
                for i, it in enumerate(obj):
                    assert_json_schema(it, items, f"{path}[{i}]")
        elif t == "string":
            assert isinstance(obj, str), f"{path}: expected string, got {type(obj).__name__}"
        elif t == "boolean":
            assert isinstance(obj, bool), f"{path}: expected boolean, got {type(obj).__name__}"
        elif t == "integer":
            assert isinstance(obj, int) and not isinstance(obj, bool), f"{path}: expected integer, got {type(obj).__name__}"
        elif t == "number":
            assert isinstance(obj, (int, float)) and not isinstance(obj, bool), f"{path}: expected number, got {type(obj).__name__}"
        else:
            raise AssertionError(f"{path}: unsupported type '{t}'")
    if "enum" in schema:
        assert obj in schema["enum"], f"{path}: value '{obj}' not in enum {schema['enum']}"


# -------------------------
# Pytest fixtures
# -------------------------

@pytest.fixture(scope="session")
def client() -> SimpleHttpClient:
    return SimpleHttpClient(BASE_URL, bearer=BEARER)


# -------------------------
# Core contract tests
# -------------------------

def test_health_contract(client: SimpleHttpClient) -> None:
    status, headers, body, elapsed_ms = client.request_json("GET", "/v1/health")

    # Status code
    assert status == 200, f"/v1/health status={status}, body={body}"

    # Content-Type
    assert "application/json" in headers.get("Content-Type", ""), "missing or wrong Content-Type"

    # Schema
    schema = {
        "type": "object",
        "required": ["status", "time", "uptime", "version"],
        "properties": {
            "status": {"type": "string", "enum": ["ok", "degraded"]},
            "time": {"type": "string"},   # RFC3339 expected, format not enforced in minimal validator
            "uptime": {"type": "number"},
            "version": {"type": "string"},
            "checks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["name", "ok"],
                    "properties": {
                        "name": {"type": "string"},
                        "ok": {"type": "boolean"},
                        "latency_ms": {"type": "number"},
                        "detail": {"type": "string"},
                    },
                },
            },
        },
    }
    assert_json_schema(body, schema)

    # SLA
    assert elapsed_ms <= HEALTH_SLA_MS, f"/v1/health latency {elapsed_ms:.1f} ms exceeds SLA {HEALTH_SLA_MS} ms"


@pytest.mark.skipif(not TEST_404, reason="404 contract test disabled (set OBLIVIONVAULT_TEST_404=1 to enable)")
def test_404_error_contract(client: SimpleHttpClient) -> None:
    status, headers, body, _ = client.request_json("GET", "/v1/__not_found_contract_probe__")
    assert status == 404, f"Expected 404, got {status}"
    assert "application/json" in headers.get("Content-Type", "")
    schema = {
        "type": "object",
        "required": ["error"],
        "properties": {
            "error": {"type": "string"},
            "code": {"type": "integer"},
            "request_id": {"type": "string"},
        },
    }
    assert_json_schema(body, schema)


# -------------------------
# Manifest-driven tests
# -------------------------

def _load_manifest(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    try:
        data = json.loads(text)
    except Exception as e:
        raise AssertionError(f"Invalid manifest JSON: {e}")
    assert isinstance(data, list), "Manifest must be a list of endpoint objects"
    return data


@pytest.mark.skipif(not MANIFEST_PATH, reason="No manifest provided (set OBLIVIONVAULT_CONTRACT_PATH)")
@pytest.mark.parametrize("entry", _load_manifest(MANIFEST_PATH))
def test_manifest_entry(client: SimpleHttpClient, entry: Dict[str, Any]) -> None:
    name = entry.get("name", "")
    method = (entry.get("method") or "GET").upper()
    path = entry["path"]
    expected_status = int(entry.get("expected_status", 200))
    payload = entry.get("json")
    query = entry.get("query")
    schema = entry.get("schema")
    idempotent = bool(entry.get("idempotent", method in ("GET", "HEAD")))

    status, headers, body, _ = client.request_json(method, path, json_body=payload, query=query)
    assert status == expected_status, f"{name or path}: status={status}, expected={expected_status}, body={body}"

    if "application/json" in headers.get("Content-Type", "") and schema:
        assert_json_schema(body, schema)

    # Optional idempotency check (same request twice should be equivalent in code/status)
    if idempotent:
        status2, headers2, body2, _ = client.request_json(method, path, json_body=payload, query=query)
        assert status2 == status, f"{name or path}: idempotent status mismatch"
        # If body is JSON object, weak check: same shape (keys)
        if isinstance(body, dict) and isinstance(body2, dict):
            assert set(body2.keys()) == set(body.keys()), f"{name or path}: response keys changed on repeat"


# -------------------------
# Smoke: CORS/Headers (non-fatal)
# -------------------------

def test_response_headers_basic(client: SimpleHttpClient) -> None:
    status, headers, body, _ = client.request_json("GET", "/v1/health")
    assert status == 200
    # JSON content type
    assert "application/json" in headers.get("Content-Type", "")
    # Optional: server must not leak stack traces on health
    if isinstance(body, dict):
        assert "traceback" not in body, "Health JSON must not expose 'traceback'"
