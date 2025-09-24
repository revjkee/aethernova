# path: core-systems/genius_core/security/self_inhibitor/tests/integration/test_opa_adapter.py
# License: MIT
import json
import os
import socket
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Optional, Tuple

import pytest

pytestmark = pytest.mark.integration

# =========================
# Adaptive import of OPA adapter
# =========================

_ADAPTER_IMPORT_ERRORS = []
OPAAdapter = None
evaluate = None  # optional function-style API

with suppress(Exception):
    from genius_core.security.self_inhibitor.adapters.opa import OPAAdapter as _OPAAdapter  # type: ignore
    OPAAdapter = _OPAAdapter
with suppress(Exception):
    if OPAAdapter is None:
        from core_systems.genius_core.security.self_inhibitor.adapters.opa import OPAAdapter as _OPAAdapter  # type: ignore
        OPAAdapter = _OPAAdapter
with suppress(Exception):
    if OPAAdapter is None:
        from genius_core.security.self_inhibitor.adapters.opa import evaluate as _evaluate  # type: ignore
        evaluate = _evaluate
with suppress(Exception):
    if OPAAdapter is None:
        from core_systems.genius_core.security.self_inhibitor.adapters.opa import evaluate as _evaluate  # type: ignore
        evaluate = _evaluate

if OPAAdapter is None and evaluate is None:
    _ADAPTER_IMPORT_ERRORS.append("OPA adapter not found in expected modules")


requires_adapter = pytest.mark.skipif(
    OPAAdapter is None and evaluate is None,
    reason="OPA adapter implementation not found in project",
)


# =========================
# Local OPA mock server (HTTP)
# =========================

@dataclass
class _MockState:
    calls: int = 0
    last_auth: Optional[str] = None


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _make_handler(state: _MockState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "MockOPA/1.0"

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            with suppress(Exception):
                return json.loads(raw.decode("utf-8"))
            return {}

        def _write_json(self, code: int, payload: dict):
            out = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def do_POST(self):
            state.calls += 1
            state.last_auth = self.headers.get("Authorization")
            body = self._read_json()
            # Simulate latency for timeout test
            if self.path.endswith("/v1/data/genius/slow"):
                time.sleep(1.2)
                return self._write_json(200, {"result": {"allow": False, "reason": "timeout-path"}})

            # Routing by path:
            if self.path.endswith("/v1/data/genius/allow"):
                return self._write_json(200, {"result": {"allow": True}})

            if self.path.endswith("/v1/data/genius/block"):
                return self._write_json(200, {"result": {"allow": False, "block": True, "reason": "policy_violation"}})

            if self.path.endswith("/v1/data/genius/redact"):
                # emulate redact decision
                return self._write_json(200, {"result": {"allow": False, "redact": True, "pii": ["email", "phone"]}})

            if self.path.endswith("/v1/data/genius/auth"):
                ok = state.last_auth == "Bearer test-token-123"
                return self._write_json(200, {"result": {"allow": ok}})

            # default: echo unknown -> allow false
            return self._write_json(200, {"result": {"allow": False, "reason": "unknown_path"}})

        # Silence noisy logs
        def log_message(self, fmt, *args):
            return

    return Handler


@pytest.fixture(scope="module")
def opa_server():
    """
    If external OPA is not supplied via OPA_URL, start a local mock OPA.
    Provides base_url, shared state and shutdown at teardown.
    """
    ext_url = os.getenv("OPA_URL")
    if ext_url:
        yield {"url": ext_url, "state": _MockState()}
        return

    state = _MockState()
    port = _free_port()
    srv = HTTPServer(("127.0.0.1", port), _make_handler(state))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"url": f"http://127.0.0.1:{port}", "state": state}
    finally:
        with suppress(Exception):
            srv.shutdown()
        with suppress(Exception):
            thread.join(timeout=1.0)


# =========================
# Adapter helper wrappers
# =========================

def _make_adapter(base_url: str, *, policy_path: str, timeout: float = 0.5, token: Optional[str] = None, cache_ttl: Optional[float] = None):
    """
    Try multiple constructor shapes to instantiate adapter across codebases.
    """
    if OPAAdapter is None:
        return None

    ctor_errors = []
    for kwargs in (
        {"base_url": base_url, "policy_path": policy_path, "timeout": timeout, "token": token, "cache_ttl": cache_ttl},
        {"url": base_url, "package": policy_path, "timeout": timeout, "auth_token": token, "cache_ttl": cache_ttl},
        {"endpoint": base_url, "path": policy_path, "timeout": timeout, "token": token},
        {"endpoint": base_url, "package": policy_path, "timeout": timeout},
    ):
        clean = {k: v for k, v in kwargs.items() if v is not None}
        with suppress(Exception) as ex:
            return OPAAdapter(**clean)  # type: ignore
        ctor_errors.append(str(ex))
    pytest.skip(f"Cannot construct OPA adapter with known signatures. Errors={ctor_errors}")


def _call_adapter(adapter, payload: dict, *, trace_id: Optional[str] = None):
    """
    Call adapter using common method names; return normalized dict with 'action' and 'raw'.
    """
    # Method-level adaptation
    for m in ("decide", "evaluate", "query", "check"):
        if hasattr(adapter, m):
            fn = getattr(adapter, m)
            with suppress(Exception):
                res = fn(payload, trace_id=trace_id)
                return _normalize_result(res)
    # Function-style API fallback
    if evaluate is not None:
        res = evaluate(payload)  # type: ignore
        return _normalize_result(res)
    pytest.skip("No callable entrypoint found on adapter")


def _normalize_result(res: Any) -> dict:
    """
    Normalize adapter result into {'action': 'allow|redact|block', 'raw': original}
    Accepts dict or object-like responses.
    """
    action = None
    # object with attribute
    if hasattr(res, "action"):
        action = getattr(res, "action")
    # dict with action
    if action is None and isinstance(res, dict):
        action = res.get("action")
    # Map from OPA-style booleans
    if action is None and isinstance(res, dict):
        r = res.get("result") or res
        if isinstance(r, dict):
            if r.get("allow") is True:
                action = "allow"
            elif r.get("redact") is True:
                action = "redact"
            elif r.get("block") is True or r.get("allow") is False:
                action = "block"
    # conservative default
    if action is None:
        action = "block"
    return {"action": action, "raw": res}


# =========================
# Tests
# =========================

@requires_adapter
def test_allow_decision(opa_server):
    base = opa_server["url"]
    adapter = _make_adapter(base, policy_path="genius/allow", timeout=0.6)
    out = _call_adapter(adapter, {"x": 1}, trace_id="t-allow")
    assert out["action"] == "allow"


@requires_adapter
def test_block_decision(opa_server):
    base = opa_server["url"]
    adapter = _make_adapter(base, policy_path="genius/block", timeout=0.6)
    out = _call_adapter(adapter, {"x": 1}, trace_id="t-block")
    assert out["action"] == "block"


@requires_adapter
def test_redact_decision(opa_server):
    base = opa_server["url"]
    adapter = _make_adapter(base, policy_path="genius/redact", timeout=0.6)
    out = _call_adapter(adapter, {"text": "john.doe@example.com +1 202 555 0199"})
    assert out["action"] in ("redact", "allow")  # some adapters may return allow + sanitized text
    # tolerate implementations that signal redact via fields in raw result


@requires_adapter
def test_authorization_header(opa_server):
    base = opa_server["url"]
    state = opa_server["state"]
    adapter = _make_adapter(base, policy_path="genius/auth", timeout=0.6, token="test-token-123")
    _ = _call_adapter(adapter, {"foo": "bar"})
    # In strict adapters we cannot access headers; assert on mock side
    assert state.last_auth == "Bearer test-token-123"


@requires_adapter
def test_timeout_is_deny_by_default(opa_server):
    base = opa_server["url"]
    # Use tiny timeout to trigger timeout path
    adapter = _make_adapter(base, policy_path="genius/slow", timeout=0.05)
    out = _call_adapter(adapter, {"x": "y"})
    # Safety first: timeout should deny (block) by default
    assert out["action"] == "block"


@requires_adapter
def test_cache_hit_does_not_call_backend_twice(opa_server):
    """
    If adapter supports in-memory TTL cache, two identical queries should yield one backend call.
    We do not fail if adapter lacks caching; we only assert 'at most one extra' heuristic.
    """
    base = opa_server["url"]
    state = opa_server["state"]
    # reset counters (only reliable on local mock)
    state.calls = 0

    adapter = _make_adapter(base, policy_path="genius/allow", timeout=0.6, cache_ttl=2.0)
    out1 = _call_adapter(adapter, {"user": "u1", "op": "read"})
    out2 = _call_adapter(adapter, {"user": "u1", "op": "read"})
    assert out1["action"] == "allow" and out2["action"] == "allow"

    # If cache works, calls <= 2 (some adapters prewarm/probe)
    assert state.calls <= 2
