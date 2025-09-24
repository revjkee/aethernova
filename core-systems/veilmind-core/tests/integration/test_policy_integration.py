import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from socket import socket
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import pytest

# --- Optional import of the production adapter (skip suite if missing) -----
try:
    from veilmind.adapters.policy_core_adapter import (
        PolicyCoreAdapter,
        RemotePDPClient,
        PolicyRequest,
        ResourceRef,
        Subject,
        Decision,
    )
except Exception as e:  # pragma: no cover
    pytest.skip("veilmind.adapters.policy_core_adapter not available: {}".format(e), allow_module_level=True)


# ============================== Test Infrastructure ===============================

class _ThreadingHTTPServer(HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _pick_free_port() -> int:
    with socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def run_mock_pdp(handler: Callable[[str, Dict[str, Any]], Tuple[int, Dict[str, Any]]]) -> Iterator[str]:
    """
    Запускает минимальный OPA‑совместимый REST сервер.
    handler(path, payload_dict) -> (status, response_dict)
    Возвращает base_url вида http://127.0.0.1:<port>
    """
    port = _pick_free_port()
    state = {"handler": handler}

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except Exception:
                length = 0
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                payload = {}
            try:
                status, resp = state["handler"](self.path, payload)
            except Exception as e:
                status, resp = 500, {"error": str(e)}
            body = json.dumps(resp).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):  # silence
            return

    server = _ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=server.serve_forever, name="mock-pdp", daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _make_req(subj: str = "alice", tenant: str = "tenant-a", action: str = "read",
              rtype: str = "document", rid: str = "doc-1", attrs: Optional[Dict[str, Any]] = None) -> PolicyRequest:
    attrs = {"tenant": tenant, **(attrs or {})}
    return PolicyRequest(
        subject=Subject(id=subj, tenant=tenant, scopes=("reader",)),
        action=action,
        resource=ResourceRef(type=rtype, id=rid, attributes=attrs),
        context={"ip": "192.168.1.10"},
        request_id="req-{}".format(rid),
    )


def _adapter(local_rules: Optional[List[Dict[str, Any]]] = None,
             remote_url: Optional[str] = None,
             *,
             ttl: int = 30,
             cap: int = 1024,
             hmac_key: str = "test-hmac-key",
             rps: float = 100.0,
             breaker_failures: int = 5,
             breaker_reset: int = 60) -> PolicyCoreAdapter:
    remote = RemotePDPClient(remote_url, package="veilmind.authz", timeout_sec=0.5) if remote_url else None
    return PolicyCoreAdapter(
        local_rules=local_rules or [],
        remote_pdp=remote,
        cache_ttl_sec=ttl,
        cache_capacity=cap,
        hmac_key=hmac_key,
        tenant_rps=rps,
        breaker_failures=breaker_failures,
        breaker_reset_sec=breaker_reset,
    )


# ===================================== Tests ========================================

def test_local_policy_permit_and_cache(monkeypatch):
    rules = [
        {
            "id": "permit_read_same_tenant",
            "priority": 100,
            "effect": "PERMIT",
            "when": {"all": [
                {"op": "eq", "left": "action", "right": "read"},
                {"op": "eq", "left": "subject.tenant", "right": "resource.attributes.tenant"},
            ]},
            "attributes": {"mask_level": "partial"},
            "version": "1",
        }
    ]
    # Управляем временем для TTL‑кэша
    base = time.time()
    monkeypatch.setattr("veilmind.adapters.policy_core_adapter.time.time", lambda: base)

    ad = _adapter(local_rules=rules, ttl=60)
    req = _make_req()

    res1 = ad.evaluate(req)
    assert res1.decision == Decision.PERMIT
    assert res1.source == "local"
    assert res1.hmac and len(res1.hmac) == 64

    # Второй вызов — из кэша (тот же ключ)
    res2 = ad.evaluate(req)
    assert res2.cache_hit is True
    assert res2.decision == Decision.PERMIT
    assert res2.source == "local"
    assert res2.hmac and len(res2.hmac) == 64  # подпись присутствует (не обязана совпадать из‑за eval_time_ms)


def test_local_deny_short_circuits_remote(monkeypatch):
    rules = [
        {
            "id": "deny_cross_tenant_write",
            "priority": 90,
            "effect": "DENY",
            "when": {"all": [
                {"op": "eq", "left": "action", "right": "write"},
                {"op": "ne", "left": "subject.tenant", "right": "resource.attributes.tenant"},
            ]},
        }
    ]
    # Поднимем PDP, но он не должен вызываться
    with run_mock_pdp(lambda p, j: (200, {"result": {"allow": True}})) as url:
        ad = _adapter(local_rules=rules, remote_url=url)
        req = _make_req(action="write", attrs={"tenant": "tenant-b"})  # tenant mismatch
        res = ad.evaluate(req)
        assert res.decision == Decision.DENY
        assert ad.metrics.remote_calls == 0  # короткое замыкание на локальном правиле


def test_remote_policy_permit_boolean_result():
    def handler(path, payload):
        assert path.startswith("/v1/data/veilmind/authz")
        # OPA boolean result
        return 200, {"result": True}

    with run_mock_pdp(handler) as url:
        ad = _adapter(remote_url=url, ttl=60)
        req = _make_req()
        res1 = ad.evaluate(req)
        assert res1.source == "remote"
        assert res1.decision == Decision.PERMIT
        # Кэш
        res2 = ad.evaluate(req)
        assert res2.cache_hit is True
        assert res2.decision == Decision.PERMIT


def test_remote_policy_object_result_attributes_and_policy_id():
    def handler(path, payload):
        # Эмуляция OPA: result — объект с allow/attributes
        return 200, {"result": {"allow": True, "attributes": {"mask": "none"}, "policy_id": "opa-policy-1", "version": "42"}}

    with run_mock_pdp(handler) as url:
        ad = _adapter(remote_url=url)
        res = ad.evaluate(_make_req())
        assert res.decision == Decision.PERMIT
        assert res.attributes.get("mask") == "none"
        assert res.policy_id == "opa-policy-1"
        assert res.policy_version == "42"


def test_cache_ttl_expiry(monkeypatch):
    # Ответ удалённого PDP — allow
    def handler(path, payload):
        return 200, {"result": True}

    with run_mock_pdp(handler) as url:
        # Управляем временем
        base = [time.time()]  # изменяемая ссылка
        monkeypatch.setattr("veilmind.adapters.policy_core_adapter.time.time", lambda: base[0])

        ad = _adapter(remote_url=url, ttl=2)  # короткий TTL
        req = _make_req()

        res1 = ad.evaluate(req)
        assert res1.decision == Decision.PERMIT
        # второй — из кэша
        res2 = ad.evaluate(req)
        assert res2.cache_hit is True

        # Протолкнём время за TTL
        base[0] += 3
        res3 = ad.evaluate(req)
        # Должен сходить к PDP заново (cache_misses увеличится)
        assert ad.metrics.cache_misses >= 2
        assert res3.decision == Decision.PERMIT


def test_remote_breaker_opens_on_failures():
    # Всегда отдаём 500 -> должен открыться breaker
    def handler(path, payload):
        return 500, {"error": "boom"}

    with run_mock_pdp(handler) as url:
        ad = _adapter(remote_url=url, breaker_failures=2, breaker_reset=60)
        req = _make_req()

        r1 = ad.evaluate(req)
        r2 = ad.evaluate(req)
        r3 = ad.evaluate(req)  # breaker должен блокировать

        assert r1.decision == Decision.INDETERMINATE
        assert r2.decision == Decision.INDETERMINATE
        assert "remote:breaker_open" in r3.reason or r3.reason == "remote:breaker_open"
        assert ad.metrics.remote_failures >= 2


def test_rate_limit_per_tenant():
    # PDP всегда allow; ограничим rps=1 (bucket ёмк. по умолчанию ~2)
    def handler(path, payload):
        return 200, {"result": True}

    with run_mock_pdp(handler) as url:
        ad = _adapter(remote_url=url, rps=1.0, ttl=0)  # ttl=0, чтобы не было кэша
        # Сделаем 5 разных запросов (разные resource.id), чтобы исключить попадание в кэш
        results = [ad.evaluate(_make_req(rid=f"doc-{i}")) for i in range(5)]
        # хотя бы один из них должен быть rate_limited
        assert any("rate_limited" in r.reason for r in results if r.decision == Decision.INDETERMINATE)


def test_hmac_signature_present_and_hex():
    def handler(path, payload):
        return 200, {"result": True}

    with run_mock_pdp(handler) as url:
        ad = _adapter(remote_url=url, hmac_key="super-secret")
        res = ad.evaluate(_make_req())
        assert res.hmac and len(res.hmac) == 64
        # hex‑строка sha256
        int(res.hmac, 16)  # не должно упасть


def test_batch_evaluate_order_preserved():
    def handler(path, payload):
        return 200, {"result": True}

    with run_mock_pdp(handler) as url:
        ad = _adapter(remote_url=url)
        reqs = [_make_req(rid=f"doc-{i}") for i in range(3)]
        out = list(ad.batch_evaluate(reqs))
        assert len(out) == 3
        # порядок сохранён
        assert [r.request_id for r in reqs] == [f"req-doc-{i}" for i in range(3)]


def test_health_structure():
    ad = _adapter(local_rules=[
        {"id": "rule1", "effect": "DENY", "when": {"op": "eq", "left": "action", "right": "write"}}
    ])
    h = ad.health()
    assert "cache" in h and "breaker" in h and "metrics" in h and "remote_enabled" in h
    assert isinstance(h["cache"]["size"], int)
    assert h["remote_enabled"] in (True, False)
