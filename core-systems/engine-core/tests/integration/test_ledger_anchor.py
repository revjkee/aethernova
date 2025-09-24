# engine/tests/integration/test_ledger_anchor.py
"""
Интеграционные тесты якорения (ledger anchoring).

Ожидаем модуль: engine.ledger.anchor с одним из API:
  - AnchorClient.from_env() -> клиент
  - или create_client(**cfg)
Клиент должен (частично или полностью) поддерживать:
  - health() -> dict  |  async health_async() -> dict
  - anchor(payload: bytes|str, *, tags: list[str]|None=None, idempotent: bool=True) -> dict
  - verify(anchor_id: str=None, digest: str=None) -> dict|bool
  - get(anchor_id: str) -> dict
  - list_anchors(limit:int=..., since:float|None=None, until:float|None=None, page_token:str|None=None) -> dict
  - prune_older_than(seconds:int) -> dict|int
  - optional: batch_anchor(digests: list[str]|bytes, merkle: bool=True) -> dict
  - attrs/flags: supports_batch, supports_merkle, supports_pagination, supports_prune

Конфиг через ENV (пример):
  LEDGER_ENDPOINT, LEDGER_API_KEY, LEDGER_BACKEND, TEST_BACKEND_REQUIRED
Если TEST_BACKEND_REQUIRED=1 и клиент создать не удалось — тесты упадут.
"""

from __future__ import annotations

import base64
import os
import time
import random
import string
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

mod = pytest.importorskip("engine.ledger.anchor", reason="engine.ledger.anchor not found")
AnchorClient = getattr(mod, "AnchorClient", None)
create_client = getattr(mod, "create_client", None)

# --------- Конфиг и фабрика клиента ---------

@dataclass
class TestCfg:
    endpoint: Optional[str] = os.getenv("LEDGER_ENDPOINT")
    api_key: Optional[str] = os.getenv("LEDGER_API_KEY")
    backend: Optional[str] = os.getenv("LEDGER_BACKEND")
    require_backend: bool = os.getenv("TEST_BACKEND_REQUIRED", "0") in ("1", "true", "yes", "on")

def _make_client() -> Any:
    cfg = TestCfg()
    if AnchorClient and hasattr(AnchorClient, "from_env"):
        try:
            return AnchorClient.from_env()
        except Exception as e:
            if cfg.require_backend:
                raise
            pytest.skip(f"AnchorClient.from_env() failed: {e}")
    if create_client:
        try:
            kwargs = {}
            if cfg.endpoint: kwargs["endpoint"] = cfg.endpoint
            if cfg.api_key: kwargs["api_key"] = cfg.api_key
            if cfg.backend:  kwargs["backend"] = cfg.backend
            return create_client(**kwargs)  # type: ignore
        except Exception as e:
            if cfg.require_backend:
                raise
            pytest.skip(f"create_client failed: {e}")
    pytest.skip("No client factory available (AnchorClient|create_client)")

# --------- Хелперы ---------

def _rand_bytes(n: int = 256) -> bytes:
    return os.urandom(n)

def _rand_text(n: int = 256) -> str:
    alpha = string.ascii_letters + string.digits
    return "".join(random.choice(alpha) for _ in range(n))

def _digest_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _payload() -> bytes:
    # детерминированная часть + шум
    base = f"ai-npc-event:{int(time.time()*1000)}:{_rand_text(8)}".encode("utf-8")
    return base + b"|" + _rand_bytes(64)

# --------- Фикстуры ---------

@pytest.fixture(scope="module")
def client():
    return _make_client()

@pytest.fixture()
def sample_payload() -> bytes:
    return _payload()

@pytest.fixture()
def sample_digest(sample_payload: bytes) -> str:
    return _digest_sha256(sample_payload)

# --------- Базовое здоровье ---------

def test_health_basic(client):
    health_fn = getattr(client, "health", None)
    if not callable(health_fn):
        pytest.skip("Client.health() not implemented")
    h = health_fn()
    assert isinstance(h, dict)
    assert any(k in h for k in ("backend", "status", "time"))

# --------- Создание и верификация якоря ---------

def test_anchor_and_verify_by_id(client, sample_payload):
    anchor = client.anchor(sample_payload, tags=["integration","npc"], idempotent=True)
    assert isinstance(anchor, dict)
    assert "anchor_id" in anchor
    assert anchor.get("digest") or anchor.get("merkle_root")
    # По anchor_id
    ok = client.verify(anchor_id=anchor["anchor_id"])
    assert ok is True or ok.get("valid") is True  # допускаем bool или dict

def test_anchor_and_verify_by_digest(client, sample_payload, sample_digest):
    # Анкорим digest явно, если API допускает bytes/строку
    anchor = client.anchor(sample_digest, tags=["digest"], idempotent=True)  # допускаем строковый digest
    assert anchor.get("digest") in (sample_digest, sample_digest.lower())
    res = client.verify(digest=sample_digest)
    assert res is True or res.get("valid") is True

# --------- Idempotency ---------

def test_idempotent_same_payload_returns_same_anchor(client, sample_payload):
    a1 = client.anchor(sample_payload, tags=["idem"], idempotent=True)
    a2 = client.anchor(sample_payload, tags=["idem"], idempotent=True)
    # Один и тот же anchor_id ожидается при идемпотентности
    if "anchor_id" in a1 and "anchor_id" in a2:
        assert a1["anchor_id"] == a2["anchor_id"]
    else:
        pytest.skip("Client does not expose anchor_id for idempotency assertion")

# --------- Tamper detection ---------

def test_verify_fails_on_tamper(client, sample_payload):
    anchor = client.anchor(sample_payload, tags=["tamper"], idempotent=True)
    tampered = sample_payload + b"_evil"
    bad = client.verify(digest=_digest_sha256(tampered))
    assert bad is False or bad.get("valid") is False

# --------- Пагинация и выборка ---------

@pytest.mark.parametrize("limit", [1, 2, 5])
def test_list_anchors_pagination_if_supported(client, limit):
    if not getattr(client, "supports_pagination", False) and not hasattr(client, "list_anchors"):
        pytest.xfail("Pagination not supported")
    got: List[Dict[str, Any]] = []
    token = None
    for _ in range(3):
        page = client.list_anchors(limit=limit, page_token=token)  # type: ignore[arg-type]
        assert isinstance(page, dict)
        items = page.get("items") or page.get("anchors") or []
        assert isinstance(items, list)
        got.extend(items)
        token = page.get("next_token")
        if not token:
            break
    # Ничего страшного, если бекенд пока пуст — проверяем, что протокол работает
    assert isinstance(got, list)

# --------- Прическа старых данных (retention) ---------

def test_prune_older_than_if_supported(client):
    if not getattr(client, "supports_prune", False) and not hasattr(client, "prune_older_than"):
        pytest.xfail("Prune not supported")
    # 0 секунд — NOOP или минимум удалений
    res = client.prune_older_than(0)
    if isinstance(res, dict):
        assert "removed" in res
    else:
        assert isinstance(res, int) and res >= 0

# --------- Batch/Merkle ---------

def test_batch_anchor_merkle_if_supported(client):
    supports_batch = getattr(client, "supports_batch", False) or hasattr(client, "batch_anchor")
    if not supports_batch:
        pytest.xfail("Batch anchor not supported")
    digests = [_digest_sha256(_payload()) for _ in range(8)]
    out = client.batch_anchor(digests, merkle=True)  # type: ignore[arg-type]
    # Ожидаем хотя бы merkle_root или список результатов
    assert isinstance(out, dict)
    assert out.get("merkle_root") or out.get("results")

# --------- Конкурентные гонки и идемпотентность ---------

def test_concurrent_anchor_same_digest_single_anchor(client):
    payload = _payload()
    dg = _digest_sha256(payload)

    def work():
        # тот же digest много раз
        a = client.anchor(dg, tags=["race"], idempotent=True)
        return a.get("anchor_id")

    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(work) for _ in range(16)]
        ids = [f.result(timeout=5) for f in as_completed(futs)]
    ids = [i for i in ids if i]
    # либо один общий anchor_id, либо бэкенд возвращает одну и ту же запись
    if ids:
        assert len(set(ids)) == 1

# --------- get(anchor_id) ---------

def test_get_anchor_by_id_if_supported(client, sample_payload):
    if not hasattr(client, "get"):
        pytest.xfail("get(anchor_id) not supported")
    a = client.anchor(sample_payload, tags=["get"], idempotent=True)
    g = client.get(a["anchor_id"])
    assert isinstance(g, dict)
    assert g.get("anchor_id") == a["anchor_id"]

# --------- Временные границы выборки ---------

def test_list_since_until_window_if_supported(client):
    if not getattr(client, "supports_pagination", False) and not hasattr(client, "list_anchors"):
        pytest.xfail("Range listing not supported")
    t0 = time.time()
    client.anchor(_payload(), tags=["window"], idempotent=True)
    time.sleep(0.01)
    t1 = time.time()
    page = client.list_anchors(limit=50, since=t0 - 1, until=t1 + 1)  # type: ignore[arg-type]
    assert isinstance(page, dict)
    items = page.get("items") or page.get("anchors") or []
    assert isinstance(items, list)

# --------- Стабильность представления дайджеста ---------

@pytest.mark.parametrize("fmt", ["hex", "b64"])
def test_digest_formats_if_accepted(client, fmt, sample_payload):
    # Если клиент принимает не hex, а bytes/b64 — тоже проверим.
    if fmt == "hex":
        dig = _digest_sha256(sample_payload)
        a = client.anchor(dig, idempotent=True)
    else:
        b = hashlib.sha256(sample_payload).digest()
        dig_b64 = base64.b64encode(b).decode("ascii")
        try:
            a = client.anchor(dig_b64, idempotent=True)  # может быть неподдержано — тогда просто skip
        except Exception:
            pytest.skip("Base64 digest not accepted by client")
    assert isinstance(a, dict)
    assert a.get("anchor_id")

# --------- Поведение verify(...) при отсутствии данных ---------

def test_verify_unknown_returns_false(client):
    res = client.verify(anchor_id="nonexistent-anchor-id")
    assert res is False or res.get("valid") is False

# --------- Маркеры pytest для CI ---------

def pytest_configure(config):  # type: ignore[func-annotations]
    config.addinivalue_line("markers", "integration: marks tests as integration (deselect with '-m \"not integration\"')")

@pytest.mark.integration
def test_marker_attached():
    # Маркер присутствует на suite‑уровне; этот тест — заглушка для селекции.
    assert True
