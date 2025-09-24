# oblivionvault-core/tests/unit/test_legal_hold.py
"""
Specification-oriented tests for the Legal Hold subsystem of OblivionVault.

Required public API (to be implemented in `oblivionvault/legal/legal_hold.py`):

Classes / Exceptions:
- LegalHoldManager(audit_sink: AuditSinkLike | None = None, *, clock: Callable[[], float] = time.time)
- LegalHoldViolation(Exception)

Interfaces:
- class AuditSinkLike:
    def write(self, event: dict) -> None  # called on enable/disable operations

LegalHoldManager methods (async/sync are acceptable; tests call them synchronously):
- enable(scope: Literal["global","namespace","key"], *, namespace: str | None = None,
         key: str | None = None, actor: str, reason: str) -> dict
- disable(scope: Literal["global","namespace","key"], *, namespace: str | None = None,
          key: str | None = None, actor: str, reason: str) -> dict
- is_held(namespace: str, key: str) -> bool
- guard_delete(namespace: str, key: str) -> None | raise LegalHoldViolation
- guard_mutation(namespace: str, key: str) -> None | raise LegalHoldViolation
- list_active() -> list[dict]                               # active holds
- snapshot() -> dict                                        # serializable state
- load(snapshot: dict) -> None                              # restore state

Notes:
- Scope precedence: global > namespace > key.
- Disabling key-level hold does NOT cancel an active namespace/global hold.
- Idempotency: enabling the same scope twice is a no-op (no duplicate active records).
- Each enable/disable operation MUST write an audit event with keys:
  {"ts": float, "actor": str, "reason": str, "op": "enable"|"disable", "scope": "...",
   "namespace": str|None, "key": str|None}

Metrics (soft requirement; collected via oblivionvault.observability.metrics):
- counter_inc("ov_legal_hold_ops_total", labels={"op": "enable"|"disable", "scope": ...})
- counter_inc("ov_legal_hold_enforced_total", labels={"op": "delete"|"mutation"})
"""

from __future__ import annotations

import asyncio
import os
import random
import string
import time
from typing import Any, Dict, List, Tuple

import pytest

# --- Skip whole file if legal_hold module is not present yet -------------------
lh = pytest.importorskip("oblivionvault.legal.legal_hold", reason="Legal Hold module not implemented yet")

# We will also try to import metrics facade; if missing, tests will stub via monkeypatch.
try:
    from oblivionvault.observability import metrics as ov_metrics
    _METRICS_IMPORT_OK = True
except Exception:  # pragma: no cover
    _METRICS_IMPORT_OK = False


# ---------------------------- Fixtures & helpers -------------------------------

class _AuditRecorder:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    def write(self, event: Dict[str, Any]) -> None:
        # Minimal schema validation
        assert set(["ts", "actor", "reason", "op", "scope", "namespace", "key"]).issubset(event.keys())
        self.events.append(event)


@pytest.fixture()
def audit_recorder() -> _AuditRecorder:
    return _AuditRecorder()


@pytest.fixture(autouse=True)
def metrics_spy(monkeypatch):
    """
    Replace metrics counters with spies to assert calls without requiring exporters.
    """
    calls = {
        "counter": [],  # (name, amount, labels)
        "hist": [],     # not used here, reserved
    }

    def _counter_inc(name: str, amount: float = 1.0, *, labels: Dict[str, Any] | None = None, **_):
        calls["counter"].append((name, float(amount), dict(labels or {})))

    def _histogram_observe(name: str, value: float, *, labels: Dict[str, Any] | None = None, **_):
        calls["hist"].append((name, float(value), dict(labels or {})))

    if _METRICS_IMPORT_OK:
        monkeypatch.setattr(ov_metrics, "counter_inc", _counter_inc, raising=False)
        monkeypatch.setattr(ov_metrics, "histogram_observe", _histogram_observe, raising=False)

    yield calls


@pytest.fixture()
def manager(audit_recorder: _AuditRecorder):
    # Prefer deterministic time in tests
    base = 1_725_000_000.0
    def _clock() -> float:
        return base
    return lh.LegalHoldManager(audit_sink=audit_recorder, clock=_clock)


def _random_key(prefix: str = "k") -> str:
    return prefix + "_" + "".join(random.choices(string.ascii_lowercase, k=6))


# ------------------------------- Core behavior --------------------------------

def test_enable_disable_key_level_hold(manager, audit_recorder, metrics_spy):
    ns, key = "payments", "stripe_api_key"
    # enable key-level
    res1 = manager.enable("key", namespace=ns, key=key, actor="qa", reason="case-123")
    assert manager.is_held(ns, key) is True
    assert res1["scope"] == "key" and res1["namespace"] == ns and res1["key"] == key

    # idempotent enable: no duplication in list_active
    res2 = manager.enable("key", namespace=ns, key=key, actor="qa", reason="duplicate")
    active = manager.list_active()
    assert sum(1 for h in active if h["scope"] == "key" and h["namespace"] == ns and h["key"] == key) == 1

    # guard deletion must fail
    with pytest.raises(lh.LegalHoldViolation):
        manager.guard_delete(ns, key)

    # disable key-level
    manager.disable("key", namespace=ns, key=key, actor="qa", reason="resolved")
    assert manager.is_held(ns, key) is False

    # audit trail: at least enable + disable for key scope present
    ops = [e for e in audit_recorder.events if e["scope"] == "key" and e["namespace"] == ns and e["key"] == key]
    assert {e["op"] for e in ops} == {"enable", "disable"}

    # metrics were emitted (soft check)
    if _METRICS_IMPORT_OK:
        names = [c[0] for c in metrics_spy["counter"]]
        assert "ov_legal_hold_ops_total" in names


def test_namespace_and_global_precedence(manager):
    ns, key = "auth", "refresh_token"

    # enable namespace hold
    manager.enable("namespace", namespace=ns, actor="qa", reason="litigation")
    assert manager.is_held(ns, key) is True

    # enabling key-level disable SHOULD NOT cancel namespace/global hold
    manager.disable("key", namespace=ns, key=key, actor="qa", reason="attempt_to_override")
    assert manager.is_held(ns, key) is True, "namespace hold must still enforce"

    # global hold enforces across all
    manager.enable("global", actor="qa", reason="company-wide")
    assert manager.is_held("any", "thing") is True

    # disable namespace but keep global => still held
    manager.disable("namespace", namespace=ns, actor="qa", reason="ns_resolved")
    assert manager.is_held(ns, key) is True

    # disable global => finally released
    manager.disable("global", actor="qa", reason="global_resolved")
    assert manager.is_held(ns, key) is False


def test_guard_mutation_blocks_when_held(manager):
    ns, key = "profiles", "pii_blob"
    manager.enable("key", namespace=ns, key=key, actor="dpo", reason="dpia")
    with pytest.raises(lh.LegalHoldViolation):
        manager.guard_mutation(ns, key)


def test_list_active_and_snapshot_roundtrip(manager):
    n1, k1 = "ns1", "a"
    n2, k2 = "ns2", "b"
    manager.enable("key", namespace=n1, key=k1, actor="qa", reason="x")
    manager.enable("namespace", namespace=n2, actor="qa", reason="y")

    active = manager.list_active()
    # sanity: contains both scopes
    scopes = sorted({h["scope"] for h in active})
    assert scopes == ["key", "namespace"]

    snap = manager.snapshot()

    # Create a fresh manager and load snapshot
    m2 = lh.LegalHoldManager(audit_sink=None, clock=time.time)
    m2.load(snap)
    assert m2.is_held(n1, k1) is True
    assert m2.is_held(n2, "whatever") is True
    assert m2.is_held("other", "z") is False


# ------------------------------ Deletion guards --------------------------------

class _InMemoryStorage:
    """
    Minimal storage adapter used to validate guard_delete integration semantics.
    It delegates enforcement to LegalHoldManager.guard_delete(...).
    """
    def __init__(self, manager: Any):
        self.manager = manager
        self._rows: Dict[Tuple[str, str, int], bytes] = {}

    def seed(self, namespace: str, key: str, version: int, payload: bytes) -> None:
        self._rows[(namespace, key, version)] = payload

    async def list_secrets(self, namespace: str, *, prefix=None, limit=100, offset=0, latest_only=False):
        # Only what compactor expects
        from types import SimpleNamespace
        rows = []
        for (ns, k, ver), payload in self._rows.items():
            if namespace != "*" and ns != namespace:
                continue
            rows.append(SimpleNamespace(namespace=ns, key=k, version=ver, ciphertext=payload, metadata={}, created_at=str(int(time.time()))))
        # stable order by (key,version desc)
        rows.sort(key=lambda r: (r.key, -int(r.version)))
        return rows[offset: offset + limit]

    async def read_secret(self, namespace: str, key: str, version: int):
        from types import SimpleNamespace
        payload = self._rows[(namespace, key, version)]
        return SimpleNamespace(namespace=namespace, key=key, version=version, ciphertext=payload, metadata={})

    async def delete_secret(self, namespace: str, key: str, *, version: int) -> int:
        # Enforce Legal Hold
        self.manager.guard_delete(namespace, key)
        try:
            del self._rows[(namespace, key, version)]
            return 1
        except KeyError:
            return 0


@pytest.mark.asyncio
async def test_storage_delete_blocked_under_legal_hold(manager):
    store = _InMemoryStorage(manager)
    ns, key = "billing", "old_invoice_pdf"
    store.seed(ns, key, 1, b"X")
    manager.enable("key", namespace=ns, key=key, actor="legal", reason="request")

    with pytest.raises(lh.LegalHoldViolation):
        await store.delete_secret(ns, key, version=1)

    # after releasing hold, deletion must succeed
    manager.disable("key", namespace=ns, key=key, actor="legal", reason="closed")
    n = await store.delete_secret(ns, key, version=1)
    assert n == 1


# ------------------------- Compactor integration (non-destructive) -------------

@pytest.mark.asyncio
async def test_compactor_skips_deletions_when_held(tmp_path, manager):
    """
    Integration with ArchiveCompactor: entries under Legal Hold must NOT be deleted.
    Archiving itself is allowed (read-only), but delete phase must be no-op.
    """
    # Import compactor and config from workers module provided in the codebase
    from oblivionvault.workers.archive_compactor import ArchiveCompactor, CompactorConfig, LocalDirSink

    # seed storage with two versions: one free, one under hold
    store = _InMemoryStorage(manager)
    free_ns, free_key = "vault", "rotated_key"
    held_ns, held_key = "vault", "to_be_preserved"

    store.seed(free_ns, free_key, 1, b"A" * 10)
    store.seed(held_ns, held_key, 1, b"B" * 10)

    # enable legal hold only for held_key
    manager.enable("key", namespace=held_ns, key=held_key, actor="legal", reason="hold-42")

    cfg = CompactorConfig(
        retention_keep_last=0,       # everything is a candidate
        retention_min_age_s=0,       # ignore age
        batch_size=100,
        target_archive_size=1024,    # small package
        concurrency=4,
        interval_s=0,                # single run
        dry_run=False,
        sink_type="local",
        local_dir=str(tmp_path),
    )
    sink = LocalDirSink(tmp_path)
    compactor = ArchiveCompactor(store, cfg, sink)

    # run a single cycle (via private method to avoid periodic loop)
    await compactor._compact_cycle()

    # free secret must be deleted, held secret must remain
    remaining_keys = {(ns, k, v) for (ns, k, v) in store._rows.keys()}
    assert (free_ns, free_key, 1) not in remaining_keys
    assert (held_ns, held_key, 1) in remaining_keys


# ---------------------------- Concurrency semantics ----------------------------

@pytest.mark.asyncio
async def test_concurrent_enable_disable_is_consistent(manager):
    """
    Concurrency smoke test: toggling holds in parallel should leave a valid final state
    without raising and without duplicating active entries.
    """
    ns, key = "parallel", "doc"
    async def enable_then_disable():
        manager.enable("key", namespace=ns, key=key, actor="t1", reason="r1")
        # simulate race
        await asyncio.sleep(0)
        manager.disable("key", namespace=ns, key=key, actor="t1", reason="r1")

    async def enable_only():
        manager.enable("key", namespace=ns, key=key, actor="t2", reason="r2")

    await asyncio.gather(*(enable_then_disable() for _ in range(5)), enable_only())
    # final state: held (because of last enable_only)
    assert manager.is_held(ns, key) is True
    # no duplicates in active list
    active = [h for h in manager.list_active() if h["scope"] == "key" and h["namespace"] == ns and h["key"] == key]
    assert len(active) == 1
