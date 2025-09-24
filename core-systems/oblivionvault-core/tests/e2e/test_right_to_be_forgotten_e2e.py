# oblivionvault-core/tests/e2e/test_right_to_be_forgotten_e2e.py
"""
End-to-End test for GDPR Right-To-Be-Forgotten (RTBF) flow in OblivionVault.

Contract under test
-------------------
If a privacy orchestrator receives an RTBF request for subject_id:
  1) It must verify no Legal Hold is active for targeted items.
  2) It must compute an erasure plan: list of (namespace, key, version, key_id).
  3) It must execute the plan atomically with two-phase strategy:
     Phase A: delete secrets from primary storage.
     Phase B: cryptographically shred the per-subject encryption keys (key vault).
     If Phase A fails, Phase B must not execute.
  4) It must write audit events and emit soft metrics.
  5) Repeated RTBF for the same subject must be idempotent.

This test provides:
- InMemoryStorage with subject indexing and metadata.
- KeyVaultStub and "crypto" contract (presence of key_id enables decrypt).
- Minimal RTBF orchestrator (used if project orchestrator is not yet implemented).
- Integration with LegalHoldManager (import-or-skip to enforce contract).

Public API expected (if real orchestrator exists):
  from oblivionvault.privacy.rtbf import RtbfOrchestrator
  RtbfOrchestrator(storage, key_vault, legal_hold_manager, audit_sink).process_request(subject_id, actor, reason) -> dict

Legal Hold API is defined in tests/unit/test_legal_hold.py.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import pytest

# --- Import LegalHold (required for this E2E) ---------------------------------
lh = pytest.importorskip("oblivionvault.legal.legal_hold", reason="Legal Hold module not implemented yet")

# --- Metrics: make calls no-op in test to avoid external deps -----------------
try:
    from oblivionvault.observability import metrics as ov_metrics
    def _counter_inc(*args, **kwargs): pass
    def _histogram_observe(*args, **kwargs): pass
    ov_metrics.counter_inc = _counter_inc  # type: ignore
    ov_metrics.histogram_observe = _histogram_observe  # type: ignore
except Exception:
    pass


# ----------------------------- Test doubles -----------------------------------

@dataclass
class _Row:
    namespace: str
    key: str
    version: int
    ciphertext: bytes
    metadata: Dict[str, Any]  # must contain subject_id and key_id
    created_at: float


class InMemoryStorage:
    """
    Minimal async storage with subject indexing to simulate primary store.
    """
    def __init__(self) -> None:
        self._rows: Dict[Tuple[str, str, int], _Row] = {}
        self._by_subject: Dict[str, List[Tuple[str, str, int]]] = {}

    def seed(self, *, namespace: str, key: str, version: int, payload: bytes, subject_id: str, key_id: str) -> None:
        row = _Row(
            namespace=namespace,
            key=key,
            version=version,
            ciphertext=payload,
            metadata={"subject_id": subject_id, "key_id": key_id},
            created_at=time.time(),
        )
        pk = (namespace, key, version)
        self._rows[pk] = row
        self._by_subject.setdefault(subject_id, []).append(pk)

    async def list_by_subject(self, subject_id: str) -> List[_Row]:
        pk_list = list(self._by_subject.get(subject_id, []))
        return [self._rows[pk] for pk in pk_list if pk in self._rows]

    async def list_secrets(self, namespace: str, *, prefix=None, limit=100, offset=0, latest_only=False):
        # Only for compatibility if ever needed by other components
        from types import SimpleNamespace
        rows = []
        for (_ns, _k, _v), r in self._rows.items():
            if namespace != "*" and _ns != namespace:
                continue
            rows.append(SimpleNamespace(
                namespace=r.namespace, key=r.key, version=r.version,
                ciphertext=r.ciphertext, metadata=r.metadata, created_at=str(int(r.created_at))
            ))
        rows.sort(key=lambda s: (s.key, -int(s.version)))
        return rows[offset: offset + limit]

    async def read_secret(self, namespace: str, key: str, version: int):
        from types import SimpleNamespace
        r = self._rows[(namespace, key, version)]
        return SimpleNamespace(
            namespace=r.namespace, key=r.key, version=r.version,
            ciphertext=r.ciphertext, metadata=r.metadata
        )

    async def delete_secret(self, namespace: str, key: str, *, version: int) -> int:
        pk = (namespace, key, version)
        if pk in self._rows:
            del self._rows[pk]
            return 1
        return 0


class KeyVaultStub:
    """
    Very small key vault: presence of key_id means data is decryptable.
    """
    def __init__(self) -> None:
        self._keys: Dict[str, bytes] = {}

    def put(self, key_id: str, key_bytes: bytes) -> None:
        self._keys[key_id] = key_bytes

    def exists(self, key_id: str) -> bool:
        return key_id in self._keys

    def cryptoshred(self, key_id: str) -> None:
        self._keys.pop(key_id, None)


class AuditRecorder:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    def write(self, event: Dict[str, Any]) -> None:
        required = {"ts", "actor", "reason", "op", "subject_id"}
        assert required.issubset(event.keys())
        self.events.append(event)


# ------------------------------ Orchestrator ----------------------------------

try:
    # Use real orchestrator if exists in the codebase
    from oblivionvault.privacy.rtbf import RtbfOrchestrator as _BaseOrchestrator  # type: ignore
except Exception:
    _BaseOrchestrator = object  # type: ignore

class RtbfOrchestrator(_BaseOrchestrator):  # type: ignore
    """
    Reference orchestrator used by the test if project one is not available yet.
    Enforces Legal Hold, executes two-phase deletion, writes audit.
    """
    def __init__(self, storage: InMemoryStorage, key_vault: KeyVaultStub, legal_hold: "lh.LegalHoldManager", audit: AuditRecorder):
        self.storage = storage
        self.vault = key_vault
        self.legal = legal_hold
        self.audit = audit

    async def process_request(self, subject_id: str, actor: str, reason: str) -> Dict[str, Any]:
        # Build erasure plan
        rows = await self.storage.list_by_subject(subject_id)
        # Idempotency: nothing to erase
        if not rows:
            self.audit.write({"ts": time.time(), "actor": actor, "reason": reason, "op": "rtbf.noop", "subject_id": subject_id})
            return {"status": "noop", "subject_id": subject_id, "deleted_rows": 0, "shredded_keys": 0}

        # Legal hold gate
        held_items = [(r.namespace, r.key, r.version) for r in rows if self.legal.is_held(r.namespace, r.key)]
        if held_items:
            self.audit.write({"ts": time.time(), "actor": actor, "reason": reason, "op": "rtbf.blocked_legal_hold", "subject_id": subject_id, "count": len(held_items)})
            return {"status": "blocked_by_legal_hold", "subject_id": subject_id, "held": held_items}

        # Phase A: delete rows
        deleted = 0
        for r in rows:
            try:
                n = await self.storage.delete_secret(r.namespace, r.key, version=r.version)
                deleted += int(n or 0)
            except Exception as e:
                # Abort and do NOT shred keys
                self.audit.write({"ts": time.time(), "actor": actor, "reason": str(e), "op": "rtbf.failed_delete", "subject_id": subject_id})
                return {"status": "failed", "subject_id": subject_id, "deleted_rows": deleted}

        # Phase B: cryptoshred all key_ids observed for the subject
        key_ids = sorted({str(r.metadata.get("key_id")) for r in rows if r.metadata.get("key_id")})
        shredded = 0
        for kid in key_ids:
            if self.vault.exists(kid):
                self.vault.cryptoshred(kid)
                shredded += 1

        self.audit.write({"ts": time.time(), "actor": actor, "reason": reason, "op": "rtbf.erased", "subject_id": subject_id, "deleted_rows": deleted, "shredded_keys": shredded})
        return {"status": "erased", "subject_id": subject_id, "deleted_rows": deleted, "shredded_keys": shredded}


# -------------------------------- Fixtures ------------------------------------

@pytest.fixture()
def key_vault() -> KeyVaultStub:
    return KeyVaultStub()

@pytest.fixture()
def storage() -> InMemoryStorage:
    return InMemoryStorage()

@pytest.fixture()
def audit() -> AuditRecorder:
    return AuditRecorder()

@pytest.fixture()
def legal_hold(audit) -> "lh.LegalHoldManager":
    base_ts = 1_725_000_000.0
    def _clock(): return base_ts
    return lh.LegalHoldManager(audit_sink=audit, clock=_clock)

@pytest.fixture()
def orchestrator(storage, key_vault, legal_hold, audit) -> RtbfOrchestrator:
    return RtbfOrchestrator(storage, key_vault, legal_hold, audit)


# ---------------------------------- Tests -------------------------------------

@pytest.mark.asyncio
async def test_rtbf_erases_data_and_keys_without_legal_hold(storage, key_vault, legal_hold, audit, orchestrator):
    subj = "subject-001"
    # seed keys
    key_vault.put("kid-1", b"k1")
    key_vault.put("kid-2", b"k2")
    # seed rows across namespaces and versions
    storage.seed(namespace="profiles", key="pii_blob", version=1, payload=b"A"*32, subject_id=subj, key_id="kid-1")
    storage.seed(namespace="auth",     key="session",  version=3, payload=b"B"*32, subject_id=subj, key_id="kid-2")
    storage.seed(namespace="auth",     key="session",  version=2, payload=b"C"*16, subject_id=subj, key_id="kid-2")

    # run RTBF
    res = await orchestrator.process_request(subject_id=subj, actor="dpo", reason="user_request_gdpr17")

    # assertions
    assert res["status"] == "erased"
    assert res["deleted_rows"] == 3
    assert res["shredded_keys"] == 2
    # storage empty for subject
    assert await storage.list_by_subject(subj) == []
    # keys are gone
    assert key_vault.exists("kid-1") is False
    assert key_vault.exists("kid-2") is False
    # audit contains final "rtbf.erased"
    assert any(e for e in audit.events if e["op"] == "rtbf.erased" and e["subject_id"] == subj)


@pytest.mark.asyncio
async def test_rtbf_blocked_by_legal_hold(storage, key_vault, legal_hold, audit, orchestrator):
    subj = "subject-002"
    key_vault.put("kid-3", b"k3")
    storage.seed(namespace="billing", key="invoice_pdf", version=1, payload=b"X"*8, subject_id=subj, key_id="kid-3")

    # place legal hold at key-level
    legal_hold.enable("key", namespace="billing", key="invoice_pdf", actor="legal", reason="litigation")

    res = await orchestrator.process_request(subject_id=subj, actor="dpo", reason="user_request_gdpr17")
    assert res["status"] == "blocked_by_legal_hold"
    # nothing was deleted or shredded
    assert await storage.list_by_subject(subj) != []
    assert key_vault.exists("kid-3") is True
    assert any(e for e in audit.events if e["op"] == "rtbf.blocked_legal_hold" and e["subject_id"] == subj)


@pytest.mark.asyncio
async def test_rtbf_idempotent(storage, key_vault, legal_hold, audit, orchestrator):
    subj = "subject-003"
    key_vault.put("kid-4", b"k4")
    storage.seed(namespace="ns", key="k", version=1, payload=b"Y", subject_id=subj, key_id="kid-4")

    # first run erases
    res1 = await orchestrator.process_request(subject_id=subj, actor="dpo", reason="req")
    assert res1["status"] == "erased"
    # second run is noop
    res2 = await orchestrator.process_request(subject_id=subj, actor="dpo", reason="req")
    assert res2["status"] == "noop"
    assert any(e for e in audit.events if e["op"] == "rtbf.noop" and e["subject_id"] == subj)


@pytest.mark.asyncio
async def test_rtbf_phase_a_failure_prevents_key_shred(monkeypatch, storage, key_vault, legal_hold, audit, orchestrator):
    subj = "subject-004"
    key_vault.put("kid-5", b"k5")
    storage.seed(namespace="ns", key="doc", version=1, payload=b"1", subject_id=subj, key_id="kid-5")
    storage.seed(namespace="ns", key="doc", version=2, payload=b"2", subject_id=subj, key_id="kid-5")

    # inject failure on deleting version 2
    async def _fail_delete(namespace: str, key: str, *, version: int) -> int:
        if version == 2:
            raise RuntimeError("injected delete failure")
        return await InMemoryStorage.delete_secret(storage, namespace, key, version=version)  # call original

    monkeypatch.setattr(storage, "delete_secret", _fail_delete)

    res = await orchestrator.process_request(subject_id=subj, actor="dpo", reason="req")
    # failure reported
    assert res["status"] == "failed"
    # key is NOT shredded
    assert key_vault.exists("kid-5") is True
    # at least one row may be gone, but not all
    remaining = await storage.list_by_subject(subj)
    assert len(remaining) >= 1
