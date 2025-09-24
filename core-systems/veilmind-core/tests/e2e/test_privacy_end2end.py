# veilmind-core/tests/e2e/test_privacy_end2end.py
# Industrial E2E privacy test-suite for VeilMind Core
# Requirements: python3.10+, pytest
# External deps: none (cryptography is NOT required; a secure test cipher is implemented with HMAC+XOR stream)
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import re
import secrets
import string
import time
import typing as t
from dataclasses import dataclass, field

import pytest

###############################################################################
# Utility: strong typing helpers
###############################################################################

Json = t.Dict[str, t.Any]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))


###############################################################################
# Policy, RBAC, PII Detection, Redaction
###############################################################################


@dataclass(frozen=True)
class PurposePolicy:
    name: str
    # fields allowed to be persisted for this purpose (after minimization/redaction)
    allowed_fields: t.Set[str]
    # fields allowed to be returned to a given role for this purpose
    role_view: t.Dict[str, t.Set[str]]


@dataclass(frozen=True)
class Rbac:
    # role -> allowed purposes
    role_purposes: t.Dict[str, t.Set[str]]

    def check(self, role: str, purpose: str) -> None:
        allowed = self.role_purposes.get(role, set())
        if purpose not in allowed:
            raise PermissionError(f"role '{role}' is not permitted to access purpose '{purpose}'")


class PiiDetector:
    # simple industrial-grade regexes for E2E tests (not exhaustive)
    EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
    PHONE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3}[-.\s]?\d{2,4}[-.\s]?\d{2,4}\b")
    CARD = re.compile(r"\b(?:\d[ -]*?){13,19}\b")  # rough Luhn-agnostic
    NAME_FIELDS = {"name", "first_name", "last_name", "full_name"}

    def find_in_value(self, v: str) -> t.Set[str]:
        kinds: t.Set[str] = set()
        if self.EMAIL.search(v):
            kinds.add("email")
        if self.PHONE.search(v):
            kinds.add("phone")
        if self.CARD.search(v):
            kinds.add("card")
        return kinds

    def is_name_field(self, key: str) -> bool:
        return key in self.NAME_FIELDS


class Redactor:
    def __init__(self, salt: bytes) -> None:
        self._salt = salt

    def mask_email(self, email: str) -> str:
        # keep first char + domain, mask local-part
        try:
            local, domain = email.split("@", 1)
        except ValueError:
            return "***"
        head = local[:1]
        return f"{head}***@{domain}"

    def mask_phone(self, phone: str) -> str:
        digits = [c for c in phone if c.isdigit()]
        if len(digits) < 4:
            return "***"
        return "***" + "".join(digits[-4:])

    def mask_card(self, card: str) -> str:
        digits = [c for c in card if c.isdigit()]
        if len(digits) < 4:
            return "****"
        return "**** **** **** " + "".join(digits[-4:])

    def mask_name(self, name: str) -> str:
        if not name:
            return ""
        return name[0] + "***"

    def tokenize(self, value: str) -> str:
        # deterministic non-reversible token for joins without revealing PII
        digest = hashlib.sha256(self._salt + value.encode("utf-8")).hexdigest()
        return f"tok_{digest[:32]}"

    def redact_field(self, key: str, value: t.Any, detector: PiiDetector) -> t.Any:
        if not isinstance(value, str):
            return value
        kinds = detector.find_in_value(value)
        if "email" in kinds:
            return self.mask_email(value)
        if "phone" in kinds:
            return self.mask_phone(value)
        if "card" in kinds:
            return self.mask_card(value)
        if detector.is_name_field(key):
            return self.mask_name(value)
        # default — tokenize free-form fields that contain PII-like data
        # to avoid storing raw content
        if kinds:
            return self.tokenize(value)
        return value


###############################################################################
# Consent Registry
###############################################################################


@dataclass
class ConsentRecord:
    user_id: str
    purpose: str
    granted_at_ms: int
    terms_version: str
    expires_at_ms: int | None = None


class ConsentRegistry:
    def __init__(self) -> None:
        self._by_user: dict[tuple[str, str], ConsentRecord] = {}

    def grant(self, user_id: str, purpose: str, terms_version: str, ttl_seconds: int | None = None) -> None:
        rec = ConsentRecord(
            user_id=user_id,
            purpose=purpose,
            granted_at_ms=_now_ms(),
            terms_version=terms_version,
            expires_at_ms=(_now_ms() + ttl_seconds * 1000) if ttl_seconds else None,
        )
        self._by_user[(user_id, purpose)] = rec

    def has_valid(self, user_id: str, purpose: str, min_terms_version: str | None = None) -> bool:
        rec = self._by_user.get((user_id, purpose))
        if not rec:
            return False
        if rec.expires_at_ms and rec.expires_at_ms < _now_ms():
            return False
        if min_terms_version and rec.terms_version < min_terms_version:
            return False
        return True

    def revoke_all(self, user_id: str) -> None:
        keys = [k for k in self._by_user if k[0] == user_id]
        for k in keys:
            self._by_user.pop(k, None)


###############################################################################
# Key Manager & Crypto Vault (versioned keys + rotation, test-grade cipher)
###############################################################################


class KeyManager:
    def __init__(self) -> None:
        self._keys: dict[int, bytes] = {}
        self._active_version: int = 0
        self.rotate()  # initialize v1

    @property
    def active_version(self) -> int:
        return self._active_version

    def get(self, version: int) -> bytes:
        if version not in self._keys:
            raise KeyError(f"missing key version {version}")
        return self._keys[version]

    def rotate(self) -> int:
        self._active_version += 1
        self._keys[self._active_version] = secrets.token_bytes(32)
        return self._active_version


class CryptoVault:
    """
    Test-grade AEAD-like construction using HMAC-DRBG to derive XOR keystream
    and HMAC-SHA256 for integrity. Not for production cryptography, but
    deterministic and dependency-free for tests.
    """
    NONCE_LEN = 16

    def __init__(self, km: KeyManager) -> None:
        self._km = km

    def encrypt(self, plaintext: bytes) -> tuple[str, int]:
        version = self._km.active_version
        key = self._km.get(version)
        nonce = secrets.token_bytes(self.NONCE_LEN)
        stream = self._keystream(key, nonce, len(plaintext))
        ct = bytes(a ^ b for a, b in zip(plaintext, stream))
        tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
        blob = _b64e(b"V" + version.to_bytes(2, "big") + nonce + ct + tag)
        return blob, version

    def decrypt(self, blob: str) -> bytes:
        raw = _b64d(blob)
        if not raw or raw[0:1] != b"V":
            raise ValueError("invalid blob header")
        version = int.from_bytes(raw[1:3], "big")
        key = self._km.get(version)
        nonce = raw[3:3 + self.NONCE_LEN]
        rest = raw[3 + self.NONCE_LEN :]
        if len(rest) < 32:
            raise ValueError("invalid blob length")
        ct, tag = rest[:-32], rest[-32:]
        exp_tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, exp_tag):
            raise ValueError("authentication failed")
        stream = self._keystream(key, nonce, len(ct))
        pt = bytes(a ^ b for a, b in zip(ct, stream))
        return pt

    @staticmethod
    def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < n:
            counter_bytes = counter.to_bytes(8, "big")
            block = hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest()
            out.extend(block)
            counter += 1
        return bytes(out[:n])


###############################################################################
# Audit log with hash-chain (tamper-evident)
###############################################################################


@dataclass
class AuditEvent:
    ts_ms: int
    kind: str
    user_id: str | None
    record_id: str | None
    purpose: str | None
    details: Json
    prev_hash_hex: str | None
    hash_hex: str


class AuditLog:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, kind: str, user_id: str | None, record_id: str | None, purpose: str | None, details: Json) -> AuditEvent:
        prev_hash_hex = self._events[-1].hash_hex if self._events else None
        data = {
            "ts": _now_ms(),
            "kind": kind,
            "user_id": user_id,
            "record_id": record_id,
            "purpose": purpose,
            "details": details,
            "prev": prev_hash_hex,
        }
        block = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        hh = hashlib.sha256(block).hexdigest()
        ev = AuditEvent(
            ts_ms=data["ts"],
            kind=kind,
            user_id=user_id,
            record_id=record_id,
            purpose=purpose,
            details=details,
            prev_hash_hex=prev_hash_hex,
            hash_hex=hh,
        )
        self._events.append(ev)
        return ev

    def verify_chain(self) -> bool:
        prev = None
        for ev in self._events:
            data = {
                "ts": ev.ts_ms,
                "kind": ev.kind,
                "user_id": ev.user_id,
                "record_id": ev.record_id,
                "purpose": ev.purpose,
                "details": ev.details,
                "prev": prev,
            }
            block = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
            hh = hashlib.sha256(block).hexdigest()
            if hh != ev.hash_hex:
                return False
            prev = ev.hash_hex
        return True

    @property
    def events(self) -> list[AuditEvent]:
        return self._events


###############################################################################
# VeilMind Core (in-memory for E2E)
###############################################################################


@dataclass
class StoredRecord:
    record_id: str
    user_id: str
    purpose: str
    encrypted_blob: str
    key_version: int
    created_at_ms: int
    fields_persisted: set[str]


class VeilMindCore:
    def __init__(self) -> None:
        # RBAC & Purpose policies
        self.rbac = Rbac(
            role_purposes={
                "support_agent": {"support"},
                "marketing_analyst": {"marketing"},
                "admin_auditor": {"support", "marketing"},
            }
        )
        self.policies: dict[str, PurposePolicy] = {
            "support": PurposePolicy(
                name="support",
                allowed_fields={"user_id", "issue", "contact_email", "contact_phone_token", "name_masked"},
                role_view={
                    "support_agent": {"record_id", "user_id", "issue", "contact_email", "created_at_ms", "purpose", "name_masked"},
                    "admin_auditor": {"record_id", "user_id", "issue", "contact_email", "created_at_ms", "purpose", "name_masked"},
                },
            ),
            "marketing": PurposePolicy(
                name="marketing",
                allowed_fields={"user_id", "cohort_tag"},
                role_view={
                    "marketing_analyst": {"record_id", "user_id", "cohort_tag", "created_at_ms", "purpose"},
                    "admin_auditor": {"record_id", "user_id", "cohort_tag", "created_at_ms", "purpose"},
                },
            ),
        }
        # Privacy tooling
        self.detector = PiiDetector()
        self.redactor = Redactor(salt=secrets.token_bytes(32))
        self.consents = ConsentRegistry()
        # Crypto & storage
        self.keys = KeyManager()
        self.crypto = CryptoVault(self.keys)
        self._records: dict[str, StoredRecord] = {}
        self._index_by_user: dict[str, set[str]] = {}
        # Audit
        self.audit = AuditLog()

    # --------------------- Public API ---------------------

    def grant_consent(self, user_id: str, purpose: str, terms_version: str, ttl_seconds: int | None = None) -> None:
        self.consents.grant(user_id, purpose, terms_version, ttl_seconds)
        self.audit.append("consent_granted", user_id=user_id, record_id=None, purpose=purpose, details={"version": terms_version})

    def ingest(self, user_id: str, payload: Json, purpose: str, require_consent: bool = True) -> str:
        if purpose not in self.policies:
            raise ValueError(f"unknown purpose '{purpose}'")
        policy = self.policies[purpose]
        has_consent = self.consents.has_valid(user_id, purpose)
        if require_consent and not has_consent:
            # enforce minimization & redaction
            payload = self._minimize_and_redact(payload, policy)
            consent_status = "no_consent_minimized"
        else:
            # even with consent, still minimize to allowed fields, with masking where relevant
            payload = self._minimize_and_redact(payload, policy)
            consent_status = "with_consent_minimized"

        record_id = self._new_record_id()
        blob, v = self.crypto.encrypt(json.dumps(payload).encode("utf-8"))
        rec = StoredRecord(
            record_id=record_id,
            user_id=user_id,
            purpose=purpose,
            encrypted_blob=blob,
            key_version=v,
            created_at_ms=_now_ms(),
            fields_persisted=set(payload.keys()),
        )
        self._records[record_id] = rec
        self._index_by_user.setdefault(user_id, set()).add(record_id)
        self.audit.append(
            kind="ingest",
            user_id=user_id,
            record_id=record_id,
            purpose=purpose,
            details={"key_version": v, "persisted_fields": sorted(rec.fields_persisted), "consent": consent_status},
        )
        return record_id

    def retrieve(self, record_id: str, role: str) -> Json:
        rec = self._records.get(record_id)
        if not rec:
            raise KeyError("record not found")
        self.rbac.check(role, rec.purpose)
        policy = self.policies[rec.purpose]
        raw = json.loads(self.crypto.decrypt(rec.encrypted_blob).decode("utf-8"))
        # filter view per role
        visible_fields = policy.role_view.get(role, set())
        if not visible_fields:
            raise PermissionError(f"role '{role}' has no view over purpose '{rec.purpose}'")
        view = {k: v for k, v in {
            **raw,
            "record_id": rec.record_id,
            "created_at_ms": rec.created_at_ms,
            "purpose": rec.purpose,
        }.items() if k in visible_fields}
        self.audit.append("retrieve", user_id=rec.user_id, record_id=rec.record_id, purpose=rec.purpose, details={"role": role})
        return view

    def forget_user(self, user_id: str) -> int:
        # delete all user records and revoke consent; append tombstones
        record_ids = list(self._index_by_user.get(user_id, []))
        deleted = 0
        for rid in record_ids:
            rec = self._records.pop(rid, None)
            if rec:
                deleted += 1
                self.audit.append("tombstone", user_id=user_id, record_id=rid, purpose=rec.purpose, details={"reason": "rtbf"})
        self._index_by_user.pop(user_id, None)
        self.consents.revoke_all(user_id)
        self.audit.append("forget_user", user_id=user_id, record_id=None, purpose=None, details={"deleted_count": deleted})
        return deleted

    def rotate_keys(self) -> int:
        new_ver = self.keys.rotate()
        self.audit.append("key_rotation", user_id=None, record_id=None, purpose=None, details={"new_version": new_ver})
        return new_ver

    # --------------------- Internals ---------------------

    def _minimize_and_redact(self, payload: Json, policy: PurposePolicy) -> Json:
        minimized: Json = {}
        # normalize some canonical fields
        if "email" in payload:
            contact_email = self.redactor.mask_email(str(payload["email"]))
            minimized["contact_email"] = contact_email
        if "phone" in payload:
            minimized["contact_phone_token"] = self.redactor.tokenize(str(payload["phone"]))
        if "name" in payload:
            minimized["name_masked"] = self.redactor.mask_name(str(payload["name"]))
        if "issue" in payload:
            # tokenize PII inside free text
            text = str(payload["issue"])
            kinds = self.detector.find_in_value(text)
            minimized["issue"] = self.redactor.tokenize(text) if kinds else text
        if "cohort_tag" in payload:
            # cohort tags must be non-PII, enforce whitelist-ish format
            tag = str(payload["cohort_tag"]).lower()
            if not re.fullmatch(r"[a-z0-9_\-]{2,32}", tag):
                tag = "invalid_tag"
            minimized["cohort_tag"] = tag
        if "user_id" in payload:
            uid = str(payload["user_id"])
            minimized["user_id"] = uid

        # keep only allowed fields for this purpose
        minimized = {k: v for k, v in minimized.items() if k in policy.allowed_fields}
        return minimized

    def _new_record_id(self) -> str:
        alphabet = string.ascii_lowercase + string.digits
        return "rec_" + "".join(secrets.choice(alphabet) for _ in range(20))


###############################################################################
# Pytest fixtures
###############################################################################


@pytest.fixture()
def veilmind() -> VeilMindCore:
    return VeilMindCore()


@pytest.fixture()
def sample_support_payload() -> Json:
    return {
        "user_id": "user_123",
        "name": "Alice",
        "email": "alice@example.com",
        "phone": "+1 415 555 2671",
        "issue": "I cannot login; my backup phone is +1-202-555-0199",
    }


@pytest.fixture()
def sample_marketing_payload() -> Json:
    return {
        "user_id": "user_123",
        "cohort_tag": "VIP_2025",
    }


###############################################################################
# E2E Tests
###############################################################################


def test_ingest_without_consent_redacts_and_minimizes(veilmind: VeilMindCore, sample_support_payload: Json) -> None:
    """
    Ingest support payload WITHOUT consent:
    - PII must be redacted/minimized
    - Stored fields limited to policy.allowed_fields
    - Audit trail appended and chain valid
    - No raw PII appears in storage
    """
    rid = veilmind.ingest(user_id="user_123", payload=sample_support_payload, purpose="support", require_consent=True)
    rec = veilmind._records[rid]
    stored = json.loads(veilmind.crypto.decrypt(rec.encrypted_blob).decode("utf-8"))

    # Only allowed fields persisted
    assert rec.fields_persisted.issubset(veilmind.policies["support"].allowed_fields)

    # PII redaction checks
    assert stored["contact_email"].endswith("@example.com") and stored["contact_email"].startswith("a***")
    assert stored["contact_phone_token"].startswith("tok_")
    # free-text issue contained a phone; should be tokenized
    assert stored["issue"].startswith("tok_")
    assert "name_masked" in stored and stored["name_masked"].startswith("A")

    # No raw email/phone/name in ciphertext (best-effort surface check)
    blob_bytes = _b64d(rec.encrypted_blob)
    assert b"alice@example.com" not in blob_bytes
    assert b"+1 415 555 2671" not in blob_bytes
    assert b"Alice" not in blob_bytes

    # Audit chain is valid and includes ingest event
    assert any(e.kind == "ingest" and e.record_id == rid for e in veilmind.audit.events)
    assert veilmind.audit.verify_chain() is True


def test_ingest_with_consent_still_minimized(veilmind: VeilMindCore, sample_support_payload: Json) -> None:
    """
    Ingest WITH consent:
    - Even with consent, only minimal allowed fields are stored
    - Support agent can retrieve a minimal view
    """
    veilmind.grant_consent("user_123", "support", terms_version="1.0")
    rid = veilmind.ingest(user_id="user_123", payload=sample_support_payload, purpose="support", require_consent=True)

    view = veilmind.retrieve(rid, role="support_agent")
    assert set(view.keys()).issubset(veilmind.policies["support"].role_view["support_agent"])
    assert view["purpose"] == "support"
    assert view["user_id"] == "user_123"
    # email must be masked, not raw
    assert view["contact_email"].startswith("a***")


def test_purpose_limitation_blocks_marketing_access(veilmind: VeilMindCore, sample_support_payload: Json) -> None:
    """
    Marketing analyst must NOT access support purpose data.
    """
    rid = veilmind.ingest(user_id="user_999", payload=sample_support_payload, purpose="support", require_consent=False)
    with pytest.raises(PermissionError):
        _ = veilmind.retrieve(rid, role="marketing_analyst")


def test_right_to_be_forgotten_erases_all_user_data(veilmind: VeilMindCore, sample_support_payload: Json) -> None:
    """
    After RTBF, all user's records are removed and consent revoked.
    """
    rid1 = veilmind.ingest(user_id="user_del", payload=sample_support_payload, purpose="support", require_consent=False)
    rid2 = veilmind.ingest(user_id="user_del", payload={"user_id": "user_del", "cohort_tag": "vip"}, purpose="marketing", require_consent=False)

    deleted = veilmind.forget_user("user_del")
    assert deleted == 2
    assert rid1 not in veilmind._records and rid2 not in veilmind._records
    # retrieval must fail
    with pytest.raises(KeyError):
        veilmind.retrieve(rid1, role="support_agent")
    # audit has tombstones and forget_user events
    kinds = [e.kind for e in veilmind.audit.events]
    assert "tombstone" in kinds and "forget_user" in kinds
    assert veilmind.audit.verify_chain() is True


def test_encryption_roundtrip_and_key_rotation(veilmind: VeilMindCore) -> None:
    """
    Validate encryption/decryption and key rotation behavior:
    - Existing records remain decryptable after rotation
    - New records use a new key version
    """
    rid_old = veilmind.ingest(
        user_id="user_rot",
        payload={"user_id": "user_rot", "issue": "old key path"},
        purpose="support",
        require_consent=False,
    )
    old_ver = veilmind._records[rid_old].key_version

    new_ver = veilmind.rotate_keys()
    assert new_ver > old_ver

    rid_new = veilmind.ingest(
        user_id="user_rot",
        payload={"user_id": "user_rot", "issue": "new key path"},
        purpose="support",
        require_consent=False,
    )
    assert veilmind._records[rid_new].key_version == new_ver

    # Both records must be readable by support agent
    v_old = veilmind.retrieve(rid_old, role="support_agent")
    v_new = veilmind.retrieve(rid_new, role="support_agent")
    assert v_old["issue"].startswith("tok_")  # still minimized
    assert v_new["issue"].startswith("tok_")
    assert veilmind.audit.verify_chain() is True


def test_audit_log_tamper_detection(veilmind: VeilMindCore, sample_marketing_payload: Json) -> None:
    """
    Tamper-evident audit: if an event is modified, verify_chain() must detect it.
    """
    rid = veilmind.ingest(user_id="user_tx", payload=sample_marketing_payload, purpose="marketing", require_consent=False)
    assert veilmind.retrieve(rid, role="marketing_analyst")["purpose"] == "marketing"
    assert veilmind.audit.verify_chain() is True

    # Tamper with an event details
    ev = veilmind.audit.events[0]
    ev.details["tamper"] = "x"  # corrupt
    assert veilmind.audit.verify_chain() is False
