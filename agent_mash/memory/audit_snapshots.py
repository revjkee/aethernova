# agent_mash/memory/audit_snapshots.py
from __future__ import annotations

import dataclasses
import gzip
import hashlib
import hmac
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, Union


JsonDict = Dict[str, Any]
JsonLike = Union[JsonDict, List[Any], str, int, float, bool, None]


class AuditSnapshotError(RuntimeError):
    pass


class PayloadInvalid(AuditSnapshotError):
    pass


class IntegrityError(AuditSnapshotError):
    pass


class StorageError(AuditSnapshotError):
    pass


def _now_ms() -> int:
    return int(time.time() * 1000)


def _stable_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError as e:
        raise PayloadInvalid(f"Not JSON-serializable: {e}") from e


def _blake2b_hex(data: bytes, digest_size: int = 32) -> str:
    h_ = hashlib.blake2b(digest_size=digest_size)
    h_.update(data)
    return h_.hexdigest()


def _hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


_REDACT_KEY_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"pass(word)?", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"cookie", re.IGNORECASE),
    re.compile(r"session", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"iban", re.IGNORECASE),
    re.compile(r"pan", re.IGNORECASE),
    re.compile(r"card", re.IGNORECASE),
    re.compile(r"cvv", re.IGNORECASE),
    re.compile(r"ssn", re.IGNORECASE),
    re.compile(r"passport", re.IGNORECASE),
    re.compile(r"inn", re.IGNORECASE),
)


def redact(
    obj: Any,
    *,
    redaction: str = "[REDACTED]",
    key_patterns: Sequence[re.Pattern[str]] = _REDACT_KEY_PATTERNS,
    max_depth: int = 12,
    max_list: int = 512,
) -> JsonLike:
    def _should_redact(k: str) -> bool:
        for p in key_patterns:
            if p.search(k):
                return True
        return False

    def _walk(v: Any, depth: int) -> JsonLike:
        if depth <= 0:
            return "[TRUNCATED]"
        if isinstance(v, Mapping):
            out: Dict[str, JsonLike] = {}
            for kk, vv in v.items():
                k = str(kk)
                out[k] = redaction if _should_redact(k) else _walk(vv, depth - 1)
            return out
        if isinstance(v, (list, tuple)):
            out_list: List[JsonLike] = []
            for i, item in enumerate(v):
                if i >= max_list:
                    out_list.append("[TRUNCATED_LIST]")
                    break
                out_list.append(_walk(item, depth - 1))
            return out_list
        if isinstance(v, (str, int, float, bool)) or v is None:
            return v
        return str(v)

    return _walk(obj, max_depth)


def _merkle_root_hex(leaves: Sequence[str]) -> str:
    if not leaves:
        return _blake2b_hex(b"", digest_size=32)

    level = [bytes.fromhex(x) for x in leaves]
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.blake2b(left + right, digest_size=32).digest())
        level = nxt
    return level[0].hex()


@dataclasses.dataclass(frozen=True)
class SnapshotMeta:
    snapshot_id: str
    created_at_ms: int
    tenant_id: Optional[str]
    actor_id: Optional[str]
    category: str
    subject_id: str
    prev_hash: Optional[str]
    merkle_root: str
    payload_hash: str
    signature: Optional[str]
    policy_version: str


@dataclasses.dataclass(frozen=True)
class AuditSnapshot:
    meta: SnapshotMeta
    payload: Mapping[str, JsonLike]
    redacted: Mapping[str, JsonLike]

    def to_dict(self) -> JsonDict:
        return {
            "meta": dataclasses.asdict(self.meta),
            "payload": dict(self.payload),
            "redacted": dict(self.redacted),
        }


class SnapshotStore(Protocol):
    def put(self, snapshot: AuditSnapshot) -> None:
        ...

    def get(self, snapshot_id: str) -> Optional[AuditSnapshot]:
        ...

    def list_ids(self, *, category: Optional[str] = None, subject_id: Optional[str] = None) -> Sequence[str]:
        ...


class InMemorySnapshotStore:
    def __init__(self) -> None:
        self._data: Dict[str, AuditSnapshot] = {}

    def put(self, snapshot: AuditSnapshot) -> None:
        self._data[snapshot.meta.snapshot_id] = snapshot

    def get(self, snapshot_id: str) -> Optional[AuditSnapshot]:
        return self._data.get(snapshot_id)

    def list_ids(self, *, category: Optional[str] = None, subject_id: Optional[str] = None) -> Sequence[str]:
        out: List[str] = []
        for sid, snap in self._data.items():
            if category and snap.meta.category != category:
                continue
            if subject_id and snap.meta.subject_id != subject_id:
                continue
            out.append(sid)
        out.sort()
        return out


class FileSnapshotStore:
    def __init__(self, base_dir: Path) -> None:
        self._base = base_dir
        self._base.mkdir(parents=True, exist_ok=True)

    def _path_for(self, snapshot_id: str) -> Path:
        # shard by prefix to avoid large dirs
        pfx = snapshot_id[:2]
        d = self._base / pfx
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{snapshot_id}.json.gz"

    def put(self, snapshot: AuditSnapshot) -> None:
        path = self._path_for(snapshot.meta.snapshot_id)
        raw = _stable_json(snapshot.to_dict()).encode("utf-8")
        try:
            with gzip.open(path, "wb", compresslevel=6) as f:
                f.write(raw)
        except Exception as e:
            raise StorageError(str(e)) from e

    def get(self, snapshot_id: str) -> Optional[AuditSnapshot]:
        path = self._path_for(snapshot_id)
        if not path.exists():
            return None
        try:
            with gzip.open(path, "rb") as f:
                raw = f.read()
            obj = json.loads(raw.decode("utf-8"))
            meta = SnapshotMeta(**obj["meta"])
            payload = obj["payload"]
            redacted = obj["redacted"]
            return AuditSnapshot(meta=meta, payload=payload, redacted=redacted)
        except Exception as e:
            raise StorageError(str(e)) from e

    def list_ids(self, *, category: Optional[str] = None, subject_id: Optional[str] = None) -> Sequence[str]:
        out: List[str] = []
        try:
            for p in self._base.rglob("*.json.gz"):
                sid = p.name.replace(".json.gz", "")
                out.append(sid)
        except Exception as e:
            raise StorageError(str(e)) from e

        if category is None and subject_id is None:
            out.sort()
            return out

        filtered: List[str] = []
        for sid in out:
            snap = self.get(sid)
            if snap is None:
                continue
            if category and snap.meta.category != category:
                continue
            if subject_id and snap.meta.subject_id != subject_id:
                continue
            filtered.append(sid)
        filtered.sort()
        return filtered


@dataclasses.dataclass(frozen=True)
class SnapshotPolicy:
    policy_version: str = "audit-snapshots-v1"
    signature_hmac_key: Optional[bytes] = None
    max_payload_bytes: int = 2_000_000
    max_depth: int = 12
    max_list: int = 512


def _size_guard(payload: Mapping[str, Any], *, max_bytes: int) -> None:
    raw = _stable_json(payload).encode("utf-8")
    if len(raw) > max_bytes:
        raise PayloadInvalid(f"payload too large: {len(raw)} > {max_bytes}")


def _payload_hash(payload: Mapping[str, Any]) -> str:
    return _blake2b_hex(_stable_json(payload).encode("utf-8"), digest_size=32)


def _snapshot_id(meta: Mapping[str, Any]) -> str:
    raw = _stable_json(meta).encode("utf-8")
    return _blake2b_hex(raw, digest_size=16)


def _sign(policy: SnapshotPolicy, meta: SnapshotMeta) -> Optional[str]:
    if not policy.signature_hmac_key:
        return None
    msg = _stable_json(dataclasses.asdict(meta)).encode("utf-8")
    return _hmac_sha256_hex(policy.signature_hmac_key, msg)


class AuditSnapshotManager:
    def __init__(
        self,
        *,
        store: SnapshotStore,
        policy: SnapshotPolicy,
    ) -> None:
        if not policy.policy_version:
            raise PayloadInvalid("policy_version must be non-empty")
        self._store = store
        self._policy = policy

    def create_snapshot(
        self,
        *,
        category: str,
        subject_id: str,
        payload: Mapping[str, JsonLike],
        tenant_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        prev_hash: Optional[str] = None,
        created_at_ms: Optional[int] = None,
    ) -> AuditSnapshot:
        if not category or not subject_id:
            raise PayloadInvalid("category and subject_id are required")

        created = created_at_ms or _now_ms()

        _size_guard(payload, max_bytes=self._policy.max_payload_bytes)

        red = redact(payload, max_depth=self._policy.max_depth, max_list=self._policy.max_list)
        if not isinstance(red, Mapping):
            raise PayloadInvalid("payload must be a mapping/dict")

        # Merkle over stable leaf hashes of top-level keys for tamper evidence
        leaves: List[str] = []
        for k in sorted(payload.keys()):
            leaf = {"k": k, "v": payload.get(k)}
            leaves.append(_blake2b_hex(_stable_json(leaf).encode("utf-8"), digest_size=32))
        merkle = _merkle_root_hex(leaves)

        ph = _payload_hash(payload)

        meta_base = {
            "created_at_ms": created,
            "tenant_id": tenant_id,
            "actor_id": actor_id,
            "category": category,
            "subject_id": subject_id,
            "prev_hash": prev_hash,
            "merkle_root": merkle,
            "payload_hash": ph,
            "policy_version": self._policy.policy_version,
        }
        sid = _snapshot_id(meta_base)

        meta = SnapshotMeta(
            snapshot_id=sid,
            created_at_ms=created,
            tenant_id=tenant_id,
            actor_id=actor_id,
            category=category,
            subject_id=subject_id,
            prev_hash=prev_hash,
            merkle_root=merkle,
            payload_hash=ph,
            signature=None,
            policy_version=self._policy.policy_version,
        )
        sig = _sign(self._policy, meta)
        meta2 = dataclasses.replace(meta, signature=sig)

        snapshot = AuditSnapshot(meta=meta2, payload=dict(payload), redacted=dict(red))
        self._store.put(snapshot)
        return snapshot

    def verify_snapshot(self, snapshot: AuditSnapshot) -> None:
        # verify payload hash
        ph = _payload_hash(snapshot.payload)
        if ph != snapshot.meta.payload_hash:
            raise IntegrityError("payload hash mismatch")

        leaves: List[str] = []
        for k in sorted(snapshot.payload.keys()):
            leaf = {"k": k, "v": snapshot.payload.get(k)}
            leaves.append(_blake2b_hex(_stable_json(leaf).encode("utf-8"), digest_size=32))
        merkle = _merkle_root_hex(leaves)
        if merkle != snapshot.meta.merkle_root:
            raise IntegrityError("merkle root mismatch")

        if self._policy.signature_hmac_key:
            expected = _sign(self._policy, dataclasses.replace(snapshot.meta, signature=None))
            # meta.signature stores signature over meta without signature field
            if snapshot.meta.signature != expected:
                raise IntegrityError("signature mismatch")

    def get(self, snapshot_id: str) -> Optional[AuditSnapshot]:
        snap = self._store.get(snapshot_id)
        if snap is None:
            return None
        return snap

    def list_ids(self, *, category: Optional[str] = None, subject_id: Optional[str] = None) -> Sequence[str]:
        return self._store.list_ids(category=category, subject_id=subject_id)

    def export_json(self, snapshot_id: str) -> str:
        snap = self.get(snapshot_id)
        if snap is None:
            raise StorageError("snapshot not found")
        return _stable_json(snap.to_dict())
