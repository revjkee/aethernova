# cybersecurity-core/cybersecurity/crypto/kms.py
"""
Industrial-grade KMS module for cybersecurity-core.

Features:
- Key types: AES-256-GCM, CHACHA20-POLY1305, ED25519, ECDSA-P256, RSA-3072/4096
- Key lifecycle: Enabled, Disabled, PendingDeletion (with scheduled_at)
- Key versions: rotation, primary version, per-version state
- Allowed operations per key (encrypt/decrypt, wrap/unwrap, sign/verify)
- Envelope encryption:
    * generate_data_key (returns plaintext DEK + wrapped DEK)
    * encrypt_envelope / decrypt_envelope (AEAD: AES-GCM or ChaCha20-Poly1305)
- Key wrapping:
    * Symmetric KEK -> AEAD wrap
    * Asymmetric KEK (RSA) -> RSA-OAEP(SHA-256)
- Signatures:
    * Ed25519, ECDSA-P256(SHA-256), RSA-PSS(SHA-256)
- Storage:
    * Abstract Storage
    * InMemoryStorage
    * FilesystemStorage: encrypted-at-rest via PBKDF2-HMAC-SHA256 + AES-GCM
      (atomic write, integrity via AEAD)
- Audit events stream (callback or in-memory ring)
- Thread-safety via RLock
- Full typing; stdlib + cryptography only

NOTE:
- This is a KMS library; network/HSM integrations can be added via new Storage backends.
- Ensure secure management of the FilesystemStorage passphrase out-of-band.

License: MIT (or project default)
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum, Flag, auto
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# cryptography primitives
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import (
    ed25519,
    ec,
    rsa,
    padding,
)
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend

# ---------------------------
# Helpers
# ---------------------------

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)

def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)

def _rand_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)

def _atomic_write_bytes(path: Path, data: bytes) -> None:
    tmp = Path(tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_", suffix=".bin")[1])
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if tmp.exists():
                tmp.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass

# ---------------------------
# Domain model
# ---------------------------

class KeyAlgorithm(str, Enum):
    AES256_GCM = "AES256_GCM"
    CHACHA20_POLY1305 = "CHACHA20_POLY1305"
    ED25519 = "ED25519"
    ECDSA_P256 = "ECDSA_P256"
    RSA_3072 = "RSA_3072"
    RSA_4096 = "RSA_4096"

class KeyOp(Flag):
    ENCRYPT = auto()
    DECRYPT = auto()
    WRAP = auto()
    UNWRAP = auto()
    SIGN = auto()
    VERIFY = auto()

ALG_OPS: Mapping[KeyAlgorithm, KeyOp] = {
    KeyAlgorithm.AES256_GCM: KeyOp.ENCRYPT | KeyOp.DECRYPT | KeyOp.WRAP | KeyOp.UNWRAP,
    KeyAlgorithm.CHACHA20_POLY1305: KeyOp.ENCRYPT | KeyOp.DECRYPT | KeyOp.WRAP | KeyOp.UNWRAP,
    KeyAlgorithm.ED25519: KeyOp.SIGN | KeyOp.VERIFY,
    KeyAlgorithm.ECDSA_P256: KeyOp.SIGN | KeyOp.VERIFY,
    KeyAlgorithm.RSA_3072: KeyOp.SIGN | KeyOp.VERIFY | KeyOp.WRAP | KeyOp.UNWRAP,
    KeyAlgorithm.RSA_4096: KeyOp.SIGN | KeyOp.VERIFY | KeyOp.WRAP | KeyOp.UNWRAP,
}

class VersionState(str, Enum):
    ENABLED = "Enabled"
    DISABLED = "Disabled"
    PENDING_DELETION = "PendingDeletion"

@dataclass
class KeyVersion:
    version_id: int
    created_at: datetime
    state: VersionState
    algorithm: KeyAlgorithm
    # Materials are serialized; internal use only
    private_material_b64: Optional[str] = None  # for symmetric keys, the raw key; for asymmetric, private PEM
    public_material_b64: Optional[str] = None   # for asymmetric public PEM (if applicable)
    # Optional metadata (e.g., kid/kcv)
    meta: Mapping[str, Any] = field(default_factory=dict)

@dataclass
class KeyRecord:
    key_id: str
    name: str
    description: str = ""
    created_at: datetime = field(default_factory=_now_utc)
    primary_version: int = 1
    rotation_period: Optional[timedelta] = None
    pending_deletion_at: Optional[datetime] = None
    versions: Tuple[KeyVersion, ...] = field(default_factory=tuple)
    # allowed operations at key-level (further limited by alg)
    allowed_ops: KeyOp = KeyOp.ENCRYPT | KeyOp.DECRYPT | KeyOp.WRAP | KeyOp.UNWRAP | KeyOp.SIGN | KeyOp.VERIFY
    tags: Mapping[str, str] = field(default_factory=dict)

# ---------------------------
# Exceptions
# ---------------------------

class KMSError(Exception):
    pass

class NotFound(KMSError):
    pass

class Forbidden(KMSError):
    pass

class InvalidState(KMSError):
    pass

class InvalidArgument(KMSError):
    pass

# ---------------------------
# Audit
# ---------------------------

@dataclass
class AuditEvent:
    at: datetime
    actor: Optional[str]
    action: str
    key_id: Optional[str] = None
    version_id: Optional[int] = None
    success: bool = True
    message: Optional[str] = None
    meta: Mapping[str, Any] = field(default_factory=dict)

AuditSink = Callable[[AuditEvent], None]

class InMemoryAuditSink:
    def __init__(self, capacity: int = 1000) -> None:
        self.capacity = max(10, capacity)
        self._events: List[AuditEvent] = []
        self._lock = RLock()

    def __call__(self, ev: AuditEvent) -> None:
        with self._lock:
            self._events.append(ev)
            if len(self._events) > self.capacity:
                self._events = self._events[-self.capacity :]

    def list(self) -> Tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._events)

# ---------------------------
# Storage abstraction
# ---------------------------

class Storage:
    def save(self, rec: KeyRecord) -> None:
        raise NotImplementedError

    def load(self, key_id: str) -> KeyRecord:
        raise NotImplementedError

    def delete(self, key_id: str) -> None:
        raise NotImplementedError

    def list_ids(self) -> Tuple[str, ...]:
        raise NotImplementedError

class InMemoryStorage(Storage):
    def __init__(self) -> None:
        self._data: Dict[str, KeyRecord] = {}
        self._lock = RLock()

    def save(self, rec: KeyRecord) -> None:
        with self._lock:
            self._data[rec.key_id] = rec

    def load(self, key_id: str) -> KeyRecord:
        with self._lock:
            if key_id not in self._data:
                raise NotFound(f"Key {key_id} not found")
            return self._data[key_id]

    def delete(self, key_id: str) -> None:
        with self._lock:
            self._data.pop(key_id, None)

    def list_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._data.keys())

# Filesystem storage with AEAD-at-rest
class FilesystemStorage(Storage):
    """
    Stores each KeyRecord as a single encrypted JSON file:
    {
      "v": 1,
      "salt": <b64>,
      "nonce": <b64>,
      "ciphertext": <b64>
    }
    DEK for storage is derived from passphrase via PBKDF2-HMAC-SHA256.
    """
    def __init__(self, root: Union[str, Path], passphrase: bytes, iterations: int = 200_000) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.passphrase = passphrase
        self.iterations = max(50_000, iterations)

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=self.iterations, backend=default_backend())
        return kdf.derive(self.passphrase)

    def _enc(self, payload: bytes) -> bytes:
        salt = _rand_bytes(16)
        key = self._derive_key(salt)
        nonce = _rand_bytes(12)
        aead = AESGCM(key)
        ct = aead.encrypt(nonce, payload, b"kmstore-v1")
        obj = {"v": 1, "salt": _b64e(salt), "nonce": _b64e(nonce), "ciphertext": _b64e(ct)}
        return json.dumps(obj, separators=(",", ":")).encode("utf-8")

    def _dec(self, blob: bytes) -> bytes:
        obj = json.loads(blob.decode("utf-8"))
        if obj.get("v") != 1:
            raise KMSError("Unsupported storage version")
        salt = _b64d(obj["salt"])
        nonce = _b64d(obj["nonce"])
        ct = _b64d(obj["ciphertext"])
        key = self._derive_key(salt)
        aead = AESGCM(key)
        return aead.decrypt(nonce, ct, b"kmstore-v1")

    def _path(self, key_id: str) -> Path:
        return self.root / f"{key_id}.kms.json"

    def save(self, rec: KeyRecord) -> None:
        data = json.dumps(_serialize_key_record(rec), default=_json_dt, separators=(",", ":")).encode("utf-8")
        blob = self._enc(data)
        _atomic_write_bytes(self._path(rec.key_id), blob)

    def load(self, key_id: str) -> KeyRecord:
        p = self._path(key_id)
        if not p.exists():
            raise NotFound(f"Key {key_id} not found")
        blob = p.read_bytes()
        data = self._dec(blob)
        obj = json.loads(data.decode("utf-8"))
        return _deserialize_key_record(obj)

    def delete(self, key_id: str) -> None:
        try:
            self._path(key_id).unlink()
        except FileNotFoundError:
            pass

    def list_ids(self) -> Tuple[str, ...]:
        return tuple(sorted([f.stem.replace(".kms", "") for f in self.root.glob("*.kms.json")]))

# ---------------------------
# Serialization helpers
# ---------------------------

def _json_dt(o: Any) -> Any:
    if isinstance(o, datetime):
        return {"__dt__": True, "v": o.isoformat()}
    raise TypeError("Unsupported type")

def _json_dt_load(obj: Any) -> Any:
    if isinstance(obj, dict) and obj.get("__dt__") is True:
        return datetime.fromisoformat(obj["v"])
    return obj

def _serialize_key_record(rec: KeyRecord) -> Mapping[str, Any]:
    return {
        "key_id": rec.key_id,
        "name": rec.name,
        "description": rec.description,
        "created_at": _json_dt(rec.created_at),
        "primary_version": rec.primary_version,
        "rotation_period": int(rec.rotation_period.total_seconds()) if rec.rotation_period else None,
        "pending_deletion_at": _json_dt(rec.pending_deletion_at) if rec.pending_deletion_at else None,
        "allowed_ops": int(rec.allowed_ops.value),
        "tags": dict(rec.tags),
        "versions": [
            {
                "version_id": v.version_id,
                "created_at": _json_dt(v.created_at),
                "state": v.state.value,
                "algorithm": v.algorithm.value,
                "private_material_b64": v.private_material_b64,
                "public_material_b64": v.public_material_b64,
                "meta": dict(v.meta),
            }
            for v in rec.versions
        ],
    }

def _deserialize_key_record(obj: Mapping[str, Any]) -> KeyRecord:
    versions = []
    for v in obj["versions"]:
        versions.append(
            KeyVersion(
                version_id=int(v["version_id"]),
                created_at=_json_dt_load(v["created_at"]),
                state=VersionState(v["state"]),
                algorithm=KeyAlgorithm(v["algorithm"]),
                private_material_b64=v.get("private_material_b64"),
                public_material_b64=v.get("public_material_b64"),
                meta=v.get("meta", {}),
            )
        )
    rp = obj.get("rotation_period")
    return KeyRecord(
        key_id=str(obj["key_id"]),
        name=str(obj["name"]),
        description=str(obj.get("description", "")),
        created_at=_json_dt_load(obj["created_at"]),
        primary_version=int(obj["primary_version"]),
        rotation_period=timedelta(seconds=int(rp)) if rp is not None else None,
        pending_deletion_at=_json_dt_load(obj["pending_deletion_at"]) if obj.get("pending_deletion_at") else None,
        allowed_ops=KeyOp(int(obj["allowed_ops"])),
        tags=obj.get("tags", {}),
        versions=tuple(versions),
    )

# ---------------------------
# KMS core
# ---------------------------

class KMS:
    def __init__(self, storage: Storage, audit: Optional[AuditSink] = None) -> None:
        self.storage = storage
        self.audit = audit or InMemoryAuditSink()
        self._lock = RLock()

    # ----- Key management -----

    def create_key(
        self,
        *,
        key_id: str,
        name: str,
        algorithm: KeyAlgorithm,
        description: str = "",
        rotation_period: Optional[timedelta] = None,
        allowed_ops: Optional[KeyOp] = None,
        tags: Optional[Mapping[str, str]] = None,
    ) -> KeyRecord:
        with self._lock:
            try:
                _ = self.storage.load(key_id)
                raise InvalidArgument(f"Key {key_id} already exists")
            except NotFound:
                pass

            v1 = self._generate_version(algorithm=algorithm, version_id=1)
            rec = KeyRecord(
                key_id=key_id,
                name=name,
                description=description,
                created_at=_now_utc(),
                primary_version=1,
                rotation_period=rotation_period,
                versions=(v1,),
                allowed_ops=allowed_ops if allowed_ops is not None else ALG_OPS[algorithm],
                tags=tags or {},
            )
            self.storage.save(rec)
            self._audit(actor=None, action="create_key", key_id=key_id, version_id=1)
            return rec

    def rotate_key(self, key_id: str) -> KeyRecord:
        with self._lock:
            rec = self.storage.load(key_id)
            new_vid = max(v.version_id for v in rec.versions) + 1
            new_v = self._generate_version(algorithm=rec.versions[0].algorithm, version_id=new_vid)
            versions = list(rec.versions)
            versions.append(new_v)
            rec = KeyRecord(
                **{**asdict(rec), "versions": tuple(versions), "primary_version": new_vid}  # type: ignore[arg-type]
            )
            rec = _restore_keyrecord_from_asdict(rec)
            self.storage.save(rec)
            self._audit(actor=None, action="rotate_key", key_id=key_id, version_id=new_vid)
            return rec

    def disable_version(self, key_id: str, version_id: int) -> KeyRecord:
        return self._set_version_state(key_id, version_id, VersionState.DISABLED, "disable_version")

    def enable_version(self, key_id: str, version_id: int) -> KeyRecord:
        return self._set_version_state(key_id, version_id, VersionState.ENABLED, "enable_version")

    def schedule_key_deletion(self, key_id: str, days: int = 30) -> KeyRecord:
        if days < 7:
            raise InvalidArgument("Minimal deletion window is 7 days")
        with self._lock:
            rec = self.storage.load(key_id)
            rec.pending_deletion_at = _now_utc() + timedelta(days=days)
            self.storage.save(rec)
            self._audit(None, "schedule_key_deletion", key_id=key_id)
            return rec

    def cancel_key_deletion(self, key_id: str) -> KeyRecord:
        with self._lock:
            rec = self.storage.load(key_id)
            rec.pending_deletion_at = None
            self.storage.save(rec)
            self._audit(None, "cancel_key_deletion", key_id=key_id)
            return rec

    def delete_key_if_due(self, key_id: str) -> bool:
        with self._lock:
            rec = self.storage.load(key_id)
            if rec.pending_deletion_at and rec.pending_deletion_at <= _now_utc():
                self.storage.delete(key_id)
                self._audit(None, "delete_key", key_id=key_id)
                return True
            return False

    def list_keys(self) -> Tuple[str, ...]:
        return self.storage.list_ids()

    def get_metadata(self, key_id: str) -> KeyRecord:
        rec = self.storage.load(key_id)
        # Materials are not removed here; caller should not expose them externally.
        return rec

    # ----- Envelope encryption -----

    def generate_data_key(
        self,
        *,
        key_id: str,
        aad: Optional[bytes] = None,
        dek_length: int = 32,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Returns (plaintext_dek, wrapped_info) where wrapped_info contains:
            {
              "key_id": ...,
              "version_id": ...,
              "algorithm": ...,
              "wrapped_dek_b64": ...,
              "method": "AEAD" | "RSA-OAEP",
              "nonce_b64": "...",  # for AEAD
              "aad_b64": "...",
            }
        """
        with self._lock:
            rec = self.storage.load(key_id)
            v = _require_primary_version(rec)
            _assert_op_allowed(rec, KeyOp.WRAP)
            dek = _rand_bytes(max(16, dek_length))

            if v.algorithm in (KeyAlgorithm.AES256_GCM, KeyAlgorithm.CHACHA20_POLY1305):
                aead, nonce = _aead_for_version(v)
                ct = aead.encrypt(nonce, dek, aad)
                wrapped = {
                    "key_id": key_id,
                    "version_id": v.version_id,
                    "algorithm": v.algorithm.value,
                    "method": "AEAD",
                    "nonce_b64": _b64e(nonce),
                    "wrapped_dek_b64": _b64e(ct),
                    "aad_b64": _b64e(aad or b""),
                }
            elif v.algorithm in (KeyAlgorithm.RSA_3072, KeyAlgorithm.RSA_4096):
                pk = _load_public_key_from_version(v)
                ct = pk.encrypt(
                    dek,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=aad),
                )
                wrapped = {
                    "key_id": key_id,
                    "version_id": v.version_id,
                    "algorithm": v.algorithm.value,
                    "method": "RSA-OAEP",
                    "wrapped_dek_b64": _b64e(ct),
                    "aad_b64": _b64e(aad or b""),
                }
            else:
                raise InvalidArgument("Key algorithm does not support wrap/unwrap")
            self._audit(None, "generate_data_key", key_id=key_id, version_id=v.version_id)
            return dek, wrapped

    def decrypt_data_key(self, *, wrapped_info: Mapping[str, Any]) -> bytes:
        key_id = str(wrapped_info["key_id"])
        version_id = int(wrapped_info["version_id"])
        method = str(wrapped_info["method"])
        with self._lock:
            rec = self.storage.load(key_id)
            v = _require_version(rec, version_id)
            _assert_op_allowed(rec, KeyOp.UNWRAP)
            if v.state != VersionState.ENABLED:
                raise InvalidState("Key version is not enabled")

            aad = _b64d(wrapped_info.get("aad_b64", "")) if wrapped_info.get("aad_b64") else None
            if method == "AEAD":
                nonce = _b64d(wrapped_info["nonce_b64"])
                ct = _b64d(wrapped_info["wrapped_dek_b64"])
                aead, _ = _aead_for_version(v)
                dek = aead.decrypt(nonce, ct, aad)
            elif method == "RSA-OAEP":
                sk = _load_private_key_from_version(v)
                ct = _b64d(wrapped_info["wrapped_dek_b64"])
                dek = sk.decrypt(
                    ct,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=aad),
                )
            else:
                raise InvalidArgument("Unknown wrap method")
            self._audit(None, "decrypt_data_key", key_id=key_id, version_id=v.version_id)
            return dek

    def encrypt_envelope(
        self,
        *,
        key_id: str,
        plaintext: bytes,
        aad: Optional[bytes] = None,
        data_cipher: KeyAlgorithm = KeyAlgorithm.AES256_GCM,
    ) -> Mapping[str, Any]:
        """
        Encrypts data using a one-time DEK (data_cipher), wrapped with KEK (key_id).
        Returns an envelope dict containing all parameters for decryption.
        """
        if data_cipher not in (KeyAlgorithm.AES256_GCM, KeyAlgorithm.CHACHA20_POLY1305):
            raise InvalidArgument("data_cipher must be AEAD algorithm")
        dek_len = 32 if data_cipher == KeyAlgorithm.AES256_GCM else 32
        dek, wrapped = self.generate_data_key(key_id=key_id, aad=aad, dek_length=dek_len)
        nonce = _rand_bytes(12)
        if data_cipher == KeyAlgorithm.AES256_GCM:
            aead = AESGCM(dek)
        else:
            aead = ChaCha20Poly1305(dek)
        ct = aead.encrypt(nonce, plaintext, aad)
        env = {
            "kek": wrapped,
            "data": {
                "cipher": data_cipher.value,
                "nonce_b64": _b64e(nonce),
                "ciphertext_b64": _b64e(ct),
                "aad_b64": _b64e(aad or b""),
            },
        }
        self._audit(None, "encrypt_envelope", key_id=key_id, version_id=wrapped["version_id"])
        return env

    def decrypt_envelope(self, *, envelope: Mapping[str, Any]) -> bytes:
        wrapped = envelope["kek"]
        data = envelope["data"]
        dek = self.decrypt_data_key(wrapped_info=wrapped)
        cipher_alg = KeyAlgorithm(data["cipher"])
        nonce = _b64d(data["nonce_b64"])
        ct = _b64d(data["ciphertext_b64"])
        aad = _b64d(data.get("aad_b64", "")) if data.get("aad_b64") else None
        if cipher_alg == KeyAlgorithm.AES256_GCM:
            aead = AESGCM(dek)
        elif cipher_alg == KeyAlgorithm.CHACHA20_POLY1305:
            aead = ChaCha20Poly1305(dek)
        else:
            raise InvalidArgument("Unsupported data cipher in envelope")
        pt = aead.decrypt(nonce, ct, aad)
        self._audit(None, "decrypt_envelope", key_id=str(wrapped["key_id"]), version_id=int(wrapped["version_id"]))
        return pt

    # ----- Signatures -----

    def sign(self, *, key_id: str, data: bytes) -> Dict[str, Any]:
        with self._lock:
            rec = self.storage.load(key_id)
            v = _require_primary_version(rec)
            _assert_op_allowed(rec, KeyOp.SIGN)
            sig: bytes
            alg = v.algorithm
            if alg == KeyAlgorithm.ED25519:
                sk = _load_private_key_from_version(v)
                assert isinstance(sk, ed25519.Ed25519PrivateKey)
                sig = sk.sign(data)
                method = "ED25519"
            elif alg == KeyAlgorithm.ECDSA_P256:
                sk = _load_private_key_from_version(v)
                assert isinstance(sk, ec.EllipticCurvePrivateKey)
                sig = sk.sign(data, ec.ECDSA(hashes.SHA256()))
                method = "ECDSA-P256-SHA256"
            elif alg in (KeyAlgorithm.RSA_3072, KeyAlgorithm.RSA_4096):
                sk = _load_private_key_from_version(v)
                assert isinstance(sk, rsa.RSAPrivateKey)
                sig = sk.sign(
                    data,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256(),
                )
                method = "RSA-PSS-SHA256"
            else:
                raise InvalidArgument("Key algorithm does not support signing")
            self._audit(None, "sign", key_id=key_id, version_id=v.version_id)
            return {"key_id": key_id, "version_id": v.version_id, "algorithm": alg.value, "method": method, "signature_b64": _b64e(sig)}

    def verify(self, *, key_id: str, version_id: Optional[int], data: bytes, signature_b64: str) -> bool:
        with self._lock:
            rec = self.storage.load(key_id)
            v = _require_version(rec, version_id or rec.primary_version)
            _assert_op_allowed(rec, KeyOp.VERIFY)
            sig = _b64d(signature_b64)
            ok = False
            try:
                if v.algorithm == KeyAlgorithm.ED25519:
                    pk = _load_public_key_from_version(v)
                    assert isinstance(pk, ed25519.Ed25519PublicKey)
                    pk.verify(sig, data)
                    ok = True
                elif v.algorithm == KeyAlgorithm.ECDSA_P256:
                    pk = _load_public_key_from_version(v)
                    assert isinstance(pk, ec.EllipticCurvePublicKey)
                    pk.verify(sig, data, ec.ECDSA(hashes.SHA256()))
                    ok = True
                elif v.algorithm in (KeyAlgorithm.RSA_3072, KeyAlgorithm.RSA_4096):
                    pk = _load_public_key_from_version(v)
                    assert isinstance(pk, rsa.RSAPublicKey)
                    pk.verify(
                        sig,
                        data,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256(),
                    )
                    ok = True
                else:
                    raise InvalidArgument("Key algorithm does not support verification")
            except Exception:
                ok = False
            self._audit(None, "verify", key_id=key_id, version_id=v.version_id, meta={"ok": ok})
            return ok

    # ----- Internals -----

    def _set_version_state(self, key_id: str, version_id: int, st: VersionState, audit_action: str) -> KeyRecord:
        with self._lock:
            rec = self.storage.load(key_id)
            versions = []
            found = False
            for v in rec.versions:
                if v.version_id == version_id:
                    versions.append(KeyVersion(**{**asdict(v), "state": st}))  # type: ignore[arg-type]
                    found = True
                else:
                    versions.append(v)
            if not found:
                raise NotFound(f"Version {version_id} not found for key {key_id}")
            rec = KeyRecord(**{**asdict(rec), "versions": tuple(versions)})  # type: ignore[arg-type]
            rec = _restore_keyrecord_from_asdict(rec)
            self.storage.save(rec)
            self._audit(None, audit_action, key_id=key_id, version_id=version_id)
            return rec

    def _generate_version(self, *, algorithm: KeyAlgorithm, version_id: int) -> KeyVersion:
        created = _now_utc()
        if algorithm == KeyAlgorithm.AES256_GCM:
            key = _rand_bytes(32)
            return KeyVersion(version_id=version_id, created_at=created, state=VersionState.ENABLED,
                              algorithm=algorithm, private_material_b64=_b64e(key), meta={"kcv": _kcv_sha256(key)})
        if algorithm == KeyAlgorithm.CHACHA20_POLY1305:
            key = _rand_bytes(32)
            return KeyVersion(version_id=version_id, created_at=created, state=VersionState.ENABLED,
                              algorithm=algorithm, private_material_b64=_b64e(key), meta={"kcv": _kcv_sha256(key)})
        if algorithm == KeyAlgorithm.ED25519:
            sk = ed25519.Ed25519PrivateKey.generate()
            return _make_asym_version(version_id, created, algorithm, sk)
        if algorithm == KeyAlgorithm.ECDSA_P256:
            sk = ec.generate_private_key(ec.SECP256R1())
            return _make_asym_version(version_id, created, algorithm, sk)
        if algorithm in (KeyAlgorithm.RSA_3072, KeyAlgorithm.RSA_4096):
            size = 3072 if algorithm == KeyAlgorithm.RSA_3072 else 4096
            sk = rsa.generate_private_key(public_exponent=65537, key_size=size)
            return _make_asym_version(version_id, created, algorithm, sk)
        raise InvalidArgument("Unsupported algorithm")

    def _audit(self, actor: Optional[str], action: str, *, key_id: Optional[str] = None, version_id: Optional[int] = None, success: bool = True, message: Optional[str] = None, meta: Optional[Mapping[str, Any]] = None) -> None:
        try:
            self.audit(AuditEvent(at=_now_utc(), actor=actor, action=action, key_id=key_id, version_id=version_id, success=success, message=message, meta=meta or {}))
        except Exception:
            # audit must never break crypto operations
            pass

# ---------------------------
# Internal crypto helpers
# ---------------------------

def _kcv_sha256(key_bytes: bytes) -> str:
    h = hashes.Hash(hashes.SHA256())
    h.update(key_bytes)
    return h.finalize().hex()[:16]

def _make_asym_version(version_id: int, created: datetime, algorithm: KeyAlgorithm, sk: Union[ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]) -> KeyVersion:
    sk_pem = sk.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    pk = sk.public_key()
    pk_pem = pk.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return KeyVersion(version_id=version_id, created_at=created, state=VersionState.ENABLED, algorithm=algorithm, private_material_b64=_b64e(sk_pem), public_material_b64=_b64e(pk_pem), meta={"kcv": _kcv_pub_sha256(pk_pem)})

def _kcv_pub_sha256(pub_pem: bytes) -> str:
    h = hashes.Hash(hashes.SHA256())
    h.update(pub_pem)
    return h.finalize().hex()[:16]

def _require_primary_version(rec: KeyRecord) -> KeyVersion:
    v = _require_version(rec, rec.primary_version)
    if v.state != VersionState.ENABLED:
        raise InvalidState("Primary version is not enabled")
    return v

def _require_version(rec: KeyRecord, version_id: int) -> KeyVersion:
    for v in rec.versions:
        if v.version_id == version_id:
            return v
    raise NotFound(f"Version {version_id} not found for key {rec.key_id}")

def _assert_op_allowed(rec: KeyRecord, op: KeyOp) -> None:
    if not (rec.allowed_ops & op):
        raise Forbidden(f"Operation {op} not allowed for key {rec.key_id}")

def _aead_for_version(v: KeyVersion) -> Tuple[Union[AESGCM, ChaCha20Poly1305], bytes]:
    if v.algorithm == KeyAlgorithm.AES256_GCM:
        key = _b64d(_require(v.private_material_b64, "missing key material"))
        return AESGCM(key), _rand_bytes(12)
    if v.algorithm == KeyAlgorithm.CHACHA20_POLY1305:
        key = _b64d(_require(v.private_material_b64, "missing key material"))
        return ChaCha20Poly1305(key), _rand_bytes(12)
    raise InvalidArgument("AEAD not supported by version algorithm")

def _load_public_key_from_version(v: KeyVersion):
    if v.public_material_b64:
        pem = _b64d(v.public_material_b64)
        return serialization.load_pem_public_key(pem)
    # For RSA private-only storage, derive public from private
    sk = _load_private_key_from_version(v)
    return sk.public_key()

def _load_private_key_from_version(v: KeyVersion):
    if not v.private_material_b64:
        raise InvalidState("Version has no private material")
    pem_or_key = _b64d(v.private_material_b64)
    # For symmetric keys, this is raw key, not PEM
    if v.algorithm in (KeyAlgorithm.AES256_GCM, KeyAlgorithm.CHACHA20_POLY1305):
        return pem_or_key
    return serialization.load_pem_private_key(pem_or_key, password=None)

def _require(v: Optional[str], msg: str) -> str:
    if v is None:
        raise InvalidState(msg)
    return v

def _restore_keyrecord_from_asdict(rec: KeyRecord) -> KeyRecord:
    # asdict() flattens Enums etc.; restore types
    return KeyRecord(
        key_id=rec.key_id,
        name=rec.name,
        description=rec.description,
        created_at=rec.created_at,
        primary_version=rec.primary_version,
        rotation_period=rec.rotation_period,
        pending_deletion_at=rec.pending_deletion_at,
        versions=tuple(
            KeyVersion(
                version_id=v.version_id,
                created_at=v.created_at,
                state=VersionState(v.state) if isinstance(v.state, str) else v.state,
                algorithm=KeyAlgorithm(v.algorithm) if isinstance(v.algorithm, str) else v.algorithm,
                private_material_b64=v.private_material_b64,
                public_material_b64=v.public_material_b64,
                meta=v.meta,
            )
            for v in rec.versions
        ),
        allowed_ops=KeyOp(rec.allowed_ops) if isinstance(rec.allowed_ops, int) else rec.allowed_ops,
        tags=rec.tags,
    )

# ---------------------------
# Example minimal usage (not executed)
# ---------------------------
# storage = FilesystemStorage("./kms_store", passphrase=os.environ["KMS_PASSPHRASE"].encode("utf-8"))
# kms = KMS(storage=storage)
# kms.create_key(key_id="kek1", name="Primary KEK", algorithm=KeyAlgorithm.RSA_3072)
# dek, wrapped = kms.generate_data_key(key_id="kek1", aad=b"context")
# env = kms.encrypt_envelope(key_id="kek1", plaintext=b"secret", aad=b"context")
# pt = kms.decrypt_envelope(envelope=env)
# sig = kms.sign(key_id="kek1", data=b"abc")  # for RSA/Ed25519/ECDSA keys
# ok = kms.verify(key_id="kek1", version_id=None, data=b"abc", signature_b64=sig["signature_b64"])
