# cybersecurity-core/api/http/routers/v1/secrets.py
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, validator

# ===== Optional crypto deps with safe fallbacks =================================
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import padding, rsa  # type: ignore
    from cryptography.hazmat.primitives import serialization, hashes  # type: ignore
    from cryptography.hazmat.primitives.keywrap import (  # type: ignore
        aes_key_wrap,
        aes_key_unwrap,
    )
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False
    AESGCM = None  # type: ignore

# ===== Try import server-scoped helpers (auth, settings, logger, limiter) =======
try:
    # server.py is located at: api/http/server.py (two levels up from this file)
    from ...server import require_auth, get_settings, AuthContext, rate_limiter  # type: ignore
    try:
        from ...server import _log as server_log  # type: ignore
    except Exception:  # pragma: no cover
        server_log = None
except Exception:  # pragma: no cover
    # Minimal fallbacks when running router in isolation (tests, linters)
    class AuthContext(BaseModel):  # type: ignore
        subject: Optional[str] = None
        scopes: List[str] = []
        api_key_id: Optional[str] = None

    def require_auth() -> AuthContext:  # type: ignore
        return AuthContext()

    class _MiniSettings(BaseModel):
        APP_NAME: str = "cybersecurity-core"
        APP_ENV: str = "prod"
        SECRET_KEK_PUBLIC_PEM: Optional[str] = None
        SECRET_KEK_PRIVATE_PEM: Optional[str] = None
        SECRET_KEK_HEX: Optional[str] = None
        SECRETS_MAX_NAME_LEN: int = 128
        SECRETS_MAX_VALUE_BYTES: int = 64 * 1024
        SECRETS_MAX_LABELS: int = 32
        SECRETS_MAX_LABEL_KEY_LEN: int = 64
        SECRETS_MAX_LABEL_VAL_LEN: int = 256

    _FALLBACK_SETTINGS = _MiniSettings()

    def get_settings() -> _MiniSettings:  # type: ignore
        # Read minimal env overrides for tests
        s = _MiniSettings()
        s.SECRET_KEK_PUBLIC_PEM = os.environ.get("SECRET_KEK_PUBLIC_PEM")
        s.SECRET_KEK_PRIVATE_PEM = os.environ.get("SECRET_KEK_PRIVATE_PEM")
        s.SECRET_KEK_HEX = os.environ.get("SECRET_KEK_HEX")
        return s

    rate_limiter = None  # type: ignore
    server_log = None

# ===== Local logger =============================================================
def _log():
    if server_log:
        return server_log()
    return logging.getLogger(get_settings().APP_NAME)

# ===== Security scopes and helpers =============================================
READ_META_SCOPE = "secrets:read"
READ_PLAINTEXT_SCOPE = "secrets:read:plaintext"
WRITE_SCOPE = "secrets:write"
DELETE_SCOPE = "secrets:delete"
ADMIN_SCOPE = "secrets:admin"

def _has_scope(ctx: AuthContext, required: List[str]) -> bool:
    if not required:
        return True
    user_scopes = set(getattr(ctx, "scopes", []) or [])
    return any(s in user_scopes for s in required) or ADMIN_SCOPE in user_scopes

def _require_scopes(required: List[str]):
    async def _dep(ctx: AuthContext = Depends(require_auth)) -> AuthContext:
        if not _has_scope(ctx, required):
            raise HTTPException(status_code=403, detail="Insufficient scope")
        return ctx
    return _dep

# ===== Models ===================================================================
class LabelsType(BaseModel):
    __root__: Dict[str, str] = Field(default_factory=dict)

    @validator("__root__")
    def validate_labels(cls, v: Dict[str, str]) -> Dict[str, str]:
        cfg = get_settings()
        if len(v) > cfg.SECRETS_MAX_LABELS:
            raise ValueError("too many labels")
        for k, val in v.items():
            if not k or len(k) > cfg.SECRETS_MAX_LABEL_KEY_LEN:
                raise ValueError("invalid label key")
            if len(val) > cfg.SECRETS_MAX_LABEL_VAL_LEN:
                raise ValueError("invalid label value")
        return v

class SecretCreate(BaseModel):
    name: str = Field(..., regex=r"^[a-zA-Z0-9_\-./]{1,128}")
    value: str = Field(..., min_length=1, description="Secret value as str or base64, defined by encoding")
    encoding: str = Field("utf-8", description="utf-8 or base64")
    labels: LabelsType = Field(default_factory=LabelsType)
    expires_at: Optional[datetime] = Field(default=None, description="UTC timestamp")

    @validator("name")
    def name_len(cls, v: str) -> str:
        if len(v) > get_settings().SECRETS_MAX_NAME_LEN:
            raise ValueError("name too long")
        return v

class SecretRotate(BaseModel):
    # If new_value omitted and rewrap=True, performs key rewrap only.
    new_value: Optional[str] = None
    encoding: str = Field("utf-8", description="utf-8 or base64")
    rewrap: bool = False
    labels: Optional[LabelsType] = None
    expires_at: Optional[datetime] = None

class SecretMeta(BaseModel):
    name: str
    version: int
    created_at: datetime
    created_by: Optional[str] = None
    checksum: str
    bytes: int
    labels: Dict[str, str] = Field(default_factory=dict)
    expires_at: Optional[datetime] = None
    deleted: bool = False

class SecretValueResponse(BaseModel):
    name: str
    version: int
    value: str
    encoding: str = "base64"  # always returns base64 to avoid encoding ambiguity

class SecretListResponse(BaseModel):
    items: List[SecretMeta]
    next_offset: Optional[int] = None

# ===== Crypto Manager ===========================================================
class CryptoError(Exception):
    pass

class CryptoManager:
    """
    Envelope encryption:
      - Generate random DEK (32 bytes) per version
      - Encrypt plaintext with AES-256-GCM
      - Wrap DEK with KEK:
          * RSA-OAEP (if SECRET_KEK_PUBLIC_PEM is set)
          * AES Key Wrap RFC3394 (if SECRET_KEK_HEX is set)
      - Store: {nonce, ct, aad, wrapped_dek, dek_alg, kek_alg}
    """
    def __init__(self) -> None:
        self.cfg = get_settings()
        self._rsa_public = None
        self._rsa_private = None
        self._kwk: Optional[bytes] = None
        self._load_kek()

    def _load_kek(self) -> None:
        if not _HAS_CRYPTO:
            raise CryptoError("cryptography package not installed")
        pub_pem = getattr(self.cfg, "SECRET_KEK_PUBLIC_PEM", None)
        priv_pem = getattr(self.cfg, "SECRET_KEK_PRIVATE_PEM", None)
        kek_hex = getattr(self.cfg, "SECRET_KEK_HEX", None)

        if pub_pem:
            try:
                self._rsa_public = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
            except Exception as e:
                raise CryptoError(f"invalid SECRET_KEK_PUBLIC_PEM: {e}")

        if priv_pem:
            try:
                self._rsa_private = serialization.load_pem_private_key(priv_pem.encode("utf-8"), password=None)
            except Exception as e:
                raise CryptoError(f"invalid SECRET_KEK_PRIVATE_PEM: {e}")

        if kek_hex:
            try:
                raw = bytes.fromhex(kek_hex.strip())
                if len(raw) not in (16, 24, 32):
                    raise CryptoError("SECRET_KEK_HEX length must be 128/192/256-bit")
                self._kwk = raw
            except Exception as e:
                raise CryptoError(f"invalid SECRET_KEK_HEX: {e}")

        if not self._rsa_public and not self._kwk:
            raise CryptoError("No KEK configured: set SECRET_KEK_PUBLIC_PEM or SECRET_KEK_HEX")

    @staticmethod
    def _b64e(b: bytes) -> str:
        return base64.b64encode(b).decode("ascii")

    @staticmethod
    def _b64d(s: str) -> bytes:
        return base64.b64decode(s.encode("ascii"))

    def encrypt(self, name: str, version: int, plaintext: bytes) -> Dict[str, Any]:
        try:
            aad = f"{name}:{version}".encode("utf-8")
            dek = os.urandom(32)
            nonce = os.urandom(12)
            aead = AESGCM(dek)
            ct = aead.encrypt(nonce, plaintext, aad)

            if self._rsa_public is not None:
                wrapped = self._rsa_public.encrypt(
                    dek,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
                )
                kek_alg = "RSA-OAEP-SHA256"
            else:
                # AES Key Wrap
                wrapped = aes_key_wrap(self._kwk, dek)  # type: ignore[arg-type]
                kek_alg = f"AES-KW-{len(self._kwk)*8}"  # type: ignore[operator]

            blob = {
                "nonce": self._b64e(nonce),
                "ct": self._b64e(ct),
                "aad": self._b64e(aad),
                "wrapped_dek": self._b64e(wrapped),
                "dek_alg": "AES-256-GCM",
                "kek_alg": kek_alg,
            }
            return blob
        except Exception as e:
            raise CryptoError(f"encrypt failed: {e}")

    def _unwrap_dek(self, wrapped_b64: str) -> bytes:
        wrapped = self._b64d(wrapped_b64)
        if self._rsa_private is not None:
            return self._rsa_private.decrypt(
                wrapped,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
            )
        if self._kwk is not None:
            return aes_key_unwrap(self._kwk, wrapped)  # type: ignore[arg-type]
        raise CryptoError("No private KEK available for unwrap")

    def decrypt(self, blob: Dict[str, Any]) -> bytes:
        try:
            dek = self._unwrap_dek(blob["wrapped_dek"])
            aead = AESGCM(dek)
            nonce = self._b64d(blob["nonce"])
            ct = self._b64d(blob["ct"])
            aad = self._b64d(blob.get("aad", ""))
            return aead.decrypt(nonce, ct, aad)
        except Exception as e:
            raise CryptoError(f"decrypt failed: {e}")

    def rewrap(self, blob: Dict[str, Any]) -> Dict[str, Any]:
        """
        Re-wrap existing DEK with current KEK, without touching ciphertext.
        Requires ability to unwrap current wrapped_dek (private RSA or kwk present).
        """
        try:
            dek = self._unwrap_dek(blob["wrapped_dek"])
            if self._rsa_public is not None:
                wrapped = self._rsa_public.encrypt(
                    dek,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
                )
                kek_alg = "RSA-OAEP-SHA256"
            else:
                wrapped = aes_key_wrap(self._kwk, dek)  # type: ignore[arg-type]
                kek_alg = f"AES-KW-{len(self._kwk)*8}"  # type: ignore[operator]
            new_blob = dict(blob)
            new_blob["wrapped_dek"] = self._b64e(wrapped)
            new_blob["kek_alg"] = kek_alg
            return new_blob
        except Exception as e:
            raise CryptoError(f"rewrap failed: {e}")

# ===== Secret Store (in-memory with asyncio lock; replaceable later) ============
class _SecretVersion(BaseModel):
    version: int
    created_at: datetime
    created_by: Optional[str]
    labels: Dict[str, str] = Field(default_factory=dict)
    expires_at: Optional[datetime] = None
    bytes: int
    checksum: str  # sha256 of ciphertext for tracking
    blob: Dict[str, Any]

class _SecretRecord(BaseModel):
    name: str
    deleted: bool = False
    versions: List[_SecretVersion] = Field(default_factory=list)

class SecretStore:
    def __init__(self) -> None:
        self._data: Dict[str, _SecretRecord] = {}
        self._lock = asyncio.Lock()
        self.crypto = CryptoManager()

    async def create(self, name: str, plaintext: bytes, labels: Dict[str, str], expires_at: Optional[datetime], created_by: Optional[str]) -> _SecretVersion:
        async with self._lock:
            rec = self._data.get(name)
            vnum = 1 if not rec else (rec.versions[-1].version + 1)
            blob = self.crypto.encrypt(name, vnum, plaintext)
            checksum = hashlib.sha256(base64.b64decode(blob["ct"])).hexdigest()
            ver = _SecretVersion(
                version=vnum,
                created_at=datetime.now(timezone.utc),
                created_by=created_by,
                labels=dict(labels or {}),
                expires_at=expires_at,
                bytes=len(plaintext),
                checksum=checksum,
                blob=blob,
            )
            if not rec:
                rec = _SecretRecord(name=name, deleted=False, versions=[ver])
                self._data[name] = rec
            else:
                if rec.deleted:
                    raise HTTPException(status_code=409, detail="secret is deleted")
                rec.versions.append(ver)
            return ver

    async def rewrap(self, name: str, version: Optional[int]) -> _SecretVersion:
        async with self._lock:
            rec = self._get_rec(name)
            ver = self._get_version(rec, version)
            ver.blob = self.crypto.rewrap(ver.blob)
            return ver

    async def update(self, name: str, plaintext: bytes, labels: Optional[Dict[str, str]], expires_at: Optional[datetime], created_by: Optional[str]) -> _SecretVersion:
        # Create new version with new plaintext
        return await self.create(name, plaintext, labels or {}, expires_at, created_by)

    async def get_meta(self, name: str, version: Optional[int]) -> _SecretVersion:
        async with self._lock:
            rec = self._get_rec(name)
            return self._get_version(rec, version)

    async def get_value(self, name: str, version: Optional[int]) -> Tuple[_SecretVersion, bytes]:
        async with self._lock:
            rec = self._get_rec(name)
            ver = self._get_version(rec, version)
            if ver.expires_at and ver.expires_at <= datetime.now(timezone.utc):
                raise HTTPException(status_code=410, detail="secret expired")
            # decrypt outside lock to minimize critical section if desired
        plaintext = self.crypto.decrypt(ver.blob)
        return ver, plaintext

    async def list(self, prefix: Optional[str], offset: int, limit: int) -> Tuple[List[_SecretVersion], Optional[int]]:
        items: List[_SecretVersion] = []
        async with self._lock:
            names = sorted(self._data.keys())
            if prefix:
                names = [n for n in names if n.startswith(prefix)]
            # Simple pagination over names; return latest versions
            slice_names = names[offset:offset + limit]
            for n in slice_names:
                rec = self._data[n]
                if not rec.versions:
                    continue
                items.append(rec.versions[-1])
            next_off = offset + limit if (offset + limit) < len(names) else None
        return items, next_off

    async def delete(self, name: str, purge: bool = False) -> None:
        async with self._lock:
            rec = self._data.get(name)
            if not rec:
                return
            if purge:
                del self._data[name]
                return
            rec.deleted = True

    def _get_rec(self, name: str) -> _SecretRecord:
        rec = self._data.get(name)
        if not rec:
            raise HTTPException(status_code=404, detail="secret not found")
        if rec.deleted:
            raise HTTPException(status_code=410, detail="secret deleted")
        return rec

    @staticmethod
    def _get_version(rec: _SecretRecord, version: Optional[int]) -> _SecretVersion:
        if version is None:
            return rec.versions[-1]
        for v in rec.versions:
            if v.version == version:
                return v
        raise HTTPException(status_code=404, detail="version not found")

# ===== Helpers =================================================================
def _decode_value(value: str, encoding: str) -> bytes:
    if encoding == "utf-8":
        return value.encode("utf-8")
    if encoding == "base64":
        try:
            return base64.b64decode(value.encode("ascii"))
        except Exception:
            raise HTTPException(status_code=400, detail="invalid base64 value")
    raise HTTPException(status_code=400, detail="unsupported encoding")

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

# Optional extra rate-cost for sensitive reads
async def _extra_rate_cost(req: Request, cost: float = 2.0) -> None:
    try:
        if rate_limiter:
            identity = req.headers.get(getattr(get_settings(), "API_KEY_HEADER", "X-API-Key")) or req.client.host
            allowed = await rate_limiter.allow(identity or "-", cost=cost)  # type: ignore[attr-defined]
            if not allowed:
                raise HTTPException(status_code=429, detail="Too Many Requests")
    except Exception:
        # Fail-closed to avoid leaking errors, but do not block if limiter missing
        return

# ===== Router ==================================================================
router = APIRouter(prefix="/v1/secrets", tags=["secrets"])
_STORE = SecretStore()
_LOG = _log()

@router.post("", response_model=SecretMeta, status_code=201, dependencies=[Depends(_require_scopes([WRITE_SCOPE]))])
async def create_secret(payload: SecretCreate, ctx: AuthContext = Depends(require_auth)):
    cfg = get_settings()

    # Validate size and time
    raw = _decode_value(payload.value, payload.encoding)
    if len(raw) > getattr(cfg, "SECRETS_MAX_VALUE_BYTES", 64 * 1024):
        raise HTTPException(status_code=413, detail="secret value too large")
    if payload.expires_at and payload.expires_at.tzinfo is None:
        raise HTTPException(status_code=400, detail="expires_at must be UTC with tzinfo")
    created_by = ctx.subject or ctx.api_key_id

    ver = await _STORE.create(
        name=payload.name,
        plaintext=raw,
        labels=payload.labels.__root__,
        expires_at=payload.expires_at,
        created_by=created_by,
    )
    _LOG.info("secret_created", name=payload.name, version=ver.version, sub=created_by)
    return SecretMeta(
        name=payload.name,
        version=ver.version,
        created_at=ver.created_at,
        created_by=ver.created_by,
        checksum=ver.checksum,
        bytes=ver.bytes,
        labels=ver.labels,
        expires_at=ver.expires_at,
        deleted=False,
    )

@router.get("", response_model=SecretListResponse, dependencies=[Depends(_require_scopes([READ_META_SCOPE]))])
async def list_secrets(
    prefix: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
):
    items, next_off = await _STORE.list(prefix=prefix, offset=offset, limit=limit)
    metas = [
        SecretMeta(
            name=item.blob and item.blob.get("aad", "").encode() and item.blob.get("aad"),  # placeholder, fixed below
            version=item.version,
            created_at=item.created_at,
            created_by=item.created_by,
            checksum=item.checksum,
            bytes=item.bytes,
            labels=item.labels,
            expires_at=item.expires_at,
            deleted=False,
        )
        for item in items
    ]
    # Fix name extraction from record by mapping during list; store name directly
    # Reconstruct proper metas:
    metas = []
    for item in items:
        metas.append(
            SecretMeta(
                name=_extract_name_from_aad(item.blob.get("aad", "")) or "unknown",
                version=item.version,
                created_at=item.created_at,
                created_by=item.created_by,
                checksum=item.checksum,
                bytes=item.bytes,
                labels=item.labels,
                expires_at=item.expires_at,
                deleted=False,
            )
        )
    return SecretListResponse(items=metas, next_offset=next_off)

def _extract_name_from_aad(aad_b64: str) -> Optional[str]:
    try:
        aad = base64.b64decode(aad_b64.encode("ascii")).decode("utf-8")
        name, _ = aad.split(":", 1)
        return name
    except Exception:
        return None

@router.get("/{name}", response_model=SecretMeta, dependencies=[Depends(_require_scopes([READ_META_SCOPE]))])
async def get_secret_meta(
    name: str,
    version: Optional[int] = Query(default=None, ge=1),
):
    ver = await _STORE.get_meta(name, version)
    return SecretMeta(
        name=name,
        version=ver.version,
        created_at=ver.created_at,
        created_by=ver.created_by,
        checksum=ver.checksum,
        bytes=ver.bytes,
        labels=ver.labels,
        expires_at=ver.expires_at,
        deleted=False,
    )

@router.get("/{name}/value", response_model=SecretValueResponse, dependencies=[Depends(_require_scopes([READ_PLAINTEXT_SCOPE]))])
async def get_secret_value(
    request: Request,
    name: str,
    version: Optional[int] = Query(default=None, ge=1),
):
    await _extra_rate_cost(request, cost=2.0)
    ver, plaintext = await _STORE.get_value(name, version)
    # Never return raw text; always base64 for neutrality and to avoid accidental logs
    return SecretValueResponse(name=name, version=ver.version, value=_b64e(plaintext), encoding="base64")

@router.post("/{name}/rotate", response_model=SecretMeta, dependencies=[Depends(_require_scopes([WRITE_SCOPE]))])
async def rotate_secret(
    name: str,
    payload: SecretRotate,
    ctx: AuthContext = Depends(require_auth),
):
    if payload.rewrap and payload.new_value:
        raise HTTPException(status_code=400, detail="either rewrap or new_value, not both")

    if payload.rewrap:
        ver = await _STORE.rewrap(name, version=None)
        _LOG.info("secret_rewrap", name=name, version=ver.version, sub=ctx.subject or ctx.api_key_id)
        return SecretMeta(
            name=name,
            version=ver.version,
            created_at=ver.created_at,
            created_by=ver.created_by,
            checksum=ver.checksum,
            bytes=ver.bytes,
            labels=ver.labels,
            expires_at=ver.expires_at,
            deleted=False,
        )

    if not payload.new_value:
        raise HTTPException(status_code=400, detail="new_value required unless rewrap=true")

    raw = _decode_value(payload.new_value, payload.encoding)
    created_by = ctx.subject or ctx.api_key_id
    ver = await _STORE.update(
        name=name,
        plaintext=raw,
        labels=(payload.labels.__root__ if payload.labels else None),
        expires_at=payload.expires_at,
        created_by=created_by,
    )
    _LOG.info("secret_rotated", name=name, version=ver.version, sub=created_by)
    return SecretMeta(
        name=name,
        version=ver.version,
        created_at=ver.created_at,
        created_by=ver.created_by,
        checksum=ver.checksum,
        bytes=ver.bytes,
        labels=ver.labels,
        expires_at=ver.expires_at,
        deleted=False,
    )

@router.delete("/{name}", status_code=204, dependencies=[Depends(_require_scopes([DELETE_SCOPE]))])
async def delete_secret(name: str, purge: bool = Query(default=False)):
    await _STORE.delete(name, purge=purge)
    _LOG.info("secret_deleted", name=name, purge=purge)
    return

# ===== Notes ===================================================================
# Production notes:
# - Configure one of:
#     SECRET_KEK_PUBLIC_PEM / SECRET_KEK_PRIVATE_PEM for RSA-OAEP
#     SECRET_KEK_HEX for AES Key Wrap (16/24/32 bytes hex)
# - Scopes:
#     secrets:read                -> list and metadata
#     secrets:read:plaintext      -> read decrypted values
#     secrets:write               -> create/update/rotate/rewrap
#     secrets:delete              -> delete/purge
#     secrets:admin               -> bypass any scope checks
# - Store is in-memory; back it by database or Vault adapter by swapping SecretStore.
# - All plaintext responses are base64 to avoid encoding ambiguity and accidental logs.
