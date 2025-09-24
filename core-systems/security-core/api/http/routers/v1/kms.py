# security-core/api/http/routers/v1/kms.py
# Copyright (c) Aethernova.
# SPDX-License-Identifier: Apache-2.0
#
# Industrial-grade KMS API router (FastAPI/Starlette, Pydantic v2).
# Features:
#   - List/Get keys, Encrypt/Decrypt, Generate Data Key, Sign/Verify, Rotate, Get Public Key.
#   - OAuth2-like scopes (logical): kms.read, kms.write, kms.sign, kms.verify, kms.decrypt.plaintext, kms.datakey.plaintext.
#   - Correlation & idempotency headers: X-Request-ID, X-Idempotency-Key (forwarded to service layer).
#   - Consistent error model, structured logging, pagination.
#   - Pluggable KMS backends via KMSService protocol (AWS/GCP/Azure/Vault/HSM/Local).
#
# Integration:
#   app.state.kms_service = <YourKMSService>()
#   app.state.auth_resolver = <callable(Request) -> Principal with scopes>

from __future__ import annotations

import base64
import logging
import uuid
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Security, status
from fastapi.security import SecurityScopes
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("security_core.kms")

router = APIRouter(prefix="/v1/kms", tags=["KMS"])


# ======= Security / Principal =======

class Principal(BaseModel):
    subject_id: str
    tenant_id: Optional[str] = None
    project_id: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)


async def get_principal(request: Request, security_scopes: SecurityScopes) -> Principal:
    """
    Resolve principal from app.state.auth_resolver or simple header fallback:
      - Prefer: request.app.state.auth_resolver(request) -> Principal
      - Fallback: X-Subject-Id, X-Scopes (comma-separated). For dev/testing only.
    """
    resolver = getattr(request.app.state, "auth_resolver", None)
    principal: Optional[Principal] = None
    if callable(resolver):
        principal = await resolver(request) if hasattr(resolver, "__await__") else resolver(request)  # type: ignore

    if principal is None:
        subj = request.headers.get("X-Subject-Id")
        scopes = [s.strip() for s in request.headers.get("X-Scopes", "").split(",") if s.strip()]
        if not subj:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "unauthorized", "message": "Missing authentication"})
        principal = Principal(subject_id=subj, scopes=scopes)

    # Scope check
    needed = list(security_scopes.scopes)
    if needed and not set(needed).issubset(set(principal.scopes)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"error": "forbidden", "message": f"Missing scopes: {needed}"})

    return principal


def get_request_ids(request: Request) -> Tuple[str, Optional[str]]:
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    idem_key = request.headers.get("X-Idempotency-Key")
    return req_id, idem_key


# ======= Error model =======

class APIError(BaseModel):
    error: str
    message: str
    request_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


def raise_api_error(status_code: int, request_id: str, error: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
    raise HTTPException(status_code=status_code, detail=APIError(error=error, message=message, request_id=request_id, details=details).model_dump())


# ======= KMS Service Protocol =======

class KeyMeta(BaseModel):
    key_id: str
    alias: Optional[str] = None
    provider: str  # e.g., AWS|GCP|AZURE|VAULT|LOCAL_HSM|NITRO
    algorithm: str  # e.g., AES-256-GCM, RSA-2048-PSS, ECDSA-P256-SHA256, Ed25519
    purpose: str    # e.g., encrypt/decrypt, sign/verify, wrap/unwrap
    state: str      # e.g., ENABLED|DISABLED|PENDING_ROTATION|SCHEDULED_DELETION
    region: Optional[str] = None
    resource: Optional[str] = None  # ARN/resource path
    created_at: Optional[str] = None
    rotation_policy: Optional[Dict[str, Any]] = None
    tags: Dict[str, str] = Field(default_factory=dict)


class ListKeysResponse(BaseModel):
    items: List[KeyMeta]
    next_page_token: Optional[str] = None
    request_id: str


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid base64: {e}")


class EncryptRequest(BaseModel):
    algorithm: Optional[str] = Field(None, description="Override algorithm if key supports multiple")
    plaintext_b64: str = Field(..., description="Plaintext, base64")
    aad_b64: Optional[str] = Field(None, description="Additional Authenticated Data (base64)")
    context: Dict[str, str] = Field(default_factory=dict)

    @field_validator("plaintext_b64")
    @classmethod
    def _validate_plain_b64(cls, v: str) -> str:
        _ = _b64d(v)
        return v

    @field_validator("aad_b64")
    @classmethod
    def _validate_aad_b64(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            _ = _b64d(v)
        return v


class EncryptResponse(BaseModel):
    request_id: str
    key_id: str
    algorithm: str
    ciphertext_b64: str
    iv_b64: Optional[str] = None
    tag_b64: Optional[str] = None
    aad_b64: Optional[str] = None


class DecryptRequest(BaseModel):
    algorithm: Optional[str] = None
    ciphertext_b64: str
    iv_b64: Optional[str] = None
    tag_b64: Optional[str] = None
    aad_b64: Optional[str] = None
    context: Dict[str, str] = Field(default_factory=dict)

    @field_validator("ciphertext_b64")
    @classmethod
    def _validate_ct_b64(cls, v: str) -> str:
        _ = _b64d(v)
        return v

    @field_validator("iv_b64", "tag_b64", "aad_b64")
    @classmethod
    def _validate_opt_b64(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            _ = _b64d(v)
        return v


class DecryptResponse(BaseModel):
    request_id: str
    key_id: str
    algorithm: str
    plaintext_b64: str


class DataKeyRequest(BaseModel):
    key_spec: str = Field(..., description="e.g., AES_256, AES_128, XCHACHA20")
    return_plaintext: bool = Field(False, description="Requires scope kms.datakey.plaintext")


class DataKeyResponse(BaseModel):
    request_id: str
    key_id: str
    key_spec: str
    encrypted_key_b64: str
    plaintext_key_b64: Optional[str] = None


class SignRequest(BaseModel):
    algorithm: Optional[str] = None  # e.g., RSASSA-PSS-SHA256, ECDSA-SHA256, ED25519
    message_b64: Optional[str] = None
    digest_b64: Optional[str] = None
    prehashed: bool = False

    @field_validator("message_b64", "digest_b64")
    @classmethod
    def _validate_msg_b64(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            _ = _b64d(v)
        return v


class SignResponse(BaseModel):
    request_id: str
    key_id: str
    algorithm: str
    signature_b64: str


class VerifyRequest(BaseModel):
    algorithm: Optional[str] = None
    message_b64: Optional[str] = None
    digest_b64: Optional[str] = None
    signature_b64: str

    @field_validator("message_b64", "digest_b64", "signature_b64")
    @classmethod
    def _validate_b64(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            _ = _b64d(v)
        return v


class VerifyResponse(BaseModel):
    request_id: str
    key_id: str
    algorithm: str
    is_valid: bool


class PublicKeyResponse(BaseModel):
    request_id: str
    key_id: str
    algorithm: str
    public_key_pem: str


class RotateKeyResponse(BaseModel):
    request_id: str
    key: KeyMeta


# Back-end KMS protocol
class KMSService(Protocol):
    async def list_keys(self, *, page_size: int, page_token: Optional[str], principal: Principal) -> Tuple[List[KeyMeta], Optional[str]]: ...
    async def get_key(self, key_id: str, *, principal: Principal) -> KeyMeta: ...
    async def encrypt(self, key_id: str, *, plaintext: bytes, aad: Optional[bytes], context: Dict[str, str], algorithm: Optional[str], principal: Principal, request_id: str, idempotency_key: Optional[str]) -> Tuple[str, bytes, Optional[bytes], Optional[bytes], Optional[bytes]]: ...
    async def decrypt(self, key_id: str, *, ciphertext: bytes, iv: Optional[bytes], tag: Optional[bytes], aad: Optional[bytes], context: Dict[str, str], algorithm: Optional[str], principal: Principal, request_id: str) -> Tuple[str, bytes]: ...
    async def generate_data_key(self, key_id: str, *, key_spec: str, return_plaintext: bool, principal: Principal, request_id: str, idempotency_key: Optional[str]) -> Tuple[str, bytes, Optional[bytes]]: ...
    async def get_public_key(self, key_id: str, *, principal: Principal) -> Tuple[str, bytes]: ...
    async def sign(self, key_id: str, *, algorithm: Optional[str], message: Optional[bytes], digest: Optional[bytes], prehashed: bool, principal: Principal, request_id: str, idempotency_key: Optional[str]) -> Tuple[str, bytes]: ...
    async def verify(self, key_id: str, *, algorithm: Optional[str], message: Optional[bytes], digest: Optional[bytes], signature: bytes, principal: Principal, request_id: str) -> Tuple[str, bool]: ...
    async def rotate_key(self, key_id: str, *, principal: Principal, request_id: str) -> KeyMeta: ...


def get_kms_service(request: Request) -> KMSService:
    svc = getattr(request.app.state, "kms_service", None)
    if svc is None:
        req_id, _ = get_request_ids(request)
        raise_api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, req_id, "kms_unavailable", "KMS service is not configured")
    return svc


# ======= Routes =======

@router.get("/keys", response_model=ListKeysResponse)
async def list_keys(
    request: Request,
    page_size: int = 50,
    page_token: Optional[str] = None,
    principal: Principal = Security(get_principal, scopes=["kms.read"]),
    kms: KMSService = Depends(get_kms_service),
):
    req_id, _ = get_request_ids(request)
    page_size = max(1, min(page_size, 500))
    items, next_token = await kms.list_keys(page_size=page_size, page_token=page_token, principal=principal)
    logger.debug("list_keys request_id=%s subject=%s size=%d", req_id, principal.subject_id, len(items))
    return ListKeysResponse(items=items, next_page_token=next_token, request_id=req_id)


@router.get("/keys/{key_id}", response_model=KeyMeta)
async def get_key(
    request: Request,
    key_id: str,
    principal: Principal = Security(get_principal, scopes=["kms.read"]),
    kms: KMSService = Depends(get_kms_service),
):
    req_id, _ = get_request_ids(request)
    key = await kms.get_key(key_id, principal=principal)
    logger.debug("get_key request_id=%s key_id=%s subject=%s", req_id, key_id, principal.subject_id)
    return key


@router.post("/keys/{key_id}/encrypt", response_model=EncryptResponse, status_code=status.HTTP_200_OK)
async def encrypt(
    request: Request,
    key_id: str,
    body: EncryptRequest,
    principal: Principal = Security(get_principal, scopes=["kms.write"]),
    kms: KMSService = Depends(get_kms_service),
):
    req_id, idem = get_request_ids(request)
    try:
        plaintext = _b64d(body.plaintext_b64)
        aad = _b64d(body.aad_b64) if body.aad_b64 else None
    except ValueError as e:
        raise_api_error(status.HTTP_400_BAD_REQUEST, req_id, "bad_request", str(e))

    algo, ct, iv, tag, aad_echo = await kms.encrypt(
        key_id,
        plaintext=plaintext,
        aad=aad,
        context=body.context,
        algorithm=body.algorithm,
        principal=principal,
        request_id=req_id,
        idempotency_key=idem,
    )
    logger.info("encrypt ok request_id=%s key_id=%s bytes=%d", req_id, key_id, len(ct))
    return EncryptResponse(
        request_id=req_id,
        key_id=key_id,
        algorithm=algo,
        ciphertext_b64=_b64e(ct),
        iv_b64=_b64e(iv) if iv else None,
        tag_b64=_b64e(tag) if tag else None,
        aad_b64=_b64e(aad_echo) if aad_echo else None,
    )


@router.post("/keys/{key_id}/decrypt", response_model=DecryptResponse, status_code=status.HTTP_200_OK)
async def decrypt(
    request: Request,
    key_id: str,
    body: DecryptRequest,
    principal: Principal = Security(get_principal, scopes=["kms.decrypt.plaintext"]),
    kms: KMSService = Depends(get_kms_service),
):
    req_id, _ = get_request_ids(request)
    try:
        ct = _b64d(body.ciphertext_b64)
        iv = _b64d(body.iv_b64) if body.iv_b64 else None
        tag = _b64d(body.tag_b64) if body.tag_b64 else None
        aad = _b64d(body.aad_b64) if body.aad_b64 else None
    except ValueError as e:
        raise_api_error(status.HTTP_400_BAD_REQUEST, req_id, "bad_request", str(e))

    algo, pt = await kms.decrypt(
        key_id,
        ciphertext=ct,
        iv=iv,
        tag=tag,
        aad=aad,
        context=body.context,
        algorithm=body.algorithm,
        principal=principal,
        request_id=req_id,
    )
    logger.info("decrypt ok request_id=%s key_id=%s bytes=%d", req_id, key_id, len(pt))
    return DecryptResponse(request_id=req_id, key_id=key_id, algorithm=algo, plaintext_b64=_b64e(pt))


@router.post("/keys/{key_id}/datakey", response_model=DataKeyResponse, status_code=status.HTTP_201_CREATED)
async def generate_data_key(
    request: Request,
    key_id: str,
    body: DataKeyRequest,
    principal: Principal = Security(get_principal, scopes=["kms.write"]),
    kms: KMSService = Depends(get_kms_service),
):
    req_id, idem = get_request_ids(request)
    # If plaintext requested, enforce additional scope
    if body.return_plaintext and "kms.datakey.plaintext" not in set(principal.scopes):
        raise_api_error(status.HTTP_403_FORBIDDEN, req_id, "forbidden", "Missing scope kms.datakey.plaintext")

    spec, ek, pk = await kms.generate_data_key(
        key_id,
        key_spec=body.key_spec,
        return_plaintext=body.return_plaintext,
        principal=principal,
        request_id=req_id,
        idempotency_key=idem,
    )
    logger.info("generate_data_key ok request_id=%s key_id=%s spec=%s", req_id, key_id, spec)
    return DataKeyResponse(
        request_id=req_id,
        key_id=key_id,
        key_spec=spec,
        encrypted_key_b64=_b64e(ek),
        plaintext_key_b64=_b64e(pk) if pk else None,
    )


@router.get("/keys/{key_id}/public", response_model=PublicKeyResponse)
async def get_public_key(
    request: Request,
    key_id: str,
    principal: Principal = Security(get_principal, scopes=["kms.read"]),
    kms: KMSService = Depends(get_kms_service),
):
    req_id, _ = get_request_ids(request)
    algo, pub = await kms.get_public_key(key_id, principal=principal)
    logger.debug("get_public_key request_id=%s key_id=%s", req_id, key_id)
    return PublicKeyResponse(request_id=req_id, key_id=key_id, algorithm=algo, public_key_pem=pub.decode("utf-8"))


@router.post("/keys/{key_id}/sign", response_model=SignResponse)
async def sign(
    request: Request,
    key_id: str,
    body: SignRequest,
    principal: Principal = Security(get_principal, scopes=["kms.sign"]),
    kms: KMSService = Depends(get_kms_service),
):
    req_id, idem = get_request_ids(request)
    if not body.message_b64 and not body.digest_b64:
        raise_api_error(status.HTTP_400_BAD_REQUEST, req_id, "bad_request", "Either message_b64 or digest_b64 must be provided")
    message = _b64d(body.message_b64) if body.message_b64 else None
    digest = _b64d(body.digest_b64) if body.digest_b64 else None

    algo, sig = await kms.sign(
        key_id,
        algorithm=body.algorithm,
        message=message,
        digest=digest,
        prehashed=body.prehashed,
        principal=principal,
        request_id=req_id,
        idempotency_key=idem,
    )
    logger.info("sign ok request_id=%s key_id=%s algo=%s", req_id, key_id, algo)
    return SignResponse(request_id=req_id, key_id=key_id, algorithm=algo, signature_b64=_b64e(sig))


@router.post("/keys/{key_id}/verify", response_model=VerifyResponse)
async def verify(
    request: Request,
    key_id: str,
    body: VerifyRequest,
    principal: Principal = Security(get_principal, scopes=["kms.verify"]),
    kms: KMSService = Depends(get_kms_service),
):
    req_id, _ = get_request_ids(request)
    if not body.message_b64 and not body.digest_b64:
        raise_api_error(status.HTTP_400_BAD_REQUEST, req_id, "bad_request", "Either message_b64 or digest_b64 must be provided")
    message = _b64d(body.message_b64) if body.message_b64 else None
    digest = _b64d(body.digest_b64) if body.digest_b64 else None
    signature = _b64d(body.signature_b64)

    algo, ok = await kms.verify(
        key_id,
        algorithm=body.algorithm,
        message=message,
        digest=digest,
        signature=signature,
        principal=principal,
        request_id=req_id,
    )
    logger.debug("verify result request_id=%s key_id=%s valid=%s", req_id, key_id, ok)
    return VerifyResponse(request_id=req_id, key_id=key_id, algorithm=algo, is_valid=ok)


@router.post("/keys/{key_id}/rotate", response_model=RotateKeyResponse)
async def rotate_key(
    request: Request,
    key_id: str,
    principal: Principal = Security(get_principal, scopes=["kms.write"]),
    kms: KMSService = Depends(get_kms_service),
):
    req_id, _ = get_request_ids(request)
    key = await kms.rotate_key(key_id, principal=principal, request_id=req_id)
    logger.info("rotate_key ok request_id=%s key_id=%s", req_id, key_id)
    return RotateKeyResponse(request_id=req_id, key=key)


@router.get("/health", status_code=status.HTTP_200_OK)
async def health(request: Request):
    req_id, _ = get_request_ids(request)
    return {"status": "ok", "request_id": req_id}
