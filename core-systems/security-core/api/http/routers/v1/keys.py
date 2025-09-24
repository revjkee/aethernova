# security-core/api/http/routers/v1/keys.py
from __future__ import annotations

import hashlib
import json
import logging
from datetime import timedelta
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Protocol, Tuple

from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, constr, field_validator

logger = logging.getLogger("security_core.keys_router")

router = APIRouter(prefix="/api/v1", tags=["keys"])

# ============================= Enums =============================

class KeyAlgorithm(str, Enum):
    RSA_2048 = "RSA_2048"
    RSA_3072 = "RSA_3072"
    RSA_4096 = "RSA_4096"
    ECDSA_P256 = "ECDSA_P256"
    ECDSA_P384 = "ECDSA_P384"
    SECP256K1 = "SECP256K1"
    ED25519 = "ED25519"
    X25519 = "X25519"
    AES_128_GCM = "AES_128_GCM"
    AES_256_GCM = "AES_256_GCM"
    CHACHA20_POLY1305 = "CHACHA20_POLY1305"
    ML_KEM_768 = "ML_KEM_768"
    ML_KEM_1024 = "ML_KEM_1024"
    ML_DSA_65 = "ML_DSA_65"
    ML_DSA_87 = "ML_DSA_87"


class SignatureAlgorithm(str, Enum):
    RSASSA_PSS_SHA256 = "RSASSA_PSS_SHA256"
    RSASSA_PSS_SHA384 = "RSASSA_PSS_SHA384"
    RSASSA_PKCS1_V15_SHA256 = "RSASSA_PKCS1_V15_SHA256"
    ECDSA_P256_SHA256 = "ECDSA_P256_SHA256"
    ECDSA_P384_SHA384 = "ECDSA_P384_SHA384"
    ED25519_SIGN = "ED25519_SIGN"
    SECP256K1_ECDSA_SHA256 = "SECP256K1_ECDSA_SHA256"
    ML_DSA_65_SIGN = "ML_DSA_65_SIGN"
    ML_DSA_87_SIGN = "ML_DSA_87_SIGN"


class EncryptionAlgorithm(str, Enum):
    RSA_OAEP_SHA256 = "RSA_OAEP_SHA256"
    ECIES_X25519_XCHACHA20_POLY1305 = "ECIES_X25519_XCHACHA20_POLY1305"
    AES_GCM_128_ENC = "AES_GCM_128_ENC"
    AES_GCM_256_ENC = "AES_GCM_256_ENC"
    CHACHA20_POLY1305_ENC = "CHACHA20_POLY1305_ENC"
    ML_KEM_768_HKDF_SHA256 = "ML_KEM_768_HKDF_SHA256"
    ML_KEM_1024_HKDF_SHA384 = "ML_KEM_1024_HKDF_SHA384"


class WrappingAlgorithm(str, Enum):
    AES_KW_256_RFC3394 = "AES_KW_256_RFC3394"
    AES_KWP_256_RFC5649 = "AES_KWP_256_RFC5649"
    RSA_OAEP_SHA256_WRAP = "RSA_OAEP_SHA256_WRAP"
    X25519_XCHACHA20_WRAP = "X25519_XCHACHA20_WRAP"
    ML_KEM_768_WRAP = "ML_KEM_768_WRAP"


class KeyEncoding(str, Enum):
    RAW = "RAW"
    DER = "DER"
    PEM = "PEM"
    JWK = "JWK"


class KeyPurpose(str, Enum):
    SIGN = "SIGN"
    VERIFY = "VERIFY"
    ENCRYPT = "ENCRYPT"
    DECRYPT = "DECRYPT"
    WRAP_KEY = "WRAP_KEY"
    UNWRAP_KEY = "UNWRAP_KEY"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    ATTESTATION = "ATTESTATION"
    DERIVE = "DERIVE"


class KeyState(str, Enum):
    PENDING_GENERATION = "PENDING_GENERATION"
    PENDING_IMPORT = "PENDING_IMPORT"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    COMPROMISED = "COMPROMISED"
    PENDING_DELETION = "PENDING_DELETION"
    DESTROYED = "DESTROYED"


class ProtectionLevel(str, Enum):
    SOFTWARE = "SOFTWARE"
    HSM = "HSM"
    EXTERNAL_KMS = "EXTERNAL_KMS"
    TEE = "TEE"
    SHAMIR_SPLIT = "SHAMIR_SPLIT"


class AttestationFormat(str, Enum):
    TPM_TPM2_QUOTE = "TPM_TPM2_QUOTE"
    INTEL_SGX_ECDSA = "INTEL_SGX_ECDSA"
    AMD_SEV_SNP = "AMD_SEV_SNP"
    ARM_CCA_REALM = "ARM_CCA_REALM"
    GOOGLE_TITAN = "GOOGLE_TITAN"


# ============================= Models =============================

b64url = constr(pattern=r"^[A-Za-z0-9_-]+$")  # без '=' padding
b64 = constr(pattern=r"^[A-Za-z0-9+/=\r\n]+$")

class Wrapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    algorithm: WrappingAlgorithm
    wrapping_key_uri: Optional[str] = None
    iv: Optional[b64url] = None
    aad: Optional[b64url] = None


class KeyAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: AttestationFormat
    quote: b64
    evidence: Dict[str, b64] = Field(default_factory=dict)
    verified_at: Optional[int] = Field(None, description="Unix timestamp, seconds")
    verified: bool = False
    verifier: Optional[str] = None


class ComplianceTags(BaseModel):
    model_config = ConfigDict(extra="forbid")
    standards: List[str] = Field(default_factory=list)
    fips_approved: bool = False


class KeyAccessPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_service_accounts: List[str] = Field(default_factory=list)
    allowed_principals: List[str] = Field(default_factory=list)
    allowed_networks: List[str] = Field(default_factory=list)
    require_attestation: bool = False
    abac_conditions: Dict[str, str] = Field(default_factory=dict)


class KeyRotationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    automatic: bool = False
    rotation_period_seconds: Optional[int] = Field(None, ge=60, le=365 * 24 * 3600)
    max_active_versions: Optional[int] = Field(None, ge=1, le=10)
    min_active_days: Optional[int] = Field(None, ge=1, le=365)
    next_rotation_time: Optional[int] = Field(None, description="Unix timestamp, seconds")


class PublicKey(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    algorithm: KeyAlgorithm
    encoding: KeyEncoding
    key_bytes: Optional[b64] = None
    pem: Optional[str] = None
    fingerprint: Optional[str] = None


class CertificateSigningRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    pkcs10_der: Optional[b64] = None
    pem: Optional[str] = None


class KeyVersion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    version_id: int
    state: KeyState
    algorithm: KeyAlgorithm
    public_key: PublicKey
    public_encoding: KeyEncoding
    create_time: int
    expire_time: Optional[int] = None
    destroy_time: Optional[int] = None
    attestation: Optional[KeyAttestation] = None


class CryptoKey(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    tenant: str
    description: Optional[str] = None
    algorithm: KeyAlgorithm
    protection_level: ProtectionLevel
    state: KeyState
    primary_purpose: KeyPurpose
    purposes: List[KeyPurpose] = Field(default_factory=list)
    rotation_policy: Optional[KeyRotationPolicy] = None
    access_policy: Optional[KeyAccessPolicy] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    compliance: Optional[ComplianceTags] = None
    kms_uri: Optional[str] = None
    create_time: int
    update_time: int
    destroy_safety_period_days: Optional[int] = Field(None, ge=1, le=90)
    primary_version: Optional[KeyVersion] = None


# ----------------------- JWK/JWKS -----------------------

class Jwk(BaseModel):
    model_config = ConfigDict(extra="allow")  # допускаем расширения по RFC
    kty: Literal["RSA", "EC", "OKP", "oct"]
    kid: Optional[str] = None
    use: Optional[Literal["sig", "enc"]] = None
    key_ops: Optional[List[Literal[
        "sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"
    ]]] = None
    alg: Optional[str] = None
    # RSA
    n: Optional[b64url] = None
    e: Optional[b64url] = None
    d: Optional[b64url] = None
    p: Optional[b64url] = None
    q: Optional[b64url] = None
    dp: Optional[b64url] = None
    dq: Optional[b64url] = None
    qi: Optional[b64url] = None
    # EC / OKP
    crv: Optional[Literal["P-256", "P-384", "P-521", "Ed25519", "Ed448", "X25519", "X448"]] = None
    x: Optional[b64url] = None
    y: Optional[b64url] = None
    # oct
    k: Optional[b64url] = None
    # x5*
    x5u: Optional[HttpUrl] = None
    x5c: Optional[List[b64]] = None
    x5t: Optional[b64url] = None
    x5t__S256: Optional[b64url] = Field(default=None, alias="x5t#S256")

    @field_validator("x5c")
    @classmethod
    def _x5c_non_empty(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is not None and len(v) == 0:
            raise ValueError("x5c must be non-empty when present")
        return v


class Jwks(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    keys: List[Jwk]


# ============================= Request payloads =============================

class CreateKeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key_id: str = Field(..., min_length=1, max_length=128)
    algorithm: KeyAlgorithm
    protection_level: ProtectionLevel
    primary_purpose: KeyPurpose
    purposes: List[KeyPurpose] = Field(default_factory=list)
    description: Optional[str] = None
    rotation_policy: Optional[KeyRotationPolicy] = None
    access_policy: Optional[KeyAccessPolicy] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    generate_primary: bool = True


class ImportKeyVersionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key_id: str = Field(..., min_length=1, max_length=128)
    key_metadata: Optional[CryptoKey] = None  # опционально для первичного импорта
    # Материал приватного ключа передаётся вашей реализацией через безопасный канал.
    # Здесь — только ссылка/дескриптор (например, на внешний KMS/HSM/TEE).
    external_kms_uri: Optional[str] = None
    hsm_key_id: Optional[str] = None
    tee_object_id: Optional[str] = None
    wrapped_private_key: Optional[b64url] = None
    wrapping: Optional[Wrapping] = None
    public: Optional[PublicKey] = None


class UpdateKeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: Optional[str] = None
    labels: Optional[Dict[str, str]] = None
    rotation_policy: Optional[KeyRotationPolicy] = None
    access_policy: Optional[KeyAccessPolicy] = None
    state: Optional[KeyState] = None  # допустим DISABLED/ACTIVE


class RotateKeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    effective_time: Optional[int] = None


class ScheduleDestructionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    destroy_time: Optional[int] = None  # должен учитывать safety period


class VerifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    signature_algorithm: SignatureAlgorithm
    digest: Optional[b64url] = None
    plaintext: Optional[b64url] = None
    signature: b64url
    public_key: Optional[PublicKey] = None  # либо используется имя версии


class SignIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    signature_algorithm: SignatureAlgorithm
    digest: Optional[b64url] = None
    plaintext: Optional[b64url] = None
    salt: Optional[b64url] = None
    context: Dict[str, str] = Field(default_factory=dict)


class EncryptIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    encryption_algorithm: EncryptionAlgorithm
    plaintext: b64url
    aad: Optional[b64url] = None


class DecryptIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    encryption_algorithm: EncryptionAlgorithm
    ciphertext: b64url
    aad: Optional[b64url] = None
    iv: Optional[b64url] = None
    tag: Optional[b64url] = None


class WrapIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    algorithm: WrappingAlgorithm
    target_key_material: b64url
    aad: Optional[b64url] = None


class UnwrapIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    algorithm: WrappingAlgorithm
    wrapped_key: b64url
    aad: Optional[b64url] = None


class AttestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claims: Dict[str, Any] = Field(default_factory=dict)


class ListKeysOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    keys: List[CryptoKey]
    next_page_token: Optional[str] = None


# ============================= Service Protocol =============================

class KeyService(Protocol):
    async def create_key(self, tenant: str, payload: CreateKeyIn) -> CryptoKey: ...
    async def import_key(self, tenant: str, payload: ImportKeyVersionIn) -> CryptoKey: ...
    async def get_key(self, tenant: str, key: str, include_versions: bool) -> CryptoKey: ...
    async def list_keys(
        self, tenant: str, page_size: int, page_token: Optional[str], flt: Optional[str], order_by: Optional[str]
    ) -> Tuple[List[CryptoKey], Optional[str]]: ...
    async def update_key(self, tenant: str, key: str, payload: UpdateKeyIn) -> CryptoKey: ...
    async def rotate_key(self, tenant: str, key: str, payload: RotateKeyIn) -> CryptoKey: ...
    async def schedule_key_destruction(self, tenant: str, key: str, version: int, payload: ScheduleDestructionIn) -> KeyVersion: ...
    async def restore_key_version(self, tenant: str, key: str, version: int) -> KeyVersion: ...
    async def get_public_key(self, tenant: str, key: str, version: int, preferred_encoding: Optional[KeyEncoding]) -> PublicKey: ...
    async def generate_csr(self, tenant: str, key: str, version: int, subject_dn: Optional[str], sans: List[str], extensions: Dict[str, str]) -> CertificateSigningRequest: ...
    async def sign(self, tenant: str, key: str, version: int, payload: SignIn) -> bytes: ...
    async def verify(self, tenant: str, payload: VerifyIn, name_ref: Optional[str]) -> bool: ...
    async def encrypt(self, tenant: str, name_ref: str, payload: EncryptIn) -> Dict[str, bytes]: ...
    async def decrypt(self, tenant: str, name_ref: str, payload: DecryptIn) -> bytes: ...
    async def wrap_key(self, tenant: str, name_ref: str, payload: WrapIn) -> bytes: ...
    async def unwrap_key(self, tenant: str, name_ref: str, payload: UnwrapIn) -> bytes: ...
    async def attest_key(self, tenant: str, name_ref: str, payload: AttestIn) -> KeyAttestation: ...
    async def get_jwks(self, tenant: str, flt: Optional[str], include_inactive: bool) -> Jwks: ...


# ============================= DI hooks (override in app) =============================

async def get_key_service() -> KeyService:
    raise HTTPException(status_code=500, detail="KeyService is not configured")


def _etag_of(obj: Any) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _json_response(model: BaseModel, response: Response, cache_seconds: Optional[int] = None) -> BaseModel:
    etag = _etag_of(model.model_dump(by_alias=True))
    response.headers["ETag"] = etag
    if cache_seconds is not None:
        response.headers["Cache-Control"] = f"public, max-age={int(cache_seconds)}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return model


# ============================= Routes =============================

@router.post(
    "/tenants/{tenant}/keys",
    response_model=CryptoKey,
    status_code=status.HTTP_201_CREATED,
)
async def create_key(
    tenant: str = Path(..., min_length=1),
    payload: CreateKeyIn = Body(...),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    key = await svc.create_key(tenant, payload)
    return _json_response(key, response)


@router.post(
    "/tenants/{tenant}/keys:import",
    response_model=CryptoKey,
    status_code=status.HTTP_200_OK,
)
async def import_key(
    tenant: str = Path(..., min_length=1),
    payload: ImportKeyVersionIn = Body(...),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    key = await svc.import_key(tenant, payload)
    return _json_response(key, response)


@router.get(
    "/tenants/{tenant}/keys/{key}",
    response_model=CryptoKey,
    status_code=status.HTTP_200_OK,
)
async def get_key(
    tenant: str = Path(..., min_length=1),
    key: str = Path(..., min_length=1),
    include_versions: bool = Query(False),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    res = await svc.get_key(tenant, key, include_versions)
    return _json_response(res, response)


@router.get(
    "/tenants/{tenant}/keys",
    response_model=ListKeysOut,
    status_code=status.HTTP_200_OK,
)
async def list_keys(
    tenant: str = Path(..., min_length=1),
    page_size: int = Query(50, ge=1, le=500),
    page_token: Optional[str] = Query(None),
    filter: Optional[str] = Query(None, alias="filter"),
    order_by: Optional[str] = Query(None),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    items, next_token = await svc.list_keys(tenant, page_size, page_token, filter, order_by)
    out = ListKeysOut(keys=items, next_page_token=next_token)
    return _json_response(out, response)


@router.patch(
    "/tenants/{tenant}/keys/{key}",
    response_model=CryptoKey,
    status_code=status.HTTP_200_OK,
)
async def update_key(
    tenant: str,
    key: str,
    payload: UpdateKeyIn = Body(...),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    res = await svc.update_key(tenant, key, payload)
    return _json_response(res, response)


@router.post(
    "/tenants/{tenant}/keys/{key}:rotate",
    response_model=CryptoKey,
)
async def rotate_key(
    tenant: str,
    key: str,
    payload: RotateKeyIn = Body(default=RotateKeyIn()),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    res = await svc.rotate_key(tenant, key, payload)
    return _json_response(res, response)


@router.post(
    "/tenants/{tenant}/keys/{key}/versions/{version}:schedule-destruction",
    response_model=KeyVersion,
)
async def schedule_key_destruction(
    tenant: str,
    key: str,
    version: int = Path(..., ge=1),
    payload: ScheduleDestructionIn = Body(default=ScheduleDestructionIn()),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    res = await svc.schedule_key_destruction(tenant, key, version, payload)
    return _json_response(res, response)


@router.post(
    "/tenants/{tenant}/keys/{key}/versions/{version}:restore",
    response_model=KeyVersion,
)
async def restore_key_version(
    tenant: str,
    key: str,
    version: int = Path(..., ge=1),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    res = await svc.restore_key_version(tenant, key, version)
    return _json_response(res, response)


@router.get(
    "/tenants/{tenant}/keys/{key}/versions/{version}/public",
    response_model=PublicKey,
)
async def get_public_key(
    tenant: str,
    key: str,
    version: int = Path(..., ge=1),
    preferred_encoding: Optional[KeyEncoding] = Query(None),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    res = await svc.get_public_key(tenant, key, version, preferred_encoding)
    # публичный ключ можно кешировать безопасно
    return _json_response(res, response, cache_seconds=int(timedelta(hours=1).total_seconds()))


@router.post(
    "/tenants/{tenant}/keys/{key}/versions/{version}:csr",
    response_model=CertificateSigningRequest,
)
async def generate_csr(
    tenant: str,
    key: str,
    version: int = Path(..., ge=1),
    subject_dn: Optional[str] = Body(None),
    subject_alt_names: List[str] = Body(default_factory=list),
    extensions: Dict[str, str] = Body(default_factory=dict),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    res = await svc.generate_csr(tenant, key, version, subject_dn, subject_alt_names, extensions)
    return _json_response(res, response)


@router.post(
    "/tenants/{tenant}/keys/{key}/versions/{version}:sign",
    responses={200: {"content": {"application/json": {}}}},
)
async def sign(
    tenant: str,
    key: str,
    version: int = Path(..., ge=1),
    payload: SignIn = Body(...),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    sig = await svc.sign(tenant, key, version, payload)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return {"signature": sig.decode("utf-8") if isinstance(sig, bytes) else sig}


@router.post(
    "/tenants/{tenant}/keys:verify",
    responses={200: {"content": {"application/json": {}}}},
)
async def verify(
    tenant: str,
    payload: VerifyIn = Body(...),
    name_ref: Optional[str] = Query(None, description="Полное имя ключа/версии, если public_key не задан"),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    ok = await svc.verify(tenant, payload, name_ref)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return {"valid": bool(ok)}


@router.post(
    "/tenants/{tenant}/keys/{name_ref}:encrypt",
    responses={200: {"content": {"application/json": {}}}},
)
async def encrypt(
    tenant: str,
    name_ref: str = Path(..., description="keys/{key} или keys/{key}/versions/{version}"),
    payload: EncryptIn = Body(...),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    out = await svc.encrypt(tenant, name_ref, payload)
    response.headers["X-Content-Type-Options"] = "nosniff"
    # ожидаем поля ciphertext, iv, tag (при AEAD)
    result = {k: (v.decode("utf-8") if isinstance(v, bytes) else v) for k, v in out.items()}
    return result


@router.post(
    "/tenants/{tenant}/keys/{name_ref}:decrypt",
    responses={200: {"content": {"application/json": {}}}},
)
async def decrypt(
    tenant: str,
    name_ref: str,
    payload: DecryptIn = Body(...),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    pt = await svc.decrypt(tenant, name_ref, payload)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return {"plaintext": pt.decode("utf-8") if isinstance(pt, bytes) else pt}


@router.post(
    "/tenants/{tenant}/keys/{name_ref}:wrap",
    responses={200: {"content": {"application/json": {}}}},
)
async def wrap_key(
    tenant: str,
    name_ref: str,
    payload: WrapIn = Body(...),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    wrapped = await svc.wrap_key(tenant, name_ref, payload)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return {"wrapped_key": wrapped.decode("utf-8") if isinstance(wrapped, bytes) else wrapped}


@router.post(
    "/tenants/{tenant}/keys/{name_ref}:unwrap",
    responses={200: {"content": {"application/json": {}}}},
)
async def unwrap_key(
    tenant: str,
    name_ref: str,
    payload: UnwrapIn = Body(...),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    keymat = await svc.unwrap_key(tenant, name_ref, payload)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return {"key_material": keymat.decode("utf-8") if isinstance(keymat, bytes) else keymat}


@router.post(
    "/tenants/{tenant}/keys/{name_ref}:attest",
    response_model=KeyAttestation,
)
async def attest_key(
    tenant: str,
    name_ref: str,
    payload: AttestIn = Body(default=AttestIn()),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    res = await svc.attest_key(tenant, name_ref, payload)
    return _json_response(res, response)


@router.get(
    "/tenants/{tenant}/.well-known/jwks.json",
    response_model=Jwks,
)
async def get_jwks(
    tenant: str,
    filter: Optional[str] = Query(None, alias="filter"),
    include_inactive: bool = Query(False),
    svc: KeyService = Depends(get_key_service),
    response: Response = None,
):
    jwks = await svc.get_jwks(tenant, filter, include_inactive)
    # JWKS безопасно кешировать на короткое время (ротация ключей учитывается)
    return _json_response(jwks, response, cache_seconds=int(timedelta(minutes=5).total_seconds()))


# ============================= Error handlers (optional wiring) =============================

@router.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    return Response(
        content=json.dumps({"error": "http_error", "status": exc.status_code, "detail": exc.detail}),
        status_code=exc.status_code,
        media_type="application/json",
        headers={"X-Content-Type-Options": "nosniff"},
    )
