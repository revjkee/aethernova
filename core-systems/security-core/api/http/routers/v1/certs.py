"""
PKI HTTP Router (v1) — security-core

Функции:
- CA: создание root/intermediate, просмотр, список.
- CSR: создание заявки (без возврата приватного ключа), просмотр, список.
- Certificates: выпуск по CSR, просмотр, список, цепочка, отзыв.
- CRL: генерация и выдача PEM CRL по CA.
- OCSP (упрощ.): статус GOOD/REVOKED/UNKNOWN на основе локального реестра.
Безопасность:
- RBAC (require_scopes), Rate limit (token-bucket), идемпотентность по заголовку Idempotency-Key,
  аудит (фоновые события), единый формат ошибок, пагинация.

Зависимости:
- fastapi>=0.110, pydantic>=2.5, cryptography>=41 (для x509).
В продакшн:
- Хранение: заменить in-memory на БД.
- Ключи: вынести в HSM/KMS, отключить импорт приватных ключей через API.
"""

from __future__ import annotations

import ipaddress
import logging
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Callable, Annotated

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, EmailStr

# cryptography
from cryptography import x509
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import ExtensionOID

# ------------------------------------------------------------
# Логирование
# ------------------------------------------------------------
logger = logging.getLogger("security_core.certs")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ------------------------------------------------------------
# Ошибки / RBAC / Общие структуры (совместимо с admin.py)
# ------------------------------------------------------------

class ErrorCode(str, Enum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    UNAUTHORIZED = "UNAUTHORIZED"
    INVALID_INPUT = "INVALID_INPUT"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    RATE_LIMITED = "RATE_LIMITED"
    INTERNAL = "INTERNAL"
    IDEMPOTENCY_REPLAY = "IDEMPOTENCY_REPLAY"

class AuthScope(str, Enum):
    PKI_ADMIN = "PKI_ADMIN"
    PKI_READ = "PKI_READ"
    SECURITY_AUDITOR = "SECURITY_AUDITOR"
    # Доп. скопы при необходимости
    IAM_READ = "IAM_READ"

class Error(BaseModel):
    code: ErrorCode
    message: str
    details: Optional[Dict[str, Any]] = None

class OperationOk(BaseModel):
    ok: bool = True

class PageMeta(BaseModel):
    limit: int
    next_cursor: Optional[str] = Field(None, alias="nextCursor")
    total: int

class Page(BaseModel):
    data: List[Any]
    meta: PageMeta

class Principal(BaseModel):
    id: str
    name: str
    scopes: List[AuthScope]

class SecurityContext(BaseModel):
    principal: Principal
    tenant_id: Optional[str] = None

def get_security_context(
    authorization: Annotated[Optional[str], Header(alias="Authorization")] = None,
) -> SecurityContext:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=Error(code=ErrorCode.UNAUTHENTICATED, message="Missing Authorization").model_dump(),
        )
    token = authorization.replace("Bearer", "").strip()
    if token == "admin":
        scopes = [s for s in AuthScope]
    elif token == "pki":
        scopes = [AuthScope.PKI_ADMIN, AuthScope.PKI_READ]
    elif token == "auditor":
        scopes = [AuthScope.PKI_READ, AuthScope.SECURITY_AUDITOR]
    else:
        raise HTTPException(status_code=401, detail=Error(code=ErrorCode.UNAUTHENTICATED, message="Invalid token").model_dump())
    principal = Principal(id="u-" + token, name=token, scopes=scopes)
    return SecurityContext(principal=principal, tenant_id="t-default")

def require_scopes(*required: AuthScope) -> Callable[[SecurityContext], SecurityContext]:
    def _checker(ctx: SecurityContext = Depends(get_security_context)) -> SecurityContext:
        have = set(ctx.principal.scopes)
        need = set(required)
        if not need.issubset(have):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=Error(code=ErrorCode.UNAUTHORIZED, message=f"Missing scopes: {sorted(need - have)}").model_dump(),
            )
        return ctx
    return _checker

# Rate limit (in-memory)
_BUCKETS: Dict[str, Tuple[float, float]] = {}
def rate_limiter(
    request: Request,
    response: Response,
    ctx: SecurityContext = Depends(get_security_context),
    max_per_minute: int = 180,
):
    key = f"{ctx.principal.id}:{request.url.path}"
    now = time.time()
    refill_rate = max_per_minute / 60.0
    tokens, last = _BUCKETS.get(key, (max_per_minute, now))
    tokens = min(max_per_minute, tokens + (now - last) * refill_rate)
    if tokens < 1:
        response.headers["X-RateLimit-Limit"] = str(max_per_minute)
        response.headers["X-RateLimit-Remaining"] = "0"
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=Error(code=ErrorCode.RATE_LIMITED, message="Rate limit exceeded").model_dump(),
        )
    _BUCKETS[key] = (tokens - 1, now)
    response.headers["X-RateLimit-Limit"] = str(max_per_minute)
    response.headers["X-RateLimit-Remaining"] = str(int(tokens - 1))

# Идемпотентность (in-memory)
_IDEMPOTENCY_CACHE: Dict[str, Tuple[int, Dict[str, Any], float]] = {}
def idempotency_guard(
    request: Request,
    response: Response,
    idempotency_key: Annotated[Optional[str], Header(alias="Idempotency-Key")] = None,
):
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if not idempotency_key:
            return
        now = time.time()
        hit = _IDEMPOTENCY_CACHE.get(idempotency_key)
        if hit and (now - hit[2] < 600):
            status_code, payload, _ = hit
            response.headers["Idempotency-Replayed"] = "true"
            raise HTTPException(
                status_code=status_code,
                detail=Error(code=ErrorCode.IDEMPOTENCY_REPLAY, message="Replayed idempotent request").model_dump() | {"payload": payload},
            )
        request.state.idem_key = idempotency_key

def save_idempotency_result(request: Request, status_code: int, payload: Dict[str, Any]):
    idem_key = getattr(request.state, "idem_key", None)
    if idem_key:
        _IDEMPOTENCY_CACHE[idem_key] = (status_code, payload, time.time())

# Аудит
_AUDIT_LOG: List[Dict[str, Any]] = []
def emit_audit(
    background: BackgroundTasks,
    action: str,
    ctx: SecurityContext,
    outcome: str = "ALLOW",
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
):
    def _task():
        evt = {
            "id": str(uuid.uuid4()),
            "time": time.time(),
            "action": action,
            "actor_id": ctx.principal.id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome,
            "details": details or {},
        }
        _AUDIT_LOG.append(evt)
        logger.info("AUDIT %s", evt)
    background.add_task(_task)

# ------------------------------------------------------------
# PKI: модели DTO
# ------------------------------------------------------------

class KeyAlgorithm(str, Enum):
    RSA_2048 = "RSA_2048"
    RSA_3072 = "RSA_3072"
    RSA_4096 = "RSA_4096"
    EC_P256 = "EC_P256"
    EC_P384 = "EC_P384"

class CertificateStatus(str, Enum):
    GOOD = "GOOD"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    UNKNOWN = "UNKNOWN"

class CaCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    is_root: bool = Field(True, alias="isRoot")
    parent_id: Optional[str] = Field(None, alias="parentId", description="Для intermediate CA")
    subject: Dict[str, str] = Field(
        ..., description="DN поля, напр.: {C:'SE', O:'Aethernova', CN:'Aethernova Root CA'}"
    )
    path_len: Optional[int] = Field(1, alias="pathLen", ge=0, le=5)
    algo: KeyAlgorithm = Field(KeyAlgorithm.RSA_3072, description="Алгоритм ключа CA")
    not_after_days: int = Field(3650, alias="notAfterDays", ge=365, le=36500)

class CaOut(BaseModel):
    id: str
    name: str
    subject: str
    is_root: bool = Field(..., alias="isRoot")
    parent_id: Optional[str] = Field(None, alias="parentId")
    path_len: Optional[int] = Field(None, alias="pathLen")
    pem: str
    created_at: float = Field(..., alias="createdAt")

    class Config:
        populate_by_name = True

class CsrCreate(BaseModel):
    subject: Dict[str, str] = Field(..., description="DN")
    san_dns: Optional[List[str]] = Field(None, alias="sanDNS")
    san_ip: Optional[List[str]] = Field(None, alias="sanIP")
    algo: KeyAlgorithm = Field(KeyAlgorithm.RSA_2048)
    # Приватный ключ НЕ возвращаем. Для демо можно сохранить в памяти (не делайте так в проде).

class CsrOut(BaseModel):
    id: str
    csr_pem: str = Field(..., alias="csrPem")
    subject: str
    san_dns: Optional[List[str]] = Field(None, alias="sanDNS")
    san_ip: Optional[List[str]] = Field(None, alias="sanIP")
    status: str
    requested_at: float = Field(..., alias="requestedAt")
    approved_at: Optional[float] = Field(None, alias="approvedAt")
    class Config:
        populate_by_name = True

class CertIssueByCsr(BaseModel):
    request_id: str = Field(..., alias="requestId")
    ca_id: str = Field(..., alias="caId")
    not_after_days: int = Field(397, alias="notAfterDays", ge=1, le=825)  # баланс совместимости

class CertOut(BaseModel):
    id: str
    serial: str
    subject: str
    issuer: str
    not_before: float = Field(..., alias="notBefore")
    not_after: float = Field(..., alias="notAfter")
    status: CertificateStatus
    fingerprint_sha256: str = Field(..., alias="fingerprint")
    san_dns: Optional[List[str]] = Field(None, alias="sanDNS")
    san_ip: Optional[List[str]] = Field(None, alias="sanIP")
    pem: str
    ca_id: str = Field(..., alias="caId")
    created_at: float = Field(..., alias="createdAt")

    class Config:
        populate_by_name = True

class RevokeCert(BaseModel):
    reason: Optional[str] = Field(None, max_length=256)

# ------------------------------------------------------------
# Вспомогательные функции PKI
# ------------------------------------------------------------

def _now() -> float:
    return time.time()

def _pydn_to_x509_name(dn: Dict[str, str]) -> x509.Name:
    mapping = {
        "C": NameOID.COUNTRY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "L": NameOID.LOCALITY_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "CN": NameOID.COMMON_NAME,
        "emailAddress": NameOID.EMAIL_ADDRESS,
        "serialNumber": NameOID.SERIAL_NUMBER,
    }
    rdns = []
    for k, v in dn.items():
        oid = mapping.get(k)
        if not oid:
            raise HTTPException(status_code=400, detail=Error(code=ErrorCode.INVALID_INPUT, message=f"Unsupported DN attribute: {k}").model_dump())
        rdns.append(x509.NameAttribute(oid, v))
    return x509.Name(rdns)

def _algo_gen(algo: KeyAlgorithm):
    if algo == KeyAlgorithm.RSA_2048:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if algo == KeyAlgorithm.RSA_3072:
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if algo == KeyAlgorithm.RSA_4096:
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    if algo == KeyAlgorithm.EC_P256:
        return ec.generate_private_key(ec.SECP256R1())
    if algo == KeyAlgorithm.EC_P384:
        return ec.generate_private_key(ec.SECP384R1())
    raise HTTPException(status_code=400, detail=Error(code=ErrorCode.INVALID_INPUT, message="Unsupported algorithm").model_dump())

def _pubkey_algo(private_key):
    if isinstance(private_key, rsa.RSAPrivateKey):
        return "RSA"
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return "EC"
    return "OTHER"

def _pem_private_key(priv) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

def _pem_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

def _sha256_fp(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()

def _name_to_str(name: x509.Name) -> str:
    return ", ".join([f"{attr.oid._name}={attr.value}" for attr in name])

def _build_san(san_dns: Optional[List[str]], san_ip: Optional[List[str]]):
    san = []
    if san_dns:
        for d in san_dns:
            san.append(x509.DNSName(d))
    if san_ip:
        for s in san_ip:
            ip = ipaddress.ip_address(s)
            san.append(x509.IPAddress(ip))
    return x509.SubjectAlternativeName(san) if san else None

# ------------------------------------------------------------
# In-memory хранилища
# ------------------------------------------------------------
_CAS: Dict[str, Dict[str, Any]] = {}
_CSRS: Dict[str, Dict[str, Any]] = {}
_CERTS: Dict[str, Dict[str, Any]] = {}
_REVOKED: Dict[str, Dict[str, Any]] = {}  # key: cert_id

# ------------------------------------------------------------
# Роутер
# ------------------------------------------------------------
router = APIRouter(
    prefix="/api/v1/certs",
    tags=["PKI"],
    dependencies=[Depends(rate_limiter), Depends(idempotency_guard)],
)

# ---------------------- CA ----------------------

@router.get(
    "/ca",
    response_model=Page,
    responses={401: {"model": Error}, 403: {"model": Error}},
)
def list_cas(
    response: Response,
    limit: int = Query(20, ge=1, le=200),
    start_after: Optional[str] = Query(None),
    ctx: SecurityContext = Depends(require_scopes(AuthScope.PKI_READ)),
):
    items = list(_CAS.values())
    items.sort(key=lambda c: (c["createdAt"], c["id"]))
    def _page(items_, limit_, cursor_):
        if cursor_:
            try:
                idx = next(i for i, it in enumerate(items_) if it["id"] == cursor_)
                start = idx + 1
            except StopIteration:
                start = 0
        else:
            start = 0
        batch = items_[start:start + limit_]
        next_cursor = batch[-1]["id"] if len(batch) == limit_ and (start + limit_) < len(items_) else None
        return batch, next_cursor
    batch, next_cursor = _page(items, limit, start_after)
    total = len(items)
    if next_cursor:
        response.headers["Link"] = f'</api/v1/certs/ca?start_after={next_cursor}&limit={limit}>; rel="next"'
    return Page(data=batch, meta=PageMeta(limit=limit, nextCursor=next_cursor, total=total))

@router.post(
    "/ca",
    response_model=CaOut,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": Error}, 401: {"model": Error}, 403: {"model": Error}},
)
def create_ca(
    request: Request,
    payload: CaCreate,
    background: BackgroundTasks,
    ctx: SecurityContext = Depends(require_scopes(AuthScope.PKI_ADMIN)),
):
    if not payload.is_root and not payload.parent_id:
        raise HTTPException(status_code=400, detail=Error(code=ErrorCode.INVALID_INPUT, message="parentId required for intermediate CA").model_dump())
    if not payload.is_root and payload.parent_id not in _CAS:
        raise HTTPException(status_code=404, detail=Error(code=ErrorCode.NOT_FOUND, message="Parent CA not found").model_dump())

    priv = _algo_gen(payload.algo)
    subject = _pydn_to_x509_name(payload.subject)
    now = int(time.time())
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject).issuer_name(subject)
    builder = builder.public_key(priv.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(x509.datetime.datetime.utcfromtimestamp(now - 1))
    builder = builder.not_valid_after(x509.datetime.datetime.utcfromtimestamp(now + payload.not_after_days * 86400))
    # CA extensions
    basic = x509.BasicConstraints(ca=True, path_length=(payload.path_len if payload.is_root else payload.path_len))
    builder = builder.add_extension(basic, critical=True)
    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )
    builder = builder.add_extension(key_usage, critical=True)
    subject_key_id = x509.SubjectKeyIdentifier.from_public_key(priv.public_key())
    builder = builder.add_extension(subject_key_id, critical=False)

    # Self-signed (root) или подпись родителем
    if payload.is_root:
        issuer_priv = priv
        issuer_name = subject
        parent_id = None
    else:
        parent = _CAS[payload.parent_id]
        issuer_priv = parent["private_key"]
        issuer_name = parent["cert"].subject
        parent_id = parent["id"]
        # Authority Key Identifier от родителя
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_priv.public_key())
        builder = builder.add_extension(aki, critical=False)

    cert = builder.sign(private_key=issuer_priv, algorithm=hashes.SHA256())
    ca_id = "ca-" + uuid.uuid4().hex
    rec = {
        "id": ca_id,
        "name": payload.name,
        "isRoot": payload.is_root,
        "parentId": parent_id,
        "pathLen": payload.path_len,
        "cert": cert,
        "private_key": priv,
        "pem": _pem_cert(cert),
        "subject": _name_to_str(cert.subject),
        "createdAt": _now(),
        "crl_serials": set(),  # набор серийников отозванных
    }
    _CAS[ca_id] = rec
    emit_audit(background, action="CA_CREATE", ctx=ctx, resource_type="CA", resource_id=ca_id, details={"name": payload.name})
    body = CaOut(
        id=ca_id,
        name=rec["name"],
        subject=rec["subject"],
        isRoot=rec["isRoot"],
        parentId=rec["parentId"],
        pathLen=rec["pathLen"],
        pem=rec["pem"],
        createdAt=rec["createdAt"],
    ).model_dump(by_alias=True)
    save_idempotency_result(request, status.HTTP_201_CREATED, body)
    return body

@router.get(
    "/ca/{ca_id}",
    response_model=CaOut,
    responses={404: {"model": Error}, 401: {"model": Error}, 403: {"model": Error}},
)
def get_ca(
    ca_id: str,
    ctx: SecurityContext = Depends(require_scopes(AuthScope.PKI_READ)),
):
    rec = _CAS.get(ca_id)
    if not rec:
        raise HTTPException(status_code=404, detail=Error(code=ErrorCode.NOT_FOUND, message="CA not found").model_dump())
    return CaOut(
        id=rec["id"],
        name=rec["name"],
        subject=rec["subject"],
        isRoot=rec["isRoot"],
        parentId=rec["parentId"],
        pathLen=rec["pathLen"],
        pem=rec["pem"],
        createdAt=rec["createdAt"],
    )

# ---------------------- CSR ----------------------

@router.post(
    "/csr",
    response_model=CsrOut,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": Error}, 401: {"model": Error}, 403: {"model": Error}},
)
def create_csr(
    request: Request,
    payload: CsrCreate,
    background: BackgroundTasks,
    ctx: SecurityContext = Depends(require_scopes(AuthScope.PKI_ADMIN)),
):
    subject = _pydn_to_x509_name(payload.subject)
    priv = _algo_gen(payload.algo)
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    san_ext = _build_san(payload.san_dns, payload.san_ip)
    if san_ext:
        csr_builder = csr_builder.add_extension(san_ext, critical=False)
    csr = csr_builder.sign(priv, hashes.SHA256())
    csr_id = "csr-" + uuid.uuid4().hex
    rec = {
        "id": csr_id,
        "subject": _name_to_str(subject),
        "sanDNS": payload.san_dns or [],
        "sanIP": payload.san_ip or [],
        "csr": csr,
        "csrPem": csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "private_key": priv,  # только для демо; в проде храните вне API
        "status": "PENDING",
        "requestedAt": _now(),
        "approvedAt": None,
        "issuedCertId": None,
    }
    _CSRS[csr_id] = rec
    emit_audit(background, action="CERT_CSR_CREATE", ctx=ctx, resource_type="CERTIFICATE_REQUEST", resource_id=csr_id)
    body = CsrOut(
        id=csr_id,
        csrPem=rec["csrPem"],
        subject=rec["subject"],
        sanDNS=rec["sanDNS"],
        sanIP=rec["sanIP"],
        status=rec["status"],
        requestedAt=rec["requestedAt"],
        approvedAt=rec["approvedAt"],
    ).model_dump(by_alias=True)
    save_idempotency_result(request, status.HTTP_201_CREATED, body)
    return body

@router.get(
    "/csr",
    response_model=Page,
    responses={401: {"model": Error}, 403: {"model": Error}},
)
def list_csrs(
    response: Response,
    limit: int = Query(20, ge=1, le=200),
    start_after: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None),
    ctx: SecurityContext = Depends(require_scopes(AuthScope.PKI_READ)),
):
    items = list(_CSRS.values())
    if status_filter:
        items = [c for c in items if c["status"] == status_filter]
    items.sort(key=lambda c: (c["requestedAt"], c["id"]))
    def _page(items_, limit_, cursor_):
        if cursor_:
            try:
                idx = next(i for i, it in enumerate(items_) if it["id"] == cursor_)
                start = idx + 1
            except StopIteration:
                start = 0
        else:
            start = 0
        batch = items_[start:start + limit_]
        next_cursor = batch[-1]["id"] if len(batch) == limit_ and (start + limit_) < len(items_) else None
        return batch, next_cursor
    batch, next_cursor = _page(items, limit, start_after)
    total = len(items)
    if next_cursor:
        response.headers["Link"] = f'</api/v1/certs/csr?start_after={next_cursor}&limit={limit}>; rel="next"'
    # маппинг к DTO
    out = [
        CsrOut(
            id=r["id"], csrPem=r["csrPem"], subject=r["subject"], sanDNS=r["sanDNS"], sanIP=r["sanIP"],
            status=r["status"], requestedAt=r["requestedAt"], approvedAt=r["approvedAt"]
        ).model_dump(by_alias=True) for r in batch
    ]
    return Page(data=out, meta=PageMeta(limit=limit, nextCursor=next_cursor, total=total))

@router.get(
    "/csr/{request_id}",
    response_model=CsrOut,
    responses={404: {"model": Error}, 401: {"model": Error}, 403: {"model": Error}},
)
def get_csr(
    request_id: str,
    ctx: SecurityContext = Depends(require_scopes(AuthScope.PKI_READ)),
):
    rec = _CSRS.get(request_id)
    if not rec:
        raise HTTPException(status_code=404, detail=Error(code=ErrorCode.NOT_FOUND, message="CSR not found").model_dump())
    return CsrOut(
        id=rec["id"], csrPem=rec["csrPem"], subject=rec["subject"],
        sanDNS=rec["sanDNS"], sanIP=rec["sanIP"], status=rec["status"],
        requestedAt=rec["requestedAt"], approvedAt=rec["approvedAt"]
    )

# ---------------------- Certificates ----------------------

@router.post(
    "/certs:issueByCsr",
    response_model=CertOut,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": Error}, 401: {"model": Error}, 403: {"model": Error}, 404: {"model": Error}},
)
def issue_certificate_by_csr(
    request: Request,
    payload: CertIssueByCsr,
    background: BackgroundTasks,
    ctx: SecurityContext = Depends(require_scopes(AuthScope.PKI_ADMIN)),
):
    csr_rec = _CSRS.get(payload.request_id)
    if not csr_rec:
        raise HTTPException(status_code=404, detail=Error(code=ErrorCode.NOT_FOUND, message="CSR not found").model_dump())
    if csr_rec["status"] not in ("PENDING",):
        raise HTTPException(status_code=409, detail=Error(code=ErrorCode.CONFLICT, message="CSR already processed").model_dump())
    ca = _CAS.get(payload.ca_id)
    if not ca:
        raise HTTPException(status_code=404, detail=Error(code=ErrorCode.NOT_FOUND, message="CA not found").model_dump())

    csr: x509.CertificateSigningRequest = csr_rec["csr"]
    now = int(time.time())
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject).issuer_name(ca["cert"].subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(x509.datetime.datetime.utcfromtimestamp(now - 1))
    builder = builder.not_valid_after(x509.datetime.datetime.utcfromtimestamp(now + payload.not_after_days * 86400))

    # перенесем SAN из CSR
    try:
        csr_san = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        builder = builder.add_extension(csr_san, critical=False)
    except x509.ExtensionNotFound:
        pass

    # Key Usage/Ext Key Usage
    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    builder = builder.add_extension(key_usage, critical=True)

    eku = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])
    builder = builder.add_extension(eku, critical=False)

    # SKI/AKI
    ski = x509.SubjectKeyIdentifier.from_public_key(csr.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca["private_key"].public_key())
    builder = builder.add_extension(ski, critical=False)
    builder = builder.add_extension(aki, critical=False)

    cert = builder.sign(private_key=ca["private_key"], algorithm=hashes.SHA256())

    cert_id = "crt-" + uuid.uuid4().hex
    rec = {
        "id": cert_id,
        "cert": cert,
        "pem": _pem_cert(cert),
        "caId": ca["id"],
        "serial": format(cert.serial_number, "x").upper(),
        "subject": _name_to_str(cert.subject),
        "issuer": _name_to_str(cert.issuer),
        "notBefore": cert.not_valid_before.timestamp(),
        "notAfter": cert.not_valid_after.timestamp(),
        "status": "GOOD",
        "fingerprint": _sha256_fp(cert),
        "sanDNS": csr_rec["sanDNS"],
        "sanIP": csr_rec["sanIP"],
        "createdAt": _now(),
    }
    _CERTS[cert_id] = rec
    csr_rec["status"] = "ISSUED"
    csr_rec["approvedAt"] = _now()
    csr_rec["issuedCertId"] = cert_id

    emit_audit(background, action="CERT_ISSUE", ctx=ctx, resource_type="CERTIFICATE", resource_id=cert_id, details={"request_id": payload.request_id, "ca_id": payload.ca_id})
    body = CertOut(
        id=rec["id"], serial=rec["serial"], subject=rec["subject"], issuer=rec["issuer"],
        notBefore=rec["notBefore"], notAfter=rec["notAfter"], status=CertificateStatus.GOOD,
        fingerprint=rec["fingerprint"], sanDNS=rec["sanDNS"], sanIP=rec["sanIP"], pem=rec["pem"],
        caId=rec["caId"], createdAt=rec["createdAt"]
    ).model_dump(by_alias=True)
    save_idempotency_result(request, status.HTTP_201_CREATED, body)
    return body

@router.get(
    "/certs",
    response_model=Page,
    responses={401: {"model": Error}, 403: {"model": Error}},
)
def list_certs(
    response: Response,
    limit: int = Query(20, ge=1, le=200),
    start_after: Optional[str] = Query(None),
    status_filter: Optional[CertificateStatus] = Query(None),
    cn: Optional[str] = Query(None, description="Фильтр по CN подстроке"),
    ctx: SecurityContext = Depends(require_scopes(AuthScope.PKI_READ)),
):
    items = list(_CERTS.values())
    if status_filter:
        items = [c for c in items if c["status"] == status_filter.value]
    if cn:
        items = [c for c in items if "CN=" in c["subject"] and cn.lower() in c["subject"].lower()]
    items.sort(key=lambda c: (c["createdAt"], c["id"]))
    def _page(items_, limit_, cursor_):
        if cursor_:
            try:
                idx = next(i for i, it in enumerate(items_) if it["id"] == cursor_)
                start = idx + 1
            except StopIteration:
                start = 0
        else:
            start = 0
        batch = items_[start:start + limit_]
        next_cursor = batch[-1]["id"] if len(batch) == limit_ and (start + limit_) < len(items_) else None
        return batch, next_cursor
    batch, next_cursor = _page(items, limit, start_after)
    total = len(items)
    if next_cursor:
        response.headers["Link"] = f'</api/v1/certs/certs?start_after={next_cursor}&limit={limit}>; rel="next"'
    out = [
        CertOut(
            id=r["id"], serial=r["serial"], subject=r["subject"], issuer=r["issuer"],
            notBefore=r["notBefore"], notAfter=r["notAfter"],
            status=CertificateStatus(r["status"]), fingerprint=r["fingerprint"],
            sanDNS=r["sanDNS"], sanIP=r["sanIP"], pem=r["pem"], caId=r["caId"], createdAt=r["createdAt"]
        ).model_dump(by_alias=True) for r in batch
    ]
    return Page(data=out, meta=PageMeta(limit=limit, nextCursor=next_cursor, total=total))

@router.get(
    "/certs/{cert_id}",
    response_model=CertOut,
    responses={404: {"model": Error}, 401: {"model": Error}, 403: {"model": Error}},
)
def get_cert(
    cert_id: str,
    ctx: SecurityContext = Depends(require_scopes(AuthScope.PKI_READ)),
):
    rec = _CERTS.get(cert_id)
    if not rec:
        raise HTTPException(status_code=404, detail=Error(code=ErrorCode.NOT_FOUND, message="Certificate not found").model_dump())
    return CertOut(
        id=rec["id"], serial=rec["serial"], subject=rec["subject"], issuer=rec["issuer"],
        notBefore=rec["notBefore"], notAfter=rec["notAfter"], status=CertificateStatus(rec["status"]),
        fingerprint=rec["fingerprint"], sanDNS=rec["sanDNS"], sanIP=rec["sanIP"], pem=rec["pem"],
        caId=rec["caId"], createdAt=rec["createdAt"]
    )

@router.get(
    "/certs/{cert_id}/chain",
    response_model=List[str],
    responses={404: {"model": Error}, 401: {"model": Error}, 403: {"model": Error}},
)
def get_chain(
    cert_id: str,
    ctx: SecurityContext = Depends(require_scopes(AuthScope.PKI_READ)),
):
    rec = _CERTS.get(cert_id)
    if not rec:
        raise HTTPException(status_code=404, detail=Error(code=ErrorCode.NOT_FOUND, message="Certificate not found").model_dump())
    chain = [rec["pem"]]
    ca = _CAS.get(rec["caId"])
    while ca:
        chain.append(ca["pem"])
        if not ca["parentId"]:
            break
        ca = _CAS.get(ca["parentId"])
    return chain

@router.post(
    "/certs/{cert_id}:revoke",
    response_model=OperationOk,
    responses={404: {"model": Error}, 401: {"model": Error}, 403: {"model": Error}},
)
def revoke_cert(
    request: Request,
    cert_id: str,
    payload: RevokeCert,
    background: BackgroundTasks,
    ctx: SecurityContext = Depends(require_scopes(AuthScope.PKI_ADMIN)),
):
    rec = _CERTS.get(cert_id)
    if not rec:
        raise HTTPException(status_code=404, detail=Error(code=ErrorCode.NOT_FOUND, message="Certificate not found").model_dump())
    if rec["status"] == "REVOKED":
        return OperationOk(ok=True)

    rec["status"] = "REVOKED"
    _REVOKED[cert_id] = {"reason": payload.reason or "unspecified", "time": _now(), "serial": rec["serial"], "caId": rec["caId"]}
    _CAS[rec["caId"]]["crl_serials"].add(rec["serial"])
    emit_audit(background, action="CERT_REVOKE", ctx=ctx, resource_type="CERTIFICATE", resource_id=cert_id, details={"reason": payload.reason})
    body = OperationOk(ok=True).model_dump()
    save_idempotency_result(request, status.HTTP_200_OK, body)
    return body

# ---------------------- CRL / OCSP (simple) ----------------------

@router.get(
    "/crl/{ca_id}",
    response_model=str,
    responses={404: {"model": Error}, 401: {"model": Error}, 403: {"model": Error}},
)
def get_crl_pem(
    ca_id: str,
    ctx: SecurityContext = Depends(require_scopes(AuthScope.PKI_READ)),
):
    ca = _CAS.get(ca_id)
    if not ca:
        raise HTTPException(status_code=404, detail=Error(code=ErrorCode.NOT_FOUND, message="CA not found").model_dump())

    # Синтетическая CRL (не подписываем для простоты; при необходимости — подписывать как x509.CertificateRevocationList)
    # Для демонстрации вернём PEM сертификата CA плюс перечень отозванных серийников в текстовом блоке.
    lines = ["-----BEGIN X-REVOKED-SERIALS-----"]
    for s in sorted(ca["crl_serials"]):
        lines.append(s)
    lines.append("-----END X-REVOKED-SERIALS-----")
    return "\n".join([ca["pem"], *lines])

@router.get(
    "/ocsp/{cert_id}",
    response_model=str,
    responses={401: {"model": Error}, 403: {"model": Error}, 404: {"model": Error}},
)
def ocsp_status(
    cert_id: str,
    ctx: SecurityContext = Depends(require_scopes(AuthScope.PKI_READ)),
):
    rec = _CERTS.get(cert_id)
    if not rec:
        raise HTTPException(status_code=404, detail=Error(code=ErrorCode.NOT_FOUND, message="Certificate not found").model_dump())
    return "REVOKED" if rec["status"] == "REVOKED" else "GOOD"

# ---------------------- Demo bootstrap ----------------------

def _bootstrap_demo():
    # Root CA
    if not _CAS:
        req = CaCreate(
            name="Aethernova Root CA",
            isRoot=True,
            parentId=None,
            subject={"C": "SE", "O": "Aethernova", "CN": "Aethernova Root CA"},
            pathLen=2,
            algo=KeyAlgorithm.RSA_3072,
            notAfterDays=3650,
        )
        create_ca.__wrapped__(  # type: ignore
            request=type("obj", (), {"state": type("s", (), {})()})(),  # dummy request for idempotency
            payload=req,
            background=BackgroundTasks(),
            ctx=SecurityContext(principal=Principal(id="u-seed", name="seed", scopes=[AuthScope.PKI_ADMIN, AuthScope.PKI_READ])),
        )

_bootstrap_demo()
