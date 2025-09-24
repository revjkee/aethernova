# oblivionvault-core/api/http/routers/v1/evidence.py
# Industrial-grade Evidence API router for OblivionVault-Core
# Requires: fastapi, pydantic>=2, python-jose[cryptography], jsonschema>=4, httpx

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import json
import os
import typing as t
import uuid

import httpx
from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse
from jose import jwk, jwt
from jose.utils import base64url_decode
from jsonschema import Draft202012Validator

# --------------------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------------------

class Settings(t.TypedDict, total=False):
    # OIDC / JWT
    OIDC_ISSUER: str
    OIDC_AUDIENCE: str
    OIDC_JWKS_URL: str
    OIDC_JWKS_STATIC: str  # optional literal JWKS JSON
    JWKS_CACHE_TTL: int

    # Paths
    EVIDENCE_SCHEMA_PATH: str

    # Dev fallbacks
    DEV_INMEMORY: str  # "1" to enable

def get_settings() -> Settings:
    return {
        "OIDC_ISSUER": os.getenv("OVAULT_OIDC_ISSUER", "https://idp.oblivionvault.example"),
        "OIDC_AUDIENCE": os.getenv("OVAULT_OIDC_AUDIENCE", "oblivionvault-core"),
        "OIDC_JWKS_URL": os.getenv("OVAULT_OIDC_JWKS_URL", f'{os.getenv("OVAULT_OIDC_ISSUER","https://idp.oblivionvault.example")}/protocol/openid-connect/certs'),
        "OIDC_JWKS_STATIC": os.getenv("OVAULT_OIDC_JWKS_STATIC", ""),
        "JWKS_CACHE_TTL": int(os.getenv("OVAULT_JWKS_CACHE_TTL", "300")),
        "EVIDENCE_SCHEMA_PATH": os.getenv(
            "OVAULT_EVIDENCE_SCHEMA_PATH",
            os.path.join(os.path.dirname(__file__), "../../../../schemas/jsonschema/v1/evidence_package.schema.json"),
        ),
        "DEV_INMEMORY": os.getenv("OVAULT_DEV_INMEMORY", "0"),
    }

SETTINGS = get_settings()

# --------------------------------------------------------------------------------------
# Utilities: Request IDs, hashing, ULID-like
# --------------------------------------------------------------------------------------

ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

def make_ulid_like() -> str:
    ts = int(dt.datetime.utcnow().timestamp() * 1000)
    tpart = ""
    while ts > 0:
        tpart = ULID_ALPHABET[ts % 32] + tpart
        ts //= 32
    rpart = "".join(ULID_ALPHABET[n % 32] for n in os.urandom(16))
    return (tpart + rpart)[:26]

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# --------------------------------------------------------------------------------------
# JWKS cache and JWT verification
# --------------------------------------------------------------------------------------

class JWKSCache:
    def __init__(self, url: str, static_jwks: str = "", ttl: int = 300):
        self.url = url
        self.ttl = ttl
        self._jwks: dict | None = json.loads(static_jwks) if static_jwks else None
        self._exp = 0

    async def get(self) -> dict:
        now = int(dt.datetime.utcnow().timestamp())
        if self._jwks and now < self._exp:
            return self._jwks
        if self._jwks and self.ttl <= 0:
            return self._jwks
        # refresh
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(self.url)
            r.raise_for_status()
            self._jwks = r.json()
            self._exp = now + max(30, self.ttl)
            return self._jwks

JWKS = JWKSCache(
    url=SETTINGS["OIDC_JWKS_URL"],
    static_jwks=SETTINGS.get("OIDC_JWKS_STATIC", ""),
    ttl=int(SETTINGS["JWKS_CACHE_TTL"]),
)

class User(t.TypedDict, total=False):
    sub: str
    email: str
    roles: t.List[str]
    scopes: t.List[str]

async def get_current_user(
    request: Request,
    authorization: t.Annotated[str | None, Header(alias="Authorization")] = None,
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        unverified = jwt.get_unverified_header(token)
        kid = unverified.get("kid")
        jwks = await JWKS.get()
        key = None
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                key = k
                break
        if not key:
            raise HTTPException(status_code=401, detail="Signing key not found")
        claims = jwt.decode(
            token,
            jwk.construct(key),
            algorithms=[key.get("alg", "RS256"), "RS256", "ES256"],
            audience=SETTINGS["OIDC_AUDIENCE"],
            issuer=SETTINGS["OIDC_ISSUER"],
            options={"verify_at_hash": False},
        )
        return {
            "sub": claims.get("sub", ""),
            "email": claims.get("email", ""),
            "roles": claims.get("roles", []) or claims.get("realm_access", {}).get("roles", []),
            "scopes": (claims.get("scope", "") or "").split(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

# --------------------------------------------------------------------------------------
# JSON Schema validator (Draft 2020-12)
# --------------------------------------------------------------------------------------

_VALIDATOR: Draft202012Validator | None = None

def get_evidence_validator() -> Draft202012Validator:
    global _VALIDATOR
    if _VALIDATOR:
        return _VALIDATOR
    schema_path = os.path.abspath(SETTINGS["EVIDENCE_SCHEMA_PATH"])
    if not os.path.exists(schema_path):
        raise RuntimeError(f"Evidence schema not found at {schema_path}")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    _VALIDATOR = Draft202012Validator(schema)
    return _VALIDATOR

def validate_evidence(payload: dict) -> None:
    validator = get_evidence_validator()
    errors = sorted(validator.iter_errors(payload), key=lambda e: e.path)
    if errors:
        first = errors[0]
        loc = "/".join([str(x) for x in first.path])
        raise HTTPException(
            status_code=400,
            detail={"message": f"Schema validation failed at '{loc}': {first.message}", "errors": [e.message for e in errors[:10]]},
        )

# --------------------------------------------------------------------------------------
# Idempotency storage (in-memory fallback)
# --------------------------------------------------------------------------------------

class IdempotencyStore:
    def __init__(self):
        self._data: dict[str, tuple[float, dict]] = {}
        self._ttl = 24 * 3600

    def make_key(self, user_sub: str, path: str, key_hdr: str, body: bytes | None) -> str:
        h = sha256_hex((body or b"") + path.encode("utf-8"))
        return f"{user_sub}:{key_hdr}:{h}"

    def get(self, key: str) -> dict | None:
        v = self._data.get(key)
        if not v:
            return None
        ts, payload = v
        if (dt.datetime.utcnow().timestamp() - ts) > self._ttl:
            self._data.pop(key, None)
            return None
        return payload

    def set(self, key: str, value: dict) -> None:
        self._data[key] = (dt.datetime.utcnow().timestamp(), value)

IDEMPOTENCY = IdempotencyStore()

# --------------------------------------------------------------------------------------
# Simple rate limiter and circuit breaker (per-process)
# --------------------------------------------------------------------------------------

class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int):
        self.rate = rate_per_sec
        self.capacity = burst
        self.tokens = burst
        self.ts = dt.datetime.utcnow().timestamp()
        self.lock = asyncio.Lock()

    async def take(self):
        async with self.lock:
            now = dt.datetime.utcnow().timestamp()
            self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.rate)
            self.ts = now
            if self.tokens >= 1:
                self.tokens -= 1
                return
            # wait minimal time
            await asyncio.sleep(max(0.01, 1.0 / self.rate))

RATE_LIMITERS: dict[str, TokenBucket] = {}

def rl_for_user(sub: str) -> TokenBucket:
    if sub not in RATE_LIMITERS:
        RATE_LIMITERS[sub] = TokenBucket(rate_per_sec=5.0, burst=20)  # 300 rpm, burst 20
    return RATE_LIMITERS[sub]

# --------------------------------------------------------------------------------------
# Repository and storage abstractions
# --------------------------------------------------------------------------------------

class EvidenceRepo(t.Protocol):
    async def create(self, pkg: dict) -> dict: ...
    async def get(self, evidence_id: str) -> dict | None: ...
    async def list(self, page_size: int, page_token: str | None, from_ts: dt.datetime | None, to_ts: dt.datetime | None) -> tuple[list[dict], str | None]: ...
    async def append_custody(self, evidence_id: str, event: dict) -> dict: ...
    async def add_attachments(self, evidence_id: str, attachments: list[dict]) -> dict: ...
    async def stream(self, limit: int = 1000) -> t.AsyncIterator[dict]: ...

class BlobStorage(t.Protocol):
    async def save(self, *, namespace: str, name: str, content: bytes, content_type: str) -> str: ...
    async def open(self, uri: str) -> bytes: ...

# Dev in-memory implementations (safe defaults)
class InMemoryRepo(EvidenceRepo):
    def __init__(self):
        self._items: dict[str, dict] = {}
        self._order: list[str] = []

    async def create(self, pkg: dict) -> dict:
        eid = pkg.get("id") or make_ulid_like()
        pkg["id"] = eid
        pkg["created_at"] = pkg.get("created_at") or dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()
        self._items[eid] = pkg
        self._order.append(eid)
        return pkg

    async def get(self, evidence_id: str) -> dict | None:
        return self._items.get(evidence_id)

    async def list(self, page_size: int, page_token: str | None, from_ts: dt.datetime | None, to_ts: dt.datetime | None) -> tuple[list[dict], str | None]:
        start = 0
        if page_token:
            try:
                start = self._order.index(page_token) + 1
            except ValueError:
                start = 0
        result = []
        next_token = None
        for eid in self._order[start:start + page_size]:
            item = self._items[eid]
            ts = dt.datetime.fromisoformat(item["created_at"].replace("Z", "+00:00"))
            if from_ts and ts < from_ts:
                continue
            if to_ts and ts > to_ts:
                continue
            result.append(item)
        if (start + page_size) < len(self._order):
            next_token = self._order[start + page_size - 1]
        return result, next_token

    async def append_custody(self, evidence_id: str, event: dict) -> dict:
        item = self._items[evidence_id]
        item.setdefault("custody", {}).setdefault("events", []).append(event)
        return item

    async def add_attachments(self, evidence_id: str, attachments: list[dict]) -> dict:
        item = self._items[evidence_id]
        item.setdefault("attachments", []).extend(attachments)
        return item

    async def stream(self, limit: int = 1000) -> t.AsyncIterator[dict]:
        count = 0
        for eid in self._order:
            yield self._items[eid]
            count += 1
            if count >= limit:
                break

class InMemoryStorage(BlobStorage):
    def __init__(self):
        self._data: dict[str, bytes] = {}

    async def save(self, *, namespace: str, name: str, content: bytes, content_type: str) -> str:
        eid = make_ulid_like()
        uri = f"mem://{namespace}/{eid}/{name}"
        self._data[uri] = content
        return uri

    async def open(self, uri: str) -> bytes:
        return self._data[uri]

# DI
_INMEMORY = SETTINGS.get("DEV_INMEMORY", "0") == "1"
_REPO: EvidenceRepo = InMemoryRepo() if _INMEMORY else None  # type: ignore
_STORE: BlobStorage = InMemoryStorage() if _INMEMORY else None  # type: ignore

def get_repo() -> EvidenceRepo:
    if _REPO is None:
        raise RuntimeError("EvidenceRepo is not bound. Provide implementation via DI.")
    return _REPO

def get_storage() -> BlobStorage:
    if _STORE is None:
        raise RuntimeError("BlobStorage is not bound. Provide implementation via DI.")
    return _STORE

# --------------------------------------------------------------------------------------
# ETag utilities
# --------------------------------------------------------------------------------------

def compute_etag(obj: dict) -> str:
    # RFC8785 JSON Canonicalization not used here to avoid heavy deps; stable hash for dict
    data = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return '"' + hashlib.sha256(data).hexdigest() + '"'

# --------------------------------------------------------------------------------------
# Router
# --------------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/evidence-packages", tags=["evidence"])

# Common response headers helper
def set_common_headers(resp: Response, request_id: str):
    resp.headers["X-Request-ID"] = request_id
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"

# --------------------------------------------------------------------------------------
# POST /v1/evidence-packages  (create)
# --------------------------------------------------------------------------------------

@router.post("", status_code=status.HTTP_201_CREATED)
async def create_evidence_package(
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
    repo: EvidenceRepo = Depends(get_repo),
    idempotency_key: t.Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    verify: bool = Query(default=True, description="Валидировать schema и базовую целостность"),
):
    body_bytes = await request.body()
    try:
        payload = json.loads(body_bytes or b"{}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Idempotency
    req_id = request.headers.get("X-Request-ID") or make_ulid_like()
    set_common_headers(response, req_id)
    if idempotency_key:
        key = IDEMPOTENCY.make_key(user.get("sub", ""), str(request.url.path), idempotency_key, body_bytes)
        cached = IDEMPOTENCY.get(key)
        if cached:
            # Replay result
            resp = JSONResponse(status_code=cached["status"], content=cached["body"])
            resp.headers.update(cached["headers"])
            resp.headers["Idempotent-Replay"] = "true"
            return resp

    # Validation
    if verify:
        validate_evidence(payload)
        # basic integrity check for inline content
        content = payload.get("content")
        if content and content.get("encoding") in ("utf8", "base64") and "data" in content:
            raw = content["data"].encode("utf-8") if content["encoding"] == "utf8" else base64.b64decode(content["data"])
            declared = (content.get("digest") or {}).get("value")
            if declared and declared.lower() != sha256_hex(raw):
                raise HTTPException(status_code=400, detail="Content digest mismatch")

    # Ensure id & timestamps
    payload.setdefault("id", make_ulid_like())
    payload.setdefault("created_at", dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat())

    created = await repo.create(payload)
    etag = compute_etag(created)

    body = {"id": created["id"], "location": f"{request.base_url}v1/evidence-packages/{created['id']}"}
    response.status_code = status.HTTP_201_CREATED
    response.headers["Location"] = body["location"]
    response.headers["ETag"] = etag

    # Cache idempotent result
    if idempotency_key:
        key = IDEMPOTENCY.make_key(user.get("sub", ""), str(request.url.path), idempotency_key, body_bytes)
        IDEMPOTENCY.set(
            key,
            {
                "status": status.HTTP_201_CREATED,
                "body": body,
                "headers": {"Location": body["location"], "ETag": etag},
            },
        )
    return body

# --------------------------------------------------------------------------------------
# GET /v1/evidence-packages/{id}
# --------------------------------------------------------------------------------------

@router.get("/{evidence_id}")
async def get_evidence_package(
    evidence_id: str = Path(..., min_length=1),
    request: Request = None,
    response: Response = None,
    user: User = Depends(get_current_user),
    repo: EvidenceRepo = Depends(get_repo),
    if_none_match: t.Annotated[str | None, Header(alias="If-None-Match")] = None,
):
    pkg = await repo.get(evidence_id)
    if not pkg:
        raise HTTPException(status_code=404, detail="Not found")
    etag = compute_etag(pkg)
    if if_none_match and if_none_match == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})
    resp = JSONResponse(pkg)
    resp.headers["ETag"] = etag
    set_common_headers(resp, request.headers.get("X-Request-ID") or make_ulid_like())
    return resp

# --------------------------------------------------------------------------------------
# GET /v1/evidence-packages  (list with pagination)
# --------------------------------------------------------------------------------------

@router.get("")
async def list_evidence_packages(
    response: Response,
    user: User = Depends(get_current_user),
    repo: EvidenceRepo = Depends(get_repo),
    page_size: int = Query(100, ge=1, le=500),
    page_token: str | None = Query(None),
    from_: str | None = Query(None, alias="from"),
    to: str | None = Query(None),
):
    from_ts = dt.datetime.fromisoformat(from_.replace("Z", "+00:00")) if from_ else None
    to_ts = dt.datetime.fromisoformat(to.replace("Z", "+00:00")) if to else None
    items, next_token = await repo.list(page_size=page_size, page_token=page_token, from_ts=from_ts, to_ts=to_ts)
    resp = {"items": items, "next_page_token": next_token}
    r = JSONResponse(resp)
    set_common_headers(r, make_ulid_like())
    return r

# --------------------------------------------------------------------------------------
# GET /v1/evidence-packages:stream  (NDJSON stream)
# --------------------------------------------------------------------------------------

@router.get(":stream")
async def stream_evidence_packages(
    user: User = Depends(get_current_user),
    repo: EvidenceRepo = Depends(get_repo),
):
    async def gen():
        limiter = rl_for_user(user.get("sub", "anon"))
        await limiter.take()
        async for item in repo.stream(limit=10000):
            yield json.dumps(item, separators=(",", ":"), ensure_ascii=False) + "\n"

    return StreamingResponse(gen(), media_type="application/x-ndjson", headers={"Cache-Control": "no-store"})

# --------------------------------------------------------------------------------------
# POST /v1/evidence-packages/{id}/attachments:upload  (multipart)
# --------------------------------------------------------------------------------------

@router.post("/{evidence_id}/attachments:upload")
async def upload_attachments(
    evidence_id: str,
    response: Response,
    user: User = Depends(get_current_user),
    repo: EvidenceRepo = Depends(get_repo),
    storage: BlobStorage = Depends(get_storage),
    files: list[UploadFile] = File(..., description="Один или несколько файлов"),
    namespace: str = Form("evidence"),
):
    pkg = await repo.get(evidence_id)
    if not pkg:
        raise HTTPException(status_code=404, detail="Not found")

    uploaded: list[dict] = []
    errors: list[dict] = []

    for f in files:
        try:
            content = await f.read()
            uri = await storage.save(namespace=namespace, name=f.filename, content=content, content_type=f.content_type or "application/octet-stream")
            att = {
                "name": f.filename,
                "mediaType": f.content_type or "application/octet-stream",
                "size_bytes": len(content),
                "location": uri,
                "digest": {"alg": "sha256", "value": sha256_hex(content)},
            }
            uploaded.append(att)
        except Exception as e:
            errors.append({"name": f.filename, "error": str(e)})

    if uploaded:
        await repo.add_attachments(evidence_id, uploaded)

    body = {"uploaded": uploaded, "errors": errors}
    r = JSONResponse(body, status_code=status.HTTP_207_MULTI_STATUS if errors else status.HTTP_200_OK)
    set_common_headers(r, make_ulid_like())
    return r

# --------------------------------------------------------------------------------------
# POST /v1/evidence-packages/{id}/custody:append  (append chain-of-custody event)
# --------------------------------------------------------------------------------------

@router.post("/{evidence_id}/custody:append", status_code=status.HTTP_200_OK)
async def append_custody_event(
    evidence_id: str,
    event_type: str = Form(..., pattern="^(created|transferred|validated|sealed|unsealed|accessed|exported|destroyed)$"),
    notes: str | None = Form(None, max_length=2000),
    user: User = Depends(get_current_user),
    repo: EvidenceRepo = Depends(get_repo),
):
    event = {
        "event_id": str(uuid.uuid4()),
        "time": dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat(),
        "action": event_type,
        "actor": {"name": user.get("email") or user.get("sub", "system")},
        "notes": notes or "",
    }
    pkg = await repo.get(evidence_id)
    if not pkg:
        raise HTTPException(status_code=404, detail="Not found")
    updated = await repo.append_custody(evidence_id, event)
    return {"ok": True, "event": event, "id": evidence_id}

# --------------------------------------------------------------------------------------
# HEAD /v1/evidence-packages/{id}  (ETag only)
# --------------------------------------------------------------------------------------

@router.head("/{evidence_id}")
async def head_evidence_package(
    evidence_id: str,
    response: Response,
    repo: EvidenceRepo = Depends(get_repo),
):
    pkg = await repo.get(evidence_id)
    if not pkg:
        raise HTTPException(status_code=404, detail="Not found")
    response.headers["ETag"] = compute_etag(pkg)
    return Response(status_code=200)

# --------------------------------------------------------------------------------------
# Security headers dependency (can be added in app factory)
# --------------------------------------------------------------------------------------

@router.middleware("http")
async def _security_headers(request: Request, call_next):
    resp: Response = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp

# --------------------------------------------------------------------------------------
# Notes:
# - Подключите реальные реализации EvidenceRepo и BlobStorage в DI контейнере приложения.
# - Переменные окружения OVAULT_* позволяют указать JWKS и путь до JSON Schema.
# - Для полного соответствия вашей схеме включены базовые проверки целостности.
# - Лимиты/брейкер простые и локальные, на проде рекомендуются внешние решения (WAF/Redis).
# --------------------------------------------------------------------------------------
