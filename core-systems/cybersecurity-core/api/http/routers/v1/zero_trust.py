# cybersecurity-core/api/http/routers/v1/zero_trust.py
from __future__ import annotations

import asyncio
import base64
import functools
import hmac
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass
from fnmatch import fnmatch
from hashlib import sha256
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from pydantic import BaseModel, Field, conint, constr, validator

try:
    import redis.asyncio as aioredis  # optional
except Exception:  # pragma: no cover
    aioredis = None

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/zero-trust", tags=["zero-trust"])


# ----------------------------- Settings / Config ------------------------------

class ZeroTrustSettings(BaseModel):
    signing_key: str = Field(default_factory=lambda: os.getenv("ZERO_TRUST_SIGNING_KEY", "dev-insecure-key-change-me"))
    token_issuer: str = Field(default_factory=lambda: os.getenv("ZERO_TRUST_ISSUER", "aethernova-zero-trust"))
    token_audience: str = Field(default_factory=lambda: os.getenv("ZERO_TRUST_AUDIENCE", "aethernova-clients"))
    token_ttl_seconds: int = Field(default_factory=lambda: int(os.getenv("ZERO_TRUST_TOKEN_TTL", "900")))
    risk_threshold_allow: int = Field(default_factory=lambda: int(os.getenv("ZERO_TRUST_RISK_ALLOW", "30")))
    risk_threshold_mfa: int = Field(default_factory=lambda: int(os.getenv("ZERO_TRUST_RISK_MFA", "60")))
    redis_url: Optional[str] = Field(default_factory=lambda: os.getenv("ZERO_TRUST_REDIS_URL"))
    key_namespace: str = Field(default_factory=lambda: os.getenv("ZERO_TRUST_KEY_NS", "zt"))
    allow_localhost: bool = Field(default_factory=lambda: os.getenv("ZERO_TRUST_ALLOW_LOCALHOST", "true").lower() == "true")
    allowed_cidrs: List[str] = Field(default_factory=lambda: os.getenv("ZERO_TRUST_ALLOWED_CIDRS", "10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,127.0.0.0/8").split(","))


@functools.lru_cache(maxsize=1)
def get_settings() -> ZeroTrustSettings:
    s = ZeroTrustSettings()
    if s.signing_key == "dev-insecure-key-change-me":
        logger.warning("ZERO_TRUST_SIGNING_KEY is using a development default. Replace it in production.")
    return s


# ------------------------------ Models (Pydantic) -----------------------------

class Subject(BaseModel):
    id: constr(strip_whitespace=True, min_length=1)
    tenant: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class DevicePosture(BaseModel):
    platform: Literal["windows", "linux", "macos", "ios", "android", "other"] = "other"
    os_version: Optional[str] = None
    is_managed: bool = False
    is_rooted_or_jailbroken: bool = False
    disk_encrypted: bool = True
    secure_boot: bool = True
    realtime_protection: bool = True
    last_patch_days: Optional[conint(ge=0)] = None
    tpm_present: Optional[bool] = None
    attested: bool = False
    posture_score: Optional[conint(ge=0, le=100)] = None  # optional precomputed posture score


class NetworkContext(BaseModel):
    ip: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[int] = None
    is_tor_or_proxy: bool = False


class ResourceRef(BaseModel):
    id: str
    type: str
    owner_id: Optional[str] = None
    path: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    relationships: Dict[str, List[str]] = Field(default_factory=dict)  # e.g., {"admin": ["u1"], "editor": ["u2"]}


class ActionContext(BaseModel):
    action: str
    scopes: List[str] = Field(default_factory=list)


class RequestContext(BaseModel):
    user_agent: Optional[str] = None
    time_epoch_ms: Optional[int] = None
    previous_failures: int = 0
    trust_token: Optional[str] = None


class DecisionRequest(BaseModel):
    subject: Subject
    resource: ResourceRef
    action_ctx: ActionContext = Field(alias="action")
    device: DevicePosture
    network: NetworkContext
    context: RequestContext

    class Config:
        allow_population_by_field_name = True


class Obligation(BaseModel):
    type: Literal["mfa", "reauth", "limit-scope", "time-limit", "context-bind"]
    detail: Dict[str, Any] = Field(default_factory=dict)


class DecisionResponse(BaseModel):
    decision: Literal["allow", "deny", "mfa", "allow_limited"]
    risk_score: conint(ge=0, le=100)
    policy_id: str
    obligations: List[Obligation] = Field(default_factory=list)
    expires_in: Optional[int] = None  # seconds
    reason: Optional[str] = None
    correlation_id: str


class AttestRequest(BaseModel):
    subject: Subject
    device: DevicePosture
    attestation_type: Literal["tpm", "webauthn", "apple_devicecheck", "android_safetynet", "none"] = "none"
    evidence: Optional[str] = None  # opaque blob (base64/JSON)


class AttestResponse(BaseModel):
    active: bool
    token: Optional[str] = None
    token_type: str = "ZT-HS256"
    expires_in: int
    correlation_id: str


class IntrospectRequest(BaseModel):
    token: str


class IntrospectResponse(BaseModel):
    active: bool
    subject_id: Optional[str] = None
    tenant: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    device_ok: Optional[bool] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    iss: Optional[str] = None
    aud: Optional[str] = None
    jti: Optional[str] = None


class RevokeRequest(BaseModel):
    token: str


class SimulateRequest(BaseModel):
    request: DecisionRequest
    override_policies: Optional[List[Dict[str, Any]]] = None


class SimulateResponse(BaseModel):
    decision: DecisionResponse
    evaluated_rules: List[str]


class JITAccessRequest(BaseModel):
    subject: Subject
    resource: ResourceRef
    action_ctx: ActionContext = Field(alias="action")
    device: DevicePosture
    network: NetworkContext
    duration_seconds: conint(gt=0, le=8 * 3600) = 900

    class Config:
        allow_population_by_field_name = True


class JITAccessResponse(BaseModel):
    status: Literal["approved", "pending_approval", "denied"]
    decision: DecisionResponse


class HeartbeatRequest(BaseModel):
    session_id: str
    subject: Subject
    device: DevicePosture
    network: NetworkContext
    anomalies: List[str] = Field(default_factory=list)
    trust_token: Optional[str] = None


class HeartbeatResponse(BaseModel):
    continue_session: bool
    decision: DecisionResponse


# ------------------------------- Utilities -----------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = '=' * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _now_s() -> int:
    return int(time.time())


def _cidr_list_to_networks(cidrs: Sequence[str]) -> List[Any]:
    nets = []
    for c in cidrs:
        c = c.strip()
        if not c:
            continue
        try:
            nets.append(ip_network(c, strict=False))
        except Exception:
            logger.warning("Invalid CIDR ignored: %s", c)
    return nets


def _ip_in_cidrs(ip: Optional[str], nets: Sequence[Any]) -> bool:
    if not ip:
        return False
    try:
        addr = ip_address(ip)
    except Exception:
        return False
    return any(addr in n for n in nets)


def _require_header_request_id(x_request_id: Optional[str]) -> str:
    return x_request_id or str(uuid.uuid4())


def _no_store_headers(resp: Response, correlation_id: str, decision: Optional[str] = None) -> None:
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Request-ID"] = correlation_id
    if decision:
        resp.headers["X-Zero-Trust-Decision"] = decision


def _audit(event: str, correlation_id: str, payload: Dict[str, Any]) -> None:
    record = {"event": event, "ts": _now_s(), "correlation_id": correlation_id, **payload}
    logger.info(json.dumps(record, separators=(",", ":"), ensure_ascii=False))


# ------------------------------- Token Mint/Verify ----------------------------

class TokenError(Exception):
    pass


def mint_trust_token(claims: Dict[str, Any], ttl_seconds: int, settings: ZeroTrustSettings) -> str:
    header = {"alg": "HS256", "typ": "ZT"}
    now = _now_s()
    exp = now + ttl_seconds
    payload = {
        "iss": settings.token_issuer,
        "aud": settings.token_audience,
        "iat": now,
        "exp": exp,
        "jti": str(uuid.uuid4()),
        **claims,
    }
    head_b64 = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{head_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(settings.signing_key.encode("utf-8"), signing_input, sha256).digest()
    token = f"{head_b64}.{payload_b64}.{_b64url(sig)}"
    return token


def verify_trust_token(token: str, settings: ZeroTrustSettings) -> Dict[str, Any]:
    try:
        head_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise TokenError("Malformed token")
    signing_input = f"{head_b64}.{payload_b64}".encode("ascii")
    expected = hmac.new(settings.signing_key.encode("utf-8"), signing_input, sha256).digest()
    if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
        raise TokenError("Invalid signature")
    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    now = _now_s()
    if payload.get("iss") != settings.token_issuer or payload.get("aud") != settings.token_audience:
        raise TokenError("Invalid iss/aud")
    if int(payload.get("exp", 0)) < now:
        raise TokenError("Expired")
    return payload


# ------------------------------ Revocation Store ------------------------------

class RevocationStore:
    async def revoke(self, jti: str, exp: int) -> None:
        raise NotImplementedError

    async def is_revoked(self, jti: str) -> bool:
        raise NotImplementedError


class InMemoryRevocationStore(RevocationStore):
    def __init__(self) -> None:
        self._data: Dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def revoke(self, jti: str, exp: int) -> None:
        async with self._lock:
            self._data[jti] = exp
            # prune
            now = _now_s()
            for k, v in list(self._data.items()):
                if v <= now:
                    self._data.pop(k, None)

    async def is_revoked(self, jti: str) -> bool:
        async with self._lock:
            now = _now_s()
            exp = self._data.get(jti)
            if exp is None:
                return False
            if exp <= now:
                self._data.pop(jti, None)
                return False
            return True


class RedisRevocationStore(RevocationStore):
    def __init__(self, redis_client: Any, ns: str = "zt") -> None:
        self._r = redis_client
        self._ns = ns

    def _key(self, jti: str) -> str:
        return f"{self._ns}:revoked:{jti}"

    async def revoke(self, jti: str, exp: int) -> None:
        ttl = max(1, exp - _now_s())
        await self._r.set(self._key(jti), "1", ex=ttl)

    async def is_revoked(self, jti: str) -> bool:
        return bool(await self._r.exists(self._key(jti)))


@functools.lru_cache(maxsize=1)
def get_revocation_store() -> RevocationStore:
    s = get_settings()
    if s.redis_url:
        if aioredis is None:
            raise RuntimeError("redis.asyncio not installed but ZERO_TRUST_REDIS_URL set")
        client = aioredis.from_url(s.redis_url, encoding="utf-8", decode_responses=True)
        logger.info("ZeroTrust revocation uses Redis at %s", s.redis_url)
        return RedisRevocationStore(client, s.key_namespace)
    logger.info("ZeroTrust revocation uses InMemory store")
    return InMemoryRevocationStore()


# ----------------------------- Policy Engine ---------------------------------

@dataclass
class PolicyRule:
    id: str
    effect: Literal["allow", "deny"]
    actions: Sequence[str]  # glob patterns
    resources: Sequence[str]  # glob patterns (resource path or type:id)
    roles: Sequence[str]  # allowed subject roles (or ["*"])
    min_device_trust: Literal["low", "medium", "high"] = "low"
    allowed_cidrs: Sequence[str] = ()
    obligations: Sequence[Obligation] = ()
    condition_regex: Optional[str] = None  # optional regex against resource.path

    def matches(self, subject: Subject, resource: ResourceRef, action: str, ip: Optional[str], device_trust: str) -> bool:
        if self.roles and "*" not in self.roles:
            if not set(r.lower() for r in subject.roles) & set(x.lower() for x in self.roles):
                return False
        if not any(fnmatch(action, a) for a in self.actions):
            return False
        path = resource.path or f"{resource.type}:{resource.id}"
        if not any(fnmatch(path, r) for r in self.resources):
            return False
        if self.condition_regex:
            try:
                if not re.search(self.condition_regex, path):
                    return False
            except re.error:
                logger.warning("Invalid condition_regex in rule %s", self.id)
                return False
        trust_order = {"low": 0, "medium": 1, "high": 2}
        if trust_order.get(device_trust, 0) < trust_order.get(self.min_device_trust, 0):
            return False
        nets = _cidr_list_to_networks(self.allowed_cidrs)
        if nets and not _ip_in_cidrs(ip, nets):
            return False
        return True


def default_policies() -> List[PolicyRule]:
    return [
        PolicyRule(
            id="deny-secrets-delete",
            effect="deny",
            actions=["delete", "rotate"],
            resources=["secrets/*", "vault/*"],
            roles=["*"],
            min_device_trust="medium",
        ),
        PolicyRule(
            id="allow-doc-read",
            effect="allow",
            actions=["read", "get", "download"],
            resources=["doc/*"],
            roles=["viewer", "editor", "admin"],
            min_device_trust="low",
            obligations=[],
        ),
        PolicyRule(
            id="allow-doc-write",
            effect="allow",
            actions=["write", "update", "upload"],
            resources=["doc/*"],
            roles=["editor", "admin"],
            min_device_trust="medium",
            obligations=[Obligation(type="context-bind", detail={"bind": "ip"})],
        ),
        PolicyRule(
            id="admin-high-trust",
            effect="allow",
            actions=["*"],
            resources=["*"],
            roles=["admin"],
            min_device_trust="high",
        ),
    ]


# ------------------------------ Risk Scoring ----------------------------------

def device_trust_level(dev: DevicePosture) -> Literal["low", "medium", "high"]:
    # Deterministic trust tier from posture
    penalties = 0
    bonuses = 0
    if not dev.disk_encrypted:
        penalties += 20
    if not dev.secure_boot:
        penalties += 15
    if dev.is_rooted_or_jailbroken:
        penalties += 40
    if not dev.realtime_protection:
        penalties += 15
    if dev.last_patch_days is not None:
        if dev.last_patch_days > 60:
            penalties += 25
        elif dev.last_patch_days > 30:
            penalties += 10
    if dev.is_managed:
        bonuses += 15
    if dev.attested:
        bonuses += 10
    # simple mapping
    base = max(0, 50 - penalties + bonuses)
    if base >= 60:
        return "high"
    if base >= 35:
        return "medium"
    return "low"


def risk_score(
    device: DevicePosture, network: NetworkContext, ctx: RequestContext, subject: Subject
) -> int:
    score = 0
    # posture driven
    trust = device_trust_level(device)
    if trust == "low":
        score += 35
    elif trust == "medium":
        score += 15
    else:
        score += 5

    # network risk
    if network.is_tor_or_proxy:
        score += 25
    if network.country and subject.attributes.get("home_country") and network.country != subject.attributes["home_country"]:
        score += 10
    if network.ip:
        try:
            ip_obj = ip_address(network.ip)
            if ip_obj.is_private:
                score -= 5
            if ip_obj.is_loopback:
                score -= 10
        except Exception:
            score += 5

    # behavior
    score += min(20, ctx.previous_failures * 5)

    # clamp
    score = max(0, min(100, score))
    return score


# ------------------------------ Dependencies ----------------------------------

def get_correlation_id(x_request_id: Optional[str] = Header(None)) -> str:
    return _require_header_request_id(x_request_id)


def security_headers(resp: Response, correlation_id: str, decision: Optional[str] = None) -> None:
    _no_store_headers(resp, correlation_id, decision)


# -------------------------------- Endpoints -----------------------------------

@router.post("/decision", response_model=DecisionResponse)
async def evaluate_decision(req: DecisionRequest, response: Response, correlation_id: str = Depends(get_correlation_id)) -> DecisionResponse:
    settings = get_settings()
    rev_store = get_revocation_store()
    security_headers(response, correlation_id)

    # Introspect token if provided
    token_claims: Dict[str, Any] = {}
    if req.context.trust_token:
        try:
            claims = verify_trust_token(req.context.trust_token, settings)
            if await rev_store.is_revoked(str(claims.get("jti", ""))):
                raise TokenError("Revoked")
            token_claims = claims
        except Exception as e:
            _audit("introspection_failed", correlation_id, {"error": str(e)})
            # continue without token claims; we do not fail hard here

    rscore = risk_score(req.device, req.network, req.context, req.subject)
    dev_trust = device_trust_level(req.device)

    policies = default_policies()
    # ReBAC: owner/admin/editor relationships
    rel_roles = []
    for rel, ids in (req.resource.relationships or {}).items():
        if req.subject.id in ids:
            rel_roles.append(rel.lower())
    effective_roles = set(x.lower() for x in (req.subject.roles + rel_roles))

    # Evaluate deny first
    matched_rules: List[str] = []
    for rule in policies:
        if rule.effect == "deny" and rule.matches(req.subject, req.resource, req.action_ctx.action, req.network.ip, dev_trust):
            matched_rules.append(rule.id)
            decision = DecisionResponse(
                decision="deny",
                risk_score=rscore,
                policy_id=rule.id,
                obligations=[],
                reason="Matched deny rule",
                correlation_id=correlation_id,
            )
            _audit("decision", correlation_id, {"decision": decision.decision, "rule": rule.id, "risk": rscore})
            security_headers(response, correlation_id, decision.decision)
            return decision

    # Allow candidates
    allow_hits: List[PolicyRule] = [
        r for r in policies
        if r.effect == "allow" and r.matches(
            Subject(id=req.subject.id, tenant=req.subject.tenant, roles=list(effective_roles), groups=req.subject.groups, attributes=req.subject.attributes),
            req.resource, req.action_ctx.action, req.network.ip, dev_trust
        )
    ]
    if allow_hits:
        # Choose most specific (longest resource pattern)
        rule = sorted(allow_hits, key=lambda x: max((len(p) for p in x.resources), default=0), reverse=True)[0]
        matched_rules.append(rule.id)

        decision_kind: Literal["allow", "mfa", "allow_limited"]
        obligations: List[Obligation] = list(rule.obligations)

        if rscore >= settings.risk_threshold_mfa:
            decision_kind = "mfa"
            obligations = [Obligation(type="mfa", detail={"reason": "risk_high"})] + obligations
        elif rscore >= settings.risk_threshold_allow:
            decision_kind = "allow_limited"
            obligations = [Obligation(type="limit-scope", detail={"max_scopes": ["read"]})] + obligations
        else:
            decision_kind = "allow"

        decision = DecisionResponse(
            decision=decision_kind,
            risk_score=rscore,
            policy_id=rule.id,
            obligations=obligations,
            expires_in=300 if decision_kind == "allow" else 120,
            reason=f"Matched allow rule {rule.id} with device_trust={dev_trust}",
            correlation_id=correlation_id,
        )
        _audit("decision", correlation_id, {"decision": decision.decision, "rule": rule.id, "risk": rscore})
        security_headers(response, correlation_id, decision.decision)
        return decision

    # Default: require MFA if medium risk, deny otherwise
    if rscore >= settings.risk_threshold_mfa:
        decision = DecisionResponse(
            decision="mfa",
            risk_score=rscore,
            policy_id="default-mfa",
            obligations=[Obligation(type="mfa", detail={"reason": "no_allow_rule"})],
            expires_in=120,
            reason="No allow rule; high risk",
            correlation_id=correlation_id,
        )
    else:
        decision = DecisionResponse(
            decision="deny",
            risk_score=rscore,
            policy_id="default-deny",
            obligations=[],
            reason="No allow rule; risk not acceptable",
            correlation_id=correlation_id,
        )
    _audit("decision", correlation_id, {"decision": decision.decision, "risk": rscore})
    security_headers(response, correlation_id, decision.decision)
    return decision


@router.post("/attest", response_model=AttestResponse)
async def attest_device(req: AttestRequest, response: Response, correlation_id: str = Depends(get_correlation_id)) -> AttestResponse:
    settings = get_settings()
    security_headers(response, correlation_id)

    # Minimal verifiers (placeholders for external attestation services)
    verified = False
    if req.attestation_type == "none":
        verified = req.device.attested
    elif req.attestation_type == "tpm":
        verified = bool(req.device.tpm_present and req.evidence)  # placeholder
    elif req.attestation_type in ("webauthn", "apple_devicecheck", "android_safetynet"):
        verified = bool(req.evidence)

    if not verified:
        _audit("attest_failed", correlation_id, {"subject": req.subject.id, "type": req.attestation_type})
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Attestation verification failed")

    claims = {
        "sub": req.subject.id,
        "tenant": req.subject.tenant,
        "roles": req.subject.roles,
        "device_ok": True,
    }
    token = mint_trust_token(claims, ttl_seconds=get_settings().token_ttl_seconds, settings=settings)

    _audit("attest_success", correlation_id, {"subject": req.subject.id, "type": req.attestation_type})
    return AttestResponse(active=True, token=token, expires_in=settings.token_ttl_seconds, correlation_id=correlation_id)


@router.post("/introspect", response_model=IntrospectResponse)
async def introspect_token(req: IntrospectRequest, response: Response, correlation_id: str = Depends(get_correlation_id)) -> IntrospectResponse:
    settings = get_settings()
    rev_store = get_revocation_store()
    security_headers(response, correlation_id)

    try:
        claims = verify_trust_token(req.token, settings)
        if await rev_store.is_revoked(str(claims.get("jti", ""))):
            return IntrospectResponse(active=False)
        return IntrospectResponse(
            active=True,
            subject_id=claims.get("sub"),
            tenant=claims.get("tenant"),
            roles=list(claims.get("roles", [])),
            device_ok=bool(claims.get("device_ok")),
            exp=claims.get("exp"),
            iat=claims.get("iat"),
            iss=claims.get("iss"),
            aud=claims.get("aud"),
            jti=claims.get("jti"),
        )
    except Exception as e:
        _audit("introspection_failed", correlation_id, {"error": str(e)})
        return IntrospectResponse(active=False)


@router.post("/revoke", status_code=204)
async def revoke_token(req: RevokeRequest, response: Response, correlation_id: str = Depends(get_correlation_id)) -> Response:
    settings = get_settings()
    store = get_revocation_store()
    security_headers(response, correlation_id)

    try:
        claims = verify_trust_token(req.token, settings)
        jti = str(claims.get("jti", ""))
        exp = int(claims.get("exp", _now_s()))
        await store.revoke(jti, exp)
        _audit("token_revoked", correlation_id, {"jti": jti})
        response.status_code = status.HTTP_204_NO_CONTENT
        return response
    except Exception as e:
        _audit("revoke_failed", correlation_id, {"error": str(e)})
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")


@router.post("/simulate", response_model=SimulateResponse)
async def simulate(req: SimulateRequest, response: Response, correlation_id: str = Depends(get_correlation_id)) -> SimulateResponse:
    security_headers(response, correlation_id)
    # In this implementation override_policies is ignored for simplicity; extend if needed
    dec = await evaluate_decision(req.request, response, correlation_id)  # reuse logic with same headers already set
    return SimulateResponse(decision=dec, evaluated_rules=[dec.policy_id])


@router.post("/jit-access", response_model=JITAccessResponse)
async def jit_access(req: JITAccessRequest, response: Response, correlation_id: str = Depends(get_correlation_id)) -> JITAccessResponse:
    settings = get_settings()
    security_headers(response, correlation_id)

    # Base decision
    dec_req = DecisionRequest(
        subject=req.subject,
        resource=req.resource,
        action=req.action_ctx,
        device=req.device,
        network=req.network,
        context=RequestContext(user_agent=None, time_epoch_ms=_now_s() * 1000, previous_failures=0),
    )
    base_decision = await evaluate_decision(dec_req, response, correlation_id)

    if base_decision.decision == "deny":
        out = JITAccessResponse(status="denied", decision=base_decision)
    elif base_decision.decision in ("mfa", "allow_limited") or base_decision.risk_score >= settings.risk_threshold_mfa:
        # Require human approval / step-up flow in real system
        pending = base_decision.copy()
        pending.decision = "mfa"
        pending.obligations = [Obligation(type="mfa", detail={"reason": "jit"})]
        out = JITAccessResponse(status="pending_approval", decision=pending)
    else:
        # Auto-approve with time-limited obligation
        approved = base_decision.copy()
        approved.decision = "allow"
        approved.obligations = approved.obligations + [Obligation(type="time-limit", detail={"seconds": req.duration_seconds})]
        approved.expires_in = min(approved.expires_in or req.duration_seconds, req.duration_seconds)
        out = JITAccessResponse(status="approved", decision=approved)

    _audit("jit_access", correlation_id, {"status": out.status, "risk": out.decision.risk_score})
    security_headers(response, correlation_id, out.decision.decision)
    return out


@router.post("/session/heartbeat", response_model=HeartbeatResponse)
async def session_heartbeat(req: HeartbeatRequest, response: Response, correlation_id: str = Depends(get_correlation_id)) -> HeartbeatResponse:
    settings = get_settings()
    security_headers(response, correlation_id)

    ctx = RequestContext(user_agent=None, time_epoch_ms=_now_s() * 1000, previous_failures=len(req.anomalies), trust_token=req.trust_token)
    dec_req = DecisionRequest(
        subject=req.subject,
        resource=ResourceRef(id="session", type="session", owner_id=req.subject.id, path=f"session/{req.session_id}"),
        action=ActionContext(action="continue"),
        device=req.device,
        network=req.network,
        context=ctx,
    )
    dec = await evaluate_decision(dec_req, response, correlation_id)
    cont = dec.decision in ("allow", "allow_limited")
    _audit("session_heartbeat", correlation_id, {"continue": cont, "risk": dec.risk_score})
    security_headers(response, correlation_id, dec.decision)
    return HeartbeatResponse(continue_session=cont, decision=dec)


@router.get("/policy", response_model=List[Dict[str, Any]])
async def get_policy(response: Response, correlation_id: str = Depends(get_correlation_id)) -> List[Dict[str, Any]]:
    security_headers(response, correlation_id)
    out: List[Dict[str, Any]] = []
    for r in default_policies():
        out.append({
            "id": r.id,
            "effect": r.effect,
            "actions": list(r.actions),
            "resources": list(r.resources),
            "roles": list(r.roles),
            "min_device_trust": r.min_device_trust,
            "allowed_cidrs": list(r.allowed_cidrs),
            "obligations": [o.dict() for o in r.obligations],
        })
    return out
