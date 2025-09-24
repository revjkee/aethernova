# security-core/adapters/idp_adapter.py
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel, Field, HttpUrl, ConfigDict, ValidationError

# Reuse the industrial OIDC client previously provided
try:
    from security_core.security.authn.oauth2_oidc import (
        OIDCClient, OIDCSettings, TokenSet, IdTokenClaims, LogoutTokenClaims
    )
except Exception as e:  # pragma: no cover
    # Soft import error message is logged; OIDC adapter will fail fast if used.
    OIDCClient = None  # type: ignore
    OIDCSettings = None  # type: ignore
    TokenSet = None  # type: ignore
    IdTokenClaims = None  # type: ignore
    LogoutTokenClaims = None  # type: ignore

# -------------------------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------------------------

logger = logging.getLogger("security_core.adapters.idp")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _redact(obj: Any, keys: List[str]) -> Any:
    keyset = {k.lower() for k in keys}
    if isinstance(obj, dict):
        return {k: ("***" if k.lower() in keyset else _redact(v, keys)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(v, keys) for v in obj]
    return obj


# -------------------------------------------------------------------------------------
# Models
# -------------------------------------------------------------------------------------

class IdpType(str):
    OIDC = "OIDC"
    SAML2 = "SAML2"      # placeholder, not implemented in this module
    LDAP = "LDAP"        # placeholder for password verification scenarios


class RequestContext(BaseModel):
    model_config = ConfigDict(extra="allow")
    tenant: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    # Optionally override redirect_uri if configured to multiple callbacks per tenant
    redirect_uri: Optional[HttpUrl] = None
    # Any correlation id for observability
    correlation_id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()))


class AuthorizationRedirect(BaseModel):
    authorization_url: str
    state: str
    nonce: str
    code_verifier: Optional[str] = None
    # For convenience: when you store state/nonce in server-side TTL store, return exp
    expires_in: int = 600


class AttributeMapping(BaseModel):
    # Map IdP claim names -> internal fields
    sub: str = "sub"
    email: str = "email"
    name: str = "name"
    given_name: str = "given_name"
    family_name: str = "family_name"
    preferred_username: str = "preferred_username"
    groups: str = "groups"
    roles: Optional[str] = None  # some IdPs use "roles" or custom
    picture: Optional[str] = "picture"
    locale: Optional[str] = "locale"
    tenant: Optional[str] = None  # custom tenant claim (e.g., "tid" or "realm")


class Principal(BaseModel):
    model_config = ConfigDict(extra="allow")
    subject: str
    tenant: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None
    preferred_username: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    groups: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    acr: Optional[str] = None
    amr: List[str] = Field(default_factory=list)
    mfa: Optional[str] = None
    picture: Optional[str] = None
    locale: Optional[str] = None
    issuer: Optional[str] = None
    auth_time: Optional[int] = None
    # raw claims for auditing/debug (not to be persisted long-term)
    raw_claims: Dict[str, Any] = Field(default_factory=dict)


class SessionTokens(BaseModel):
    access_token: str
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    scope: Optional[str] = None
    expires_at: Optional[int] = None  # epoch seconds
    issuer: Optional[str] = None


class Session(BaseModel):
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    principal: Principal
    tokens: SessionTokens
    provider: str
    tenant: Optional[str] = None
    sid: Optional[str] = None  # OIDC Session ID (for front/back-channel logout)
    # TTL in seconds (advisory for stores; real expiry is tokens.expires_at)
    ttl_sec: int = 86400


class IdpError(Exception):
    pass


# -------------------------------------------------------------------------------------
# Stores (state/nonce/session)
# -------------------------------------------------------------------------------------

class TTLStore:
    """In-memory TTL store, coroutine-safe."""
    def __init__(self, capacity: int = 200_000):
        self.capacity = capacity
        self._data: Dict[str, Tuple[int, str]] = {}
        self._lock = asyncio.Lock()

    async def put(self, key: str, value: str, ttl: int) -> None:
        async with self._lock:
            now = int(time.time())
            # Evict expired
            expired = [k for k, (exp, _) in self._data.items() if exp <= now]
            for k in expired:
                self._data.pop(k, None)
            # Evict oldest if needed
            if len(self._data) >= self.capacity:
                oldest = min(self._data.items(), key=lambda kv: kv[1][0])[0]
                self._data.pop(oldest, None)
            self._data[key] = (now + ttl, value)

    async def take(self, key: str) -> Optional[str]:
        async with self._lock:
            item = self._data.pop(key, None)
            if not item:
                return None
            exp, val = item
            if exp < int(time.time()):
                return None
            return val


class SessionStore(ABC):
    @abstractmethod
    async def save(self, session: Session) -> None:
        ...

    @abstractmethod
    async def get(self, session_id: str) -> Optional[Session]:
        ...

    @abstractmethod
    async def delete(self, session_id: str) -> None:
        ...

    @abstractmethod
    async def find_by_sub_or_sid(self, issuer: str, sub: Optional[str] = None, sid: Optional[str] = None) -> List[Session]:
        ...


class InMemorySessionStore(SessionStore):
    def __init__(self):
        self._data: Dict[str, Session] = {}
        self._lock = asyncio.Lock()

    async def save(self, session: Session) -> None:
        async with self._lock:
            session.updated_at = datetime.now(timezone.utc).isoformat()
            self._data[session.session_id] = session

    async def get(self, session_id: str) -> Optional[Session]:
        async with self._lock:
            return self._data.get(session_id)

    async def delete(self, session_id: str) -> None:
        async with self._lock:
            self._data.pop(session_id, None)

    async def find_by_sub_or_sid(self, issuer: str, sub: Optional[str] = None, sid: Optional[str] = None) -> List[Session]:
        async with self._lock:
            out: List[Session] = []
            for s in self._data.values():
                if s.tokens.issuer != issuer:
                    continue
                if sub and s.principal.subject == sub:
                    out.append(s)
                elif sid and s.sid == sid:
                    out.append(s)
            return out


# -------------------------------------------------------------------------------------
# Adapter interface
# -------------------------------------------------------------------------------------

class IdpAdapter(ABC):
    name: str

    @abstractmethod
    async def build_authorization_url(self, ctx: RequestContext, extra_params: Optional[Dict[str, str]] = None) -> AuthorizationRedirect:
        ...

    @abstractmethod
    async def exchange_code_and_login(self, code: str, state: str, expected_nonce: str,
                                      code_verifier: Optional[str], ctx: RequestContext) -> Session:
        ...

    @abstractmethod
    async def refresh(self, session_id: str) -> Session:
        ...

    @abstractmethod
    async def logout_frontchannel_url(self, session_id: str, post_logout_redirect_uri: Optional[str] = None, state: Optional[str] = None) -> Optional[str]:
        ...

    @abstractmethod
    async def handle_backchannel_logout(self, logout_token: str) -> List[str]:
        """
        Process OIDC back-channel logout. Returns list of terminated session_ids.
        """
        ...

    @abstractmethod
    async def introspect(self, access_token: str) -> Optional[Dict[str, Any]]:
        ...


# -------------------------------------------------------------------------------------
# OIDC Adapter
# -------------------------------------------------------------------------------------

class OIDCProviderConfig(BaseModel):
    """Wrapper over OIDCSettings plus mapping and defaults."""
    settings: OIDCSettings  # type: ignore[name-defined]
    mapping: AttributeMapping = AttributeMapping()
    # default roles/groups if IdP doesn't provide
    default_roles: List[str] = Field(default_factory=list)
    default_groups: List[str] = Field(default_factory=list)
    # state/nonce TTLs
    state_ttl: int = 600
    nonce_ttl: int = 600
    # redact keys for logs
    redact_keys: List[str] = Field(default_factory=lambda: ["access_token", "refresh_token", "id_token", "authorization", "cookie"])

class OIDCIdpAdapter(IdpAdapter):
    def __init__(self, name: str, config: OIDCProviderConfig, store: Optional[SessionStore] = None):
        if OIDCClient is None:
            raise IdpError("OIDCClient is not available")
        self.name = name
        self.cfg = config
        self.client = OIDCClient(self.cfg.settings)  # type: ignore[arg-type]
        self.sessions: SessionStore = store or InMemorySessionStore()
        # Use client internal stores for nonce/state if available; fallback to our own TTL store
        self._state_store = getattr(self.client, "state_store", TTLStore())
        self._nonce_store = getattr(self.client, "nonce_store", TTLStore())

    async def build_authorization_url(self, ctx: RequestContext, extra_params: Optional[Dict[str, str]] = None) -> AuthorizationRedirect:
        # Allow per-request redirect override
        if ctx.redirect_uri:
            # Update a copy of settings with override
            self.client.s = self.client.s.copy(update={"redirect_uri": str(ctx.redirect_uri)})  # type: ignore[attr-defined]
        data = await self.client.build_authorization_url(
            state_ttl=self.cfg.state_ttl, nonce_ttl=self.cfg.nonce_ttl, extra_params=extra_params
        )
        # State/nonce already stored in OIDCClient TTL store; we only return details
        return AuthorizationRedirect(
            authorization_url=data["authorization_url"],
            state=data["state"],
            nonce=data["nonce"],
            code_verifier=data.get("code_verifier"),
            expires_in=self.cfg.state_ttl
        )

    async def exchange_code_and_login(self, code: str, state: str, expected_nonce: str,
                                      code_verifier: Optional[str], ctx: RequestContext) -> Session:
        # Validate state: must exist in TTL store and consume it (prevents CSRF replay)
        st = await self._state_store.take(state)
        if not st:
            raise IdpError("invalid or expired state")
        tokens: TokenSet = await self.client.exchange_code(code, code_verifier)  # type: ignore[assignment]
        claims: IdTokenClaims = await self.client.verify_id_token(  # type: ignore[assignment]
            tokens.id_token, nonce=expected_nonce, access_token=tokens.access_token
        )
        principal = self._map_claims(claims, ctx)
        # Try to extract sid (session id) for logout correlation
        sid = None
        try:
            raw = dict(claims)  # jose/authlib mapping
            sid = raw.get("sid")
        except Exception:
            pass

        sess = Session(
            principal=principal,
            tokens=SessionTokens(
                access_token=tokens.access_token,
                id_token=tokens.id_token,
                refresh_token=tokens.refresh_token,
                token_type=tokens.token_type or "Bearer",
                scope=tokens.scope,
                expires_at=tokens.expires_at,
                issuer=claims.iss,
            ),
            provider=self.name,
            tenant=principal.tenant or ctx.tenant,
            sid=sid,
            ttl_sec=86400,
        )
        await self.sessions.save(sess)
        logger.info("idp.oidc.login success provider=%s tenant=%s subject=%s sid=%s", self.name, sess.tenant, principal.subject, sid or "-")
        return sess

    async def refresh(self, session_id: str) -> Session:
        s = await self.sessions.get(session_id)
        if not s:
            raise IdpError("session not found")
        if not s.tokens.refresh_token:
            raise IdpError("no refresh token in session")
        ts: TokenSet = await self.client.refresh(s.tokens.refresh_token)  # type: ignore[assignment]
        # keep same principal; update tokens
        s.tokens.access_token = ts.access_token
        s.tokens.id_token = ts.id_token or s.tokens.id_token
        s.tokens.refresh_token = ts.refresh_token or s.tokens.refresh_token
        s.tokens.expires_at = ts.expires_at
        s.tokens.token_type = ts.token_type or "Bearer"
        s.tokens.scope = ts.scope or s.tokens.scope
        await self.sessions.save(s)
        logger.info("idp.oidc.refresh success provider=%s session=%s", self.name, s.session_id)
        return s

    async def logout_frontchannel_url(self, session_id: str, post_logout_redirect_uri: Optional[str] = None, state: Optional[str] = None) -> Optional[str]:
        s = await self.sessions.get(session_id)
        if not s:
            raise IdpError("session not found")
        # Try to construct end-session URL if provider advertises it
        try:
            meta = await self.client.discover()
            if not getattr(meta, "end_session_endpoint", None):
                return None
            params = {}
            if s.tokens.id_token:
                params["id_token_hint"] = s.tokens.id_token
            if post_logout_redirect_uri:
                params["post_logout_redirect_uri"] = post_logout_redirect_uri
            if state:
                params["state"] = state
            from urllib.parse import urlencode
            return f"{meta.end_session_endpoint}?{urlencode(params)}"
        finally:
            # Regardless of provider support, remove local session
            await self.sessions.delete(session_id)
            logger.info("idp.oidc.logout local session cleared provider=%s session=%s", self.name, session_id)

    async def handle_backchannel_logout(self, logout_token: str) -> List[str]:
        """
        Verify OIDC back-channel logout token; terminate matching sessions (by sid or sub).
        """
        ltc: LogoutTokenClaims = await self.client.verify_logout_token(logout_token)  # type: ignore[assignment]
        raw = dict(ltc)
        sid = raw.get("sid")
        sub = raw.get("sub")
        issuer = raw.get("iss")
        if not issuer:
            raise IdpError("logout token missing issuer")
        sessions = await self.sessions.find_by_sub_or_sid(issuer=issuer, sub=sub, sid=sid)
        terminated: List[str] = []
        for s in sessions:
            await self.sessions.delete(s.session_id)
            terminated.append(s.session_id)
        logger.info("idp.oidc.backchannel_logout provider=%s issuer=%s sid=%s sub=%s terminated=%d",
                    self.name, issuer, sid or "-", sub or "-", len(terminated))
        return terminated

    async def introspect(self, access_token: str) -> Optional[Dict[str, Any]]:
        try:
            return await self.client.introspect(access_token)
        except Exception as e:
            logger.warning("idp.oidc.introspect failed provider=%s err=%s", self.name, e)
            return None

    # ----------------------- internal helpers -----------------------

    def _map_claims(self, claims: IdTokenClaims, ctx: RequestContext) -> Principal:  # type: ignore[valid-type]
        """Map IdP claims to internal Principal according to AttributeMapping."""
        raw = dict(claims)
        m = self.cfg.mapping
        groups_val = raw.get(m.groups)
        if isinstance(groups_val, str):
            groups = [groups_val]
        elif isinstance(groups_val, list):
            groups = [str(x) for x in groups_val]
        else:
            groups = []
        roles: List[str] = []
        if m.roles:
            rv = raw.get(m.roles)
            if isinstance(rv, str):
                roles = [rv]
            elif isinstance(rv, list):
                roles = [str(x) for x in rv]
        # defaults
        groups = groups or list(self.cfg.default_groups)
        roles = roles or list(self.cfg.default_roles)
        principal = Principal(
            subject=str(raw.get(m.sub)),
            tenant=(raw.get(m.tenant) if m.tenant else None) or ctx.tenant,
            email=raw.get(m.email),
            name=raw.get(m.name) or raw.get(m.preferred_username),
            preferred_username=raw.get(m.preferred_username),
            given_name=raw.get(m.given_name),
            family_name=raw.get(m.family_name),
            groups=groups,
            roles=roles,
            acr=raw.get("acr"),
            amr=raw.get("amr") or [],
            mfa=("enabled" if raw.get("amr") else None),
            picture=raw.get(m.picture) if m.picture else None,
            locale=raw.get(m.locale) if m.locale else None,
            issuer=raw.get("iss"),
            auth_time=raw.get("auth_time"),
            raw_claims=raw,
        )
        if not principal.subject:
            raise IdpError("missing subject in ID Token")
        return principal


# -------------------------------------------------------------------------------------
# Registry for multi-tenant / multi-provider
# -------------------------------------------------------------------------------------

class IdpRegistry:
    """
    Holds multiple IdP adapters by name and/or tenant.
    """
    def __init__(self):
        self._by_name: Dict[str, IdpAdapter] = {}
        self._by_tenant: Dict[str, str] = {}  # tenant -> adapter name

    def register(self, adapter: IdpAdapter, tenants: Optional[List[str]] = None) -> None:
        if adapter.name in self._by_name:
            raise IdpError(f"adapter with name {adapter.name} already registered")
        self._by_name[adapter.name] = adapter
        if tenants:
            for t in tenants:
                self._by_tenant[t] = adapter.name

    def get(self, name_or_tenant: str) -> IdpAdapter:
        name = self._by_tenant.get(name_or_tenant, name_or_tenant)
        ad = self._by_name.get(name)
        if not ad:
            raise IdpError(f"idp adapter not found: {name_or_tenant}")
        return ad


# -------------------------------------------------------------------------------------
# Example of wiring (non-executable on import)
# -------------------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    async def main():
        # Build OIDC adapter
        if OIDCSettings is None:
            raise SystemExit("OIDCSettings not available")
        oidc_cfg = OIDCProviderConfig(
            settings=OIDCSettings(
                issuer="https://idp.example.com/",
                client_id="security-core-app",
                client_secret=os.getenv("OIDC_CLIENT_SECRET"),
                redirect_uri="https://app.example.com/oidc/callback",
                scopes=["openid", "profile", "email", "groups"],
                token_endpoint_auth_method="client_secret_post",
            ),
            mapping=AttributeMapping(groups="groups", roles="roles", tenant="tid"),
            default_roles=["user"],
            default_groups=[],
            state_ttl=600,
            nonce_ttl=600,
        )
        adapter = OIDCIdpAdapter("example-oidc", oidc_cfg)

        # Start auth
        ctx = RequestContext(tenant="acme", ip="203.0.113.1", user_agent="curl/8.0")
        redirect = await adapter.build_authorization_url(ctx)
        print("Go to:", redirect.authorization_url)

        # Simulate callback (code/state/nonce from browser)
        # tokens/session creation
        # session = await adapter.exchange_code_and_login(code, state, nonce, redirect.code_verifier, ctx)

    asyncio.run(main())
