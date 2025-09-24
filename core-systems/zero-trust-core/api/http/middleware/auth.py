# zero-trust-core/api/http/middleware/auth.py
from __future__ import annotations

import base64
import json
import time
import hmac
import hashlib
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Union

from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import JSONResponse
from starlette.datastructures import Headers

# Опциональные зависимости: PyJWT и cryptography (для удобной встроенной верификации).
try:
    import jwt  # type: ignore
    _HAVE_PYJWT = True
except Exception:
    _HAVE_PYJWT = False

try:
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False


# =============================== Утилиты ===============================

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64url_to_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _now() -> int:
    return int(time.time())


class TTLCache:
    def __init__(self, ttl_s: int = 300, max_items: int = 10000) -> None:
        self._ttl = int(ttl_s)
        self._max = int(max_items)
        self._store: Dict[str, Tuple[int, Any]] = {}

    def get(self, k: str) -> Optional[Any]:
        it = self._store.get(k)
        if not it:
            return None
        ts, v = it
        if _now() - ts > self._ttl:
            self._store.pop(k, None)
            return None
        return v

    def set(self, k: str, v: Any) -> None:
        if len(self._store) >= self._max:
            # простое LRU‑подобное высвобождение: удалить ~10% самых старых
            oldest = sorted(self._store.items(), key=lambda kv: kv[1][0])[: max(1, self._max // 10)]
            for kk, _ in oldest:
                self._store.pop(kk, None)
        self._store[k] = (_now(), v)


def _redact(s: str, keep: int = 6) -> str:
    if not s:
        return s
    return s[:keep] + "…REDACTED…"


def _constant_time_eq(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)


# =============================== Протоколы интеграции ===============================

class TokenVerifier(Protocol):
    """
    Верификация и разбор JWT. Возвращает claims и метаданные ключа.
    """
    def verify(self, token: str) -> Tuple[Mapping[str, Any], Mapping[str, Any]]: ...


class MTLSValidator(Protocol):
    """
    Проверка клиентского сертификата. Возвращает DER сертификат и отпечатки.
    """
    def validate(self, scope: Scope, headers: Headers) -> Optional[Mapping[str, Any]]: ...


class DPoPVerifier(Protocol):
    """
    Проверка DPoP‑proof (заголовок DPoP) для метода/URL.
    Возвращает публичный JWK (dict) и thumbprint (jkt).
    """
    def verify(self, headers: Headers, method: str, url: str) -> Optional[Tuple[Mapping[str, Any], str]]: ...


class PolicyEvaluator(Protocol):
    """
    Политическая оценка сессии/запроса.
    Возвращает решение и возможные требуемые действия (например, step‑up).
    """
    def evaluate(self, principal: str, context: Mapping[str, Any]) -> Mapping[str, Any]: ...


# =============================== Конфигурация и контекст ===============================

@dataclass
class TokenBindingConfig:
    type: str = "mtls"          # none | mtls | dpop
    required: bool = True
    clock_skew_s: int = 60      # общая терпимость по времени (для DPoP)

@dataclass
class AuthConfig:
    issuer: str
    audience: str
    allowed_algs: Sequence[str] = field(default_factory=lambda: ("RS256", "PS256", "ES256", "ES384", "EdDSA"))
    require_mtls: bool = True
    accepted_client_cert_header: Optional[str] = "x-ssl-client-cert"  # PEM от edge‑прокси; None если backend получает TLS‑пиринги
    token_binding: TokenBindingConfig = field(default_factory=TokenBindingConfig)
    jwks_url: Optional[str] = None          # если используете встроенную проверку PyJWT с JWKS
    leeway_s: int = 60
    shadow_mode: bool = False               # в shadow не отклоняем запрос, а только логируем нарушение
    decision_cache_ttl_s: int = 30
    correlation_header: str = "x-correlation-id"
    # Имена полей в claims
    tenant_claim: str = "tid"
    scopes_claim: str = "scope"
    session_claim: str = "sid"
    subject_claim: str = "sub"

@dataclass
class AuthContext:
    principal: str
    tenant_id: Optional[str]
    scopes: Sequence[str]
    token_id: Optional[str]
    session_id: Optional[str]
    trust_level: Optional[str]
    risk_score: Optional[float]
    token_binding: Optional[str]
    token_binding_thumbprint: Optional[str]
    presented_cert_thumbprint: Optional[str]
    claims: Mapping[str, Any]


# =============================== Встроенные проверяющие (по желанию) ===============================

class SimpleJWKSVerifier(TokenVerifier):
    """
    Упрощённый JWT‑верификатор на базе PyJWT, с кэшем JWKS.
    Предназначен для сценариев без внешнего KMS/STS клиента.
    """
    def __init__(self, issuer: str, audience: str, allowed_algs: Sequence[str], jwks_url: Optional[str], leeway_s: int = 60) -> None:
        if not _HAVE_PYJWT:
            raise RuntimeError("PyJWT is required for SimpleJWKSVerifier")
        self.issuer = issuer
        self.audience = audience
        self.allowed_algs = list(allowed_algs)
        self.jwks_url = jwks_url
        self.leeway = leeway_s
        self._jwks_cache = TTLCache(ttl_s=300, max_items=4)

    def _fetch_jwks(self) -> Mapping[str, Any]:
        import urllib.request  # stdlib
        cached = self._jwks_cache.get("jwks")
        if cached:
            return cached
        if not self.jwks_url:
            raise RuntimeError("jwks_url is required for JWKS fetching")
        with urllib.request.urlopen(self.jwks_url, timeout=5) as resp:
            body = resp.read().decode("utf-8")
        jwks = json.loads(body)
        self._jwks_cache.set("jwks", jwks)
        return jwks

    def _key_for_kid(self, kid: str) -> Mapping[str, Any]:
        jwks = self._fetch_jwks()
        keys = jwks.get("keys", [])
        for k in keys:
            if k.get("kid") == kid:
                return k
        raise jwt.InvalidTokenError("unknown kid")

    def verify(self, token: str) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:
        try:
            unverified = jwt.get_unverified_header(token)
            kid = unverified.get("kid")
            if not kid:
                raise jwt.InvalidTokenError("no kid")
            jwk = self._key_for_kid(kid)
            claims = jwt.decode(
                token,
                key=jwk,
                algorithms=self.allowed_algs,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={"require": ["exp", "iat"], "verify_aud": True, "verify_signature": True},
            )
            return claims, {"kid": kid, "jwk": jwk}
        except Exception as e:
            raise RuntimeError(f"jwt_verify_failed:{type(e).__name__}")


class HeaderMTLSValidator(MTLSValidator):
    """
    Извлекает клиентский сертификат из заголовка accepted_client_cert_header (PEM от edge).
    Вычисляет SHA‑256 отпечаток DER для RFC 8705 (x5t#S256).
    """
    def __init__(self, header_name: str = "x-ssl-client-cert") -> None:
        self.header = header_name.lower()

    def validate(self, scope: Scope, headers: Headers) -> Optional[Mapping[str, Any]]:
        pem = headers.get(self.header)
        if not pem:
            return None
        if not _HAVE_CRYPTO:
            # Минимальная поддержка: принимаем PEM как есть, без парсинга
            der_b64 = pem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").strip()
            der = _b64url_to_bytes(base64.urlsafe_b64encode(base64.b64decode(der_b64)).decode("ascii"))  # best effort
            fp = hashlib.sha256(der).digest()
            return {"pem": pem, "sha256_thumb": _b64url(fp)}
        try:
            cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
            der = cert.public_bytes(serialization.Encoding.DER)
            fp = hashlib.sha256(der).digest()
            return {
                "pem": pem,
                "sha256_thumb": _b64url(fp),
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": cert.not_valid_before.timestamp(),
                "not_after": cert.not_valid_after.timestamp(),
            }
        except Exception:
            return None


# =============================== Само middleware ===============================

class AuthMiddleware:
    """
    ASGI‑middleware Zero Trust аутентификации/авторизации уровня запроса.

    Функции:
      - Верификация JWT (встроенная через JWKS или внешняя через TokenVerifier).
      - Привязка токена к транспорту: mTLS (cnf.x5t#S256) или DPoP (cnf.jkt).
      - Обязательные транспортные требования (require_mtls).
      - Интеграция с политическим движком (PolicyEvaluator).
      - Shadow‑режим: логируем нарушения, но пропускаем запрос.

    request.state.auth -> AuthContext
    """
    def __init__(
        self,
        app: ASGIApp,
        *,
        config: AuthConfig,
        token_verifier: Optional[TokenVerifier] = None,
        mtls_validator: Optional[MTLSValidator] = None,
        dpop_verifier: Optional[DPoPVerifier] = None,
        policy_evaluator: Optional[PolicyEvaluator] = None,
        decision_cache: Optional[TTLCache] = None,
        logger: Optional[Callable[[str, Mapping[str, Any]], None]] = None,
    ) -> None:
        self.app = app
        self.cfg = config
        self.token_verifier = token_verifier or (SimpleJWKSVerifier(config.issuer, config.audience, config.allowed_algs, config.jwks_url, config.leeway_s) if config.jwks_url else None)
        self.mtls_validator = mtls_validator or (HeaderMTLSValidator(config.accepted_client_cert_header) if config.accepted_client_cert_header else None)
        self.dpop_verifier = dpop_verifier
        self.policy = policy_evaluator
        self.decisions = decision_cache or TTLCache(ttl_s=config.decision_cache_ttl_s)
        self.log = logger or (lambda name, tags: None)

    # ----------------------------- ASGI интерфейс -----------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        corr_id = headers.get(self.cfg.correlation_header) or f"req-{_now()}"
        method: str = scope["method"]
        url = self._full_url(scope, headers)

        # 1) Извлекаем и проверяем токен
        token, scheme = self._extract_token(headers)
        if not token:
            await self._reject(send, 401, "invalid_token", "missing bearer token", corr_id, www_auth=self._bearer_hdr())
            return

        # 2) Верификация JWT
        try:
            claims, key_meta = self._verify_token(token)
        except Exception as e:
            self._audit("auth.jwt_failed", {"cid": corr_id, "reason": str(e), "authz": _redact(token)})
            await self._reject(send, 401, "invalid_token", "jwt verification failed", corr_id, www_auth=self._bearer_hdr(realm="api", error="invalid_token"))
            return

        # 3) Проверка транспорта: mTLS / DPoP
        presented_cert_thumb = None
        jkt = None
        binding_type = self.cfg.token_binding.type

        if self.cfg.require_mtls or binding_type == "mtls":
            if not self.mtls_validator:
                await self._reject(send, 401, "invalid_request", "client certificate required", corr_id)
                return
            cert_info = self.mtls_validator.validate(scope, headers)
            if not cert_info:
                if self.cfg.shadow_mode:
                    self._audit("auth.mtls_missing_shadow", {"cid": corr_id})
                else:
                    await self._reject(send, 401, "invalid_request", "mTLS client certificate missing/invalid", corr_id)
                    return
            else:
                presented_cert_thumb = cert_info.get("sha256_thumb")

        if binding_type == "dpop":
            if not self.dpop_verifier:
                await self._reject(send, 401, "invalid_request", "DPoP binding required but verifier not configured", corr_id)
                return
            res = self.dpop_verifier.verify(headers, method, url)
            if not res:
                if self.cfg.shadow_mode:
                    self._audit("auth.dpop_missing_shadow", {"cid": corr_id})
                else:
                    await self._reject(send, 401, "invalid_token", "DPoP proof invalid/missing", corr_id, www_auth='DPoP error="invalid_proof"')
                    return
            else:
                _jwk, jkt = res

        # 4) Проверка привязки токена (cnf)
        if binding_type in ("mtls", "dpop"):
            cnf = claims.get("cnf") or {}
            if binding_type == "mtls":
                thumb = cnf.get("x5t#S256")
                if not thumb or not presented_cert_thumb or not _constant_time_eq(thumb, presented_cert_thumb):
                    msg = "token not bound to presented mTLS certificate"
                    if self.cfg.shadow_mode:
                        self._audit("auth.binding_mtls_mismatch_shadow", {"cid": corr_id, "cnf": thumb, "presented": presented_cert_thumb})
                    else:
                        await self._reject(send, 401, "invalid_token", msg, corr_id)
                        return
            elif binding_type == "dpop":
                claim_jkt = cnf.get("jkt")
                if not claim_jkt or not jkt or not _constant_time_eq(claim_jkt, jkt):
                    msg = "token not bound to DPoP key (jkt mismatch)"
                    if self.cfg.shadow_mode:
                        self._audit("auth.binding_dpop_mismatch_shadow", {"cid": corr_id, "cnf": claim_jkt, "jkt": jkt})
                    else:
                        await self._reject(send, 401, "invalid_token", msg, corr_id)
                        return

        # 5) Построение AuthContext и кэш решения политики
        principal = str(claims.get(self.cfg.subject_claim, ""))
        tenant_id = claims.get(self.cfg.tenant_claim)
        scopes_raw = claims.get(self.cfg.scopes_claim, "")
        scopes = tuple(sorted({s for s in (scopes_raw.split() if isinstance(scopes_raw, str) else scopes_raw or []) if s}))
        sid = claims.get(self.cfg.session_claim)
        jti = claims.get("jti")
        trust_level = claims.get("trust_level")
        risk_score = claims.get("risk_score")

        ctx = AuthContext(
            principal=principal,
            tenant_id=str(tenant_id) if tenant_id else None,
            scopes=scopes,
            token_id=str(jti) if jti else None,
            session_id=str(sid) if sid else None,
            trust_level=str(trust_level) if trust_level is not None else None,
            risk_score=float(risk_score) if risk_score is not None else None,
            token_binding=(binding_type if binding_type != "none" else None),
            token_binding_thumbprint=(presented_cert_thumb if binding_type == "mtls" else jkt),
            claims=claims,
        )

        # Политическая оценка
        decision_key = f"{principal}|{tenant_id}|{method}|{scope.get('path','')}"
        decision = self.decisions.get(decision_key)
        if decision is None and self.policy:
            policy_input = {
                "method": method,
                "path": scope.get("path", ""),
                "tenant": tenant_id,
                "scopes": scopes,
                "risk_score": ctx.risk_score,
                "trust_level": ctx.trust_level,
                "ip": headers.get("x-forwarded-for") or scope.get("client", ["", ""])[0],
                "user_agent": headers.get("user-agent", ""),
            }
            try:
                decision = self.policy.evaluate(principal, policy_input)
                self.decisions.set(decision_key, decision)
            except Exception as e:
                self._audit("auth.policy_error", {"cid": corr_id, "err": type(e).__name__})
                decision = {"allowed": False, "reasons": ["policy_error"]}

        allowed = True
        required_actions: Sequence[str] = ()
        reasons: Sequence[str] = ()
        if isinstance(decision, Mapping):
            allowed = bool(decision.get("allowed", True))
            required_actions = tuple(decision.get("required_actions", ()))
            reasons = tuple(decision.get("reasons", ()))

        if (not allowed) and not self.cfg.shadow_mode:
            await self._reject(send, 403, "access_denied", "policy denied access", corr_id, extra={"reasons": reasons})
            return

        # Step‑up (если требуется) — возвращаем 401
        if required_actions and "REQUIRE_MFA" in {r.upper() for r in required_actions} and not self.cfg.shadow_mode:
            await self._reject(send, 401, "insufficient_authentication", "step-up required", corr_id, www_auth=self._bearer_hdr(error="insufficient_authentication"))
            return

        # 6) Пробрасываем контекст в request.state
        scope.setdefault("state", {})
        scope["state"]["auth"] = ctx
        scope["state"]["auth_claims"] = claims
        scope["state"]["correlation_id"] = corr_id

        await self.app(scope, receive, send)

    # ----------------------------- Вспомогательные методы -----------------------------

    def _extract_token(self, headers: Headers) -> Tuple[Optional[str], Optional[str]]:
        auth = headers.get("authorization")
        if not auth:
            return None, None
        try:
            scheme, token = auth.split(" ", 1)
        except ValueError:
            return None, None
        scheme_lower = scheme.lower()
        if scheme_lower in ("bearer", "dpop"):
            return token.strip(), scheme_lower
        return None, None

    def _verify_token(self, token: str) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:
        if not self.token_verifier:
            # Без встроенного верификатора предполагаем, что upstream уже проверил токен (не рекомендуется).
            # Распарсим payload без проверки сигнатуры только для контекста — строго в DEV/STAGING.
            if not _HAVE_PYJWT:
                raise RuntimeError("no token verifier configured")
            try:
                claims = jwt.decode(token, options={"verify_signature": False})  # type: ignore
                return claims, {}
            except Exception as e:
                raise RuntimeError(f"jwt_parse_failed:{type(e).__name__}")
        return self.token_verifier.verify(token)

    def _full_url(self, scope: Scope, headers: Headers) -> str:
        scheme = headers.get("x-forwarded-proto") or scope.get("scheme", "http")
        host = headers.get("x-forwarded-host") or headers.get("host") or "localhost"
        path = scope.get("raw_path") or scope.get("path", "/")
        if isinstance(path, bytes):
            path = path.decode("utf-8", errors="ignore")
        qs = scope.get("query_string", b"")
        if isinstance(qs, (bytes, bytearray)) and qs:
            return f"{scheme}://{host}{path}?{qs.decode('utf-8', errors='ignore')}"
        return f"{scheme}://{host}{path}"

    def _bearer_hdr(self, realm: str = "api", error: Optional[str] = None) -> str:
        parts = [f'Bearer realm="{realm}"']
        if error:
            parts.append(f'error="{error}"')
        return ", ".join(parts)

    async def _reject(self, send: Send, status: int, code: str, msg: str, corr_id: str, www_auth: Optional[str] = None, extra: Optional[Mapping[str, Any]] = None) -> None:
        body: Dict[str, Any] = {"error": code, "error_description": msg, "correlation_id": corr_id}
        if extra:
            body.update(extra)
        headers = [(b"content-type", b"application/json")]
        if www_auth:
            headers.append((b"www-authenticate", www_auth.encode("ascii")))
        resp = JSONResponse(body, status_code=status, headers=dict(headers))
        await resp(None, send)

    def _audit(self, name: str, tags: Mapping[str, Any]) -> None:
        try:
            self.log(name, tags)
        except Exception:
            pass


# =============================== Пример интеграции (док) ===============================
"""
from fastapi import FastAPI, Request
from zero_trust_core.api.http.middleware.auth import AuthMiddleware, AuthConfig, TokenBindingConfig

app = FastAPI()

def logger(name, tags):  # ваш structured logger
    print(name, tags)

cfg = AuthConfig(
    issuer="https://idp.corp/",
    audience="zero-trust-core",
    jwks_url="https://idp.corp/.well-known/jwks.json",   # или передайте свой TokenVerifier
    require_mtls=True,
    accepted_client_cert_header="x-ssl-client-cert",
    token_binding=TokenBindingConfig(type="mtls", required=True),
    shadow_mode=False,
)

app.add_middleware(AuthMiddleware, config=cfg, logger=logger)

@app.get("/whoami")
async def whoami(request: Request):
    ctx = request.state.auth
    return {"sub": ctx.principal, "tenant": ctx.tenant_id, "scopes": ctx.scopes}
"""
