# -*- coding: utf-8 -*-
"""
E2E Zero Trust: OIDC -> Pre-Session -> Step-up MFA (AAL2) -> Access PII (mTLS pin + ABAC)
-> Continuous risk evaluation (impossible travel) -> Revoke -> One-time refresh.

Зависимости окружения тестов:
  - pytest
  - fastapi, starlette
  - cryptography
Примечание: При отсутствии зависимостей тест будет пропущен.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from datetime import timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional, Tuple

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("starlette.testclient")
pytest.importorskip("cryptography")

from fastapi import FastAPI, Depends, Request, HTTPException
from starlette.testclient import TestClient

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Импорт из вашего проекта (модули даны ранее)
from security.security.crypto.verifier import (
    JWTVerifier,
    VerifierConfig,
    RemoteJWKS,
    AlgorithmNotAllowed,
)
from security.security.authn.sessions import (
    InMemorySessionStore,
    SessionPolicy,
    default_inmemory_store,
)

# ============================== Утилиты =======================================

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def _b64u_json(obj: dict) -> str:
    return _b64u(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

def mint_jwt_rs256(private_key: rsa.RSAPrivateKey, header: dict, payload: dict) -> str:
    hdr = dict(header or {})
    hdr.setdefault("alg", "RS256")
    hdr.setdefault("typ", "JWT")
    h_b64 = _b64u_json(hdr)
    p_b64 = _b64u_json(payload)
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h_b64}.{p_b64}.{_b64u(sig)}"

def rsa_keypair(bits: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return priv, priv.public_key()

def jwk_from_rsa_pub(pub, kid: str, alg: str = "RS256") -> Dict:
    numbers = pub.public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "alg": alg,
        "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }

# ============================ JWKS HTTP-Сервер ================================

class _JWKSHandler(BaseHTTPRequestHandler):
    jwks_bytes: bytes = b'{"keys": []}'

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        if self.path.startswith("/.well-known/jwks.json"):
            data = _JWKSHandler.jwks_bytes
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

@pytest.fixture(scope="function")
def jwks_server():
    server = HTTPServer(("127.0.0.1", 0), _JWKSHandler)
    host, port = server.server_address
    t = threading.Thread(target=server.serve_forever, name="jwks", daemon=True)
    t.start()
    try:
        yield f"http://{host}:{port}/.well-known/jwks.json"
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=2)

# ============================== Политики ZT ===================================

class RiskEngine:
    """
    Простейший риск‑движок для теста.
    """
    def score(self, *, user_id: str, ip: str, ua: str, device: Dict[str, Any], signals: Dict[str, Any]) -> int:
        score = 10
        if signals.get("new_device"):
            score += 25
        if signals.get("ip_velocity"):
            score += 30
        if signals.get("impossible_travel"):
            score += 60
        # device posture штрафы
        if not device.get("secure_boot"):
            score += 20
        if not device.get("disk_encrypted"):
            score += 20
        if device.get("os_patch_age_days", 0) > 30:
            score += 15
        return min(score, 100)

class DevicePosture:
    """
    Базовый baseline: шифрование диска, secure boot, свежие патчи, допустимая ОС.
    """
    allowed_os = {"macos", "windows", "linux"}

    def check(self, posture: Dict[str, Any]) -> bool:
        try:
            return (
                str(posture.get("os", "")).lower() in self.allowed_os
                and posture.get("secure_boot") is True
                and posture.get("disk_encrypted") is True
                and int(posture.get("os_patch_age_days", 999)) <= 30
            )
        except Exception:
            return False

class PolicyEngine:
    """
    RBAC + ABAC (минималистично для теста).
    """
    role_permissions = {
        "user": {"profile.read"},
        "analyst": {"audit.read", "pii.read"},
        "admin": {"users.read", "users.write", "secrets.rotate", "pii.read"},
    }

    def allowed(self, *, roles: List[str], permission: str, ctx: Dict[str, Any]) -> bool:
        # RBAC
        if not any(permission in self.role_permissions.get(r, set()) for r in roles):
            return False
        # ABAC: изоляция по тенанту
        if ctx.get("tenant_id") != ctx.get("resource_tenant_id"):
            return False
        return True

# ============================== Мини‑приложение ===============================

def make_app(*, jwks_url: str, session_store: InMemorySessionStore, mTLS_pins: List[str]) -> FastAPI:
    app = FastAPI()
    risk = RiskEngine()
    dp = DevicePosture()
    pe = PolicyEngine()

    # JWT verifier
    vcfg = VerifierConfig(
        allowed_algs=("RS256",),
        allow_symmetric=False,
        expected_typ="JWT",
        leeway_seconds=60,
        jwks_cache_ttl=2,
        http_timeout=2,
        max_age_seconds=3600,
    )
    src = RemoteJWKS(jwks_url, cache_ttl=vcfg.jwks_cache_ttl, http_timeout=vcfg.http_timeout)
    jwtv = JWTVerifier(src, vcfg)

    # Фиктивный аудит
    AUDIT: List[Dict[str, Any]] = []
    app.state.AUDIT = AUDIT

    def audit(event: str, **fields):
        AUDIT.append({"event": event, **fields})

    @app.post("/v1/authn/oidc/callback")
    def oidc_callback(req: Request):
        body = req.json()
        token = body["id_token"]
        device = body.get("device_posture", {})
        ip = req.headers.get("x-real-ip", "127.0.0.1")
        ua = req.headers.get("user-agent", "UA/1.0")

        # verify JWT
        claims = jwtv.verify(token, iss=body["iss"], aud=body["aud"])
        user_id = claims["sub"]
        tenant_id = claims.get("tenant_id", "t-1")
        roles = claims.get("roles", ["user"])

        # posture baseline
        if not dp.check(device):
            audit("authn.denied.posture", user_id=user_id)
            raise HTTPException(status_code=403, detail="device posture failed")

        # risk score
        signals = {"new_device": True}  # впервые видим устройство в этом тесте
        rscore = risk.score(user_id=user_id, ip=ip, ua=ua, device=device, signals=signals)
        audit("authn.pre_session", user_id=user_id, risk=rscore)

        # pre-session + требование AAL2 при rscore >= 40
        pre = session_store.create_pre_session(user_id=user_id, username=claims.get("preferred_username", user_id), device_id=device.get("device_id", "dev-1"))
        needs_stepup = rscore >= 40
        return {
            "pre_session_id": pre.id,
            "step_up_required": needs_stepup,
            "required_aal": "AAL2" if needs_stepup else "AAL1",
            "tenant_id": tenant_id,
            "roles": roles,
        }

    @app.post("/v1/authn/mfa/verify")
    def mfa_verify(req: Request):
        body = req.json()
        pre_id = body["pre_session_id"]
        code = body.get("otp") or body.get("assertion")
        if not code:
            audit("mfa.failed", reason="no_code")
            raise HTTPException(status_code=400, detail="code required")
        s, r = session_store.upgrade_pre_session(pre_id, ip=req.headers.get("x-real-ip", "127.0.0.1"), ua=req.headers.get("user-agent", "UA/1.0"), mfa_level="AAL2", risk_score=30)
        if not s:
            audit("mfa.failed", reason="upgrade_failed")
            raise HTTPException(status_code=400, detail="upgrade failed")
        audit("mfa.verified", session_id=s.id)
        audit("session.created", session_id=s.id, refresh_id=r.id)
        return {"session_id": s.id, "refresh_id": r.id, "aal": "AAL2"}

    def _authz(req: Request, *, permission: str) -> Dict[str, Any]:
        sess_id = req.headers.get("x-session-id")
        ip = req.headers.get("x-real-ip", "127.0.0.1")
        ua = req.headers.get("user-agent", "UA/1.0")
        spki = req.headers.get("x-client-spki", "")

        # mTLS pinning
        if mTLS_pins and spki not in mTLS_pins:
            audit("access.denied.mtls", reason="pin_mismatch")
            raise HTTPException(status_code=401, detail="mTLS pin mismatch")

        s = session_store.get_session(sess_id, ip=ip, ua=ua)
        if not s:
            audit("access.denied.session", reason="invalid_or_revoked")
            raise HTTPException(status_code=401, detail="invalid session")

        # continuous risk check (имитация impossible travel флагом из заголовка)
        if req.headers.get("x-zt-impossible-travel") == "1":
            # Отзовем сессию
            session_store.revoke(s.id, reason="impossible_travel")
            audit("session.revoked", session_id=s.id, reason="impossible_travel")
            raise HTTPException(status_code=401, detail="risk reauth required")

        # Требование AAL2 для PII
        if permission == "pii.read" and s.mfa_level != "AAL2":
            audit("access.denied.aal", need="AAL2", have=s.mfa_level)
            raise HTTPException(status_code=403, detail="step-up required")

        # RBAC/ABAC
        ctx = {"tenant_id": s.tenant_id or "t-1", "resource_tenant_id": req.headers.get("x-resource-tenant-id", s.tenant_id or "t-1")}
        if not pe.allowed(roles=s.roles or ["user"], permission=permission, ctx=ctx):
            audit("access.denied.policy", permission=permission)
            raise HTTPException(status_code=403, detail="policy denied")

        # sliding window
        session_store.touch(s.id)
        return {"user_id": s.user_id, "roles": s.roles, "tenant_id": s.tenant_id or "t-1"}

    @app.get("/v1/pii")
    def get_pii(req: Request):
        _ = _authz(req, permission="pii.read")
        audit("resource.access.granted", resource="pii")
        # Возвращаем минимальный ответ
        return {"ok": True, "resource": "pii"}

    @app.post("/v1/authn/refresh")
    def refresh(req: Request):
        rid = req.json().get("refresh_id")
        ip = req.headers.get("x-real-ip", "127.0.0.1")
        ua = req.headers.get("user-agent", "UA/1.0")
        s, r = session_store.refresh(rid, ip=ip, ua=ua)
        if not s:
            audit("refresh.denied", reason="replay_or_invalid")
            raise HTTPException(status_code=401, detail="refresh denied")
        audit("refresh.ok", session_id=s.id, refresh_id=r.id)
        return {"session_id": s.id, "refresh_id": r.id}

    # прокидываем стор и аудит наружу для проверок
    app.state.session_store = session_store
    return app

# ================================ Фикстуры ====================================

@pytest.fixture(scope="function")
def rsa_keys():
    return rsa_keypair(2048)

@pytest.fixture(scope="function")
def jwk_kid():
    return "kid-zt-rs"

@pytest.fixture(scope="function")
def session_store():
    secret = b"\x02" * 32
    policy = SessionPolicy(
        access_ttl=timedelta(seconds=4),
        refresh_ttl=timedelta(seconds=60),
        absolute_ttl=timedelta(seconds=30),
        pre_session_ttl=timedelta(seconds=5),
        pin_ip=True,
        pin_ua=True,
        max_user_sessions=3,
        on_limit="evict_oldest",
    )
    return default_inmemory_store(secret, policy=policy)

# ================================ Сам тест ====================================

@pytest.mark.e2e
def test_zero_trust_full_flow(jwks_server, rsa_keys, jwk_kid, session_store):
    """
    Этапы:
      1) OIDC callback -> pre-session (риск >= 40 требует AAL2).
      2) MFA verify -> AAL2 session.
      3) Доступ к PII с mTLS‑пином -> OK.
      4) Impossible travel -> отзыв и 401.
      5) One-time refresh: первый успешен, повторная попытка отклоняется.
      6) Проверка аудита стадий.
    """
    # 0) Подготовка JWKS и приложения
    priv, pub = rsa_keys
    jwks = {"keys": [jwk_from_rsa_pub(pub, jwk_kid, "RS256")]}
    _JWKSHandler.jwks_bytes = json.dumps(jwks).encode("utf-8")

    app = make_app(jwks_url=jwks_server, session_store=session_store, mTLS_pins=["TESTPIN=="])
    client = TestClient(app)

    now = int(time.time())
    claims = {
        "iss": "https://id.example.test",
        "aud": "security-core",
        "sub": "user-zt-1",
        "preferred_username": "alice",
        "tenant_id": "t-1",
        "roles": ["analyst"],  # имеет право на pii.read согласно RBAC
        "iat": now,
        "nbf": now - 5,
        "exp": now + 600,
    }
    id_token = mint_jwt_rs256(priv, {"kid": jwk_kid, "typ": "JWT"}, claims)

    # 1) OIDC callback -> ожидаем pre-session и требование AAL2
    device = {"device_id": "dev-zt-1", "os": "macOS", "secure_boot": True, "disk_encrypted": True, "os_patch_age_days": 7}
    r1 = client.post(
        "/v1/authn/oidc/callback",
        json={"id_token": id_token, "iss": claims["iss"], "aud": claims["aud"], "device_posture": device},
        headers={"x-real-ip": "1.1.1.1", "user-agent": "UA/1.0"},
    )
    assert r1.status_code == 200, r1.text
    data1 = r1.json()
    assert data1["step_up_required"] is True
    pre_id = data1["pre_session_id"]

    # 2) MFA verify -> AAL2 session создана
    r2 = client.post(
        "/v1/authn/mfa/verify",
        json={"pre_session_id": pre_id, "otp": "000000"},
        headers={"x-real-ip": "1.1.1.1", "user-agent": "UA/1.0"},
    )
    assert r2.status_code == 200, r2.text
    data2 = r2.json()
    sess_id = data2["session_id"]
    ref_id = data2["refresh_id"]
    assert data2["aal"] == "AAL2"

    # 3) Доступ к PII при корректном mTLS‑пине -> OK
    r3 = client.get(
        "/v1/pii",
        headers={"x-session-id": sess_id, "x-real-ip": "1.1.1.1", "user-agent": "UA/1.0", "x-client-spki": "TESTPIN==", "x-resource-tenant-id": "t-1"},
    )
    assert r3.status_code == 200, r3.text
    assert r3.json()["ok"] is True

    # 4) Рост риска (impossible travel) -> отзыв и 401
    r4 = client.get(
        "/v1/pii",
        headers={
            "x-session-id": sess_id,
            "x-real-ip": "8.8.8.8",
            "user-agent": "UA/1.0",
            "x-client-spki": "TESTPIN==",
            "x-resource-tenant-id": "t-1",
            "x-zt-impossible-travel": "1",
        },
    )
    assert r4.status_code == 401

    # Повторная попытка со старым SID тоже 401
    r4b = client.get(
        "/v1/pii",
        headers={"x-session-id": sess_id, "x-real-ip": "8.8.8.8", "user-agent": "UA/1.0", "x-client-spki": "TESTPIN==", "x-resource-tenant-id": "t-1"},
    )
    assert r4b.status_code == 401

    # 5) One-time refresh: первый успешен, повторная попытка отклоняется
    r5 = client.post("/v1/authn/refresh", json={"refresh_id": ref_id}, headers={"x-real-ip": "1.1.1.1", "user-agent": "UA/1.0"})
    assert r5.status_code == 200, r5.text
    new_sess = r5.json()["session_id"]
    new_ref = r5.json()["refresh_id"]

    # Повторное использование старого refresh токена
    r5b = client.post("/v1/authn/refresh", json={"refresh_id": ref_id}, headers={"x-real-ip": "1.1.1.1", "user-agent": "UA/1.0"})
    assert r5b.status_code == 401

    # Новый SID работает
    r6 = client.get(
        "/v1/pii",
        headers={"x-session-id": new_sess, "x-real-ip": "1.1.1.1", "user-agent": "UA/1.0", "x-client-spki": "TESTPIN==", "x-resource-tenant-id": "t-1"},
    )
    assert r6.status_code == 200

    # 6) Проверяем аудит стадий
    audit = client.app.state.AUDIT
    events = [e["event"] for e in audit]
    assert "authn.pre_session" in events
    assert "mfa.verified" in events
    assert "session.created" in events
    assert {"event": "resource.access.granted", "resource": "pii"} in [{k: v for k, v in e.items() if k in ("event", "resource")} for e in audit]
    assert any(e["event"] == "session.revoked" and e.get("reason") == "impossible_travel" for e in audit)
    assert "refresh.ok" in events
    assert any(e["event"] == "refresh.denied" for e in audit)  # повторная попытка
