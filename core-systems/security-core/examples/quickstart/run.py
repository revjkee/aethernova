#!/usr/bin/env python3
# security-core/examples/quickstart/run.py
# Quickstart app: FastAPI service wiring security-core modules (JWKS, authz, inhibitor, audit).
from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import os
import signal
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel, BaseSettings, Field, HttpUrl, PositiveInt, ValidationError
from fastapi import FastAPI, HTTPException, Header, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# --- Ensure project root on sys.path so we can import `security.*` packages ---
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# --- Internal imports from security-core (provided in this repository) ---
try:
    # crypto/JWK
    from security.crypto.jwk import KeyStore
except Exception as e:
    print("Failed to import security.crypto.jwk; ensure you run from repo root.", file=sys.stderr)
    raise

# Audit exporter is optional
try:
    from security.audit.exporters.opensearch_exporter import (
        OpenSearchExporter,
        OpenSearchExporterConfig,
        TLSConfig as OSTLSConfig,
    )
except Exception:
    OpenSearchExporter = None  # type: ignore


# =========================
# Settings
# =========================

class AppSettings(BaseSettings):
    # App
    app_name: str = "security-core-quickstart"
    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "INFO"
    cors_allow_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000", "http://localhost:5173"])

    # JWKS/Keystore
    jwks_path: str = "secrets/jwks.json"
    jwk_alg: str = "EdDSA"                       # RS256 | ES256 | ES384 | EdDSA
    jwk_rsa_bits: int = 2048
    jwk_rotate_days: PositiveInt = 30
    jwk_keep_last: PositiveInt = 2

    # Admin operations
    admin_secret: Optional[str] = None           # required for inhibitor commands if set

    # Policy (for overview only; actual engine may live elsewhere)
    policy_path: str = "configs/policy.rego"
    opa_url: Optional[HttpUrl] = None

    # Audit / OpenSearch (optional)
    os_endpoints: list[HttpUrl] = Field(default_factory=list)
    os_auth_mode: str = "none"                   # none|basic|bearer|sigv4
    os_username: Optional[str] = None
    os_password: Optional[str] = None
    os_bearer_token: Optional[str] = None
    os_verify_tls: bool = True
    os_ca_path: Optional[str] = None
    os_client_cert: Optional[str] = None
    os_client_key: Optional[str] = None
    os_data_stream: bool = True
    os_data_stream_name: str = "security-audit"
    os_queue_max: int = 50_000
    os_batch_events: int = 2_000
    os_batch_bytes: int = 5_000_000
    os_flush_ms: int = 800
    os_concurrency: int = 2

    class Config:
        env_prefix = "SCQS_"
        case_sensitive = False

    def sanitized(self) -> Dict[str, Any]:
        data = self.dict()
        # redact secrets
        for k in list(data.keys()):
            if any(x in k.lower() for x in ("password", "token", "secret", "client_key")):
                if data[k] is not None:
                    data[k] = "***"
        return data

    def config_hash(self) -> str:
        raw = json.dumps(self.sanitized(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


# =========================
# State and wiring
# =========================

class AppState:
    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings
        self.keystore = KeyStore(Path(settings.jwks_path), passphrase=None)
        self.jwks_lock = asyncio.Lock()
        self.audit = None  # type: ignore
        self.inhibitor = {"armed": False, "last": None, "triggered": False}
        self.rotation_task: Optional[asyncio.Task] = None

    async def ensure_keystore(self) -> None:
        async with self.jwks_lock:
            self.keystore.load()
            created = self.keystore.rotate_if_needed(
                max_age_days=int(self.settings.jwk_rotate_days),
                keep_last=int(self.settings.jwk_keep_last),
                alg=self.settings.jwk_alg,  # type: ignore
                rsa_bits=int(self.settings.jwk_rsa_bits),
            )
            if created:
                self.keystore.save()

    async def start_rotation_loop(self) -> None:
        # Rotate once a day
        async def _loop():
            while True:
                try:
                    await self.ensure_keystore()
                except Exception as e:
                    logging.getLogger("quickstart").warning("key rotation failed: %s", e)
                await asyncio.sleep(24 * 3600)
        self.rotation_task = asyncio.create_task(_loop())

    async def stop_rotation_loop(self) -> None:
        if self.rotation_task:
            self.rotation_task.cancel()
            with contextlib.suppress(Exception):
                await self.rotation_task
            self.rotation_task = None

    async def start_audit_exporter(self) -> None:
        if OpenSearchExporter is None or not self.settings.os_endpoints:
            return
        cfg = OpenSearchExporterConfig(
            endpoints=self.settings.os_endpoints,
            auth_mode=self.settings.os_auth_mode,  # type: ignore
            username=self.settings.os_username,
            password=self.settings.os_password,
            bearer_token=self.settings.os_bearer_token,
            tls=OSTLSConfig(
                verify=self.settings.os_verify_tls,
                ca_path=self.settings.os_ca_path,
                client_cert=self.settings.os_client_cert,
                client_key=self.settings.os_client_key,
            ),
            use_data_stream=self.settings.os_data_stream,
            data_stream_name=self.settings.os_data_stream_name,
            queue_max_size=self.settings.os_queue_max,
            batch_max_events=self.settings.os_batch_events,
            batch_max_bytes=self.settings.os_batch_bytes,
            flush_interval_ms=self.settings.os_flush_ms,
            concurrency=self.settings.os_concurrency,
        )
        self.audit = OpenSearchExporter(cfg)
        await self.audit.start()  # type: ignore

    async def stop_audit_exporter(self) -> None:
        if self.audit:
            await self.audit.stop()
            self.audit = None

    async def audit_event(self, category: str, action: str, outcome: str, details: Dict[str, Any]) -> None:
        if not self.audit:
            return
        try:
            ev = {
                "producer": "quickstart",
                "category": category,
                "action": action,
                "outcome": outcome,
                "event_time": int(time.time() * 1000),
                "details": details,
            }
            await self.audit.enqueue(ev)  # type: ignore
        except Exception:
            pass


# =========================
# Minimal RBAC check (quickstart)
# =========================

class AuthzRequest(BaseModel):
    subject: Optional[str] = None
    roles: list[str] = Field(default_factory=list)
    tenant: Optional[str] = None
    env: Optional[str] = None
    ip: Optional[str] = None
    resource_id: str
    action: str
    explain: bool = False

def authz_check(req: AuthzRequest) -> Dict[str, Any]:
    """
    Minimal, demonstrative RBAC:
    - role 'admin' => allow all
    - role 'developer' => allow read on resources starting with 'service:'
    - role 'auditor' => allow read on 'audit:*'
    """
    decision = "deny"
    reason = "no matching rule"
    rules = []

    if "admin" in req.roles:
        decision, reason = "allow", "role admin"
        rules.append("role:admin -> *")
    elif "developer" in req.roles and req.action.lower() in ("read", "get", "list") and req.resource_id.startswith("service:"):
        decision, reason = "allow", "developer read on service:*"
        rules.append("role:developer -> read service:*")
    elif "auditor" in req.roles and req.action.lower() in ("read", "get", "list") and req.resource_id.startswith("audit:"):
        decision, reason = "allow", "auditor read on audit:*"
        rules.append("role:auditor -> read audit:*")

    return {"decision": decision, "reason": reason, "rules": rules if req.explain else None}


# =========================
# FastAPI app with lifespan
# =========================

logger = logging.getLogger("quickstart")

def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
    )

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = AppSettings()
    setup_logging(settings.log_level)
    logger.info("starting app with settings hash=%s", settings.config_hash())
    state = AppState(settings)
    app.state.state = state  # attach
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
        max_age=600,
    )

    # Init keystore and audit
    await state.ensure_keystore()
    await state.start_rotation_loop()
    await state.start_audit_exporter()
    try:
        yield
    finally:
        await state.stop_audit_exporter()
        if state.rotation_task:
            state.rotation_task.cancel()

app = FastAPI(title="security-core quickstart", version="1.0", lifespan=lifespan)


# =========================
# Routes
# =========================

@app.get("/v1/health")
async def health(request: Request):
    st: AppState = request.app.state.state
    try:
        jwks = st.keystore.get_public_jwks().dict()
    except Exception as e:
        jwks = {"error": str(e)}
    audit = st.audit.stats() if getattr(st, "audit", None) else None  # type: ignore
    await st.audit_event("HEALTH", "READ", "SUCCESS", {"audit_online": audit is not None})
    return {
        "status": "ok",
        "app": st.settings.app_name,
        "time": int(time.time()),
        "jwks_keys": len(jwks.get("keys", [])) if isinstance(jwks, dict) else 0,
        "audit": audit,
    }

@app.get("/v1/settings")
async def get_settings(request: Request):
    st: AppState = request.app.state.state
    data = {
        "_hash": st.settings.config_hash(),
        "policy": {"path": st.settings.policy_path},
        "opa": {"url": str(st.settings.opa_url) if st.settings.opa_url else None},
        "sanitized": st.settings.sanitized(),
    }
    return data

@app.post("/v1/reload")
async def reload_settings(request: Request):
    # For quickstart: re-read environment‑backed settings and apply audit exporter reinit if needed
    st: AppState = request.app.state.state
    old_hash = st.settings.config_hash()
    st.settings = AppSettings()
    new_hash = st.settings.config_hash()
    # Re-init audit exporter if endpoints changed materially
    await st.stop_audit_exporter()
    await st.start_audit_exporter()
    await st.ensure_keystore()
    await st.audit_event("SETTINGS", "RELOAD", "SUCCESS", {"old_hash": old_hash, "new_hash": new_hash})
    return {"status": "reloaded", "old_hash": old_hash, "new_hash": new_hash}

@app.post("/v1/authz/check")
async def authz_check_route(req: AuthzRequest, request: Request):
    st: AppState = request.app.state.state
    result = authz_check(req)
    await st.audit_event("AUTHZ", "CHECK", "SUCCESS" if result["decision"] == "allow" else "DENY", {
        "subject": req.subject, "roles": req.roles, "resource": req.resource_id, "action": req.action
    })
    return result

# --- Inhibitor ---

class InhibitorCmd(BaseModel):
    cmd: str

@app.get("/v1/inhibitor/status")
async def inhibitor_status(request: Request):
    st: AppState = request.app.state.state
    return {"armed": st.inhibitor["armed"], "triggered": st.inhibitor["triggered"], "last": st.inhibitor["last"]}

@app.post("/v1/inhibitor/cmd")
async def inhibitor_cmd(body: InhibitorCmd, request: Request, x_admin_secret: Optional[str] = Header(default=None, alias="X-Admin-Secret")):
    st: AppState = request.app.state.state
    if st.settings.admin_secret and x_admin_secret != st.settings.admin_secret:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin secret invalid")

    cmd = body.cmd.upper().strip()
    if cmd == "ARM":
        st.inhibitor.update({"armed": True, "last": time.time()})
    elif cmd == "DISARM":
        st.inhibitor.update({"armed": False, "triggered": False, "last": time.time()})
    elif cmd == "TRIGGER":
        if not st.inhibitor["armed"]:
            raise HTTPException(status_code=400, detail="not armed")
        st.inhibitor.update({"triggered": True, "last": time.time()})
    else:
        raise HTTPException(status_code=400, detail="unknown cmd")
    await st.audit_event("INHIBITOR", "CMD", "SUCCESS", {"cmd": cmd})
    return {"status": "ok", "state": st.inhibitor}

# --- JWKS ---

@app.get("/.well-known/jwks.json")
async def jwks(request: Request):
    st: AppState = request.app.state.state
    async with st.jwks_lock:
        jwks = st.keystore.get_public_jwks().dict()
    return jwks

# --- Audit stats ---

@app.get("/v1/audit/stats")
async def audit_stats(request: Request):
    st: AppState = request.app.state.state
    stats = st.audit.stats() if st.audit else {"enabled": False}
    return stats


# =========================
# Error handler (structured)
# =========================

@app.exception_handler(Exception)
async def unhandled_exc(request: Request, exc: Exception):
    logger.exception("unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"error": "internal_error"})


# =========================
# Entrypoint
# =========================

def main():
    # Allow running as: python examples/quickstart/run.py
    import uvicorn
    settings = AppSettings()
    uvicorn.run(
        "examples.quickstart.run:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        log_level=settings.log_level.lower(),
        proxy_headers=True,
        forwarded_allow_ips="*",
    )

if __name__ == "__main__":
    main()
