# veilmind-core/examples/quickstart/run.py
# -*- coding: utf-8 -*-
"""
Quickstart CLI for veilmind-core:
- server: start a minimal FastAPI app with /health, /v1/redact, /metrics
- client:  send a safe POST /v1/redact with integrity + idempotency
- ws-client: test WebSocket subprotocol "veilmind.redact.v1" (if 'websockets' available)

Security highlights:
- Secret-safe logging (redaction of tokens, PAN, emails, JWT)
- Content-SHA256 integrity and Idempotency-Key for POST
- Exponential backoff with jitter for idempotent retries
- Prometheus /metrics if prometheus_client is installed
- OpenTelemetry optional (no hard deps)
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import sys
import time
import typing as t
import uuid
from dataclasses import dataclass

# --------------------------- Safe logging / redaction ---------------------------

REDACT_MASK = "[REDACTED]"
_DENY_KEYS = {
    "authorization", "cookie", "set-cookie",
    "x-api-key", "api_key", "apikey",
    "token", "access_token", "refresh_token", "id_token", "session", "jwt",
    "password", "passwd", "secret", "private_key", "client_secret",
}
_PATTERNS = [
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]+"),
    re.compile(r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b"),
    re.compile(r"\b\d{13,19}\b"),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    re.compile(r"\+?[0-9][0-9\-\s()]{7,}"),
    re.compile(r"(?i)\b(pwd|pass(word)?|secret|token|key)\b\s*[:=]\s*\S+"),
]


def redact_text(s: str, max_len: int = 2048) -> str:
    out = str(s)
    for rx in _PATTERNS:
        out = rx.sub(REDACT_MASK, out)
    if len(out) > max_len:
        out = out[:max_len] + "...(truncated)"
    return out


def redact_headers(h: t.Mapping[str, str]) -> dict:
    out = {}
    for k, v in h.items():
        if k.lower() in _DENY_KEYS:
            out[k] = REDACT_MASK
        else:
            out[k] = redact_text(v, max_len=256)
    return out


# --------------------------- Utilities: integrity, idempotency, tracing ---------------------------

def content_sha256(obj: t.Any) -> str:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def random_hex(nbytes: int) -> str:
    return os.urandom(nbytes).hex()


def idempotency_key() -> str:
    h = random_hex(16)
    # Generate UUIDv4-like (not strict RFC, fine for idempotency correlation)
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"


def traceparent() -> str:
    # W3C: version(2)-traceid(32)-spanid(16)-flags(2)
    trace_id = random_hex(16)  # 16 bytes => 32 hex
    span_id = random_hex(8)    # 8 bytes  => 16 hex
    return f"00-{trace_id}-{span_id}-01"


# --------------------------- HTTP client (httpx) ---------------------------

try:
    import httpx  # type: ignore
except Exception:
    httpx = None  # type: ignore


@dataclass
class ClientCfg:
    base_url: str
    token: t.Optional[str] = None
    timeout_s: float = 10.0
    retries: int = 3
    retry_status: t.Tuple[int, ...] = (408, 425, 429, 500, 502, 503, 504)
    backoff_base_s: float = 0.2
    backoff_cap_s: float = 2.5


def _backoff(attempt: int, base: float, cap: float) -> float:
    b = min(cap, base * (2 ** (attempt - 1)))
    # full jitter
    return 0.5 * b + (os.urandom(1)[0] / 255.0) * 0.5 * b


def _log_req(method: str, url: str, headers: dict, body: t.Optional[dict], log_bodies: bool = False) -> None:
    print(f"-> {method} {url}\n   headers={redact_headers(headers)}")
    if log_bodies and body is not None:
        print(f"   body={redact_text(json.dumps(body, ensure_ascii=False))}")


def _log_resp(status: int, headers: dict, text: str, log_bodies: bool = False) -> None:
    print(f"<- HTTP {status}\n   headers={redact_headers(headers)}")
    if log_bodies:
        print(f"   body={redact_text(text)}")


def client_post_redact(cfg: ClientCfg, payload: dict, *, ruleset_id: t.Optional[str] = None, log_bodies: bool = False) -> dict:
    if httpx is None:
        raise RuntimeError("httpx is not installed. Install 'httpx' to use the client.")
    url = cfg.base_url.rstrip("/") + "/v1/redact"
    body = {"payload": payload}
    if ruleset_id:
        body["ruleset_id"] = ruleset_id
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Idempotency-Key": idempotency_key(),
        "Content-SHA256": content_sha256(body.get("payload")),
        "traceparent": traceparent(),
    }
    if cfg.token:
        headers["Authorization"] = f"Bearer {cfg.token}"

    _log_req("POST", url, headers, body if log_bodies else None, log_bodies=log_bodies)
    attempt = 0
    while True:
        attempt += 1
        try:
            with httpx.Client(timeout=cfg.timeout_s) as client:
                r = client.post(url, json=body, headers=headers)
            _log_resp(r.status_code, dict(r.headers), r.text, log_bodies=log_bodies)
            if r.status_code == 401:
                raise RuntimeError("Unauthorized")
            if r.status_code in cfg.retry_status and attempt <= cfg.retries:
                delay = _backoff(attempt, cfg.backoff_base_s, cfg.backoff_cap_s)
                print(f"retrying in {delay:.2f}s (status={r.status_code})")
                time.sleep(delay)
                continue
            r.raise_for_status()
            return r.json()
        except httpx.TimeoutException:
            if attempt > cfg.retries:
                raise
            delay = _backoff(attempt, cfg.backoff_base_s, cfg.backoff_cap_s)
            print(f"timeout, retrying in {delay:.2f}s")
            time.sleep(delay)


# --------------------------- FastAPI server (with fallback router) ---------------------------

def build_app():
    try:
        from fastapi import FastAPI
    except Exception as e:
        raise RuntimeError("FastAPI is required for 'server' mode. Install 'fastapi' and 'uvicorn'.") from e

    app = FastAPI(title="veilmind-core quickstart", version="1.0")

    # /health
    @app.get("/health")
    def _health():
        return {"status": "ok", "service": "veilmind-core", "ts": int(time.time() * 1000)}

    # Try to include industrial router from the project, else fall back to a minimal local one.
    try:
        # If project layout is standard, allow import when running from repo root
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
        from api.http.routers.v1.redact import router as redact_router  # type: ignore
        app.include_router(redact_router)
        print("using router: api.http.routers.v1.redact")
    except Exception:
        print("router import failed, using local fallback /v1/redact")
        from fastapi import APIRouter, Body, Header, HTTPException, status
        from pydantic import BaseModel, Field

        class RedactRequest(BaseModel):
            payload: t.Any = Field(..., description="JSON to redact")
            ruleset_id: t.Optional[str] = None
            context: t.Optional[dict] = None
            profile: t.Optional[str] = None

        class RedactionAction(BaseModel):
            masked: int = 0
            tokenized: int = 0
            hashed: int = 0
            truncated: int = 0
            dropped: int = 0

        class RedactResponse(BaseModel):
            payload: t.Any
            applied_rules: t.List[str]
            actions: RedactionAction
            classification: t.Optional[str] = None
            meta: dict

        _DENY = {
            "password", "passwd", "secret", "token", "access_token", "refresh_token", "id_token",
            "authorization", "api_key", "apikey", "cookie", "set-cookie", "private_key",
            "client_secret", "db_password", "jwt", "otp", "session"
        }
        _ID_RX = re.compile(r"(?i)^(user_)?id$")

        def _walk(node, actions: RedactionAction, applied: t.List[str]):
            if isinstance(node, dict):
                out = {}
                for k, v in node.items():
                    if str(k).lower() in _DENY:
                        out[k] = REDACT_MASK
                        actions.masked += 1
                        applied.append("denylist.keys.mask")
                        continue
                    if _ID_RX.match(str(k)) and isinstance(v, (str, int)):
                        h = hashlib.sha256(str(v).encode()).hexdigest()
                        out[k] = h
                        actions.hashed += 1
                        applied.append("id.hash.sha256")
                        continue
                    out[k] = _walk(v, actions, applied)
                return out
            if isinstance(node, list):
                return [_walk(x, actions, applied) for x in node]
            if isinstance(node, str):
                before = node
                out = redact_text(before, max_len=2048)
                if out != before:
                    actions.masked += 1
                    applied.append("patterns.mask")
                return out
            return node

        r = APIRouter(prefix="/v1", tags=["redaction"])

        @r.post("/redact", response_model=RedactResponse)
        def _redact(
            body: RedactRequest = Body(...),
            idempotency_key: t.Optional[str] = Header(None, alias="Idempotency-Key"),
            content_sha256_hdr: t.Optional[str] = Header(None, alias="Content-SHA256"),
        ):
            # integrity check if provided
            if content_sha256_hdr:
                calc = content_sha256(body.payload)
                if calc.lower() != content_sha256_hdr.lower():
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="content_sha256_mismatch")
            actions = RedactionAction()
            applied: t.List[str] = []
            red = _walk(body.payload, actions, applied)
            return {
                "payload": red,
                "applied_rules": sorted(set(applied)),
                "actions": actions,
                "classification": "SENSITIVE" if (actions.masked or actions.hashed or actions.tokenized) else "INTERNAL",
                "meta": {
                    "request_id": str(uuid.uuid4()),
                    "processing_time_ms": 0,
                    "idempotency_key": idempotency_key,
                    "version": 1,
                },
            }

        app.include_router(r)

    # /metrics (Prometheus) — only if prometheus_client present
    try:
        from veilmind.telemetry.metrics import install_prometheus_endpoint  # type: ignore
        install_prometheus_endpoint(app)
        print("Prometheus /metrics endpoint enabled")
    except Exception:
        # Fallback: try direct registration
        try:
            from prometheus_client import CONTENT_TYPE_LATEST, generate_latest  # type: ignore
            from fastapi import APIRouter, Response  # type: ignore
            pr = APIRouter()

            @pr.get("/metrics")
            def _metrics():
                return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

            app.include_router(pr)
            print("Prometheus /metrics endpoint enabled (direct)")
        except Exception:
            print("Prometheus not available; /metrics disabled")

    return app


# --------------------------- WebSocket client (optional) ---------------------------

async def ws_client(base_ws_url: str, *, subprotocol: str = "veilmind.redact.v1") -> None:
    try:
        import websockets  # type: ignore
    except Exception as e:
        raise RuntimeError("websockets is not installed. Install 'websockets' for ws-client.") from e

    url = base_ws_url.rstrip("/") + "/ws"
    print(f"WS connect {url} subprotocol={subprotocol}")
    async with websockets.connect(url, subprotocols=[subprotocol]) as ws:  # type: ignore
        hello = {
            "type": "hello",
            "payload": {
                "client": "veilmind-quickstart",
                "version": "1.0.0",
                "subprotocol": subprotocol,
                "features": [],
            },
        }
        await ws.send(json.dumps(hello, ensure_ascii=False))
        req = {
            "type": "redact.request",
            "payload": {
                "ruleset_id": None,
                "profile": None,
                "context": None,
                "data": {
                    "email": "john.doe@example.org",
                    "card": "4111 1111 1111 1111",
                    "note": "Bearer abcdef.123456.zzz",
                },
            },
        }
        await ws.send(json.dumps(req, ensure_ascii=False))
        # Read a couple of messages
        for _ in range(3):
            msg = await asyncio.wait_for(ws.recv(), timeout=5.0)  # type: ignore
            print("WS <-", redact_text(msg))


# --------------------------- CLI ---------------------------

def parse_args(argv: t.Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="veilmind-core quickstart")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("server", help="start demo server")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--reload", action="store_true")

    c = sub.add_parser("client", help="send POST /v1/redact")
    c.add_argument("--base-url", default="http://127.0.0.1:8080")
    c.add_argument("--token", default=None)
    c.add_argument("--ruleset-id", default=None)
    c.add_argument("--payload", default='{"email":"john.doe@example.org","card":"4111 1111 1111 1111"}', help="JSON string")
    c.add_argument("--log-bodies", action="store_true")

    w = sub.add_parser("ws-client", help="test WebSocket redact subprotocol")
    w.add_argument("--ws-base", default="ws://127.0.0.1:8080")

    return p.parse_args(argv)


def main(argv: t.Sequence[str]) -> int:
    args = parse_args(argv)
    if args.cmd == "server":
        try:
            import uvicorn  # type: ignore
        except Exception as e:
            raise RuntimeError("uvicorn is required for 'server' mode. Install 'uvicorn'.") from e
        app = build_app()
        uvicorn.run(app, host=args.host, port=args.port, reload=args.reload, log_level="info")
        return 0

    if args.cmd == "client":
        payload = json.loads(args.payload)
        cfg = ClientCfg(base_url=args.base_url, token=args.token)
        resp = client_post_redact(cfg, payload, ruleset_id=args.ruleset_id, log_bodies=args.log_bodies)
        print(json.dumps(resp, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "ws-client":
        asyncio.run(ws_client(args.ws_base))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
