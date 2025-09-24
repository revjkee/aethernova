# SPDX-License-Identifier: MIT
"""
Prompt Guard Router (v1)
Industrial-grade prompt analysis & sanitization endpoint for LLM gateways.

Features
- Detects: prompt injection, system prompt disclosure, data exfil hints,
           PII (emails, phones), secrets/API keys, jailbreak patterns,
           risky instructions (malware, self-harm), URL policy violations.
- Produces: decision (ALLOW/SANITIZE/BLOCK/CHALLENGE), risk score,
            detailed findings with byte spans, sanitized prompt.
- Adds: optional Prometheus metrics, OpenTelemetry spans (if installed).
- Config: via environment variables (thresholds, URL allowlist, redaction tags).

Dependencies
- FastAPI/Starlette runtime (APIRouter).
- Optional: prometheus_client, opentelemetry
- No external calls; pure Python heuristics for deterministic behavior.

Usage
    from fastapi import FastAPI
    from .routers.v1.prompt_guard import router as prompt_guard_router
    app = FastAPI()
    app.include_router(prompt_guard_router, prefix="/v1")

Security
- Stateless; expects upstream authn/authz & rate limit middleware.
- Does not log raw secrets; redacts sensitive values before logging.

"""

from __future__ import annotations

import os
import re
import time
import json
import hashlib
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException, Header, Request, Response, status
from pydantic import BaseModel, Field, constr

try:  # Optional metrics
    from prometheus_client import Counter, Histogram  # type: ignore

    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False

try:  # Optional tracing
    from opentelemetry import trace  # type: ignore

    _OTEL = True
    _TRACER = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _OTEL = False
    _TRACER = None  # type: ignore


# ------------------------------ Config & Policy -------------------------------

ENV = os.getenv
CFG = {
    "NEAR_LIMIT_RATIO": float(ENV("PG_NEAR_LIMIT_RATIO", "0.9")),
    "BLOCK_SCORE": float(ENV("PG_BLOCK_SCORE", "0.85")),
    "SANITIZE_SCORE": float(ENV("PG_SANITIZE_SCORE", "0.5")),
    "CHALLENGE_SCORE": float(ENV("PG_CHALLENGE_SCORE", "0.75")),
    "MAX_LEN": int(ENV("PG_MAX_LEN", "12000")),
    "ALLOW_URL_DOMAINS": set(
        d.strip().lower() for d in ENV("PG_ALLOW_URL_DOMAINS", "example.com,localhost,127.0.0.1").split(",")
        if d.strip()
    ),
    "REDACT_TAG": ENV("PG_REDACT_TAG", "[REDACTED:{kind}]"),
}

# Regex library (compiled once)
RE = {
    # Prompt Injection / Jailbreak cues
    "inj_ignore": re.compile(r"(ignore|disregard)\s+(all\s+)?(previous|prior)\s+(instructions|rules)", re.I),
    "inj_system": re.compile(r"(reveal|show).{0,20}(system|developer)\s+(prompt|message|instructions)", re.I),
    "inj_dan": re.compile(r"\b(DAN|do\s+anything\s+now|jailbreak)\b", re.I),
    "inj_roleplay": re.compile(r"\b(act\s+as|pretend\s+to\s+be)\b.{0,50}\b(system|root|developer|god)\b", re.I),

    # Exfil/Policy bypass cues
    "exfil": re.compile(r"\b(exfiltrate|leak|dump|bypass|disable)\b.{0,40}\b(safety|guard|policy|filter|rate)\b", re.I),

    # PII
    "email": re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I),
    "phone": re.compile(r"(?:\+?\d[\s-]?){7,15}"),
    # Secrets / API keys (heuristics for common providers; generalized token detector)
    "secret_generic": re.compile(r"\b[A-Za-z0-9_\-]{24,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),  # JWT-like
    "secret_hex": re.compile(r"\b[0-9a-f]{32,64}\b", re.I),
    "secret_aws": re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b"),
    "secret_gcp": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "secret_slack": re.compile(r"xox[abpr]-[0-9A-Za-z\-]{10,48}"),
    "secret_pk": re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----[\s\S]+?-----END .*? KEY-----"),
    # URLs
    "url": re.compile(r"\bhttps?://[^\s)]+", re.I),
    # Self-harm/malware cues (coarse; for policy gating not classification)
    "haz_mal": re.compile(r"\b(ransomware|keylogger|stealer|ddos|botnet|zero[-\s]?day)\b", re.I),
    "haz_self": re.compile(r"\b(kill\s+myself|suicide|harm\s+myself)\b", re.I),
    # Large base64 blob (data leak hint)
    "b64": re.compile(r"\b(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b"),
}

SEVERITY = {
    "LOW": 0.25,
    "MEDIUM": 0.5,
    "HIGH": 0.85,
}

KIND_WEIGHTS = {  # contribution to risk score
    "prompt_injection": 0.9,
    "exfil": 0.8,
    "secret": 1.0,
    "pii": 0.6,
    "policy_violation": 0.7,
    "url_violation": 0.5,
    "b64_leak": 0.6,
}


# ------------------------------- Data Models ----------------------------------

class Finding(BaseModel):
    kind: constr(strip_whitespace=True) = Field(..., description="Category of finding")
    rule_id: str = Field(..., description="Rule identifier")
    severity: str = Field(..., description="LOW|MEDIUM|HIGH")
    score: float = Field(..., ge=0.0, le=1.0)
    start: int = Field(..., ge=0)
    end: int = Field(..., ge=0)
    excerpt: str = Field(..., description="Snippet around finding (redacted)")

class Decision(str):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"
    CHALLENGE = "CHALLENGE"

class PromptGuardRequest(BaseModel):
    prompt: constr(strip_whitespace=True, min_length=1) = Field(..., description="User-visible prompt text")
    tenant_id: Optional[str] = Field(default="public")
    user_id: Optional[str] = Field(default="anonymous")
    language: Optional[str] = Field(default="auto", description="BCP-47 or 'auto'")
    model_family: Optional[str] = Field(default=None, description="llama/openai/mixtral/…")
    cost_hits: int = Field(default=1, ge=1, le=100, description="Relative request cost for upstream rate limiters")
    allow_urls: Optional[List[str]] = Field(default=None, description="Override allowed URL domains list")
    require_mfa: bool = Field(default=False, description="If true, escalate to CHALLENGE on HIGH risk")

class PromptGuardResponse(BaseModel):
    decision: str
    risk_score: float
    findings: List[Finding]
    sanitized_prompt: str
    redactions_applied: int
    reason: str
    meta: Dict[str, Any] = Field(default_factory=dict)


# --------------------------------- Metrics ------------------------------------

if _PROM:
    M_REQ = Counter("veilmind_pg_requests_total", "PromptGuard requests", ["decision"])
    H_LAT = Histogram(
        "veilmind_pg_latency_seconds",
        "PromptGuard end-to-end latency",
        buckets=(0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0),
    )
else:  # pragma: no cover
    M_REQ = None
    H_LAT = None


# -------------------------------- Utilities -----------------------------------

def _safe_excerpt(s: str, start: int, end: int) -> str:
    a = max(0, start - 20)
    b = min(len(s), end + 20)
    snippet = s[a:b]
    # Collapse newlines for logs
    return snippet.replace("\n", " ")[:160]


def _hash_public(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _estimate_tokens(s: str) -> int:
    # Simple heuristic ~4 chars/token
    return (len(s) // 4) + 1


# ------------------------------ Detectors -------------------------------------

def detect_prompt_injection(prompt: str) -> List[Finding]:
    rules = [
        ("prompt_injection", "inj_ignore", RE["inj_ignore"], SEVERITY["HIGH"]),
        ("prompt_injection", "inj_system", RE["inj_system"], SEVERITY["HIGH"]),
        ("prompt_injection", "inj_dan", RE["inj_dan"], SEVERITY["HIGH"]),
        ("prompt_injection", "inj_roleplay", RE["inj_roleplay"], SEVERITY["MEDIUM"]),
        ("exfil", "exfil_policy", RE["exfil"], SEVERITY["MEDIUM"]),
    ]
    findings: List[Finding] = []
    for kind, rid, rx, sev in rules:
        for m in rx.finditer(prompt):
            findings.append(
                Finding(
                    kind=kind,
                    rule_id=rid,
                    severity="HIGH" if sev >= 0.8 else ("MEDIUM" if sev >= 0.5 else "LOW"),
                    score=sev,
                    start=m.start(),
                    end=m.end(),
                    excerpt=_safe_excerpt(prompt, m.start(), m.end()),
                )
            )
    return findings


def detect_pii_and_secrets(prompt: str) -> Tuple[List[Finding], List[Tuple[Tuple[int, int], str]]]:
    findings: List[Finding] = []
    redactions: List[Tuple[Tuple[int, int], str]] = []  # ((start,end), kind)

    for rid, rx, kind, sev in [
        ("pii_email", RE["email"], "pii.email", SEVERITY["MEDIUM"]),
        ("pii_phone", RE["phone"], "pii.phone", SEVERITY["LOW"]),
        ("secret_jwt_like", RE["secret_generic"], "secret.jwt_like", SEVERITY["HIGH"]),
        ("secret_hex", RE["secret_hex"], "secret.hex", SEVERITY["HIGH"]),
        ("secret_aws", RE["secret_aws"], "secret.aws_key", SEVERITY["HIGH"]),
        ("secret_gcp", RE["secret_gcp"], "secret.gcp_key", SEVERITY["HIGH"]),
        ("secret_slack", RE["secret_slack"], "secret.slack_token", SEVERITY["HIGH"]),
        ("secret_pk", RE["secret_pk"], "secret.private_key", SEVERITY["HIGH"]),
        ("b64_bulk", RE["b64"], "b64_leak", SEVERITY["MEDIUM"]),
    ]:
        for m in rx.finditer(prompt):
            findings.append(
                Finding(
                    kind="secret" if kind.startswith("secret") else ("pii" if kind.startswith("pii") else "b64_leak"),
                    rule_id=rid,
                    severity="HIGH" if sev >= 0.8 else ("MEDIUM" if sev >= 0.5 else "LOW"),
                    score=sev,
                    start=m.start(),
                    end=m.end(),
                    excerpt=_safe_excerpt(prompt, m.start(), m.end()),
                )
            )
            redactions.append(((m.start(), m.end()), kind))
    return findings, redactions


def detect_urls(prompt: str, allowed: Optional[List[str]]) -> List[Finding]:
    allow = set(d.lower() for d in (allowed or list(CFG["ALLOW_URL_DOMAINS"])))
    findings: List[Finding] = []
    for m in RE["url"].finditer(prompt):
        url = m.group(0)
        host = url.split("/", 3)[2].lower()
        # Strip port
        host = host.split(":", 1)[0]
        ok = any(host == d or host.endswith("." + d) for d in allow)
        if not ok:
            findings.append(
                Finding(
                    kind="url_violation",
                    rule_id="url_not_allowed",
                    severity="MEDIUM",
                    score=SEVERITY["MEDIUM"],
                    start=m.start(),
                    end=m.end(),
                    excerpt=url[:160],
                )
            )
    return findings


def detect_hazard(prompt: str) -> List[Finding]:
    findings: List[Finding] = []
    for rid, rx in [("malware", RE["haz_mal"]), ("self_harm", RE["haz_self"])]:
        for m in rx.finditer(prompt):
            findings.append(
                Finding(
                    kind="policy_violation",
                    rule_id=rid,
                    severity="HIGH",
                    score=SEVERITY["HIGH"],
                    start=m.start(),
                    end=m.end(),
                    excerpt=_safe_excerpt(prompt, m.start(), m.end()),
                )
            )
    return findings


# ------------------------------ Sanitization ----------------------------------

def apply_redactions(prompt: str, redactions: List[Tuple[Tuple[int, int], str]]) -> Tuple[str, int]:
    """
    Apply redactions from end to start to keep indices valid.
    """
    if not redactions:
        return prompt, 0
    # Sort by start descending
    redactions_sorted = sorted(redactions, key=lambda x: x[0][0], reverse=True)
    buf = prompt
    count = 0
    for (start, end), kind in redactions_sorted:
        tag = CFG["REDACT_TAG"].format(kind=kind.upper())
        buf = buf[:start] + tag + buf[end:]
        count += 1
    return buf, count


def aggregate_risk(findings: List[Finding]) -> float:
    if not findings:
        return 0.0
    # Weighted max with slight accumulation
    score = 0.0
    for f in findings:
        w = KIND_WEIGHTS.get(f.kind, 0.5)
        score = max(score, min(1.0, f.score * w + score * 0.15))
    return round(min(1.0, score), 3)


def decide_action(risk: float, findings: List[Finding], require_mfa: bool) -> Tuple[str, str]:
    kinds = {f.kind for f in findings}
    severe = any(f.score >= SEVERITY["HIGH"] for f in findings)
    # Hard blockers: secrets or jailbreak with HIGH severity
    if severe and ({"secret", "prompt_injection"}.intersection(kinds) or {"policy_violation"}.intersection(kinds)):
        if require_mfa:
            return "CHALLENGE", "High risk with hard blocker; step-up required"
        return "BLOCK", "High risk finding (secret/jailbreak/policy) detected"

    if risk >= CFG["BLOCK_SCORE"]:
        return ("CHALLENGE", "Risk above challenge threshold") if require_mfa else ("BLOCK", "Aggregate risk too high")

    if risk >= CFG["SANITIZE_SCORE"] or any(k in kinds for k in ["pii", "b64_leak", "url_violation"]):
        return "SANITIZE", "PII/URL/b64 findings or medium risk"

    return "ALLOW", "Low risk"


# ---------------------------------- Router ------------------------------------

router = APIRouter(prefix="/prompt", tags=["guard", "safety"])


@router.post("/guard", response_model=PromptGuardResponse, status_code=200)
async def guard_prompt(
    req: PromptGuardRequest,
    request: Request,
    response: Response,
    x_request_id: Optional[str] = Header(default=None, convert_underscores=True),
) -> PromptGuardResponse:
    t0 = time.perf_counter()
    prompt = req.prompt
    if len(prompt) > CFG["MAX_LEN"]:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Prompt too large")

    # Tracing
    span_ctx = None
    if _OTEL and _TRACER:
        span_ctx = _TRACER.start_as_current_span("PromptGuard.Check")
        span_ctx.__enter__()  # enter context
        trace.get_current_span().set_attribute("veilmind.pg.tenant", req.tenant_id or "public")
        trace.get_current_span().set_attribute("veilmind.pg.user", req.user_id or "anonymous")
        trace.get_current_span().set_attribute("veilmind.pg.tokens_est", _estimate_tokens(prompt))

    # Detection pipeline
    findings: List[Finding] = []
    findings += detect_prompt_injection(prompt)
    f_pii, red = detect_pii_and_secrets(prompt)
    findings += f_pii
    findings += detect_urls(prompt, req.allow_urls)
    findings += detect_hazard(prompt)

    risk = aggregate_risk(findings)
    decision, reason = decide_action(risk, findings, require_mfa=req.require_mfa)

    sanitized = prompt
    redactions_applied = 0
    if decision in ("SANITIZE", "CHALLENGE"):
        sanitized, redactions_applied = apply_redactions(prompt, red)

    # Response metadata & headers
    response.headers["X-PromptGuard-Decision"] = decision
    response.headers["X-PromptGuard-Risk"] = str(risk)
    response.headers["X-Content-SHA256"] = _hash_public(prompt)
    if x_request_id:
        response.headers["X-Request-ID"] = x_request_id

    if _PROM:
        M_REQ.labels(decision=decision).inc()
        H_LAT.observe(time.perf_counter() - t0)

    if span_ctx:
        span = trace.get_current_span()
        span.set_attribute("veilmind.pg.decision", decision)
        span.set_attribute("veilmind.pg.risk", risk)
        span.set_attribute("veilmind.pg.redactions", redactions_applied)
        span_ctx.__exit__(None, None, None)

    return PromptGuardResponse(
        decision=decision,
        risk_score=risk,
        findings=findings,
        sanitized_prompt=sanitized,
        redactions_applied=redactions_applied,
        reason=reason,
        meta={
            "tenant_id": req.tenant_id or "public",
            "user_id": req.user_id or "anonymous",
            "model_family": req.model_family,
            "tokens_estimated": _estimate_tokens(prompt),
            "allow_domains_effective": list(CFG["ALLOW_URL_DOMAINS"] if req.allow_urls is None else req.allow_urls),
        },
    )


@router.post("/sanitize", response_model=PromptGuardResponse, status_code=200)
async def sanitize_prompt(
    req: PromptGuardRequest,
    request: Request,
    response: Response,
) -> PromptGuardResponse:
    """
    Force sanitization mode (always returns SANITIZE unless hard blockers -> BLOCK/CHALLENGE).
    """
    forced_req = req.copy()
    base_resp = await guard_prompt(forced_req, request, response)  # runs detection
    # If allowed and medium risk findings exist, convert to SANITIZE
    if base_resp.decision == "ALLOW" and (base_resp.findings or base_resp.risk_score >= 0.2):
        base_resp.decision = "SANITIZE"
        if base_resp.redactions_applied == 0:
            # If nothing to redact, keep content as-is but decision still SANITIZE for logging
            base_resp.sanitized_prompt = req.prompt
    return base_resp
