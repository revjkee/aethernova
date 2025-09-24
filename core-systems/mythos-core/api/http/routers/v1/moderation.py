# mythos-core/api/http/routers/v1/moderation.py
# Industrial-grade Moderation API router (FastAPI/ASGI), protobuf-compatible schemas, SSE streaming.
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, ValidationError, conlist, conint, constr

# Optional: integrate with the logging middleware if present
try:
    from mythos_core.api.http.middleware.logging import (  # type: ignore
        get_request_id,
        get_trace_id,
        get_span_id,
    )
except Exception:  # fallback stubs
    def get_request_id() -> str:  # type: ignore
        return ""

    def get_trace_id() -> str:  # type: ignore
        return ""

    def get_span_id() -> str:  # type: ignore
        return ""


# =========================
# Configuration
# =========================

API_PREFIX = "/api/v1/moderation"
MAX_ITEMS = int(os.getenv("MODERATION_MAX_ITEMS", "16"))
MAX_TEXT_BYTES = int(os.getenv("MODERATION_MAX_TEXT_BYTES", "200_000"))
MAX_TOTAL_BYTES = int(os.getenv("MODERATION_MAX_TOTAL_BYTES", "2_000_000"))
REQUIRE_TOKEN = os.getenv("MODERATION_REQUIRE_TOKEN", "false").lower() in ("1", "true", "yes")
API_TOKEN = os.getenv("MODERATION_API_TOKEN", "")  # if REQUIRE_TOKEN, must match "Bearer <token>"

# =========================
# Enums (protobuf-aligned)
# =========================

class ContentType(str, Enum):
    CONTENT_TYPE_UNSPECIFIED = "CONTENT_TYPE_UNSPECIFIED"
    CONTENT_TYPE_TEXT = "CONTENT_TYPE_TEXT"
    CONTENT_TYPE_IMAGE = "CONTENT_TYPE_IMAGE"
    CONTENT_TYPE_AUDIO = "CONTENT_TYPE_AUDIO"
    CONTENT_TYPE_VIDEO = "CONTENT_TYPE_VIDEO"
    CONTENT_TYPE_URL = "CONTENT_TYPE_URL"
    CONTENT_TYPE_DOCUMENT = "CONTENT_TYPE_DOCUMENT"


class ModerationCategory(str, Enum):
    MODERATION_CATEGORY_UNSPECIFIED = "MODERATION_CATEGORY_UNSPECIFIED"
    CATEGORY_SEXUAL = "CATEGORY_SEXUAL"
    CATEGORY_SEXUAL_MINORS = "CATEGORY_SEXUAL_MINORS"
    CATEGORY_HATE = "CATEGORY_HATE"
    CATEGORY_HARASSMENT = "CATEGORY_HARASSMENT"
    CATEGORY_VIOLENCE = "CATEGORY_VIOLENCE"
    CATEGORY_SELF_HARM = "CATEGORY_SELF_HARM"
    CATEGORY_DRUGS = "CATEGORY_DRUGS"
    CATEGORY_WEAPONS = "CATEGORY_WEAPONS"
    CATEGORY_CRIME = "CATEGORY_CRIME"
    CATEGORY_TERRORISM = "CATEGORY_TERRORISM"
    CATEGORY_EXTREMISM = "CATEGORY_EXTREMISM"
    CATEGORY_POLITICAL = "CATEGORY_POLITICAL"
    CATEGORY_ELECTIONS = "CATEGORY_ELECTIONS"
    CATEGORY_HEALTH_MISINFO = "CATEGORY_HEALTH_MISINFO"
    CATEGORY_FINANCIAL_MISINFO = "CATEGORY_FINANCIAL_MISINFO"
    CATEGORY_SPAM = "CATEGORY_SPAM"
    CATEGORY_MALWARE = "CATEGORY_MALWARE"
    CATEGORY_PHISHING = "CATEGORY_PHISHING"
    CATEGORY_PRIVACY = "CATEGORY_PRIVACY"
    CATEGORY_IP = "CATEGORY_IP"
    CATEGORY_OTHER = "CATEGORY_OTHER"


class SeverityLevel(str, Enum):
    SEVERITY_UNSPECIFIED = "SEVERITY_UNSPECIFIED"
    SEVERITY_LOW = "SEVERITY_LOW"
    SEVERITY_MEDIUM = "SEVERITY_MEDIUM"
    SEVERITY_HIGH = "SEVERITY_HIGH"
    SEVERITY_CRITICAL = "SEVERITY_CRITICAL"


class Decision(str, Enum):
    DECISION_UNSPECIFIED = "DECISION_UNSPECIFIED"
    DECISION_ALLOW = "DECISION_ALLOW"
    DECISION_WARN = "DECISION_WARN"
    DECISION_REDACT = "DECISION_REDACT"
    DECISION_TRANSFORM = "DECISION_TRANSFORM"
    DECISION_REVIEW = "DECISION_REVIEW"
    DECISION_BLOCK = "DECISION_BLOCK"
    DECISION_QUARANTINE = "DECISION_QUARANTINE"


class Action(str, Enum):
    ACTION_UNSPECIFIED = "ACTION_UNSPECIFIED"
    ACTION_NONE = "ACTION_NONE"
    ACTION_LOG_ONLY = "ACTION_LOG_ONLY"
    ACTION_MASK_TEXT = "ACTION_MASK_TEXT"
    ACTION_REPLACE_TEXT = "ACTION_REPLACE_TEXT"
    ACTION_DROP_MESSAGE = "ACTION_DROP_MESSAGE"
    ACTION_RATE_LIMIT = "ACTION_RATE_LIMIT"
    ACTION_REQUIRE_HUMAN_REVIEW = "ACTION_REQUIRE_HUMAN_REVIEW"
    ACTION_SAFE_COMPLETION = "ACTION_SAFE_COMPLETION"
    ACTION_SANDBOX_TOOL_USE = "ACTION_SANDBOX_TOOL_USE"


class LanguageGuessSource(str, Enum):
    LANGUAGE_GUESS_SOURCE_UNSPECIFIED = "LANGUAGE_GUESS_SOURCE_UNSPECIFIED"
    LANGUAGE_GUESS_SOURCE_MODEL = "LANGUAGE_GUESS_SOURCE_MODEL"
    LANGUAGE_GUESS_SOURCE_USER = "LANGUAGE_GUESS_SOURCE_USER"
    LANGUAGE_GUESS_SOURCE_HEURISTIC = "LANGUAGE_GUESS_SOURCE_HEURISTIC"


# =========================
# Schemas (protobuf-compatible)
# =========================

class TextSpan(BaseModel):
    start: int
    end: int
    snippet: Optional[str] = None


class BoundingBox(BaseModel):
    x: float
    y: float
    width: float
    height: float


class TimeRange(BaseModel):
    start_ms: int = Field(..., ge=0)  # flattened from duration for JSON API
    end_ms: int = Field(..., ge=0)


class Evidence(BaseModel):
    item_id: str
    text_span: Optional[TextSpan] = None
    box: Optional[BoundingBox] = None
    time_range: Optional[TimeRange] = None
    note: Optional[str] = None


class ContentItem(BaseModel):
    id: str
    type: ContentType
    mime_type: Optional[str] = None
    attributes: Dict[str, str] = Field(default_factory=dict)

    # Payload (oneof)
    text: Optional[str] = None
    image_b64: Optional[str] = Field(default=None, description="Base64 if inlined")
    audio_b64: Optional[str] = None
    video_b64: Optional[str] = None
    uri: Optional[str] = None

    language: Optional[str] = None
    language_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    language_source: Optional[LanguageGuessSource] = None
    content_hash: Optional[str] = None


class Rule(BaseModel):
    categories: conlist(ModerationCategory, min_items=1)
    severity_threshold: SeverityLevel = SeverityLevel.SEVERITY_LOW
    probability_threshold: float = Field(0.5, ge=0.0, le=1.0)
    decision: Decision = Decision.DECISION_REVIEW
    actions: List[Action] = Field(default_factory=list)
    note: Optional[str] = None


class Policy(BaseModel):
    rules: List[Rule] = Field(default_factory=list)
    default_decision: Decision = Decision.DECISION_ALLOW
    block_unknown_categories: bool = False
    version: Optional[str] = None


class RequestContext(BaseModel):
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    app_id: Optional[str] = None
    tenant: Optional[str] = None
    locale: Optional[str] = None
    timezone: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    allowlist_patterns: List[str] = Field(default_factory=list)
    blocklist_patterns: List[str] = Field(default_factory=list)


class ModerationRequest(BaseModel):
    request_id: Optional[str] = None
    created_at: Optional[str] = None  # RFC3339
    context: Optional[RequestContext] = None
    items: conlist(ContentItem, min_items=1, max_items=MAX_ITEMS)
    policy: Optional[Policy] = None
    thresholds: Dict[str, float] = Field(default_factory=dict)
    risk_tolerance: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    return_spans: bool = False
    return_explanations: bool = False
    dry_run: bool = False


class CategoryScore(BaseModel):
    category: ModerationCategory
    probability: float = Field(..., ge=0.0, le=1.0)
    severity: SeverityLevel
    sub_scores: Dict[str, float] = Field(default_factory=dict)
    evidence: List[Evidence] = Field(default_factory=list)
    rationale: Optional[str] = None


class RiskScore(BaseModel):
    score: float = Field(..., ge=0.0, le=1.0)
    method: str = "weighted_linear"
    components: Dict[str, float] = Field(default_factory=dict)


class Redaction(BaseModel):
    item_id: str
    span: TextSpan
    replacement: str = "***"


class ModerationOutcome(BaseModel):
    decision: Decision
    actions: List[Action] = Field(default_factory=list)
    max_severity: SeverityLevel = SeverityLevel.SEVERITY_UNSPECIFIED


class ModerationResponse(BaseModel):
    request_id: str
    policy_version: Optional[str] = None
    created_at: str  # RFC3339
    outcome: ModerationOutcome
    assessments: List[CategoryScore] = Field(default_factory=list)
    overall_risk: RiskScore
    redactions: List[Redaction] = Field(default_factory=list)
    debug_info: Dict[str, Any] = Field(default_factory=dict)
    explanation: Optional[str] = None


# =========================
# Simple moderation engine (heuristic, deterministic)
# =========================

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{2,4}\)?[\s\-]?)?\d{3,4}[\s\-]?\d{3,4}")
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
URL_RE = re.compile(r"\bhttps?://[^\s]+", re.IGNORECASE)
SECRET_WORDS = re.compile(r"\b(password|passwd|secret|api[_-]?key|token)\b", re.IGNORECASE)
MALWARE_HINT = re.compile(r"\b(base64,|powershell|cmd\.exe|wget|curl\s+http)\b", re.IGNORECASE)
SPAM_HINT = re.compile(r"(free\s+money|work\s+from\s+home|viagra|loan)", re.IGNORECASE)


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _severity_from_p(p: float) -> SeverityLevel:
    if p >= 0.9:
        return SeverityLevel.SEVERITY_CRITICAL
    if p >= 0.7:
        return SeverityLevel.SEVERITY_HIGH
    if p >= 0.4:
        return SeverityLevel.SEVERITY_MEDIUM
    if p > 0.0:
        return SeverityLevel.SEVERITY_LOW
    return SeverityLevel.SEVERITY_UNSPECIFIED


class HeuristicModerator:
    """
    Replace with a real provider by implementing .moderate()
    """

    def _scan_text(self, item: ContentItem) -> List[CategoryScore]:
        text = item.text or ""
        spans: List[CategoryScore] = []

        def add(cat: ModerationCategory, prob: float, matcher: re.Pattern, note: str) -> None:
            for m in matcher.finditer(text):
                span = TextSpan(start=m.start(), end=m.end(), snippet=text[m.start() : m.end()][:64])
                ev = Evidence(item_id=item.id, text_span=span, note=note)
                spans.append(
                    CategoryScore(
                        category=cat,
                        probability=min(1.0, prob),
                        severity=_severity_from_p(prob),
                        sub_scores={"rule": prob},
                        evidence=[ev],
                        rationale=note,
                    )
                )

        # PII / Privacy
        add(ModerationCategory.CATEGORY_PRIVACY, 0.9, EMAIL_RE, "email")
        add(ModerationCategory.CATEGORY_PRIVACY, 0.7, PHONE_RE, "phone")
        add(ModerationCategory.CATEGORY_PRIVACY, 0.95, CC_RE, "credit_card")

        # Spam/Phishing/Malware hints
        add(ModerationCategory.CATEGORY_SPAM, 0.6, SPAM_HINT, "spam_hint")
        add(ModerationCategory.CATEGORY_PHISHING, 0.6, SECRET_WORDS, "secret_keyword")
        add(ModerationCategory.CATEGORY_MALWARE, 0.7, MALWARE_HINT, "malware_hint")
        add(ModerationCategory.CATEGORY_OTHER, 0.4, URL_RE, "url")

        # Merge by category: keep max probability, accumulate evidence
        merged: Dict[ModerationCategory, CategoryScore] = {}
        for s in spans:
            cur = merged.get(s.category)
            if not cur or s.probability > cur.probability:
                merged[s.category] = s
            else:
                cur.evidence.extend(s.evidence)
                cur.sub_scores = {**cur.sub_scores, **s.sub_scores}
        return list(merged.values())

    def moderate(self, req: ModerationRequest) -> Tuple[List[CategoryScore], List[Redaction], Dict[str, Any]]:
        assessments: List[CategoryScore] = []
        redactions: List[Redaction] = []
        debug: Dict[str, Any] = {"engine": "heuristic_v1"}

        total_bytes = 0
        for it in req.items:
            if it.type == ContentType.CONTENT_TYPE_TEXT and it.text:
                b = it.text.encode("utf-8", "replace")
                total_bytes += len(b)
                if not it.content_hash:
                    it.content_hash = _sha256_hex(b)
                # size hard limit per item
                if len(b) > MAX_TEXT_BYTES:
                    # Mark as spam/other
                    assessments.append(
                        CategoryScore(
                            category=ModerationCategory.CATEGORY_SPAM,
                            probability=1.0,
                            severity=SeverityLevel.SEVERITY_HIGH,
                            sub_scores={"oversize": 1.0},
                            evidence=[
                                Evidence(
                                    item_id=it.id,
                                    text_span=TextSpan(start=0, end=min(len(it.text), 64), snippet=it.text[:64]),
                                    note="oversize_text",
                                )
                            ],
                            rationale="Text exceeds allowed size",
                        )
                    )
                assessments.extend(self._scan_text(it))
            elif it.type in (
                ContentType.CONTENT_TYPE_IMAGE,
                ContentType.CONTENT_TYPE_AUDIO,
                ContentType.CONTENT_TYPE_VIDEO,
                ContentType.CONTENT_TYPE_DOCUMENT,
            ):
                # Payloads not analyzed here; real implementation would call vision/audio models
                pass
            total_bytes += len((it.text or "").encode("utf-8", "replace"))
            if total_bytes > MAX_TOTAL_BYTES:
                break

        # Example redactions for PRIVACY when requested
        if req.return_spans:
            for a in assessments:
                if a.category == ModerationCategory.CATEGORY_PRIVACY:
                    for ev in a.evidence:
                        if ev.text_span:
                            redactions.append(
                                Redaction(item_id=ev.item_id, span=ev.text_span, replacement="[...]")
                            )

        # Overall risk = weighted sum
        weights = {
            ModerationCategory.CATEGORY_PRIVACY: 0.5,
            ModerationCategory.CATEGORY_PHISHING: 0.6,
            ModerationCategory.CATEGORY_MALWARE: 0.8,
            ModerationCategory.CATEGORY_SPAM: 0.3,
            ModerationCategory.CATEGORY_OTHER: 0.1,
        }
        comp: Dict[str, float] = {}
        for a in assessments:
            w = weights.get(a.category, 0.2)
            comp[a.category] = max(comp.get(a.category, 0.0), a.probability * w)
        overall = min(1.0, sum(comp.values()))

        debug["components"] = comp
        return assessments, redactions, {"overall": overall, **debug}


ENGINE = HeuristicModerator()


# =========================
# Policy evaluation
# =========================

def _apply_policy(
    assessments: List[CategoryScore],
    policy: Optional[Policy],
    thresholds: Dict[str, float],
) -> ModerationOutcome:
    max_sev = SeverityLevel.SEVERITY_UNSPECIFIED
    for a in assessments:
        if a.severity.value > max_sev.value:
            max_sev = a.severity

    # If policy provided, apply first matching rule
    if policy and policy.rules:
        for r in policy.rules:
            for a in assessments:
                if a.category in r.categories:
                    p_ok = a.probability >= (r.probability_threshold or 0.0)
                    s_ok = a.severity.value >= (r.severity_threshold.value if r.severity_threshold else 0)
                    if p_ok and s_ok:
                        return ModerationOutcome(decision=r.decision, actions=r.actions or [], max_severity=max_sev)

    # Fallback thresholds
    overall_th = thresholds.get("overall", 0.8)
    any_high = any(a.severity in (SeverityLevel.SEVERITY_HIGH, SeverityLevel.SEVERITY_CRITICAL) for a in assessments)

    if any_high:
        return ModerationOutcome(decision=Decision.DECISION_REVIEW, actions=[Action.ACTION_REQUIRE_HUMAN_REVIEW], max_severity=max_sev)
    if overall_th <= 0.0 or not assessments:
        return ModerationOutcome(decision=Decision.DECISION_ALLOW, actions=[Action.ACTION_NONE], max_severity=max_sev)
    # If any category exceeds its own threshold key
    for a in assessments:
        th = thresholds.get(a.category, thresholds.get(a.category.lower(), 0.9))  # allow both enum and lower key
        if a.probability >= th:
            return ModerationOutcome(decision=Decision.DECISION_REVIEW, actions=[Action.ACTION_REQUIRE_HUMAN_REVIEW], max_severity=max_sev)

    return ModerationOutcome(decision=Decision.DECISION_ALLOW, actions=[Action.ACTION_NONE], max_severity=max_sev)


# =========================
# Auth dependency
# =========================

def require_bearer(authorization: Optional[str] = Header(default=None)) -> None:
    if not REQUIRE_TOKEN:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if not API_TOKEN or token != API_TOKEN:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# =========================
# Router
# =========================

router = APIRouter(prefix=API_PREFIX, tags=["moderation"])


@router.post("/moderate", response_model=ModerationResponse)
async def moderate_endpoint(
    req: ModerationRequest,
    _: None = Depends(require_bearer),
    request: Request = None,
) -> JSONResponse:
    # Basic guardrails
    if len(req.items) > MAX_ITEMS:
        raise HTTPException(status_code=400, detail=f"Too many items; max={MAX_ITEMS}")

    # Fill metadata
    now = datetime.now(timezone.utc).isoformat()
    req_id = req.request_id or get_request_id() or f"req_{int(time.time()*1000)}"
    policy_version = req.policy.version if req.policy and req.policy.version else "policy/inline-or-default"

    # Engine
    assessments, redactions, risk = ENGINE.moderate(req)

    outcome = _apply_policy(assessments, req.policy, req.thresholds or {})
    resp = ModerationResponse(
        request_id=req_id,
        policy_version=policy_version,
        created_at=now,
        outcome=outcome,
        assessments=assessments,
        overall_risk=RiskScore(score=float(risk.get("overall", 0.0)), components={k: float(v) for k, v in risk.get("components", {}).items()}),
        redactions=redactions,
        debug_info={
            "trace_id": get_trace_id(),
            "span_id": get_span_id(),
            "client": request.client.host if request and request.client else None,
            "engine": risk.get("engine"),
        },
        explanation="Heuristic policy evaluation" if req.return_explanations else None,
    )
    return JSONResponse(status_code=200, content=json.loads(resp.json()))


@router.post("/moderate/stream")
async def moderate_stream_endpoint(
    req: ModerationRequest,
    _: None = Depends(require_bearer),
    request: Request = None,
):
    # Pre-validate
    try:
        req = ModerationRequest.model_validate(req)  # type: ignore[attr-defined]
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=e.errors())

    req_id = req.request_id or get_request_id() or f"req_{int(time.time()*1000)}"
    policy_version = req.policy.version if req.policy and req.policy.version else "policy/inline-or-default"

    async def _gen():
        # Fake partials: stream per text item chunk to show progress
        yielded_any = False
        for it in req.items:
            if it.type == ContentType.CONTENT_TYPE_TEXT and it.text:
                text = it.text
                # Emit one partial per ~1000 characters
                chunk = text[:1000]
                if chunk:
                    partial_assess, _, _ = ENGINE.moderate(
                        ModerationRequest(items=[ContentItem(**{**it.dict(), "text": chunk})], return_spans=False)
                    )
                    event = {"partial_assessments": [json.loads(a.json()) for a in partial_assess]}
                    data = json.dumps(event, ensure_ascii=False)
                    yield f"data: {data}\n\n"
                    yielded_any = True

        # Final
        assessments, redactions, risk = ENGINE.moderate(req)
        outcome = _apply_policy(assessments, req.policy, req.thresholds or {})
        now = datetime.now(timezone.utc).isoformat()
        final = ModerationResponse(
            request_id=req_id,
            policy_version=policy_version,
            created_at=now,
            outcome=outcome,
            assessments=assessments,
            overall_risk=RiskScore(score=float(risk.get("overall", 0.0)), components={k: float(v) for k, v in risk.get("components", {}).items()}),
            redactions=redactions,
            debug_info={"trace_id": get_trace_id(), "span_id": get_span_id(), "stream": True},
            explanation=None,
        )
        payload = {"final": json.loads(final.json())}
        yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"
        if not yielded_any:
            # Prevent clients waiting for intermediate events when there are none
            await request.is_disconnected()

    return StreamingResponse(_gen(), media_type="text/event-stream")
