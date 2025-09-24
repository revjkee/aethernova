# cybersecurity-core/api/http/routers/v1/adversary_emulation.py
"""
FastAPI v1 Router: Adversary Emulation

Features
--------
- APIRouter with versioned prefix and tags (FastAPI reference).            # Ref: FastAPI APIRouter
- API key auth via header dependency for OpenAPI security scheme.          # Ref: FastAPI Security APIKey
- Problem Details for HTTP APIs (RFC 9457, application/problem+json).      # Ref: RFC 9457
- In-process BackgroundTasks for non-blocking scenario execution.          # Ref: Starlette BackgroundTasks
- Idempotency-Key support for safe retries of POST /runs.
- Structured Pydantic models for requests/responses (v2 BaseModel).        # Ref: Pydantic BaseModel
- Integration with:
    * scenarios.library.scenario_phishing.PhishingScenario (safe-mode)
    * attack_simulator.safety.kill_switch.KillSwitch for controlled stop
- Minimal in-memory run registry with thread lock.
- HTTP semantics (status codes/headers) per RFC 9110.                      # Ref: RFC 9110

Security & Governance Context
-----------------------------
- NIST SP 800-115: controlled technical security testing.                  # Ref: NIST SP 800-115
- NIST SP 800-61r3: rapid containment/eradication for incidents.           # Ref: NIST SP 800-61r3
- NIST SP 800-53r5: controls catalog (IR/SI families relevant).            # Ref: NIST SP 800-53r5
- MITRE ATT&CK T1566 (Phishing) mappings surfaced in scenario metadata.    # Ref: MITRE ATT&CK T1566

Copyright
---------
(c) 2025 Aethernova / Cybersecurity Core. License: project default.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Response,
    status,
)
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

# --- Internal integrations (ensure these modules exist in the project) ---
from cybersecurity.adversary_emulation.scenarios.library.scenario_phishing import (  # noqa: E501
    PhishingScenario,
    RunConfig as PhishingRunConfig,
    METADATA as PHISHING_METADATA,
)
from cybersecurity.adversary_emulation.attack_simulator.safety.kill_switch import (  # noqa: E501
    KillSwitch,
    SafetyAbort,
)

# ------------------------------ Router ---------------------------------------

router = APIRouter(
    prefix="/api/v1/adversary-emulation",
    tags=["adversary-emulation"],
)

# ------------------------------ Security -------------------------------------

# API key header dependency (documented in OpenAPI automatically).
# Clients MUST send:  x-api-key: <token>
# Ref: FastAPI security APIKeyHeader
api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)  # :contentReference[oaicite:1]{index=1}


def _verify_api_key(x_api_key: str = Depends(api_key_header)) -> str:
    """
    Very simple verifier: compares against env AETHERNOVA_API_KEY.
    For production, replace with your own provider (JWT/OAuth2 per RFC 6750).
    """
    required = os.getenv("AETHERNOVA_API_KEY", "").strip()
    if not required or x_api_key != required:
        # RFC 9110: use 401 for authentication failures
        raise _problem_exc(
            status_code=status.HTTP_401_UNAUTHORIZED,
            title="Unauthorized",
            detail="Invalid API key",
            type_="about:blank",
        )
    return x_api_key  # may be used by handlers
# RFC 6750 bearer tokens spec if migrating to OAuth2. :contentReference[oaicite:2]{index=2}

# --------------------------- Problem Details ----------------------------------


class ProblemDetails(BaseModel):
    # RFC 9457 obsoletes 7807 and keeps fields: type, title, status, detail, instance
    type: str = Field(default="about:blank")
    title: str
    status: int
    detail: Optional[str] = None
    instance: Optional[str] = None
# RFC 9457. :contentReference[oaicite:3]{index=3}


def _problem_exc(
    status_code: int,
    title: str,
    detail: Optional[str] = None,
    type_: str = "about:blank",
    instance: Optional[str] = None,
) -> HTTPException:
    pd = ProblemDetails(type=type_, title=title, status=status_code, detail=detail, instance=instance)
    return HTTPException(
        status_code=status_code,
        detail=pd.model_dump(),
        headers={"Content-Type": "application/problem+json"},
    )

# ------------------------------- Models ---------------------------------------


def _ts() -> str:
    # RFC 3339 timestamp (ISO 8601 profile)
    return datetime.now(timezone.utc).isoformat()
# RFC 3339. :contentReference[oaicite:4]{index=4}


class ScenarioDescriptor(BaseModel):
    scenario_id: str
    name: str
    description: str
    version: str
    techniques: list[dict] = Field(default_factory=list)
    controls: list[dict] = Field(default_factory=list)
    references: dict = Field(default_factory=dict)


class ListScenariosResponse(BaseModel):
    items: list[ScenarioDescriptor]
    count: int
    generated_at: str = Field(default_factory=_ts)


class StartRunRequest(BaseModel):
    scenario_id: str = Field(examples=["ADV-EMUL-PHISHING-001"])
    seed: int = 1337
    unsafe: bool = False
    operator: str = "operator@lab.local"
    organization: str = "Acme Corp"
    campaign_name: str = "Awareness Test"
    # optional: custom output dir base (for lab environments)
    base_dir: Optional[str] = None


class StartRunResponse(BaseModel):
    run_id: str
    status: str
    created_at: str = Field(default_factory=_ts)
    summary_path: Optional[str] = None


class RunStatusResponse(BaseModel):
    run_id: str
    status: str
    safe_mode: bool
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    summary_path: Optional[str] = None
    logs_path: Optional[str] = None
    artifacts_dir: Optional[str] = None
    error: Optional[str] = None


class StopRunRequest(BaseModel):
    reason: str = "manual-stop"


# -------------------------- In-memory run registry ----------------------------

class _RunEntry(BaseModel):
    run_id: str
    scenario_id: str
    status: str  # queued|running|succeeded|failed|aborted
    safe_mode: bool
    created_at: str = Field(default_factory=_ts)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    base_dir: str
    summary_path: Optional[str] = None
    logs_path: Optional[str] = None
    artifacts_dir: Optional[str] = None
    error: Optional[str] = None


_RUNS: Dict[str, _RunEntry] = {}
_RUNS_LOCK = threading.RLock()
_IDEMPOTENCY: Dict[str, str] = {}  # Idempotency-Key -> run_id


def _runs_dir(base_dir: Optional[str]) -> Path:
    if base_dir:
        return Path(base_dir)
    return Path(os.getenv("AETHERNOVA_RUNS_DIR", "./ae_runs")).resolve()


def _hash_request(body: dict) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()


# ------------------------------ Scenarios -------------------------------------

# Static registry; could be extended via entry points later.
_SCENARIOS: Dict[str, Dict[str, Any]] = {
    PHISHING_METADATA.scenario_id: {
        "factory": PhishingScenario,
        "meta": PHISHING_METADATA.to_dict(),
    }
}


@router.get(
    "/scenarios",
    response_model=ListScenariosResponse,
    responses={401: {"model": ProblemDetails, "content": {"application/problem+json": {}}}},
)
def list_scenarios(_: str = Depends(_verify_api_key)) -> ListScenariosResponse:
    """List available adversary emulation scenarios."""
    items = [
        ScenarioDescriptor(**v["meta"])
        for _, v in _SCENARIOS.items()
    ]
    return ListScenariosResponse(items=items, count=len(items))
# APIRouter usage & Pydantic models per docs. :contentReference[oaicite:5]{index=5}


# ------------------------------ Run control -----------------------------------

def _background_run(
    run_id: str,
    scenario_id: str,
    cfg: PhishingRunConfig,
    state_dir: Path,
) -> None:
    """Execute scenario in background (after HTTP response is sent)."""
    ks = KillSwitch(state_dir)
    with _RUNS_LOCK:
        entry = _RUNS[run_id]
        entry.status = "running"
        entry.started_at = _ts()

    # Check kill-switch before starting heavy work
    try:
        ks.check_or_abort(activity=f"run:{run_id}")
    except SafetyAbort as e:
        with _RUNS_LOCK:
            entry = _RUNS[run_id]
            entry.status = "aborted"
            entry.finished_at = _ts()
            entry.error = str(e)
        return

    try:
        scenario = _SCENARIOS[scenario_id]["factory"](cfg)
        summary = scenario.run()  # internally safe_mode prevents any egress
        reports_dir = Path(cfg.output_dir) / "reports"
        logs_dir = Path(cfg.output_dir) / "logs"
        with _RUNS_LOCK:
            entry = _RUNS[run_id]
            entry.status = "succeeded"
            entry.finished_at = _ts()
            entry.summary_path = str(reports_dir / "summary.json")
            entry.logs_path = str(logs_dir / "telemetry.jsonl")
            entry.artifacts_dir = str(Path(cfg.output_dir) / "artifacts")
    except SafetyAbort as e:
        with _RUNS_LOCK:
            entry = _RUNS[run_id]
            entry.status = "aborted"
            entry.finished_at = _ts()
            entry.error = str(e)
    except Exception as e:
        with _RUNS_LOCK:
            entry = _RUNS[run_id]
            entry.status = "failed"
            entry.finished_at = _ts()
            entry.error = f"{type(e).__name__}: {e}"


@router.post(
    "/runs",
    response_model=StartRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"model": ProblemDetails, "content": {"application/problem+json": {}}},
        401: {"model": ProblemDetails, "content": {"application/problem+json": {}}},
        404: {"model": ProblemDetails, "content": {"application/problem+json": {}}},
        409: {"model": ProblemDetails, "content": {"application/problem+json": {}}},
    },
)
def start_run(
    payload: StartRunRequest,
    background: BackgroundTasks,
    response: Response,
    x_api_key: str = Depends(_verify_api_key),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
) -> StartRunResponse:
    """
    Start a scenario run. Uses BackgroundTasks (in-process) per Starlette docs.
    Returns 202 Accepted + run_id; caller polls GET /runs/{run_id}.
    """
    # Idempotency (simple): if Idempotency-Key seen, return previous run_id
    if idempotency_key:
        key = f"{idempotency_key}:{_hash_request(payload.model_dump())}"
        with _RUNS_LOCK:
            if key in _IDEMPOTENCY:
                run_id = _IDEMPOTENCY[key]
                entry = _RUNS[run_id]
                return StartRunResponse(run_id=run_id, status=entry.status, summary_path=entry.summary_path)

    # Validate scenario
    if payload.scenario_id not in _SCENARIOS:
        raise _problem_exc(status.HTTP_404_NOT_FOUND, "Unknown scenario", f"Scenario '{payload.scenario_id}' is not registered")

    run_id = uuid.uuid4().hex
    base = _runs_dir(payload.base_dir)
    out_dir = base / run_id
    state_dir = base / run_id  # kill-switch stores safety/ under this

    cfg = PhishingRunConfig(
        output_dir=out_dir,
        seed=payload.seed,
        safe_mode=not payload.unsafe,
        operator=payload.operator,
        campaign_name=payload.campaign_name,
        organization=payload.organization,
    )

    out_dir.mkdir(parents=True, exist_ok=True)

    entry = _RunEntry(
        run_id=run_id,
        scenario_id=payload.scenario_id,
        status="queued",
        safe_mode=cfg.safe_mode,
        base_dir=str(base),
    )
    with _RUNS_LOCK:
        _RUNS[run_id] = entry
        if idempotency_key:
            _IDEMPOTENCY[f"{idempotency_key}:{_hash_request(payload.model_dump())}"] = run_id

    # Schedule background execution (runs after response). Starlette BackgroundTasks. :contentReference[oaicite:6]{index=6}
    background.add_task(_background_run, run_id, payload.scenario_id, cfg, state_dir)

    # HTTP 202 Accepted per RFC 9110 for async processing acknowledgement. :contentReference[oaicite:7]{index=7}
    response.headers["Location"] = f"/api/v1/adversary-emulation/runs/{run_id}"
    return StartRunResponse(run_id=run_id, status="queued")


@router.get(
    "/runs/{run_id}",
    response_model=RunStatusResponse,
    responses={401: {"model": ProblemDetails, "content": {"application/problem+json": {}}}, 404: {"model": ProblemDetails, "content": {"application/problem+json": {}}}},  # noqa: E501
)
def run_status(run_id: str, _: str = Depends(_verify_api_key)) -> RunStatusResponse:
    """Return run status and artifact paths."""
    with _RUNS_LOCK:
        entry = _RUNS.get(run_id)
        if not entry:
            raise _problem_exc(status.HTTP_404_NOT_FOUND, "Run not found", f"Unknown run_id '{run_id}'")
        return RunStatusResponse(**entry.model_dump())


@router.post(
    "/runs/{run_id}/stop",
    response_model=RunStatusResponse,
    responses={
        401: {"model": ProblemDetails, "content": {"application/problem+json": {}}},
        404: {"model": ProblemDetails, "content": {"application/problem+json": {}}},
        409: {"model": ProblemDetails, "content": {"application/problem+json": {}}},
    },
)
def stop_run(run_id: str, body: StopRunRequest, _: str = Depends(_verify_api_key)) -> RunStatusResponse:
    """
    Engage kill-switch for the run. Scenario checks occur before start; if already
    running, the next kill-aware check in pipeline will abort. If the scenario is
    not kill-aware internally, stop takes effect before any next run.
    """
    with _RUNS_LOCK:
        entry = _RUNS.get(run_id)
        if not entry:
            raise _problem_exc(status.HTTP_404_NOT_FOUND, "Run not found", f"Unknown run_id '{run_id}'")
        if entry.status in {"succeeded", "failed", "aborted"}:
            # conflict: nothing to stop
            raise _problem_exc(status.HTTP_409_CONFLICT, "Run completed", f"Run already {entry.status}")

    base = Path(entry.base_dir)
    ks = KillSwitch(base / run_id)
    ks.engage(reason=body.reason, issued_by="api")

    # reflect status if it was queued
    with _RUNS_LOCK:
        entry = _RUNS[run_id]
        if entry.status == "queued":
            entry.status = "aborted"
            entry.finished_at = _ts()
    return RunStatusResponse(**entry.model_dump())


@router.get(
    "/runs/{run_id}/killswitch",
    responses={401: {"model": ProblemDetails, "content": {"application/problem+json": {}}}, 404: {"model": ProblemDetails, "content": {"application/problem+json": {}}}},  # noqa: E501
)
def kill_switch_status(run_id: str, _: str = Depends(_verify_api_key)) -> dict:
    """Return kill-switch status for given run."""
    with _RUNS_LOCK:
        entry = _RUNS.get(run_id)
        if not entry:
            raise _problem_exc(status.HTTP_404_NOT_FOUND, "Run not found", f"Unknown run_id '{run_id}'")
    ks = KillSwitch(Path(entry.base_dir) / run_id)
    return ks.status()
