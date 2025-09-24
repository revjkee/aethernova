# edu-ai/skill_assessment.py

import datetime
from typing import List, Dict, Optional
from uuid import UUID
from pydantic import BaseModel
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from core.db import get_session
from models.user import User
from models.skill import SkillAssessmentLog, SkillLevel
from core.auth import get_current_user
from services.siemplify import parse_siem_event
from services.ir_analyzer import analyze_ir_decision_tree
from services.behavioral import detect_anomalous_behavior
from utils.ml_scoring import predict_skill_class
from utils.time import now_utc

router = APIRouter(prefix="/skill", tags=["Skill Assessment"])

class AssessmentInput(BaseModel):
    user_id: UUID
    session_id: UUID
    event_logs: List[Dict]
    ir_decisions: Optional[Dict] = None
    siem_output: Optional[List[Dict]] = None

class AssessmentResult(BaseModel):
    user_id: UUID
    skill_score: float
    skill_level: str
    metrics: Dict[str, float]
    anomalies_detected: bool
    recommended_next_lab: Optional[str]

@router.post("/assess", response_model=AssessmentResult)
async def assess_user_skill(
    payload: AssessmentInput,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    # SIEM log scoring
    siem_score = 0.0
    siem_metrics = {}
    if payload.siem_output:
        for event in payload.siem_output:
            score, details = parse_siem_event(event)
            siem_score += score
            for k, v in details.items():
                siem_metrics[k] = siem_metrics.get(k, 0) + v

    # IR decision logic scoring
    ir_score = 0.0
    if payload.ir_decisions:
        ir_score, ir_metrics = analyze_ir_decision_tree(payload.ir_decisions)
        siem_metrics.update(ir_metrics)

    # Behavioral anomaly detection
    anomalies_detected = detect_anomalous_behavior(payload.event_logs)

    # ML scoring model
    ml_score = predict_skill_class(
        logs=payload.event_logs,
        siem_score=siem_score,
        ir_score=ir_score,
        anomalies=anomalies_detected
    )

    # Composite score
    final_score = round((siem_score * 0.4 + ir_score * 0.4 + ml_score * 0.2), 2)
    level = classify_score(final_score)

    # Log to DB
    skill_log = SkillAssessmentLog(
        id=UUID(),
        user_id=payload.user_id,
        session_id=payload.session_id,
        score=final_score,
        level=level,
        anomalies_detected=anomalies_detected,
        created_at=now_utc()
    )
    session.add(skill_log)
    await session.commit()

    return AssessmentResult(
        user_id=payload.user_id,
        skill_score=final_score,
        skill_level=level,
        metrics=siem_metrics,
        anomalies_detected=anomalies_detected,
        recommended_next_lab=next_lab_recommendation(level)
    )

def classify_score(score: float) -> str:
    if score >= 90:
        return "Advanced"
    elif score >= 70:
        return "Intermediate"
    elif score >= 50:
        return "Beginner"
    else:
        return "Novice"

def next_lab_recommendation(level: str) -> Optional[str]:
    return {
        "Novice": "siem_detection_lab.md",
        "Beginner": "ir_playbook_challenge.md",
        "Intermediate": "aeroflot_silentcrow_case.md",
        "Advanced": "redteam_live_ops_simulation.md"
    }.get(level)
