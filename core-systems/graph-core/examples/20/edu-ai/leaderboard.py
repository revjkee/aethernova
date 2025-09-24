# edu-ai/leaderboard.py

import datetime
from typing import List, Optional, Dict
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Query, Body, Depends
from uuid import UUID, uuid4
from functools import lru_cache
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from core.db import get_session
from core.auth import get_current_user
from core.logger import audit_log
from models.user import User
from models.leaderboard import LeaderboardEntry, LeaderboardRule
from services.cache import leaderboard_cache
from services.scoring import calculate_score, get_weighted_score
from utils.time import get_period_range

router = APIRouter(prefix="/leaderboard", tags=["Gamification"])

class ScoreSubmission(BaseModel):
    user_id: UUID
    event_type: str = Field(..., example="lab_completed")
    event_meta: Optional[Dict] = Field(default_factory=dict)

class LeaderboardView(BaseModel):
    user_id: UUID
    username: str
    score: int
    rank: int
    badge: Optional[str]
    category: Optional[str]

class LeaderboardConfig(BaseModel):
    category: str
    weights: Dict[str, float]  # e.g., {"lab_completed": 1.0, "challenge_passed": 1.5}

@lru_cache()
def get_default_leaderboard_rules() -> Dict[str, float]:
    return {
        "lab_completed": 1.0,
        "challenge_passed": 1.5,
        "ai_assist_used": 0.25,
        "zero_day_found": 5.0,
        "report_submitted": 2.0
    }

@router.post("/submit", summary="Submit event and recalculate score")
async def submit_score(
    payload: ScoreSubmission,
    session: AsyncSession = Depends(get_session),
):
    weights = get_default_leaderboard_rules()
    points = calculate_score(payload.event_type, payload.event_meta, weights)
    if points == 0:
        raise HTTPException(status_code=400, detail="Invalid event_type")

    stmt = select(LeaderboardEntry).where(LeaderboardEntry.user_id == payload.user_id)
    result = await session.execute(stmt)
    entry = result.scalar_one_or_none()

    if entry:
        entry.score += points
        entry.updated_at = datetime.datetime.utcnow()
    else:
        entry = LeaderboardEntry(
            id=uuid4(),
            user_id=payload.user_id,
            score=points,
            category=payload.event_meta.get("category", "default"),
            created_at=datetime.datetime.utcnow(),
            updated_at=datetime.datetime.utcnow(),
        )
        session.add(entry)

    await session.commit()
    await leaderboard_cache.invalidate("global")

    audit_log("leaderboard_update", user_id=payload.user_id, meta={"score": points})
    return {"status": "success", "added_points": points}

@router.get("/global", response_model=List[LeaderboardView])
async def get_leaderboard(
    top_n: int = Query(50, le=100),
    category: Optional[str] = Query(None),
    session: AsyncSession = Depends(get_session),
):
    cached = await leaderboard_cache.get("global")
    if cached:
        return cached[:top_n]

    stmt = select(LeaderboardEntry).order_by(LeaderboardEntry.score.desc())
    if category:
        stmt = stmt.where(LeaderboardEntry.category == category)

    result = await session.execute(stmt)
    entries = result.scalars().all()

    leaderboard = []
    for idx, entry in enumerate(entries[:top_n]):
        user_stmt = select(User).where(User.id == entry.user_id)
        user = (await session.execute(user_stmt)).scalar_one_or_none()
        leaderboard.append(LeaderboardView(
            user_id=entry.user_id,
            username=user.username if user else "Unknown",
            score=entry.score,
            rank=idx + 1,
            badge=assign_badge(entry.score),
            category=entry.category,
        ))

    await leaderboard_cache.set("global", leaderboard)
    return leaderboard

def assign_badge(score: int) -> Optional[str]:
    if score > 1000:
        return "Cyber Overlord"
    elif score > 500:
        return "Red Defender"
    elif score > 250:
        return "Blue Sentinel"
    return None
