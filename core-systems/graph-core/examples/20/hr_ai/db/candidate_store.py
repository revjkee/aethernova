from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.exc import NoResultFound, IntegrityError
from hr_ai.db.models import Candidate, Position, AuditLog
from hr_ai.schemas import CandidateCreate, CandidateUpdate
from datetime import datetime
import uuid
import logging

logger = logging.getLogger("candidate_store")

# === EXCEPTIONS ===
class CandidateNotFound(Exception):
    pass

class CandidateConflict(Exception):
    pass

# === CORE STORE FUNCTIONS ===
async def get_candidate_by_id(session: AsyncSession, candidate_id: str, tenant_id: str) -> Candidate:
    stmt = select(Candidate).where(
        Candidate.id == candidate_id,
        Candidate.tenant_id == tenant_id
    )
    result = await session.execute(stmt)
    candidate = result.scalar_one_or_none()
    if not candidate:
        raise CandidateNotFound(f"Candidate {candidate_id} not found")
    return candidate

async def list_candidates(session: AsyncSession, tenant_id: str, limit: int = 100) -> list[Candidate]:
    stmt = select(Candidate).where(Candidate.tenant_id == tenant_id).limit(limit)
    result = await session.execute(stmt)
    return result.scalars().all()

async def create_candidate(session: AsyncSession, data: CandidateCreate, tenant_id: str, user_id: str) -> Candidate:
    new_candidate = Candidate(
        id=str(uuid.uuid4()),
        full_name=data.full_name,
        email=data.email,
        phone=data.phone,
        linkedin_url=data.linkedin_url,
        resume_text=data.resume_text,
        skills=data.skills,
        languages=data.languages,
        softskills_score=data.softskills_score,
        ethics_score=data.ethics_score,
        diversity_flag=data.diversity_flag,
        status=data.status,
        explanation=data.explanation,
        metadata=data.metadata,
        position_id=data.position_id,
        tenant_id=tenant_id
    )
    session.add(new_candidate)
    await session.flush()

    await _log_audit(session, user_id, "create", f"candidate:{new_candidate.id}", tenant_id, severity=1)
    return new_candidate

async def update_candidate(session: AsyncSession, candidate_id: str, data: CandidateUpdate, tenant_id: str, user_id: str) -> Candidate:
    candidate = await get_candidate_by_id(session, candidate_id, tenant_id)

    for field, value in data.dict(exclude_unset=True).items():
        setattr(candidate, field, value)

    candidate.updated_at = datetime.utcnow()
    await session.flush()

    await _log_audit(session, user_id, "update", f"candidate:{candidate.id}", tenant_id, severity=2)
    return candidate

async def delete_candidate(session: AsyncSession, candidate_id: str, tenant_id: str, user_id: str) -> None:
    candidate = await get_candidate_by_id(session, candidate_id, tenant_id)
    await session.delete(candidate)
    await session.flush()

    await _log_audit(session, user_id, "delete", f"candidate:{candidate.id}", tenant_id, severity=5)

# === AUDIT LOGGING ===
async def _log_audit(session: AsyncSession, user_id: str, action: str, target: str, tenant_id: str, severity: int = 1):
    log_entry = AuditLog(
        id=str(uuid.uuid4()),
        user_id=user_id,
        action=action,
        target=target,
        tenant_id=tenant_id,
        severity=severity
    )
    session.add(log_entry)
    await session.flush()
