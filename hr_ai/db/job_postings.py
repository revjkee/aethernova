from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.exc import NoResultFound
from hr_ai.db.models import JobPosting, AuditLog
from hr_ai.schemas import JobPostingCreate, JobPostingUpdate
from datetime import datetime
import uuid
import logging

logger = logging.getLogger("job_postings")

class JobPostingNotFound(Exception):
    pass

# === GET SINGLE POSTING ===
async def get_job_posting(session: AsyncSession, job_id: str, tenant_id: str) -> JobPosting:
    stmt = select(JobPosting).where(
        JobPosting.id == job_id,
        JobPosting.tenant_id == tenant_id
    )
    result = await session.execute(stmt)
    job = result.scalar_one_or_none()
    if not job:
        raise JobPostingNotFound(f"Job posting {job_id} not found")
    return job

# === LIST POSTINGS ===
async def list_job_postings(session: AsyncSession, tenant_id: str, status_filter: str | None = None, limit: int = 100) -> list[JobPosting]:
    stmt = select(JobPosting).where(JobPosting.tenant_id == tenant_id)
    if status_filter:
        stmt = stmt.where(JobPosting.status == status_filter)
    result = await session.execute(stmt.limit(limit))
    return result.scalars().all()

# === CREATE POSTING ===
async def create_job_posting(session: AsyncSession, data: JobPostingCreate, tenant_id: str, user_id: str) -> JobPosting:
    job = JobPosting(
        id=str(uuid.uuid4()),
        title=data.title,
        description=data.description,
        requirements=data.requirements,
        tags=data.tags,
        location=data.location,
        department=data.department,
        status=data.status,
        salary_range=data.salary_range,
        metadata=data.metadata,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        tenant_id=tenant_id
    )
    session.add(job)
    await session.flush()

    await _log_audit(session, user_id, "create", f"job:{job.id}", tenant_id, severity=1)
    return job

# === UPDATE POSTING ===
async def update_job_posting(session: AsyncSession, job_id: str, data: JobPostingUpdate, tenant_id: str, user_id: str) -> JobPosting:
    job = await get_job_posting(session, job_id, tenant_id)

    for field, value in data.dict(exclude_unset=True).items():
        setattr(job, field, value)

    job.updated_at = datetime.utcnow()
    await session.flush()

    await _log_audit(session, user_id, "update", f"job:{job.id}", tenant_id, severity=2)
    return job

# === DELETE POSTING ===
async def delete_job_posting(session: AsyncSession, job_id: str, tenant_id: str, user_id: str):
    job = await get_job_posting(session, job_id, tenant_id)
    await session.delete(job)
    await session.flush()
    await _log_audit(session, user_id, "delete", f"job:{job.id}", tenant_id, severity=4)

# === AUDIT LOGGER ===
async def _log_audit(session: AsyncSession, user_id: str, action: str, target: str, tenant_id: str, severity: int = 1):
    log = AuditLog(
        id=str(uuid.uuid4()),
        user_id=user_id,
        action=action,
        target=target,
        tenant_id=tenant_id,
        severity=severity,
        timestamp=datetime.utcnow()
    )
    session.add(log)
    await session.flush()
