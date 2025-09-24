from sqlalchemy import (
    Column,
    String,
    Integer,
    DateTime,
    Boolean,
    ForeignKey,
    Enum,
    Float,
    Text,
    JSON,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func
from enum import Enum as PyEnum
from typing import Optional, List
import uuid

Base = declarative_base()

# === ENUMS ===
class CandidateStatus(PyEnum):
    PENDING = "pending"
    REVIEWED = "reviewed"
    INTERVIEWED = "interviewed"
    REJECTED = "rejected"
    ACCEPTED = "accepted"

class SkillLevel(PyEnum):
    JUNIOR = "junior"
    MIDDLE = "middle"
    SENIOR = "senior"
    EXPERT = "expert"

# === MIXINS ===
class TimestampMixin:
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class TenantMixin:
    tenant_id = Column(String(64), nullable=False, index=True)

# === MODELS ===
class Candidate(Base, TimestampMixin, TenantMixin):
    __tablename__ = "candidates"
    __table_args__ = (
        UniqueConstraint("email", "tenant_id", name="uq_candidate_email_tenant"),
        Index("ix_candidate_status", "status"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    full_name = Column(String(256), nullable=False)
    email = Column(String(256), nullable=False)
    phone = Column(String(32), nullable=True)
    linkedin_url = Column(String(512), nullable=True)
    resume_text = Column(Text, nullable=True)
    skills = Column(JSON, nullable=True)  # example: [{"name": "Python", "level": "senior"}]
    languages = Column(JSON, nullable=True)
    softskills_score = Column(Float, default=0.0)
    ethics_score = Column(Float, default=1.0)
    diversity_flag = Column(Boolean, default=False)
    status = Column(Enum(CandidateStatus), default=CandidateStatus.PENDING)
    explanation = Column(JSON, nullable=True)  # XAI output
    metadata = Column(JSON, nullable=True)
    position_id = Column(String(36), ForeignKey("positions.id", ondelete="SET NULL"), nullable=True)

    position = relationship("Position", back_populates="candidates")

class Position(Base, TimestampMixin, TenantMixin):
    __tablename__ = "positions"
    __table_args__ = (
        UniqueConstraint("title", "tenant_id", name="uq_position_title_tenant"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    department = Column(String(128), nullable=True)
    location = Column(String(128), nullable=True)
    required_skills = Column(JSON, nullable=True)
    min_experience_years = Column(Float, nullable=True)
    max_candidates = Column(Integer, default=100)
    is_remote = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)

    candidates = relationship("Candidate", back_populates="position")

class AuditLog(Base, TimestampMixin, TenantMixin):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(64), nullable=False)
    action = Column(String(128), nullable=False)
    target = Column(String(128), nullable=True)
    metadata = Column(JSON, nullable=True)
    severity = Column(Integer, default=1)
    source_ip = Column(String(64), nullable=True)
    x_forwarded_for = Column(String(128), nullable=True)

# === INDEXES ===
Index("ix_candidate_softskills_score", Candidate.softskills_score)
Index("ix_candidate_ethics_score", Candidate.ethics_score)
Index("ix_candidate_diversity_flag", Candidate.diversity_flag)
Index("ix_auditlog_severity", AuditLog.severity)
