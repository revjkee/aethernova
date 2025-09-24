# SPDX-License-Identifier: MIT
"""
VeilMind Core — Consent storage models (SQLAlchemy 2.x, PostgreSQL)
Schema overview:
  consent_records (root) 1--1 consent_scopes
                        1--1 consent_evidence
                        1--N consent_parties
                        1--N consent_purposes
                        1--N consent_history

Design highlights:
- Typed SQLAlchemy 2.0 models with PostgreSQL types (UUID/JSONB/ARRAY/INET)
- Strict enums with native PostgreSQL ENUM types
- Server-side timestamps (timestamptz), gen_random_uuid(), now()
- Indices for tenant/subject/time/status + GIN for JSONB/arrays
- Cascading relationships, delete-orphan, eager options ready
- Hybrid computed properties (is_active, ttl_left)
- Safe payload conversion helpers (to_payload / from_payload) aligned with JSON Schema

Notes:
- Requires PostgreSQL extension 'pgcrypto' or 'uuid-ossp' for gen_random_uuid(); prefer pgcrypto.
- Migrations: create enums/types via Alembic autogenerate, or pre-create manually.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy import (
    ARRAY,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    SmallInteger,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID as PG_UUID
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)
from sqlalchemy.ext.hybrid import hybrid_property


# --------------------------- Naming convention ---------------------------------

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s__%(column_0_N_name)s",
    "uq": "uq_%(table_name)s__%(column_0_N_name)s",
    "ck": "ck_%(table_name)s__%(constraint_name)s",
    "fk": "fk_%(table_name)s__%(column_0_N_name)s__%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# ------------------------------- Enums -----------------------------------------

ConsentStatus = Enum(
    "active",
    "withdrawn",
    "expired",
    "refused",
    "pending",
    "superseded",
    name="consent_status",
    native_enum=True,
    create_type=True,
)

LegalBasis = Enum(
    "consent",
    "contract",
    "legal_obligation",
    "vital_interests",
    "public_task",
    "legitimate_interests",
    name="legal_basis",
    native_enum=True,
    create_type=True,
)

Mechanism = Enum(
    "opt_in",
    "opt_out",
    "soft_opt_in",
    "implied",
    "granular",
    "contractual",
    name="consent_mechanism",
    native_enum=True,
    create_type=True,
)

PartyRole = Enum(
    "controller",
    "joint_controller",
    "processor",
    "subprocessor",
    name="party_role",
    native_enum=True,
    create_type=True,
)

PurposeGranularity = Enum(
    "category",
    "processing",
    "vendor",
    "feature",
    name="purpose_granularity",
    native_enum=True,
    create_type=True,
)

HistoryAction = Enum(
    "create",
    "update",
    "withdraw",
    "expire",
    "refuse",
    "supersede",
    name="history_action",
    native_enum=True,
    create_type=True,
)

EvidenceSource = Enum(
    "web_form",
    "sdk",
    "api",
    "paper",
    "voice",
    "import",
    name="evidence_source",
    native_enum=True,
    create_type=True,
)


# ------------------------------- Mixins ----------------------------------------

class TimestampMixin:
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


# ------------------------------- Root model ------------------------------------

class ConsentRecord(TimestampMixin, Base):
    __tablename__ = "consent_records"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        nullable=False,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    # Version (semver)
    version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0.0")

    # Tenant & subject (duplicated keys for query) + subject snapshot JSONB
    tenant_id: Mapped[Optional[str]] = mapped_column(String(128), index=True)
    subject_id: Mapped[Optional[uuid.UUID]] = mapped_column(PG_UUID(as_uuid=True), index=True)
    subject_email: Mapped[Optional[str]] = mapped_column(String(320))
    subject_age: Mapped[Optional[int]] = mapped_column(SmallInteger)
    subject_country: Mapped[Optional[str]] = mapped_column(String(2))
    subject_language: Mapped[Optional[str]] = mapped_column(String(32))
    subject_roles: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String(64)))
    subject_attributes: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)
    subject_guardian: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)

    # Lifecycle
    status: Mapped[str] = mapped_column(ConsentStatus, nullable=False, index=True)
    effective_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))

    # Jurisdictions / languages
    jurisdictions: Mapped[List[str]] = mapped_column(ARRAY(String(2)), default=list)
    languages: Mapped[List[str]] = mapped_column(ARRAY(String(32)), default=list)

    # Mechanism / legal basis
    mechanism: Mapped[str] = mapped_column(Mechanism, nullable=False)
    legal_basis: Mapped[str] = mapped_column(LegalBasis, nullable=False)

    # Retention policy, policy refs
    retention_policy: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    policy_references: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)

    # Revocation / refusal (optional snapshots)
    revocation: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    refusal: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)

    # Free-form extensions
    extensions: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Relationships
    scope: Mapped["ConsentScope"] = relationship(
        back_populates="record",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="joined",
    )
    evidence: Mapped["ConsentEvidence"] = relationship(
        back_populates="record",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="joined",
    )
    parties: Mapped[List["ConsentParty"]] = relationship(
        back_populates="record",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    purposes: Mapped[List["ConsentPurpose"]] = relationship(
        back_populates="record",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    history: Mapped[List["ConsentHistory"]] = relationship(
        back_populates="record",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="ConsentHistory.at.asc()",
    )

    __table_args__ = (
        # Age sanity
        CheckConstraint("subject_age IS NULL OR (subject_age >= 0 AND subject_age <= 150)", name="age_bounds"),
        # Version sanity (semver coarse)
        CheckConstraint("version ~ '^[0-9]+\\.[0-9]+\\.[0-9]+'", name="semver_format"),
        # Country codes sanity (two letters) for subject, jurisdictions validated at app-level
        CheckConstraint("subject_country IS NULL OR length(subject_country)=2", name="subject_country_len"),
        Index("ix_consent_records__tenant_subject_status", "tenant_id", "subject_id", "status"),
        Index("ix_consent_records__effective", "effective_at", "expires_at"),
        Index("ix_consent_records__languages", "languages", postgresql_using="gin"),
        Index("ix_consent_records__jurisdictions", "jurisdictions", postgresql_using="gin"),
        Index("ix_consent_records__subject_roles", "subject_roles", postgresql_using="gin"),
        Index("ix_consent_records__subject_attrs", "subject_attributes", postgresql_using="gin"),
    )

    # -------------------------- Hybrid helpers --------------------------

    @hybrid_property
    def is_active(self) -> bool:
        now = dt.datetime.now(dt.timezone.utc)
        if self.status != "active":
            return False
        if self.effective_at and self.effective_at > now:
            return False
        if self.expires_at and self.expires_at <= now:
            return False
        return True

    @hybrid_property
    def ttl_left(self) -> Optional[int]:
        """Seconds until expiration (if expires_at set and active)."""
        if not self.expires_at:
            return None
        now = dt.datetime.now(dt.timezone.utc)
        delta = self.expires_at - now
        return max(0, int(delta.total_seconds()))

    # ---------------------- Payload conversion API ----------------------

    def to_payload(self) -> Dict[str, Any]:
        """
        Convert SQL row + children to JSON payload compatible with
        schemas/jsonschema/v1/consent_record.schema.json.
        """
        payload: Dict[str, Any] = {
            "id": str(self.id),
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "status": self.status,
            "effective_at": self.effective_at.isoformat() if self.effective_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "jurisdictions": self.jurisdictions or [],
            "languages": self.languages or [],
            "mechanism": self.mechanism,
            "legal_basis": self.legal_basis,
            "data_subject": {
                "id": str(self.subject_id) if self.subject_id else None,
                "tenant_id": self.tenant_id,
                "email": self.subject_email,
                "age": self.subject_age,
                "country": self.subject_country,
                "language": self.subject_language,
                "roles": self.subject_roles or [],
                "attributes": self.subject_attributes or {},
                "guardian": self.subject_guardian or None,
            },
            "parties": {
                "controllers": [p.to_dict() for p in self.parties if p.role in ("controller", "joint_controller")],
                "processors": [p.to_dict() for p in self.parties if p.role == "processor"],
                "subprocessors": [p.to_dict() for p in self.parties if p.role == "subprocessor"],
            },
            "scope": self.scope.to_dict() if self.scope else None,
            "purposes": [pp.to_dict() for pp in self.purposes],
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "revocation": self.revocation,
            "refusal": self.refusal,
            "policy_references": self.policy_references or [],
            "history": [h.to_dict() for h in self.history],
            "extensions": self.extensions or {},
        }
        # Remove explicit Nones to keep payload clean
        def _strip_none(obj: Any) -> Any:
            if isinstance(obj, dict):
                return {k: _strip_none(v) for k, v in obj.items() if v is not None}
            if isinstance(obj, list):
                return [_strip_none(v) for v in obj if v is not None]
            return obj

        return _strip_none(payload)

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "ConsentRecord":
        """
        Construct model graph from JSON payload. Does not flush session.
        Minimal validation; rely on app-level JSON Schema validation upstream.
        """
        # Basic subject fields
        ds = payload.get("data_subject") or {}
        parties = payload.get("parties") or {}
        record = cls(
            id=uuid.UUID(payload["id"]) if "id" in payload else uuid.uuid4(),
            version=str(payload.get("version", "1.0.0")),
            status=str(payload["status"]),
            effective_at=_parse_dt(payload.get("effective_at")),
            expires_at=_parse_dt(payload.get("expires_at")),
            jurisdictions=list(payload.get("jurisdictions") or []),
            languages=list(payload.get("languages") or []),
            mechanism=str(payload["mechanism"]),
            legal_basis=str(payload["legal_basis"]),
            tenant_id=ds.get("tenant_id"),
            subject_id=uuid.UUID(ds["id"]) if "id" in ds and ds["id"] else None,
            subject_email=ds.get("email"),
            subject_age=ds.get("age"),
            subject_country=ds.get("country"),
            subject_language=ds.get("language"),
            subject_roles=list(ds.get("roles") or []),
            subject_attributes=dict(ds.get("attributes") or {}),
            subject_guardian=dict(ds.get("guardian") or {}) or None,
            retention_policy=payload.get("retention_policy"),
            policy_references=list(payload.get("policy_references") or []),
            revocation=payload.get("revocation"),
            refusal=payload.get("refusal"),
            extensions=dict(payload.get("extensions") or {}),
        )

        # Scope
        if payload.get("scope"):
            record.scope = ConsentScope.from_dict(payload["scope"])

        # Evidence
        if payload.get("evidence"):
            record.evidence = ConsentEvidence.from_dict(payload["evidence"])

        # Parties
        for kind in ("controllers", "processors", "subprocessors"):
            for p in parties.get(kind, []) or []:
                role = "controller" if kind == "controllers" and p.get("role") in ("controller", "joint_controller") else (
                    p.get("role") or ("processor" if kind == "processors" else "subprocessor")
                )
                record.parties.append(ConsentParty.from_dict({**p, "role": role}))

        # Purposes
        for pp in payload.get("purposes") or []:
            record.purposes.append(ConsentPurpose.from_dict(pp))

        # History
        for ev in payload.get("history") or []:
            record.history.append(ConsentHistory.from_dict(ev))

        return record


# ------------------------------- Scope -----------------------------------------

class ConsentScope(Base, TimestampMixin):
    __tablename__ = "consent_scopes"

    record_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("consent_records.id", ondelete="CASCADE"),
        primary_key=True,
    )

    # Arrays of categories/activities/locations; explicit for special categories
    data_categories: Mapped[List[str]] = mapped_column(ARRAY(String(64)), nullable=False)
    processing_activities: Mapped[List[str]] = mapped_column(ARRAY(String(128)), nullable=False)
    storage_locations: Mapped[List[str]] = mapped_column(ARRAY(String(2)), default=list)
    explicit: Mapped[bool] = mapped_column(nullable=False, default=False)

    record: Mapped[ConsentRecord] = relationship(back_populates="scope")

    __table_args__ = (
        Index("ix_consent_scopes__data_categories", "data_categories", postgresql_using="gin"),
        Index("ix_consent_scopes__processing", "processing_activities", postgresql_using="gin"),
        CheckConstraint("array_length(data_categories, 1) >= 1", name="data_categories_not_empty"),
        CheckConstraint("array_length(processing_activities, 1) >= 1", name="processing_not_empty"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "data_categories": list(self.data_categories or []),
            "processing_activities": list(self.processing_activities or []),
            "storage_locations": list(self.storage_locations or []),
            "explicit": bool(self.explicit),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ConsentScope":
        return cls(
            data_categories=list(d.get("data_categories") or []),
            processing_activities=list(d.get("processing_activities") or []),
            storage_locations=list(d.get("storage_locations") or []),
            explicit=bool(d.get("explicit", False)),
        )


# ------------------------------- Evidence --------------------------------------

class ConsentEvidence(Base, TimestampMixin):
    __tablename__ = "consent_evidence"

    record_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("consent_records.id", ondelete="CASCADE"),
        primary_key=True,
    )

    recorded_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    source: Mapped[Optional[str]] = mapped_column(EvidenceSource)
    operator: Mapped[Optional[str]] = mapped_column(String(128))
    ip: Mapped[Optional[str]] = mapped_column(INET)
    user_agent: Mapped[Optional[str]] = mapped_column(String(1024))
    ui_version: Mapped[Optional[str]] = mapped_column(String(64))  # semver string
    ui_screenshot_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    disclosure_ref: Mapped[Optional[str]] = mapped_column(String)  # URI
    record_hash_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    jws: Mapped[Optional[str]] = mapped_column(String)

    record: Mapped[ConsentRecord] = relationship(back_populates="evidence")

    __table_args__ = (
        CheckConstraint(
            "ui_screenshot_sha256 IS NULL OR ui_screenshot_sha256 ~ '^[a-f0-9]{64}$'",
            name="ui_screenshot_sha256_hex",
        ),
        CheckConstraint(
            "record_hash_sha256 IS NULL OR record_hash_sha256 ~ '^[a-f0-9]{64}$'",
            name="record_hash_sha256_hex",
        ),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recorded_at": self.recorded_at.isoformat() if self.recorded_at else None,
            "source": self.source,
            "operator": self.operator,
            "ip": str(self.ip) if self.ip else None,
            "user_agent": self.user_agent,
            "ui_version": self.ui_version,
            "ui_screenshot_sha256": self.ui_screenshot_sha256,
            "disclosure_ref": self.disclosure_ref,
            "record_hash_sha256": self.record_hash_sha256,
            "jws": self.jws,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ConsentEvidence":
        ip_val = d.get("ip")
        if ip_val:
            # basic validation; DB will store as INET
            ipaddress.ip_address(ip_val)
        return cls(
            recorded_at=_parse_dt(d.get("recorded_at")),
            source=d.get("source"),
            operator=d.get("operator"),
            ip=ip_val,
            user_agent=d.get("user_agent"),
            ui_version=d.get("ui_version"),
            ui_screenshot_sha256=d.get("ui_screenshot_sha256"),
            disclosure_ref=d.get("disclosure_ref"),
            record_hash_sha256=d.get("record_hash_sha256"),
            jws=d.get("jws"),
        )


# ------------------------------- Parties ---------------------------------------

class ConsentParty(Base, TimestampMixin):
    __tablename__ = "consent_parties"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    record_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("consent_records.id", ondelete="CASCADE"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(PartyRole, nullable=False, index=True)
    external_id: Mapped[Optional[str]] = mapped_column("external_id", String(128))
    country: Mapped[Optional[str]] = mapped_column(String(2))
    contact_email: Mapped[Optional[str]] = mapped_column(String(320))
    contact_url: Mapped[Optional[str]] = mapped_column(String)
    dpo_email: Mapped[Optional[str]] = mapped_column(String(320))
    dpo_url: Mapped[Optional[str]] = mapped_column(String)
    address: Mapped[Optional[str]] = mapped_column(String(1024))
    labels: Mapped[Dict[str, str]] = mapped_column(JSONB, default=dict)

    record: Mapped[ConsentRecord] = relationship(back_populates="parties")

    __table_args__ = (
        UniqueConstraint("record_id", "role", "name", name="uq_parties_record_role_name"),
        CheckConstraint("country IS NULL OR length(country)=2", name="party_country_len"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "id": self.external_id,
            "country": self.country,
            "contact_email": self.contact_email,
            "contact_url": self.contact_url,
            "dpo_email": self.dpo_email,
            "dpo_url": self.dpo_url,
            "address": self.address,
            "labels": self.labels or {},
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ConsentParty":
        return cls(
            name=d["name"],
            role=d.get("role") or "processor",
            external_id=d.get("id"),
            country=d.get("country"),
            contact_email=d.get("contact_email"),
            contact_url=d.get("contact_url"),
            dpo_email=d.get("dpo_email"),
            dpo_url=d.get("dpo_url"),
            address=d.get("address"),
            labels=dict(d.get("labels") or {}),
        )


# ------------------------------- Purposes --------------------------------------

class ConsentPurpose(Base, TimestampMixin):
    __tablename__ = "consent_purposes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    record_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("consent_records.id", ondelete="CASCADE"), nullable=False, index=True
    )

    purpose_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(2048))
    required: Mapped[bool] = mapped_column(nullable=False, default=False)
    granted: Mapped[bool] = mapped_column(nullable=False, default=False)
    granularity: Mapped[Optional[str]] = mapped_column(PurposeGranularity)
    effective_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    withdrawn_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    legal_references: Mapped[List[str]] = mapped_column(ARRAY(String), default=list)
    labels: Mapped[Dict[str, str]] = mapped_column(JSONB, default=dict)

    record: Mapped[ConsentRecord] = relationship(back_populates="purposes")

    __table_args__ = (
        UniqueConstraint("record_id", "purpose_id", name="uq_purposes_record_pid"),
        Index("ix_consent_purposes__purpose_id", "purpose_id"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.purpose_id,
            "name": self.name,
            "description": self.description,
            "required": bool(self.required),
            "granted": bool(self.granted),
            "granularity": self.granularity,
            "effective_at": self.effective_at.isoformat() if self.effective_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "withdrawn_at": self.withdrawn_at.isoformat() if self.withdrawn_at else None,
            "legal_references": list(self.legal_references or []),
            "labels": self.labels or {},
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ConsentPurpose":
        return cls(
            purpose_id=d["id"],
            name=d["name"],
            description=d.get("description"),
            required=bool(d.get("required", False)),
            granted=bool(d.get("granted", False)),
            granularity=d.get("granularity"),
            effective_at=_parse_dt(d.get("effective_at")),
            expires_at=_parse_dt(d.get("expires_at")),
            withdrawn_at=_parse_dt(d.get("withdrawn_at")),
            legal_references=list(d.get("legal_references") or []),
            labels=dict(d.get("labels") or {}),
        )


# ------------------------------- History ---------------------------------------

class ConsentHistory(Base):
    __tablename__ = "consent_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    record_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("consent_records.id", ondelete="CASCADE"), nullable=False, index=True
    )

    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    actor: Mapped[Optional[str]] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(HistoryAction, nullable=False)
    changes: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)

    record: Mapped[ConsentRecord] = relationship(back_populates="history")

    __table_args__ = (Index("ix_consent_history__record_at", "record_id", "at"),)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "at": self.at.isoformat(),
            "actor": self.actor,
            "action": self.action,
            "changes": self.changes or {},
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ConsentHistory":
        return cls(
            at=_parse_dt(d.get("at")) or dt.datetime.now(dt.timezone.utc),
            actor=d.get("actor"),
            action=d.get("action") or "update",
            changes=dict(d.get("changes") or {}),
        )


# ------------------------------- Utilities -------------------------------------

_DT_RX = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

def _parse_dt(s: Optional[str]) -> Optional[dt.datetime]:
    if not s:
        return None
    if not _DT_RX.match(s):
        # Let fromisoformat parse relaxed offsets; attach UTC if naive
        try:
            d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            raise ValueError(f"Invalid datetime: {s}")
    else:
        d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d


__all__ = [
    "Base",
    "ConsentRecord",
    "ConsentScope",
    "ConsentEvidence",
    "ConsentParty",
    "ConsentPurpose",
    "ConsentHistory",
    # Enums
    "ConsentStatus",
    "LegalBasis",
    "Mechanism",
    "PartyRole",
    "PurposeGranularity",
    "HistoryAction",
    "EvidenceSource",
]
