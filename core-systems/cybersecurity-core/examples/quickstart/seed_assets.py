# filepath: cybersecurity-core/examples/quickstart/seed_assets.py
"""
Industrial-grade async seeder for cybersecurity-core.

Features:
- Async SQLAlchemy 2.0 (no sync sessions)
- Idempotent upsert for Assets/Services/Vulnerabilities
- Input: YAML or JSON (validated with Pydantic)
- Dry-run mode, JSON logging, environment/CLI config
- Works with SQLite (aiosqlite) and PostgreSQL (asyncpg)
- Self-contained: creates tables if missing

Usage:
  python seed_assets.py --db-url "sqlite+aiosqlite:///./cybersec.db" --seed ./seed.yaml
  DATABASE_URL="postgresql+asyncpg://user:pass@localhost/db" python seed_assets.py

Exit codes:
  0 - success, >0 - error
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import uuid
import ipaddress
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Optional

# Optional YAML support
try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

from pydantic import BaseModel, Field, ValidationError, field_validator

from sqlalchemy import (
    String,
    Integer,
    Float,
    Text,
    Enum as SAEnum,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    select,
    func,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import (
    declarative_base,
    Mapped,
    mapped_column,
    relationship,
)

# -----------------------------
# Logging (JSON)
# -----------------------------


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)
        if hasattr(record, "extra"):
            try:
                base.update(record.extra)  # type: ignore
            except Exception:
                pass
        return json.dumps(base, ensure_ascii=False)


def setup_logger(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("seed_assets")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False
    return logger


log = setup_logger()


# -----------------------------
# DB models (SQLAlchemy 2.0)
# -----------------------------

Base = declarative_base()


def _uuid() -> str:
    return str(uuid.uuid4())


class Criticality(str):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class Severity(str):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("external_id", name="uq_asset_external_id"),
        UniqueConstraint("hostname", name="uq_asset_hostname"),
        UniqueConstraint("ip_address", name="uq_asset_ip"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    external_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # v4/v6
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    environment: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # prod, stage, dev
    criticality: Mapped[str] = mapped_column(
        SAEnum(
            Criticality.CRITICAL,
            Criticality.HIGH,
            Criticality.MEDIUM,
            Criticality.LOW,
            Criticality.NONE,
            name="asset_criticality",
        ),
        default=Criticality.MEDIUM,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    services: Mapped[list[Service]] = relationship("Service", back_populates="asset", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list[Vulnerability]] = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")
    tags: Mapped[list[AssetTag]] = relationship("AssetTag", back_populates="asset", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_service_asset_port_proto"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # e.g., http, ssh
    version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)  # tcp/udp
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    asset: Mapped[Asset] = relationship("Asset", back_populates="services")
    vulnerabilities: Mapped[list[Vulnerability]] = relationship("Vulnerability", back_populates="service", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("asset_id", "service_id", "cve_id", name="uq_vuln_asset_service_cve"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    service_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("services.id", ondelete="CASCADE"), nullable=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # e.g., CVE-2023-12345
    severity: Mapped[str] = mapped_column(
        SAEnum(
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.NONE,
            name="vuln_severity",
        ),
        default=Severity.MEDIUM,
        nullable=False,
    )
    cvss: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    asset: Mapped[Asset] = relationship("Asset", back_populates="vulnerabilities")
    service: Mapped[Optional[Service]] = relationship("Service", back_populates="vulnerabilities")


class AssetTag(Base):
    __tablename__ = "asset_tags"
    __table_args__ = (UniqueConstraint("asset_id", "key", name="uq_asset_tag_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    asset: Mapped[Asset] = relationship("Asset", back_populates="tags")


# -----------------------------
# Input schema (Pydantic)
# -----------------------------

class InService(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None
    port: int
    protocol: Literal["tcp", "udp"]

    @field_validator("port")
    @classmethod
    def _port_range(cls, v: int) -> int:
        if not (0 < v < 65536):
            raise ValueError("port must be 1..65535")
        return v


class InVulnerability(BaseModel):
    cve_id: Optional[str] = None
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] = "MEDIUM"
    cvss: Optional[float] = Field(default=None, ge=0, le=10)
    description: Optional[str] = None
    detected_at: Optional[datetime] = None


class InAsset(BaseModel):
    name: str
    external_id: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    owner: Optional[str] = None
    environment: Optional[str] = Field(default="prod")
    criticality: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] = "MEDIUM"
    tags: dict[str, str] = Field(default_factory=dict)
    services: list[InService] = Field(default_factory=list)
    vulnerabilities: list[InVulnerability] = Field(default_factory=list)

    @field_validator("ip_address")
    @classmethod
    def _ip_valid(cls, v: Optional[str]) -> Optional[str]:
        if v:
            try:
                ipaddress.ip_address(v)
            except Exception as e:
                raise ValueError(f"invalid ip_address: {v}") from e
        return v


class InSeed(BaseModel):
    assets: list[InAsset]


# -----------------------------
# Default seed (if no file)
# -----------------------------

DEFAULT_SEED: dict[str, Any] = {
    "assets": [
        {
            "name": "gateway-prod-01",
            "external_id": "gw-001",
            "hostname": "gw01.prod.local",
            "ip_address": "10.0.0.10",
            "owner": "platform-ops",
            "environment": "prod",
            "criticality": "CRITICAL",
            "tags": {"zone": "dmz", "tier": "edge"},
            "services": [
                {"name": "http", "version": "nginx/1.25.4", "port": 80, "protocol": "tcp"},
                {"name": "https", "version": "nginx/1.25.4", "port": 443, "protocol": "tcp"},
            ],
            "vulnerabilities": [
                {"cve_id": "CVE-2023-44487", "severity": "HIGH", "cvss": 7.5, "description": "HTTP/2 Rapid Reset"},
            ],
        },
        {
            "name": "db-core-01",
            "external_id": "db-001",
            "hostname": "pg01.core.local",
            "ip_address": "10.0.20.11",
            "owner": "data-platform",
            "environment": "prod",
            "criticality": "HIGH",
            "tags": {"engine": "postgres", "ha": "true"},
            "services": [
                {"name": "postgres", "version": "16.2", "port": 5432, "protocol": "tcp"},
            ],
            "vulnerabilities": [],
        },
    ]
}


# -----------------------------
# Engine / Session
# -----------------------------

@dataclass
class DBConfig:
    url: str
    echo: bool = False
    pool_size: int = 5
    max_overflow: int = 10


def create_engine_and_session(cfg: DBConfig):
    engine = create_async_engine(
        cfg.url,
        echo=cfg.echo,
        pool_size=None if cfg.url.startswith("sqlite") else cfg.pool_size,
        max_overflow=None if cfg.url.startswith("sqlite") else cfg.max_overflow,
        future=True,
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    return engine, session_factory


# -----------------------------
# Upsert helpers
# -----------------------------

async def upsert_asset(session: AsyncSession, inp: InAsset, dry_run: bool) -> Asset:
    # Identify existing by external_id or hostname or ip
    stmt = select(Asset).where(
        (Asset.external_id == inp.external_id) if inp.external_id else (Asset.hostname == inp.hostname)
        if inp.hostname else (Asset.ip_address == inp.ip_address)
    )
    existing = (await session.execute(stmt)).scalars().first()

    if existing:
        # update
        existing.name = inp.name
        existing.owner = inp.owner
        existing.environment = inp.environment
        existing.criticality = inp.criticality
        existing.hostname = inp.hostname
        existing.ip_address = inp.ip_address
        existing.updated_at = datetime.now(timezone.utc)
        log.info("asset.update", extra={"extra": {"asset_id": existing.id, "name": inp.name}})
        return existing

    if dry_run:
        fake = Asset(id=_uuid(), name=inp.name)  # not added
        log.info("asset.create.dry_run", extra={"extra": {"name": inp.name}})
        return fake

    asset = Asset(
        name=inp.name,
        external_id=inp.external_id,
        hostname=inp.hostname,
        ip_address=inp.ip_address,
        owner=inp.owner,
        environment=inp.environment,
        criticality=inp.criticality,
    )
    session.add(asset)
    log.info("asset.create", extra={"extra": {"name": inp.name}})
    return asset


async def upsert_tag(session: AsyncSession, asset: Asset, key: str, value: str, dry_run: bool) -> AssetTag | None:
    if not key:
        return None
    stmt = select(AssetTag).where(AssetTag.asset_id == asset.id, AssetTag.key == key)
    existing = (await session.execute(stmt)).scalars().first()
    if existing:
        if existing.value != value:
            existing.value = value
            log.info("tag.update", extra={"extra": {"asset_id": asset.id, "key": key, "value": value}})
        return existing
    if dry_run:
        log.info("tag.create.dry_run", extra={"extra": {"asset_id": asset.id, "key": key, "value": value}})
        return None
    tag = AssetTag(asset_id=asset.id, key=key, value=value)
    session.add(tag)
    log.info("tag.create", extra={"extra": {"asset_id": asset.id, "key": key, "value": value}})
    return tag


async def upsert_service(session: AsyncSession, asset: Asset, svc: InService, dry_run: bool) -> Service | None:
    stmt = select(Service).where(
        Service.asset_id == asset.id, Service.port == svc.port, Service.protocol == svc.protocol
    )
    existing = (await session.execute(stmt)).scalars().first()
    if existing:
        existing.name = svc.name
        existing.version = svc.version
        existing.updated_at = datetime.now(timezone.utc)
        log.info("service.update", extra={"extra": {"asset_id": asset.id, "port": svc.port, "protocol": svc.protocol}})
        return existing
    if dry_run:
        log.info("service.create.dry_run", extra={"extra": {"asset_id": asset.id, "port": svc.port, "protocol": svc.protocol}})
        return None
    srv = Service(
        asset_id=asset.id,
        name=svc.name,
        version=svc.version,
        port=svc.port,
        protocol=svc.protocol,
    )
    session.add(srv)
    log.info("service.create", extra={"extra": {"asset_id": asset.id, "port": svc.port, "protocol": svc.protocol}})
    return srv


async def upsert_vulnerability(
    session: AsyncSession, asset: Asset, srv: Optional[Service], vul: InVulnerability, dry_run: bool
) -> Vulnerability | None:
    stmt = select(Vulnerability).where(
        Vulnerability.asset_id == asset.id,
        Vulnerability.service_id == (srv.id if srv else None),
        Vulnerability.cve_id == vul.cve_id,
    )
    existing = (await session.execute(stmt)).scalars().first()
    if existing:
        existing.severity = vul.severity
        existing.cvss = vul.cvss
        existing.description = vul.description
        existing.detected_at = vul.detected_at or existing.detected_at
        log.info(
            "vuln.update",
            extra={"extra": {"asset_id": asset.id, "service_id": srv.id if srv else None, "cve": vul.cve_id}},
        )
        return existing
    if dry_run:
        log.info(
            "vuln.create.dry_run",
            extra={"extra": {"asset_id": asset.id, "service_id": srv.id if srv else None, "cve": vul.cve_id}},
        )
        return None
    vuln = Vulnerability(
        asset_id=asset.id,
        service_id=srv.id if srv else None,
        cve_id=vul.cve_id,
        severity=vul.severity,
        cvss=vul.cvss,
        description=vul.description,
        detected_at=vul.detected_at or datetime.now(timezone.utc),
    )
    session.add(vuln)
    log.info(
        "vuln.create",
        extra={"extra": {"asset_id": asset.id, "service_id": srv.id if srv else None, "cve": vul.cve_id}},
    )
    return vuln


# -----------------------------
# Seeding flow
# -----------------------------

@dataclass
class SeedStats:
    assets_created: int = 0
    assets_updated: int = 0
    services_created: int = 0
    services_updated: int = 0
    vulns_created: int = 0
    vulns_updated: int = 0
    tags_created: int = 0
    tags_updated: int = 0


async def ensure_schema(engine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    log.info("db.schema.ensure", extra={"extra": {"status": "ok"}})


async def seed_once(session: AsyncSession, data: InSeed, dry_run: bool) -> SeedStats:
    stats = SeedStats()
    for asset_in in data.assets:
        async with session.begin():
            # Asset
            existing_stmt = select(Asset).where(
                (Asset.external_id == asset_in.external_id) if asset_in.external_id else (Asset.hostname == asset_in.hostname)
                if asset_in.hostname else (Asset.ip_address == asset_in.ip_address)
            )
            existing = (await session.execute(existing_stmt)).scalars().first()
            if existing:
                await session.flush()
                before = (existing.name, existing.owner, existing.environment, existing.criticality, existing.hostname, existing.ip_address)
                asset = await upsert_asset(session, asset_in, dry_run)
                after = (asset.name, asset.owner, asset.environment, asset.criticality, asset.hostname, asset.ip_address)
                if before != after:
                    stats.assets_updated += 1
            else:
                asset = await upsert_asset(session, asset_in, dry_run)
                if not dry_run:
                    await session.flush()
                stats.assets_created += 0 if existing else 1

            # Tags
            for k, v in asset_in.tags.items():
                stmt = select(AssetTag).where(AssetTag.asset_id == asset.id, AssetTag.key == k)
                tag_existing = (await session.execute(stmt)).scalars().first() if not dry_run else None
                _ = await upsert_tag(session, asset, k, v, dry_run)
                if tag_existing:
                    stats.tags_updated += 1
                else:
                    if not dry_run:
                        stats.tags_created += 1

            # Services
            created_ids: list[str] = []
            for svc_in in asset_in.services:
                ev_stmt = select(Service).where(Service.asset_id == asset.id, Service.port == svc_in.port, Service.protocol == svc_in.protocol)
                ev = (await session.execute(ev_stmt)).scalars().first() if not dry_run else None
                svc = await upsert_service(session, asset, svc_in, dry_run)
                if svc and not dry_run and svc.id not in created_ids:
                    if ev:
                        stats.services_updated += 1
                    else:
                        stats.services_created += 1
                        created_ids.append(svc.id)

            # Vulnerabilities (asset-level)
            for vul_in in asset_in.vulnerabilities:
                # Try attach to first service if present; else asset-level
                target_service: Optional[Service] = None
                if asset.services:
                    target_service = asset.services[0] if not dry_run else None

                ev_stmt = select(Vulnerability).where(
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.service_id == (target_service.id if target_service else None),
                    Vulnerability.cve_id == vul_in.cve_id,
                )
                ev = (await session.execute(ev_stmt)).scalars().first() if not dry_run else None

                _ = await upsert_vulnerability(session, asset, target_service, vul_in, dry_run)
                if ev:
                    stats.vulns_updated += 1
                else:
                    if not dry_run:
                        stats.vulns_created += 1

    if not dry_run:
        await session.commit()
    return stats


# -----------------------------
# IO helpers
# -----------------------------

def load_seed(path: Optional[str]) -> InSeed:
    if not path:
        return InSeed(**DEFAULT_SEED)
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    try:
        if path.lower().endswith((".yaml", ".yml")):
            if not _HAS_YAML:
                raise RuntimeError("PyYAML is not installed. Install pyyaml or provide JSON.")
            obj = yaml.safe_load(content)
        else:
            obj = json.loads(content)
        return InSeed(**obj)
    except ValidationError as ve:
        raise SystemExit(f"Seed validation error: {ve}") from ve


# -----------------------------
# CLI
# -----------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Seed cybersecurity-core assets/services/vulnerabilities.")
    p.add_argument("--db-url", type=str, default=os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./cybersec.db"), help="SQLAlchemy async URL")
    p.add_argument("--seed", type=str, default=os.getenv("SEED_FILE"), help="Path to YAML/JSON seed file")
    p.add_argument("--dry-run", action="store_true", help="Validate and log without DB writes")
    p.add_argument("--verbose", action="store_true", help="Verbose logging")
    return p.parse_args()


async def main_async() -> int:
    args = parse_args()
    global log
    log = setup_logger(verbose=args.verbose)

    # Validate URL
    if not isinstance(args.db_url, str) or "://" not in args.db_url:
        log.error("invalid.db_url", extra={"extra": {"db_url": args.db_url}})
        return 2

    # Load seed
    try:
        seed = load_seed(args.seed)
    except Exception as e:
        log.error("seed.load.error", extra={"extra": {"error": str(e)}})
        return 3

    cfg = DBConfig(url=args.db_url, echo=args.verbose)
    engine, session_factory = create_engine_and_session(cfg)

    try:
        await ensure_schema(engine)
        async with session_factory() as session:
            stats = await seed_once(session, seed, dry_run=args.dry_run)
            log.info(
                "seed.summary",
                extra={
                    "extra": {
                        "assets_created": stats.assets_created,
                        "assets_updated": stats.assets_updated,
                        "services_created": stats.services_created,
                        "services_updated": stats.services_updated,
                        "vulns_created": stats.vulns_created,
                        "vulns_updated": stats.vulns_updated,
                        "tags_created": stats.tags_created,
                        "tags_updated": stats.tags_updated,
                        "dry_run": args.dry_run,
                    }
                },
            )
    except Exception as e:
        log.error("seed.run.error", extra={"extra": {"error": str(e)}})
        return 4
    finally:
        await engine.dispose()

    return 0


def main() -> None:
    try:
        code = asyncio.run(main_async())
    except KeyboardInterrupt:
        code = 130
    sys.exit(code)


if __name__ == "__main__":
    main()
