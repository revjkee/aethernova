# SPDX-License-Identifier: Apache-2.0
"""
physical_integration/registry/models.py

Промышленные доменные модели для реестра устройств, прошивок и OTA-планов.
SQLAlchemy 2.0 style, PostgreSQL JSONB/UUID/ARRAY/ENUM, строгие ограничения,
оптимистическая блокировка, индексы под реальные запросы.

Зависимости: sqlalchemy>=2.0, psycopg[pBinary], python-dateutil (опц.)
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    UniqueConstraint,
    text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# -------------------------------
# Базовая декларация и метаданные
# -------------------------------

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata_obj = MetaData(naming_convention=NAMING_CONVENTION)


class Base(DeclarativeBase):
    metadata = metadata_obj


# --------------
# Доменные ENUMы
# --------------

class ChannelEnum(str, enum.Enum):
    stable = "stable"
    beta = "beta"
    rc = "rc"
    dev = "dev"


class HashAlgorithmEnum(str, enum.Enum):
    sha256 = "sha256"
    sha512 = "sha512"
    blake3 = "blake3"


class SignatureAlgorithmEnum(str, enum.Enum):
    ed25519 = "ed25519"
    ecdsa_p256_sha256 = "ecdsa_p256_sha256"
    rsa_pss_2048_sha256 = "rsa_pss_2048_sha256"


class CompressionEnum(str, enum.Enum):
    none = "none"
    gzip = "gzip"
    zstd = "zstd"


class FormatEnum(str, enum.Enum):
    raw = "raw"
    tar = "tar"
    zip = "zip"
    dfu = "dfu"
    mcu_boot = "mcu_boot"
    uefi_capsule = "uefi_capsule"


class EncryptionEnum(str, enum.Enum):
    none = "none"
    aes_256_gcm = "aes-256-gcm"
    age = "age"


class UpdatePhaseEnum(str, enum.Enum):
    idle = "IDLE"
    preparing = "PREPARING"
    downloading = "DOWNLOADING"
    verifying = "VERIFYING"
    installing = "INSTALLING"
    rebooting = "REBOOTING"
    success = "SUCCESS"
    failed = "FAILED"
    canceled = "CANCELED"
    rolled_back = "ROLLED_BACK"


class FailureReasonEnum(str, enum.Enum):
    unspecified = "FAIL_UNSPECIFIED"
    download_error = "DOWNLOAD_ERROR"
    hash_mismatch = "HASH_MISMATCH"
    signature_invalid = "SIGNATURE_INVALID"
    insufficient_storage = "INSUFFICIENT_STORAGE"
    power_condition = "POWER_CONDITION"
    network_unavailable = "NETWORK_UNAVAILABLE"
    incompatible_hardware = "INCOMPATIBLE_HARDWARE"
    install_script_error = "INSTALL_SCRIPT_ERROR"
    runtime_timeout = "RUNTIME_TIMEOUT"
    user_aborted = "USER_ABORTED"
    rollback_failed = "ROLLBACK_FAILED"


# ----------------
# Базовые миксины
# ----------------

class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        index=True,
    )


class VersioningMixin:
    # Оптимистическая блокировка (ETag-подобная)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __mapper_args__ = {
        "version_id_col": "version",
        "version_id_generator": True,
    }


# -------------
# Модель Device
# -------------

class Device(Base, TimestampMixin, VersioningMixin):
    """
    Единица (устройство) реестра.
    """
    __tablename__ = "device"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Метаданные/имя
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    labels: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    annotations: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    # Идентичность
    vendor: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(64), nullable=False)
    hw_revision: Mapped[str] = mapped_column(String(32), nullable=False)
    serial_number: Mapped[str] = mapped_column(String(64), nullable=False)
    region: Mapped[str | None] = mapped_column(String(16), nullable=True)
    channel: Mapped[ChannelEnum] = mapped_column(Enum(ChannelEnum, name="channel_enum"), nullable=False, server_default=ChannelEnum.stable.value)

    # Размещение
    site: Mapped[str | None] = mapped_column(String(128))
    building: Mapped[str | None] = mapped_column(String(64))
    floor: Mapped[str | None] = mapped_column(String(32))
    room: Mapped[str | None] = mapped_column(String(64))
    geo_lat: Mapped[float | None] = mapped_column()
    geo_lon: Mapped[float | None] = mapped_column()

    # Текущее состояние (сводка)
    current_fw_version: Mapped[str | None] = mapped_column(String(64))
    bootloader_version: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        UniqueConstraint("vendor", "product", "hw_revision", "serial_number", name="uq_device_identity"),
        Index("ix_device_site", "site"),
        Index("ix_device_vendor_product", "vendor", "product"),
        Index("ix_device_labels_gin", labels, postgresql_using="gin"),
        CheckConstraint("(geo_lat IS NULL) OR (geo_lat BETWEEN -90 AND 90)", name="geo_lat_range"),
        CheckConstraint("(geo_lon IS NULL) OR (geo_lon BETWEEN -180 AND 180)", name="geo_lon_range"),
    )

    # Связи
    states: Mapped[list["DeviceState"]] = relationship(back_populates="device", cascade="all, delete-orphan")
    events: Mapped[list["UpdateStatusEvent"]] = relationship(back_populates="device", cascade="all, delete-orphan")


# --------------------
# Модель FirmwareImage
# --------------------

class FirmwareImage(Base, TimestampMixin, VersioningMixin):
    """
    Описание артефакта прошивки (binary/TAR/OCI и т. д.).
    """
    __tablename__ = "firmware_image"

    firmware_uid: Mapped[str] = mapped_column(String(128), primary_key=True)  # стабильный ID сборки

    # Идентичность таргета
    vendor: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(64), nullable=False)
    hw_revision: Mapped[str] = mapped_column(String(32), nullable=False)
    region: Mapped[str | None] = mapped_column(String(16))
    channel: Mapped[ChannelEnum] = mapped_column(Enum(ChannelEnum, name="channel_enum"), nullable=False, server_default=ChannelEnum.stable.value)

    # Версия/размер
    version: Mapped[str] = mapped_column(String(64), nullable=False)  # SemVer
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Хеш/подпись
    hash_algorithm: Mapped[HashAlgorithmEnum] = mapped_column(Enum(HashAlgorithmEnum, name="hash_algo_enum"), nullable=False)
    hash_hex: Mapped[str] = mapped_column(String(128), nullable=False)
    sig_algorithm: Mapped[SignatureAlgorithmEnum | None] = mapped_column(Enum(SignatureAlgorithmEnum, name="sig_algo_enum"))
    sig_b64: Mapped[str | None] = mapped_column(String(8192))
    sig_key_id: Mapped[str | None] = mapped_column(String(256))
    sig_issuer: Mapped[str | None] = mapped_column(String(256))

    # Хранение/формат/шифрование
    compression: Mapped[CompressionEnum] = mapped_column(Enum(CompressionEnum, name="compression_enum"), nullable=False, server_default=CompressionEnum.none.value)
    format: Mapped[FormatEnum] = mapped_column(Enum(FormatEnum, name="format_enum"), nullable=False, server_default=FormatEnum.raw.value)
    encryption: Mapped[EncryptionEnum] = mapped_column(Enum(EncryptionEnum, name="encryption_enum"), nullable=False, server_default=EncryptionEnum.none.value)
    encryption_key_id: Mapped[str | None] = mapped_column(String(256))

    # Локация артефакта
    uri: Mapped[str | None] = mapped_column(String(2048))  # https://...
    oci_reference: Mapped[str | None] = mapped_column(String(2048))  # oci://repo:tag@sha256:...

    # Прочее
    mirrors: Mapped[list[str]] = mapped_column(ARRAY(String(2048)), nullable=False, server_default=text("ARRAY[]::varchar[]"))
    annotations: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        # Уникальность варианта по идентичности и версии
        UniqueConstraint("vendor", "product", "hw_revision", "region", "channel", "version", name="uq_firmware_identity_version"),
        # Проверки: SemVer, длина SHA, XOR между uri/oci_reference, и зависимость encryption_key_id
        CheckConstraint(
            "version ~ '^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?$'",
            name="version_semver"),
        CheckConstraint(
            "(hash_algorithm <> 'sha256') OR (char_length(hash_hex) = 64)",
            name="hash_len_sha256"),
        CheckConstraint(
            "(hash_algorithm <> 'sha512') OR (char_length(hash_hex) = 128)",
            name="hash_len_sha512"),
        CheckConstraint(
            "((uri IS NOT NULL)::int + (oci_reference IS NOT NULL)::int) = 1",
            name="location_xor"),
        CheckConstraint(
            "(encryption = 'none') OR (encryption_key_id IS NOT NULL)",
            name="encryption_requires_key"),
        Index("ix_firmware_vendor_product", "vendor", "product"),
    )

    # Связи
    plans: Mapped[list["UpdatePlan"]] = relationship(back_populates="image")


# ----------------
# Модель UpdatePlan
# ----------------

class UpdatePlan(Base, TimestampMixin, VersioningMixin):
    """
    План раскатки OTA для набора устройств.
    """
    __tablename__ = "update_plan"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)  # планово-доменный ID
    firmware_uid: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("firmware_image.firmware_uid", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # Селектор устройств
    selector_labels: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    selector_device_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), nullable=False, server_default=text("'{}'::uuid[]"))

    # Стратегия раскатки
    batch_size: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("50"))
    max_parallel: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("100"))
    percent: Mapped[int | None] = mapped_column(Integer)  # 1..100
    drain_on_failure: Mapped[bool] = mapped_column(nullable=False, server_default=text("true"))
    pause_seconds_between_batches: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    canary_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("5"))
    canary_duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("600"))

    # Политики ретраев/ограничений/окон обслуживания
    retry_max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("5"))
    retry_initial_backoff: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'PT1S'"))
    retry_max_backoff: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'PT30S'"))
    retry_multiplier: Mapped[float] = mapped_column(nullable=False, server_default=text("2.0"))

    min_battery_percent: Mapped[float | None] = mapped_column()
    require_mains_power: Mapped[bool] = mapped_column(nullable=False, server_default=text("false"))
    require_network_unmetered: Mapped[bool] = mapped_column(nullable=False, server_default=text("false"))
    min_free_storage_bytes: Mapped[int | None] = mapped_column(BigInteger)
    min_signal_strength: Mapped[int | None] = mapped_column()

    mw_timezone: Mapped[str | None] = mapped_column(String(64))
    mw_cron: Mapped[str | None] = mapped_column(String(64))

    created_by: Mapped[str] = mapped_column(String(128), nullable=False)

    __table_args__ = (
        CheckConstraint("(percent IS NULL) OR (percent BETWEEN 1 AND 100)", name="percent_range"),
        CheckConstraint("(min_battery_percent IS NULL) OR (min_battery_percent BETWEEN 0 AND 100)", name="battery_range"),
        CheckConstraint("(min_signal_strength IS NULL) OR (min_signal_strength BETWEEN -150 AND 150)", name="signal_range"),
        CheckConstraint("retry_multiplier >= 1.0 AND retry_multiplier <= 10.0", name="retry_multiplier_range"),
        Index("ix_updateplan_labels_gin", selector_labels, postgresql_using="gin"),
    )

    # Связи
    image: Mapped[FirmwareImage] = relationship(back_populates="plans", lazy="joined")
    events: Mapped[list["UpdateStatusEvent"]] = relationship(back_populates="plan", cascade="all, delete-orphan")


# -------------------
# Текущее состояние Unit
# -------------------

class DeviceState(Base, TimestampMixin, VersioningMixin):
    """
    Последнее заявленное состояние устройства (не история).
    """
    __tablename__ = "device_state"

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("device.id", ondelete="CASCADE"),
        primary_key=True,
    )

    # Ключевые поля состояния
    identity: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    current_fw_version: Mapped[str] = mapped_column(String(64), nullable=False)
    bootloader_version: Mapped[str | None] = mapped_column(String(64))
    storage_total_bytes: Mapped[int | None] = mapped_column(BigInteger)
    storage_free_bytes: Mapped[int | None] = mapped_column(BigInteger)
    battery_percent: Mapped[int | None] = mapped_column()
    on_mains_power: Mapped[bool | None] = mapped_column()
    ip_address: Mapped[str | None] = mapped_column(String(64))
    labels: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    annotations: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    reported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    device: Mapped[Device] = relationship(back_populates="states")

    __table_args__ = (
        CheckConstraint("(battery_percent IS NULL) OR (battery_percent BETWEEN 0 AND 100)", name="battery_percent_range"),
    )


# ---------------------
# События статусов OTA
# ---------------------

class UpdateStatusEvent(Base):
    """
    Потоковые события жизненного цикла обновления на устройстве.
    Хранятся как фактологическая история (append-only).
    """
    __tablename__ = "update_status_event"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("device.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    plan_id: Mapped[str | None] = mapped_column(
        String(128),
        ForeignKey("update_plan.id", ondelete="SET NULL"),
        index=True,
    )
    firmware_uid: Mapped[str | None] = mapped_column(
        String(128),
        ForeignKey("firmware_image.firmware_uid", ondelete="SET NULL"),
        index=True,
    )

    phase: Mapped[UpdatePhaseEnum] = mapped_column(Enum(UpdatePhaseEnum, name="update_phase_enum"), nullable=False, index=True)
    progress_percent: Mapped[int | None] = mapped_column()
    failure: Mapped[FailureReasonEnum | None] = mapped_column(Enum(FailureReasonEnum, name="failure_reason_enum"))
    error_message: Mapped[str | None] = mapped_column(String(2048))
    observed_hash_hex: Mapped[str | None] = mapped_column(String(128))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True, server_default=func.now())

    # Привязка к трассам/заявкам
    trace_id: Mapped[str | None] = mapped_column(String(64), index=True)
    span_id: Mapped[str | None] = mapped_column(String(32))
    actor: Mapped[str | None] = mapped_column(String(128))  # кто инициировал (пользователь/клиент)

    device: Mapped[Device] = relationship(back_populates="events")
    plan: Mapped[UpdatePlan | None] = relationship(back_populates="events")
    image: Mapped[FirmwareImage | None] = relationship()

    __table_args__ = (
        CheckConstraint("(progress_percent IS NULL) OR (progress_percent BETWEEN 0 AND 100)", name="progress_range"),
    )


# ---------------------------------------
# Утилитарная таблица для идемпотентности
# ---------------------------------------

class IdempotencyKey(Base):
    """
    Хранилище идемпотентных операций верхнего уровня (POST/PUT/PATCH).
    Дает защиту от дублей при повторной доставке запросов.
    """
    __tablename__ = "idempotency_key"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    # Привязка к домену (например, "devices:create"), чтобы избежать коллизий
    scope: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Краткая сигнатура запроса/ответа (для быстрого сравнения)
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    response_headers: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    response_body: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    __table_args__ = (
        Index("ix_idempotency_expire", "expires_at"),
    )
