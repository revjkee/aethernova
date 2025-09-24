# SPDX-License-Identifier: Apache-2.0
# physical-integration-core/tests/unit/test_device_registry.py

import os
import re
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

# Модельный слой из проекта
from physical_integration.registry.models import (
    Base,
    metadata_obj,
    Device,
    DeviceState,
    FirmwareImage,
    UpdatePlan,
    UpdateStatusEvent,
    ChannelEnum,
    HashAlgorithmEnum,
    EncryptionEnum,
    UpdatePhaseEnum,
    IdempotencyKey,
)

# --- Поддержка PostgreSQL через testcontainers либо переменную окружения ---

try:
    from testcontainers.postgres import PostgresContainer  # type: ignore
    _HAS_TESTCONTAINERS = True
except Exception:
    _HAS_TESTCONTAINERS = False


def _get_db_url():
    dsn = os.getenv("POSTGRES_DSN") or os.getenv("POSTGRES_URL")
    if dsn:
        return dsn, None
    if _HAS_TESTCONTAINERS:
        pg = PostgresContainer("postgres:16-alpine")
        pg.start()
        return pg.get_connection_url(), pg
    return None, None


@pytest.fixture(scope="session")
def db_engine():
    url, container = _get_db_url()
    if not url:
        pytest.skip("PostgreSQL недоступен: задайте POSTGRES_DSN или установите testcontainers+docker")
    engine = create_engine(url, pool_pre_ping=True, future=True)
    try:
        yield engine
    finally:
        engine.dispose()
        if container:
            container.stop()


@pytest.fixture(scope="function")
def db_session(db_engine):
    # Чистая схема под каждый тест
    metadata_obj.drop_all(db_engine, checkfirst=True)
    metadata_obj.create_all(db_engine)

    SessionLocal = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False, future=True)
    with SessionLocal() as session:
        yield session
        session.rollback()
        # очистка таблиц быстрая: FK CASCADE + truncate
        with db_engine.begin() as conn:
            for tbl in reversed(metadata_obj.sorted_tables):
                conn.execute(text(f'TRUNCATE TABLE "{tbl.schema + "." if tbl.schema else ""}{tbl.name}" CASCADE'))


# --- Утилиты/фабрики ---

def _sha256_hex():
    return "a" * 64

def _uuid():
    return uuid.uuid4()

def make_device(**over):
    base = dict(
        name="unit-1",
        vendor="acme",
        product="sensor",
        hw_revision="r1",
        serial_number="SN123",
        region="eu",
        channel=ChannelEnum.stable,
        labels={"site": "plant-a", "room": "210"},
        annotations={},
        site="A",
    )
    base.update(over)
    return Device(**base)

def make_firmware(**over):
    base = dict(
        firmware_uid="fw-uid-1",
        vendor="acme",
        product="sensor",
        hw_revision="r1",
        region="eu",
        channel=ChannelEnum.stable,
        version="1.2.3",
        size_bytes=1024,
        hash_algorithm=HashAlgorithmEnum.sha256,
        hash_hex=_sha256_hex(),
        uri="https://repo/firmware/acme/sensor/1.2.3.bin",
        compression=None,  # использовать server_default
        annotations={},
    )
    base.update(over)
    return FirmwareImage(**base)

def make_update_plan(fw: FirmwareImage, **over):
    base = dict(
        id="plan-1",
        firmware_uid=fw.firmware_uid,
        selector_labels={"site": "plant-a"},
        selector_device_ids=[],
        batch_size=10,
        max_parallel=20,
        percent=10,
        created_by="tester",
    )
    base.update(over)
    return UpdatePlan(**base)


# --- Тесты моделей ---

def test_device_unique_identity(db_session: Session):
    d1 = make_device()
    db_session.add(d1)
    db_session.commit()

    d2 = make_device(name="unit-2")  # те же vendor/product/hw_revision/serial_number
    db_session.add(d2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # изменение серийника снимает конфликт
    d2.serial_number = "SN999"
    db_session.add(d2)
    db_session.commit()


def test_device_labels_jsonb_filter_and_gin_index(db_session: Session):
    d1 = make_device(name="u1", labels={"site": "plant-a", "room": "210"})
    d2 = make_device(name="u2", serial_number="SN124", labels={"site": "plant-b"})
    db_session.add_all([d1, d2])
    db_session.commit()

    # фильтрация по JSONB containment
    found = db_session.query(Device).filter(Device.labels.contains({"site": "plant-a"})).all()
    assert {x.name for x in found} == {"u1"}

    # наличие GIN индекса по labels
    idx = db_session.execute(
        text("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'device'")
    ).all()
    gin_lines = [row.indexdef for row in idx if "USING gin" in row.indexdef.lower() and "labels" in row.indexdef]
    assert gin_lines, "GIN индекс по labels не найден"


def test_firmware_semver_hash_and_location_constraints(db_session: Session):
    # Невалидная SemVer
    bad = make_firmware(firmware_uid="fw-bad1", version="1.2")
    db_session.add(bad)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # Неверная длина SHA256
    bad2 = make_firmware(firmware_uid="fw-bad2", hash_hex="deadbeef")
    db_session.add(bad2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # XOR: нельзя одновременно uri и oci_reference
    bad3 = make_firmware(firmware_uid="fw-bad3", oci_reference="oci://repo/image:1.2.3@sha256:" + _sha256_hex())
    bad3.uri = "https://repo/firmware.bin"
    db_session.add(bad3)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # Шифрование требует ключ
    bad4 = make_firmware(firmware_uid="fw-bad4", encryption=EncryptionEnum.aes_256_gcm, encryption_key_id=None)
    db_session.add(bad4)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # Валидный артефакт
    ok = make_firmware()
    db_session.add(ok)
    db_session.commit()


def test_update_plan_constraints_and_relations(db_session: Session):
    fw = make_firmware()
    db_session.add(fw)
    db_session.commit()

    # Недопустимый процент > 100
    bad = make_update_plan(fw, id="plan-bad", percent=150)
    db_session.add(bad)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # Батарея > 100
    good = make_update_plan(fw, id="plan-ok", percent=25, min_battery_percent=80)
    db_session.add(good)
    db_session.commit()

    # Связь plan -> image
    plan = db_session.get(UpdatePlan, "plan-ok")
    assert plan is not None and plan.image is not None
    assert plan.image.firmware_uid == fw.firmware_uid


def test_device_state_checks_and_cascade_delete(db_session: Session):
    d = make_device(name="to-delete", serial_number="SN999")
    db_session.add(d)
    db_session.commit()

    # Неверный диапазон батареи
    bad_state = DeviceState(
        device_id=d.id,
        identity={"k": "v"},
        current_fw_version="1.0.0",
        reported_at=datetime.now(timezone.utc),
        battery_percent=150,
        labels={},
        annotations={},
    )
    db_session.add(bad_state)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # Валидное состояние + событие
    st = DeviceState(
        device_id=d.id,
        identity={"k": "v"},
        current_fw_version="1.0.0",
        reported_at=datetime.now(timezone.utc),
        labels={},
        annotations={},
    )
    ev = UpdateStatusEvent(
        device_id=d.id,
        phase=UpdatePhaseEnum.preparing,
        progress_percent=10,
    )
    db_session.add_all([st, ev])
    db_session.commit()

    # Проверка каскада при удалении устройства
    db_session.delete(d)
    db_session.commit()

    cnt_state = db_session.query(DeviceState).count()
    cnt_event = db_session.query(UpdateStatusEvent).count()
    assert cnt_state == 0 and cnt_event == 0


def test_update_status_event_progress_range(db_session: Session):
    d = make_device(name="u3", serial_number="SN777")
    db_session.add(d)
    db_session.commit()

    ev = UpdateStatusEvent(
        device_id=d.id,
        phase=UpdatePhaseEnum.downloading,
        progress_percent=101,
    )
    db_session.add(ev)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_idempotency_key_composite_pk(db_session: Session):
    k1 = IdempotencyKey(
        key="abc",
        scope="devices:create",
        request_fingerprint="f1",
        status_code=201,
        response_headers={},
        response_body={},
        expires_at=None,
    )
    db_session.add(k1)
    db_session.commit()

    # Тот же key+scope запрещён
    k_dup = IdempotencyKey(
        key="abc",
        scope="devices:create",
        request_fingerprint="f2",
        status_code=200,
        response_headers={},
        response_body={},
        expires_at=None,
    )
    db_session.add(k_dup)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # Тот же key, но другой scope — допустимо
    k_other = IdempotencyKey(
        key="abc",
        scope="devices:update",
        request_fingerprint="f3",
        status_code=200,
        response_headers={},
        response_body={},
        expires_at=None,
    )
    db_session.add(k_other)
    db_session.commit()


def test_indices_presence_on_core_tables(db_session: Session):
    # device: индекс по vendor,product присутствует
    rows = db_session.execute(text("SELECT indexdef FROM pg_indexes WHERE tablename='device'")).scalars().all()
    assert any("vendor" in r and "product" in r for r in rows)

    # firmware_image: уникальность по identity+version
    rows_fw = db_session.execute(text("SELECT indexdef FROM pg_indexes WHERE tablename='firmware_image'")).scalars().all()
    assert any(re.search(r"UNIQUE.*\(vendor, product, hw_revision, region, channel, version\)", r) for r in rows_fw)


@pytest.mark.parametrize(
    "version,ok",
    [
        ("0.1.0", True),
        ("1.0.0-alpha+001", True),
        ("2023.01.01", True),  # формально SemVer позволяет любые числа
        ("1.0", False),
        ("1", False),
        ("", False),
    ],
)
def test_firmware_version_semver_regex_matrix(db_session: Session, version, ok):
    fw = make_firmware(firmware_uid=f"fw-{uuid.uuid4()}", version=version)
    db_session.add(fw)
    if ok:
        db_session.commit()
    else:
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()


def test_update_plan_retry_multiplier_range(db_session: Session):
    fw = make_firmware()
    db_session.add(fw)
    db_session.commit()

    # Недопустимое значение retry_multiplier
    bad = make_update_plan(fw, id="plan-retry-bad", retry_multiplier=0.5)
    db_session.add(bad)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    ok = make_update_plan(fw, id="plan-retry-ok", retry_multiplier=3.0)
    db_session.add(ok)
    db_session.commit()
