# SPDX-License-Identifier: Apache-2.0
# physical-integration-core/tests/e2e/test_field_to_twin_e2e.py

import os
import time
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

import pytest

# --- HTTP клиент ---
try:
    from fastapi import FastAPI
    from starlette.testclient import TestClient
    _HAS_FASTAPI = True
except Exception:
    _HAS_FASTAPI = False

# --- База данных / ORM ---
try:
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
    _HAS_SA = True
except Exception:
    _HAS_SA = False

# --- Testcontainers / PostgreSQL ---
try:
    from testcontainers.postgres import PostgresContainer  # type: ignore
    _HAS_TESTCONTAINERS = True
except Exception:
    _HAS_TESTCONTAINERS = False


# ====== Утилиты обнаружения приложения и моделей ======

def _discover_app() -> Tuple[Optional[FastAPI], Optional[str]]:
    """
    Пытается найти FastAPI приложение или фабрику create_app().
    Возвращает (app, source_info) или (None, reason).
    """
    if not _HAS_FASTAPI:
        return None, "FastAPI/starlette.testclient не установлены"

    candidates = [
        # (module, attribute)
        ("physical_integration.api.http.app", "create_app"),
        ("physical_integration.api.http.app", "app"),
        ("physical_integration.api.http.main", "create_app"),
        ("physical_integration.api.http.main", "app"),
        ("physical_integration.api.http", "create_app"),
        ("physical_integration.api.http", "app"),
    ]
    for mod, attr in candidates:
        try:
            m = __import__(mod, fromlist=[attr])
            obj = getattr(m, attr, None)
            if callable(obj):
                app = obj()  # create_app()
                if isinstance(app, FastAPI):
                    return app, f"{mod}:{attr}()"
            if isinstance(obj, FastAPI):
                return obj, f"{mod}:{attr}"
        except Exception:
            continue
    return None, "Не найден модуль приложения (ожидались app/create_app в physical_integration.api.http.*)"


def _import_models():
    """
    Пытается импортировать модели twin/registry для работы с БД напрямую.
    Возвращает { 'Base': Base, 'Twin': Twin, 'TwinPropertyEvent': TwinPropertyEvent, 'Device': Device } (возможны None).
    """
    out = {"Base": None, "Twin": None, "TwinPropertyEvent": None, "Device": None}
    try:
        from physical_integration.twin.models import Base as TwinBase, Twin, TwinPropertyEvent  # type: ignore
        out["Base"] = TwinBase
        out["Twin"] = Twin
        out["TwinPropertyEvent"] = TwinPropertyEvent
    except Exception:
        pass
    try:
        from physical_integration.registry.models import Base as RegBase, Device  # type: ignore
        # Если баз разные — создадим композит через metadata; тут просто вернем Device
        out["Device"] = Device
        if out["Base"] is None:
            out["Base"] = RegBase
    except Exception:
        pass
    return out


# ====== Фикстуры окружения ======

def _get_db_url():
    dsn = os.getenv("POSTGRES_DSN") or os.getenv("POSTGRES_URL") or os.getenv("DATABASE_URL")
    if dsn:
        return dsn, None
    if _HAS_TESTCONTAINERS:
        pg = PostgresContainer("postgres:16-alpine")
        pg.start()
        return pg.get_connection_url(), pg
    return None, None


@pytest.fixture(scope="session")
def db_url():
    if not _HAS_SA:
        pytest.skip("SQLAlchemy не установлен")
    url, container = _get_db_url()
    if not url:
        pytest.skip("PostgreSQL недоступен: задайте POSTGRES_DSN/POSTGRES_URL/DATABASE_URL или установите testcontainers+docker")
    yield url
    try:
        if container:
            container.stop()
    except Exception:
        pass


@pytest.fixture(scope="session")
def engine(db_url):
    eng = create_engine(db_url, pool_pre_ping=True, future=True)
    yield eng
    eng.dispose()


@pytest.fixture(scope="function")
def db_session(engine):
    models = _import_models()
    Base = models["Base"]
    if Base is None:
        pytest.skip("Не удалось импортировать модели twin/registry для подготовки схемы")
    # Чистая схема перед тестом
    Base.metadata.drop_all(engine, checkfirst=True)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    with SessionLocal() as s:
        yield s
        s.rollback()
        # Быстрая очистка каскадом
        with engine.begin() as conn:
            for tbl in reversed(Base.metadata.sorted_tables):
                conn.execute(text(f'TRUNCATE TABLE "{tbl.name}" CASCADE'))


@pytest.fixture(scope="function")
def client(engine, monkeypatch):
    if not _HAS_FASTAPI:
        pytest.skip("FastAPI/starlette.testclient отсутствуют")
    # Экспортируем DSN для приложения
    dsn = str(engine.url)
    for k in ("PIC_DB_URL", "DATABASE_URL", "POSTGRES_DSN"):
        monkeypatch.setenv(k, dsn)

    app, info = _discover_app()
    if not app:
        pytest.skip(f"Приложение FastAPI не найдено: {info}")
    return TestClient(app)


# ====== Хелперы для API ======

def _create_device_via_api(client: TestClient, payload: dict) -> Optional[str]:
    """
    Пытается создать устройство через один из распространенных эндпоинтов.
    Возвращает id устройства или None.
    """
    candidates = [
        ("POST", "/v1/devices"),
        ("POST", "/api/v1/devices"),
    ]
    for method, path in candidates:
        try:
            resp = client.request(method, path, json=payload)
            if resp.status_code in (200, 201):
                data = resp.json()
                return data.get("id") or data.get("device_id")
        except Exception:
            continue
    return None


def _send_telemetry(client: TestClient, device_id: str, telemetry: dict) -> bool:
    """
    Пытается отправить телеметрию на один из распространенных эндпоинтов.
    Возвращает True при успехе (HTTP 2xx).
    """
    candidates = [
        ("POST", f"/v1/devices/{device_id}/telemetry"),
        ("POST", "/v1/telemetry"),
        ("POST", "/api/v1/devices/telemetry"),
    ]
    for method, path in candidates:
        body = telemetry if "{device_id}" not in path else telemetry
        try:
            resp = client.request(method, path, json=body)
            if resp.status_code // 100 == 2:
                return True
        except Exception:
            continue
    return False


def _fetch_twin(client: TestClient, device_id: str) -> Optional[dict]:
    """
    Пытается получить twin по device_id.
    """
    candidates = [
        ("GET", f"/v1/twins/{device_id}"),
        ("GET", "/v1/twins", {"device_id": device_id}),
        ("GET", "/api/v1/twins", {"device_id": device_id}),
    ]
    for method, path, *rest in candidates:
        params = rest[0] if rest else None
        try:
            resp = client.request(method, path, params=params)
            if resp.status_code == 200:
                data = resp.json()
                # либо объект, либо {"items":[...]}
                if isinstance(data, dict) and data.get("id"):
                    return data
                if isinstance(data, dict) and isinstance(data.get("items"), list) and data["items"]:
                    return data["items"][0]
        except Exception:
            continue
    return None


def _json_search_number(d: dict, expected: float, eps: float = 1e-6) -> bool:
    """
    Грубый поиск числа expected в любом месте JSON (для гибкости структуры reported).
    """
    if isinstance(d, dict):
        for v in d.values():
            if _json_search_number(v, expected, eps):
                return True
    elif isinstance(d, list):
        for v in d:
            if _json_search_number(v, expected, eps):
                return True
    else:
        try:
            val = float(d)
            return abs(val - expected) <= eps
        except Exception:
            return False
    return False


# ====== Сам e2e-сценарий ======

@pytest.mark.e2e
def test_field_to_twin_reported_state_and_idempotency(db_session, client):
    """
    Сценарий:
      1) Создаем устройство (API).
      2) Шлем телеметрию (temperature, battery_percent) с idempotency_key.
      3) Ждем eventual consistency, читаем twin и проверяем reported.
      4) Шлем ту же телеметрию повторно — подтверждаем идемпотентность (нет дублей событий).
    """
    # 1) Создание устройства
    dev_payload = {
        "name": "unit-e2e",
        "vendor": "acme",
        "product": "sensor",
        "hw_revision": "r1",
        "serial_number": "SN-e2e-001",
        "region": "eu",
        "channel": "STABLE",
        "labels": {"site": "plant-a", "room": "210"},
        "annotations": {},
        "site": "A",
    }
    device_id = _create_device_via_api(client, dev_payload)
    if not device_id:
        pytest.skip("Эндпоинт создания устройства не найден — пропускаем e2e")

    # 2) Отправка телеметрии
    temp = 23.5
    battery = 87
    idem = str(uuid.uuid4())
    reported_at = datetime.now(timezone.utc).isoformat()

    telemetry = {
        "device_id": device_id,
        "idempotency_key": idem,
        "reported_at": reported_at,
        "metrics": {
            "temperature_c": temp,
            "battery_percent": battery,
        },
        "labels": {"site": "plant-a"},
    }
    ok = _send_telemetry(client, device_id, telemetry)
    assert ok, "Не удалось найти/вызвать эндпоинт телеметрии"

    # 3) Ожидание и проверка twin.reported
    twin = None
    deadline = time.time() + 10.0  # даем сервису догнать
    while time.time() < deadline:
        twin = _fetch_twin(client, device_id)
        if twin and isinstance(twin, dict):
            reported = twin.get("reported") or {}
            if ("temperature_c" in reported and abs(float(reported["temperature_c"]) - temp) < 1e-6) or _json_search_number(reported, temp):
                break
        time.sleep(0.3)

    assert twin, "Twin не найден"
    reported = twin.get("reported") or {}
    assert _json_search_number(reported, temp), f"Ожидали температуру {temp} в reported, получили: {reported}"
    assert _json_search_number(reported, battery), f"Ожидали уровень батареи {battery} в reported"

    # 4) Идемпотентность: повторная отправка не должна создавать дубль события
    models = _import_models()
    TwinPropertyEvent = models.get("TwinPropertyEvent")
    before_cnt = None
    if TwinPropertyEvent is not None:
        # считаем событий до
        before_cnt = db_session.query(TwinPropertyEvent).count()

    ok2 = _send_telemetry(client, device_id, telemetry)  # тот же idempotency_key
    assert ok2, "Повторная отправка телеметрии не удалась"

    # Небольшое ожидание и проверка числа событий
    if TwinPropertyEvent is not None and before_cnt is not None:
        time.sleep(1.0)
        after_cnt = db_session.query(TwinPropertyEvent).count()
        assert after_cnt == before_cnt, "Нарушена идемпотентность: число событий выросло при повторной отправке"


# ====== Дополнительные проверки готовности сервиса (нестрогие) ======

@pytest.mark.e2e
def test_health_endpoints_if_present(client):
    """
    Нестрогая проверка готовности сервиса (если health-эндпоинты есть).
    """
    for path in ("/health", "/live", "/ready", "/api/health"):
        try:
            r = client.get(path)
            if r.status_code == 200:
                return
        except Exception:
            continue
    pytest.skip("health-эндпоинт не найден (это допустимо для e2e)")
