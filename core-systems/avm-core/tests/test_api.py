# path: core-systems/avm_core/tests/test_api.py
# -*- coding: utf-8 -*-
"""
Промышленные тесты для health-роутов AVM Engine:
- /livez, /readyz, /healthz, /startupz (+ HEAD)
- TTL-кэширование отчета /healthz
- Строгий режим готовности (AVM_HEALTH_STRICT=1)
- Эмуляция сбоев критических и предупреждающих проверок через monkeypatch
Требования: pytest, pytest-asyncio или anyio, httpx>=0.23
"""

from __future__ import annotations

import asyncio
import os
from contextlib import contextmanager
from typing import AsyncIterator, Dict, Tuple

import httpx
import pytest
from fastapi import FastAPI

# Импортируем модуль роутов и сам роутер
import avm_core.engine.api.routes.health as health_mod
from avm_core.engine.api.routes.health import router as health_router


# -----------------------------
# Вспомогательные утилиты
# -----------------------------

@contextmanager
def _temp_env(env: Dict[str, str]):
    """Временное переопределение ENV (в т.ч. удаление при value=None)."""
    old = {}
    to_del = []
    try:
        for k, v in env.items():
            if k in os.environ:
                old[k] = os.environ[k]
            else:
                to_del.append(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k in env:
            os.environ.pop(k, None)
        for k, v in old.items():
            os.environ[k] = v


@pytest.fixture
def app() -> FastAPI:
    """Локальное FastAPI-приложение с подключенными health-роутами."""
    # Сбрасываем кэш между тестами
    health_mod._CACHE = health_mod._Cache()
    application = FastAPI(title="avm-engine-test")
    application.include_router(health_router, prefix="")
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """HTTPX клиент поверх ASGI без реального сервера."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# -----------------------------
# Тесты /livez
# -----------------------------

@pytest.mark.anyio
async def test_livez_ok(client: httpx.AsyncClient):
    r = await client.get("/livez")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] in ("alive", "stalled")
    assert isinstance(data["delay_ms"], (int, float))


@pytest.mark.anyio
async def test_livez_head_ok(client: httpx.AsyncClient):
    r = await client.head("/livez")
    assert r.status_code == 200
    # Тело у HEAD не обязательно


# -----------------------------
# Тесты /startupz
# -----------------------------

@pytest.mark.anyio
async def test_startupz_started_immediately_with_zero_grace(client: httpx.AsyncClient):
    with _temp_env({"AVM_STARTUP_GRACE_S": "0"}):
        r = await client.get("/startupz")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "started"
        assert data["grace_s"] == 0


@pytest.mark.anyio
async def test_startupz_progresses_over_time(client: httpx.AsyncClient):
    with _temp_env({"AVM_STARTUP_GRACE_S": "1"}):
        r1 = await client.get("/startupz")
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["status"] in ("starting", "started")
        # Подождём чуть дольше grace
        await asyncio.sleep(1.2)
        r2 = await client.get("/startupz")
        d2 = r2.json()
        assert d2["status"] == "started"


@pytest.mark.anyio
async def test_startupz_head(client: httpx.AsyncClient):
    r = await client.head("/startupz")
    assert r.status_code == 200


# -----------------------------
# Тесты /healthz
# -----------------------------

@pytest.mark.anyio
async def test_healthz_structure_and_ttl_cache(client: httpx.AsyncClient):
    # Обнулим кэш перед тестом
    health_mod._CACHE = health_mod._Cache()
    r1 = await client.get("/healthz")
    assert r1.status_code == 200
    data1 = r1.json()
    # Базовая структура
    for key in ("service", "version", "status", "liveness_ok", "readiness_ok", "uptime_s", "checks", "summary", "node"):
        assert key in data1
    assert isinstance(data1["checks"], list)
    assert isinstance(data1["summary"], dict)

    # Второй вызов должен вернуть кэш за ~1 сек — ожидаем идентичный ответ
    r2 = await client.get("/healthz")
    data2 = r2.json()
    assert data2 == data1  # TTL по умолчанию ~1s в модуле


@pytest.mark.anyio
async def test_healthz_version_overridden_by_monkeypatch(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch):
    # Подменим детектор версии до сборки отчёта
    monkeypatch.setattr(health_mod, "_detect_version", lambda: "test-1.2.3", raising=True)
    health_mod._CACHE = health_mod._Cache()  # сброс кэша
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["version"] == "test-1.2.3"


# -----------------------------
# Тесты /readyz (успех по умолчанию)
# -----------------------------

@pytest.mark.anyio
async def test_readyz_ok_default(client: httpx.AsyncClient):
    # В стандартной среде при наличии базовых бинарей статус чаще "ready".
    # Не завязываемся жёстко — проверим корректный JSON и один из статусов.
    r = await client.get("/readyz")
    assert r.status_code in (200, 503)
    data = r.json()
    assert "status" in data and data["status"] in ("ready", "not_ready")
    assert isinstance(data["summary"], dict)


# -----------------------------
# Тесты /readyz (отказ при CRITICAL)
# -----------------------------

@pytest.mark.anyio
async def test_readyz_503_on_critical_failure(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch):
    # Эмулируем отказ критической проверки (disk_space)
    async def fail_disk() -> Tuple[bool, Dict[str, str]]:
        return False, {"reason": "simulated"}

    monkeypatch.setattr(health_mod, "_check_disk_space", fail_disk, raising=True)
    health_mod._CACHE = health_mod._Cache()  # сброс кэша
    r = await client.get("/readyz")
    assert r.status_code == 503
    data = r.json()
    assert data["status"] == "not_ready"
    assert data["summary"]["crit_bad"] >= 1


# -----------------------------
# Тесты /readyz (строгий режим: WARNING => 503)
# -----------------------------

@pytest.mark.anyio
async def test_readyz_strict_mode_warning_causes_503(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch):
    # Подменим warning-проверку "binaries" на отказ
    async def fail_bins() -> Tuple[bool, Dict[str, str]]:
        return False, {"missing": "simulated"}

    monkeypatch.setattr(health_mod, "_check_binaries", fail_bins, raising=True)
    health_mod._CACHE = health_mod._Cache()

    with _temp_env({"AVM_HEALTH_STRICT": "1"}):
        r = await client.get("/readyz")
        assert r.status_code == 503
        data = r.json()
        assert data["strict"] is True
        assert data["status"] == "not_ready"


# -----------------------------
# HEAD /readyz
# -----------------------------

@pytest.mark.anyio
async def test_readyz_head(client: httpx.AsyncClient):
    r = await client.head("/readyz")
    # Код должен соответствовать логике GET; тело несущественно
    assert r.status_code in (200, 503)
