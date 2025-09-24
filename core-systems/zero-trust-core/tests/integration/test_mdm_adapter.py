# path: zero-trust-core/tests/integration/test_mdm_adapter.py
# -*- coding: utf-8 -*-
"""
Integration tests for zero_trust.adapters.mdm_adapter

Требуемые зависимости для запуска тестов:
  pip install pytest pytest-asyncio respx httpx

Ожидаемый интерфейс MDM-адаптера:
  from zero_trust.adapters.mdm_adapter import MDMRESTAdapter, MDMConfig
  adapter = MDMRESTAdapter(config: MDMConfig)
  await adapter.fetch(since: Optional[datetime], limit: int) -> Sequence[DevicePosture]
  await adapter.close()

Гарантии тестов:
- Корректная авторизация (Authorization header)
- Пагинация и объединение результатов
- Маппинг в DevicePosture с tz-aware assessed_at (UTC)
- Ретраи на 500/429 (достаточно одного успешного повтора)
- Правильная передача фильтра updated_after (ISO-8601, UTC)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta

import pytest
import respx
import httpx

# Пропуск всего файла, если адаптер не найден (чтобы CI не «падал» при неполной сборке)
mdm_mod = pytest.importorskip("zero_trust.adapters.mdm_adapter", reason="MDM adapter not available")
casb_mod = pytest.importorskip("zero_trust.adapters.casb_adapter", reason="CASB domain not available")

MDMRESTAdapter = mdm_mod.MDMRESTAdapter
MDMConfig = mdm_mod.MDMConfig
DevicePosture = casb_mod.DevicePosture


@pytest.fixture
def mdm_base() -> str:
    return "https://mdm.example.com"


@pytest.fixture
def mdm_cfg(mdm_base: str) -> MDMConfig:
    # В конфиге допускается api_token или oauth_token — используем api_token
    return MDMConfig(
        base_url=mdm_base,
        api_version="v1",
        api_token="test-token",
        timeout_sec=5.0,
        max_retries=2,
        backoff_factor=0.0,  # в тестах не ждём между ретраями
        verify_ssl=True,
    )


@pytest.fixture
async def adapter(mdm_cfg: MDMConfig):
    ad = MDMRESTAdapter(mdm_cfg)
    try:
        yield ad
    finally:
        try:
            await ad.close()
        except Exception:
            pass


@pytest.mark.asyncio
@respx.mock
async def test_fetch_success_pagination_and_mapping(adapter: MDMRESTAdapter, mdm_base: str):
    """
    Проверяем:
    - Пагинацию: две страницы устройств
    - Маппинг полей в DevicePosture
    - Авторизационный заголовок
    """
    page1 = {
        "items": [
            {
                "id": "dev-1",
                "last_seen": "2025-08-20T10:10:00Z",
                "posture": {
                    "os": "Windows 11",
                    "os_version": "23H2",
                    "av": {"status": "ok"},
                    "disk_encryption": True,
                    "assessed_at": "2025-08-20T10:10:00Z",
                },
            }
        ],
        "next_page": "2",
    }
    page2 = {
        "items": [
            {
                "id": "dev-2",
                "last_seen": "2025-08-20T11:00:00Z",
                "posture": {
                    "os": "macOS",
                    "os_version": "14.5",
                    "av": {"status": "ok"},
                    "disk_encryption": True,
                    "assessed_at": "2025-08-20T11:00:00Z",
                },
            }
        ],
        "next_page": None,
    }

    r1 = respx.get(f"{mdm_base}/v1/devices").mock(
        side_effect=lambda request: httpx.Response(
            200,
            json=page1,
            headers={"Content-Type": "application/json"},
        )
        if request.headers.get("Authorization") == "ApiToken test-token"
        else httpx.Response(401)
    )
    r2 = respx.get(f"{mdm_base}/v1/devices", params={"page": "2"}).mock(
        return_value=httpx.Response(200, json=page2)
    )

    since = None
    out = await adapter.fetch(since=since, limit=100)

    assert r1.called and r2.called, "Обе страницы должны быть запрошены"
    assert isinstance(out, (list, tuple)) and len(out) == 2

    d1 = out[0]
    assert isinstance(d1, DevicePosture)
    assert d1.device_id == "dev-1"
    assert d1.posture["os"] == "Windows 11"
    assert d1.assessed_at == datetime(2025, 8, 20, 10, 10, 0, tzinfo=timezone.utc)

    d2 = out[1]
    assert d2.device_id == "dev-2"
    assert d2.posture["os"] == "macOS"
    assert d2.assessed_at.tzinfo is not None and d2.assessed_at.tzinfo.utcoffset(d2.assessed_at) == timedelta(0)


@pytest.mark.asyncio
@respx.mock
async def test_retry_on_500_then_success(adapter: MDMRESTAdapter, mdm_base: str):
    """
    Проверяем, что при 500 выполняется ретрай и затем успешный ответ возвращается корректно.
    """
    route = respx.get(f"{mdm_base}/v1/devices").mock(
        side_effect=[
            httpx.Response(500),
            httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "id": "dev-3",
                            "posture": {"assessed_at": "2025-08-20T12:00:00Z", "os": "Linux"},
                        }
                    ],
                    "next_page": None,
                },
            ),
        ]
    )

    out = await adapter.fetch(since=None, limit=50)
    assert route.call_count == 2, "Ожидались две попытки (500 -> 200)"
    assert len(out) == 1 and out[0].device_id == "dev-3"


@pytest.mark.asyncio
@respx.mock
async def test_retry_on_429_then_success(adapter: MDMRESTAdapter, mdm_base: str):
    """
    Проверяем ретрай после 429. Retry-After можно игнорировать во времени, но важен успешный повтор.
    """
    route = respx.get(f"{mdm_base}/v1/devices").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "1"}),
            httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "id": "dev-4",
                            "posture": {"assessed_at": "2025-08-20T13:00:00Z", "os": "Linux"},
                        }
                    ],
                    "next_page": None,
                },
            ),
        ]
    )
    out = await adapter.fetch(since=None, limit=10)
    assert route.call_count == 2
    assert len(out) == 1 and out[0].device_id == "dev-4"


@pytest.mark.asyncio
@respx.mock
async def test_updated_after_param_is_passed(adapter: MDMRESTAdapter, mdm_base: str):
    """
    Проверяем, что параметр updated_after передается как ISO-8601 UTC строка.
    """
    called = {"ok": False, "value": None}

    def _cb(request: httpx.Request) -> httpx.Response:
        updated_after = request.url.params.get("updated_after")
        called["ok"] = updated_after is not None
        called["value"] = updated_after
        return httpx.Response(
            200,
            json={"items": [], "next_page": None},
        )

    respx.get(f"{mdm_base}/v1/devices").mock(side_effect=_cb)

    since = datetime(2025, 8, 20, 9, 30, tzinfo=timezone.utc)
    await adapter.fetch(since=since, limit=5)

    assert called["ok"], "Ожидался параметр updated_after"
    assert isinstance(called["value"], str) and called["value"].endswith("Z")


@pytest.mark.asyncio
@respx.mock
async def test_mapping_timezone_and_required_fields(adapter: MDMRESTAdapter, mdm_base: str):
    """
    Проверяем, что assessed_at становится tz-aware UTC, и обязательные поля присутствуют.
    """
    respx.get(f"{mdm_base}/v1/devices").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": "dev-5",
                        "posture": {"assessed_at": "2025-08-20T14:15:30Z", "os": "Windows"},
                    }
                ],
                "next_page": None,
            },
        )
    )
    out = await adapter.fetch(since=None, limit=1)
    assert len(out) == 1
    dp = out[0]
    assert dp.device_id == "dev-5"
    assert dp.assessed_at == datetime(2025, 8, 20, 14, 15, 30, tzinfo=timezone.utc)
    assert "os" in dp.posture


@pytest.mark.asyncio
@respx.mock
async def test_close_is_idempotent(adapter: MDMRESTAdapter, mdm_base: str):
    """
    Закрытие адаптера не должно приводить к ошибкам при повторных вызовах.
    """
    await adapter.close()
    await adapter.close()  # повторное закрытие — без исключений
