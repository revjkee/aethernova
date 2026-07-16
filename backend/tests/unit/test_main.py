from __future__ import annotations

from backend.src.main import HealthResponse, app, health, settings


def test_system_routes_are_registered() -> None:
    paths = {route.path for route in app.routes}
    assert {"/", "/health", "/ready"}.issubset(paths)


async def test_health_contract() -> None:
    response = await health()

    assert isinstance(response, HealthResponse)
    assert response.status == "ok"
    assert response.app == settings.APP_NAME
    assert response.version == settings.APP_VERSION
    assert response.uptime_ms >= 0


def test_default_branding_is_aethernova() -> None:
    assert settings.APP_NAME == "Aethernova Backend"
