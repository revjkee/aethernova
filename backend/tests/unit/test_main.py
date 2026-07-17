from __future__ import annotations

from fastapi.testclient import TestClient

from backend.src.main import HealthResponse, app, health, settings


def test_system_routes_are_registered() -> None:
    paths = {route.path for route in app.routes}
    assert {"/", "/health", "/ready", "/metrics"}.issubset(paths)


async def test_health_contract() -> None:
    response = await health()

    assert isinstance(response, HealthResponse)
    assert response.status == "ok"
    assert response.app == settings.APP_NAME
    assert response.version == settings.APP_VERSION
    assert response.uptime_ms >= 0


def test_default_branding_is_aethernova() -> None:
    assert settings.APP_NAME == "Aethernova Backend"


def test_prometheus_metrics_endpoint_records_templated_route() -> None:
    client = TestClient(app, base_url="http://localhost")

    assert client.get("/health").status_code == 200
    response = client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "http_requests_total" in response.text
    assert 'handler="/health"' in response.text
