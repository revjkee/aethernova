from fastapi.testclient import TestClient

from observability_core.api import app


def test_health_ready_status_and_metrics_endpoints() -> None:
    with TestClient(app) as client:
        assert client.get("/ready").json() == {"status": "ready"}

        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] in {"healthy", "degraded"}

        runtime_status = client.get("/status")
        assert runtime_status.status_code == 200
        assert runtime_status.json()["system_name"] == "observability-core"

        metrics = client.get("/metrics")
        assert metrics.status_code == 200
        assert "aethernova_observability_http_requests_total" in metrics.text
