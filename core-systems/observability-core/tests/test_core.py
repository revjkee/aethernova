from pathlib import Path

import pytest

from observability_core import ObservabilityCore, ObservabilityCoreConfig


@pytest.mark.asyncio
async def test_lifecycle_collects_metrics_and_stops_cleanly(tmp_path: Path) -> None:
    settings = ObservabilityCoreConfig(
        core_systems_path=tmp_path,
        integration_systems=[],
        collection_interval_seconds=0.01,
    )
    core = ObservabilityCore(settings)

    await core.start()
    await core.collect_once()

    status = core.get_status()
    health = await core.health_check()
    assert status["category"] == "Monitoring"
    assert status["metrics"]["collection_cycles"] >= 1
    assert health["status"] == "healthy"
    assert "encryption_key" not in status["config"]

    await core.stop()
    assert core.is_running is False


@pytest.mark.asyncio
async def test_missing_required_integration_degrades_health(tmp_path: Path) -> None:
    settings = ObservabilityCoreConfig(
        core_systems_path=tmp_path,
        integration_systems=["engine-core"],
        required_systems=["engine-core"],
    )
    core = ObservabilityCore(settings)

    await core.start()
    health = await core.health_check()
    await core.stop()

    assert health["status"] == "degraded"
    assert health["checks"]["required_integrations_available"] is False


@pytest.mark.asyncio
async def test_required_integration_is_discovered_even_if_not_optional(
    tmp_path: Path,
) -> None:
    (tmp_path / "engine-core").mkdir()
    settings = ObservabilityCoreConfig(
        core_systems_path=tmp_path,
        integration_systems=[],
        required_systems=["engine-core"],
    )
    core = ObservabilityCore(settings)

    await core.start()
    health = await core.health_check()
    await core.stop()

    assert health["status"] == "healthy"
