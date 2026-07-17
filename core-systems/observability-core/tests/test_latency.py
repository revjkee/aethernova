import asyncio

import pytest

from observability_core.latency import (
    LatencyAggregator,
    LatencyEvent,
    get_tracker,
    reset_tracker,
    track_latency,
)
from observability_core.latency.latency_exporter import LatencyExporterConfig
from observability_core.latency.latency_validator import is_valid_latency_event


def test_latency_event_and_aggregator_share_one_contract() -> None:
    event = LatencyEvent(
        "database",
        metadata={"trace_id": "trace-1", "stage": "query"},
    ).stop()
    payload = event.to_dict()

    aggregator = LatencyAggregator()
    aggregator.record(event)

    assert payload["duration_ms"] is not None
    assert is_valid_latency_event(payload)
    assert aggregator.get_summary()["database"]["count"] == 1
    assert aggregator.get_stage_breakdown()["query"]["count"] == 1
    assert aggregator.get_trace_events("trace-1") == [event]


@pytest.mark.asyncio
async def test_latency_decorator_tracks_sync_and_async_calls() -> None:
    reset_tracker()

    @track_latency("sync-work")
    def sync_work() -> int:
        return 1

    @track_latency("async-work", context_getter=lambda: {"trace_id": "trace-1"})
    async def async_work() -> int:
        await asyncio.sleep(0)
        return 2

    assert sync_work() == 1
    assert await async_work() == 2

    summary = get_tracker().summary()
    assert [event["name"] for event in summary["events"]] == [
        "sync-work",
        "async-work",
    ]
    assert summary["events"][1]["metadata"]["trace_id"] == "trace-1"


def test_enabled_latency_exporter_requires_an_endpoint() -> None:
    with pytest.raises(ValueError):
        LatencyExporterConfig(enabled=True)
