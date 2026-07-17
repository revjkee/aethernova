"""Lifecycle and health model for Aethernova Observability Core."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Any

from .settings import ObservabilityCoreConfig, config

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


class ObservabilityCore:
    """Small, dependency-free runtime coordinating observability components."""

    category = "Monitoring"

    def __init__(self, settings: ObservabilityCoreConfig | None = None) -> None:
        self.config = settings or config
        self.is_initialized = False
        self.is_running = False
        self.components: dict[str, dict[str, Any]] = {}
        self.integrations: dict[str, bool] = {}
        self.metrics: dict[str, Any] = {}
        self._run_task: asyncio.Task[None] | None = None

    async def initialize(self) -> bool:
        """Initialize local components without requiring optional integrations."""

        if self.is_initialized:
            return True

        self.components = {
            "metrics_collector": {"healthy": True},
            "alert_manager": {"healthy": True},
            "trace_recorder": {
                "healthy": True,
                "sampling_rate": self.config.trace_sampling_rate,
            },
        }
        self.metrics = {
            "started_at": _utc_now(),
            "started_monotonic": time.monotonic(),
            "collection_cycles": 0,
            "error_count": 0,
            "last_collection_at": None,
            "last_alert_check_at": None,
            "last_trace_flush_at": None,
        }
        self.integrations = self._discover_integrations()
        self.is_initialized = True
        logger.info("%s initialized", self.config.system_name)
        return True

    async def start(self) -> None:
        """Start the background collection loop; safe to call repeatedly."""

        await self.initialize()
        if self.is_running:
            return
        self.is_running = True
        self._run_task = asyncio.create_task(
            self._run_loop(),
            name="observability-core-collector",
        )
        logger.info("%s started", self.config.system_name)

    async def stop(self) -> None:
        """Stop background work and leave the instance in a consistent state."""

        self.is_running = False
        task = self._run_task
        self._run_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        logger.info("%s stopped", self.config.system_name)

    async def collect_once(self) -> None:
        """Execute one local metrics, alerts, and tracing collection cycle."""

        if not self.is_initialized:
            await self.initialize()
        now = _utc_now()
        self.metrics["collection_cycles"] += 1
        self.metrics["last_collection_at"] = now
        self.metrics["last_alert_check_at"] = now
        self.metrics["last_trace_flush_at"] = now

    def record_error(self) -> None:
        """Record a processing error without exposing exception details."""

        if not self.is_initialized:
            return
        self.metrics["error_count"] += 1

    def get_status(self) -> dict[str, Any]:
        """Return a serializable operational snapshot."""

        uptime = 0.0
        if self.metrics:
            uptime = max(
                0.0,
                time.monotonic() - float(self.metrics.get("started_monotonic", 0.0)),
            )
        return {
            "system_name": self.config.system_name,
            "version": self.config.version,
            "category": self.category,
            "environment": self.config.environment,
            "is_initialized": self.is_initialized,
            "is_running": self.is_running,
            "components": self.components,
            "integrations": self.integrations,
            "metrics": {
                key: value for key, value in self.metrics.items() if key != "started_monotonic"
            },
            "uptime_seconds": round(uptime, 3),
            "config": self.config.public_dict(),
        }

    async def health_check(self) -> dict[str, Any]:
        """Return health without treating optional integrations as fatal."""

        required_available = all(
            self.integrations.get(name, False) for name in self.config.required_systems
        )
        checks = {
            "initialized": self.is_initialized,
            "running": self.is_running,
            "components_healthy": bool(self.components)
            and all(bool(item.get("healthy")) for item in self.components.values()),
            "required_integrations_available": required_available,
        }
        if all(checks.values()):
            status = "healthy"
        elif self.is_initialized and checks["components_healthy"]:
            status = "degraded"
        else:
            status = "unhealthy"
        return {
            "status": status,
            "timestamp": _utc_now(),
            "checks": checks,
            "metrics": {
                key: value for key, value in self.metrics.items() if key != "started_monotonic"
            },
        }

    def _discover_integrations(self) -> dict[str, bool]:
        if not self.config.integration_enabled:
            return {}
        root = self.config.core_systems_path
        systems = dict.fromkeys([*self.config.integration_systems, *self.config.required_systems])
        return {name: (root / name).is_dir() for name in systems}

    async def _run_loop(self) -> None:
        try:
            while self.is_running:
                try:
                    await self.collect_once()
                except Exception:
                    self.record_error()
                    logger.exception("observability collection cycle failed")
                await asyncio.sleep(self.config.collection_interval_seconds)
        except asyncio.CancelledError:
            raise


# Compatibility aliases used by older integration code.
ObservabilityCoreCore = ObservabilityCore
ObservabilitycoreCore = ObservabilityCore


async def create_observability_core_instance() -> ObservabilityCore:
    instance = ObservabilityCore()
    await instance.initialize()
    return instance
