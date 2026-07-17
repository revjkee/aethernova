"""Compatibility entry point for local source checkouts."""

from src.observability_core.api import app
from src.observability_core.core import (
    ObservabilityCore,
    ObservabilityCoreCore,
    ObservabilitycoreCore,
    create_observability_core_instance,
)

__all__ = [
    "ObservabilityCore",
    "ObservabilityCoreCore",
    "ObservabilitycoreCore",
    "app",
    "create_observability_core_instance",
]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8080)
