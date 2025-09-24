from enum import Enum
from typing import List, Optional, Set
import os
import logging

logger = logging.getLogger("latency.config")


class LatencyLevel(str, Enum):
    DISABLED = "disabled"
    MINIMAL = "minimal"     # только общие точки: start/end
    VERBOSE = "verbose"     # все этапы, включая вложенные
    DEBUG = "debug"         # всё, включая trace_id, контексты и payload


class LatencyConfig:
    """
    Глобальный конфиг latency-трассировки. Управляет:
    - уровнем детализации
    - исключёнными этапами
    - включением по условиям
    """

    def __init__(
        self,
        level: LatencyLevel = LatencyLevel.MINIMAL,
        include_stages: Optional[Set[str]] = None,
        exclude_stages: Optional[Set[str]] = None,
        enabled_env_var: str = "LATENCY_TRACKING_ENABLED"
    ):
        self.level = level
        self.include_stages = include_stages or set()
        self.exclude_stages = exclude_stages or set()
        self.enabled_env_var = enabled_env_var

    def is_enabled(self) -> bool:
        val = os.getenv(self.enabled_env_var, "true").lower()
        if val in {"1", "true", "yes", "on"}:
            return True
        logger.debug("Latency tracking disabled by env")
        return False

    def should_track_stage(self, stage_name: str) -> bool:
        """Решает, нужно ли отслеживать конкретный этап."""
        if not self.is_enabled():
            return False
        if stage_name in self.exclude_stages:
            return False
        if self.include_stages and stage_name not in self.include_stages:
            return False
        return True

    def set_level(self, level: LatencyLevel):
        logger.info(f"Setting latency level: {level}")
        self.level = level

    def enable_stage(self, stage: str):
        logger.info(f"Enabling latency stage: {stage}")
        self.include_stages.add(stage)

    def disable_stage(self, stage: str):
        logger.info(f"Disabling latency stage: {stage}")
        self.exclude_stages.add(stage)


# Промышленный экземпляр по умолчанию
default_latency_config = LatencyConfig(
    level=LatencyLevel.MINIMAL,
    exclude_stages={"heartbeat", "noop"},
    enabled_env_var="LATENCY_TRACKING_ENABLED"
)
