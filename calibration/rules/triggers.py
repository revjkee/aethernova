import logging
import threading
import time
from typing import Callable, Dict, List, Optional, Any

from calibration.core.calibration_engine import CalibrationEngine

logger = logging.getLogger("TriggerManager")


class Trigger:
    def __init__(
        self,
        name: str,
        condition: Callable[[], bool],
        on_trigger: Callable[[], None],
        interval: float = 1.0,
        enabled: bool = True,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.name = name
        self.condition = condition
        self.on_trigger = on_trigger
        self.interval = interval
        self.enabled = enabled
        self.metadata = metadata or {}
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if not self.enabled:
            return
        logger.info(f"Trigger [{self.name}] started")
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._stop_event.clear()
        self._thread.start()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                if self.condition():
                    logger.info(f"Trigger condition met for [{self.name}]")
                    self.on_trigger()
            except Exception as e:
                logger.error(f"Trigger [{self.name}] failed: {e}")
            time.sleep(self.interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join()
            logger.info(f"Trigger [{self.name}] stopped")


class TriggerManager:
    def __init__(self):
        self.triggers: List[Trigger] = []

    def register_trigger(self, trigger: Trigger) -> None:
        logger.debug(f"Registered trigger: {trigger.name}")
        self.triggers.append(trigger)

    def start_all(self) -> None:
        logger.info("Starting all triggers...")
        for trigger in self.triggers:
            trigger.start()

    def stop_all(self) -> None:
        logger.info("Stopping all triggers...")
        for trigger in self.triggers:
            trigger.stop()

    def clear(self) -> None:
        self.stop_all()
        self.triggers.clear()
        logger.debug("All triggers cleared.")


# Пример интеграции с CalibrationEngine через управляющую функцию
def build_metric_trigger(
    name: str,
    metric_provider: Callable[[], float],
    threshold: float,
    calibration_engine: CalibrationEngine,
    affected_parameters: Optional[List[str]] = None,
    interval: float = 2.0,
) -> Trigger:
    def condition() -> bool:
        try:
            value = metric_provider()
            logger.debug(f"Trigger[{name}] metric: {value}, threshold: {threshold}")
            return value > threshold
        except Exception as e:
            logger.warning(f"Metric fetch failed in trigger [{name}]: {e}")
            return False

    def on_trigger() -> None:
        logger.info(f"Trigger [{name}] activated recalibration")
        calibration_engine.recalibrate(params=affected_parameters or [])

    return Trigger(
        name=name,
        condition=condition,
        on_trigger=on_trigger,
        interval=interval
    )
