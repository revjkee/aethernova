import random
import logging
import traceback
from typing import Callable, Dict, List, Optional, Any

logger = logging.getLogger("chaos_engine")
logger.setLevel(logging.INFO)

class ChaosEvent:
    def __init__(self, name: str, action: Callable[[], Any], rollback: Optional[Callable[[], Any]] = None):
        self.name = name
        self.action = action
        self.rollback = rollback

    def execute(self) -> Dict[str, Any]:
        logger.info(f"Executing chaos event: {self.name}")
        try:
            result = self.action()
            return {"event": self.name, "status": "success", "result": result}
        except Exception as e:
            logger.error(f"Chaos event failed: {self.name} -> {str(e)}")
            traceback.print_exc()
            return {"event": self.name, "status": "failed", "error": str(e)}

    def revert(self) -> None:
        if self.rollback:
            try:
                logger.info(f"Rolling back chaos event: {self.name}")
                self.rollback()
            except Exception as e:
                logger.error(f"Rollback failed: {self.name} -> {str(e)}")
                traceback.print_exc()

class ChaosEngine:
    def __init__(self):
        self.events: Dict[str, ChaosEvent] = {}
        self.history: List[Dict[str, Any]] = []

    def register_event(self, event: ChaosEvent):
        if event.name in self.events:
            raise ValueError(f"Event '{event.name}' already registered.")
        self.events[event.name] = event
        logger.debug(f"Registered chaos event: {event.name}")

    def run_scenario(self, event_names: List[str], retries: int = 1):
        logger.info(f"Running chaos scenario with events: {event_names}")
        for name in event_names:
            event = self.events.get(name)
            if not event:
                logger.warning(f"Event not found: {name}")
                continue

            attempt = 0
            result = None
            while attempt < retries:
                result = event.execute()
                self.history.append(result)
                if result["status"] == "success":
                    break
                attempt += 1
                logger.warning(f"Retrying event {name}, attempt {attempt}/{retries}")

            if result and result["status"] == "failed":
                logger.warning(f"Triggering rollback for failed event: {name}")
                event.revert()

    def run_random(self, count: int = 3, retries: int = 1):
        if not self.events:
            logger.warning("No events registered to run.")
            return

        selected = random.sample(list(self.events.keys()), min(count, len(self.events)))
        logger.info(f"Running random chaos events: {selected}")
        self.run_scenario(selected, retries=retries)

    def reset(self):
        self.history.clear()
        logger.info("Chaos engine history reset.")

    def report(self) -> Dict[str, Any]:
        summary = {"total": len(self.history), "success": 0, "failed": 0}
        for entry in self.history:
            if entry["status"] == "success":
                summary["success"] += 1
            else:
                summary["failed"] += 1
        logger.info(f"Chaos test summary: {summary}")
        return summary
