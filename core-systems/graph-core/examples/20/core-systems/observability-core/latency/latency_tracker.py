import time
import uuid
import contextvars
import logging
from typing import Optional, Dict, List, Any
from threading import RLock

_logger = logging.getLogger("latency_tracker")
_tracker_context = contextvars.ContextVar("latency_tracker_context", default=None)

class LatencyEvent:
    def __init__(self, name: str):
        self.name = name
        self.start_time = time.perf_counter()
        self.end_time = None
        self.duration = None
        self.metadata: Dict[str, Any] = {}

    def stop(self):
        self.end_time = time.perf_counter()
        self.duration = self.end_time - self.start_time

    def to_dict(self):
        return {
            "name": self.name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": round(self.duration * 1000, 3) if self.duration else None,
            "metadata": self.metadata
        }

class LatencyTracker:
    def __init__(self, request_id: Optional[str] = None):
        self.request_id = request_id or str(uuid.uuid4())
        self.events: Dict[str, LatencyEvent] = {}
        self.lock = RLock()

    def start(self, name: str, metadata: Optional[Dict[str, Any]] = None):
        with self.lock:
            if name in self.events:
                _logger.warning(f"Event '{name}' already started")
            event = LatencyEvent(name)
            if metadata:
                event.metadata.update(metadata)
            self.events[name] = event
            _logger.debug(f"[{self.request_id}] Started event '{name}'")

    def stop(self, name: str):
        with self.lock:
            event = self.events.get(name)
            if not event:
                _logger.warning(f"Event '{name}' not found")
                return
            if event.end_time is not None:
                _logger.warning(f"Event '{name}' already stopped")
                return
            event.stop()
            _logger.debug(f"[{self.request_id}] Stopped event '{name}' - {event.duration:.3f}s")

    def summary(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "request_id": self.request_id,
                "events": [event.to_dict() for event in self.events.values()]
            }

    def stop_all(self):
        with self.lock:
            for name, event in self.events.items():
                if event.end_time is None:
                    event.stop()

def get_tracker() -> LatencyTracker:
    tracker = _tracker_context.get()
    if tracker is None:
        tracker = LatencyTracker()
        _tracker_context.set(tracker)
    return tracker

def reset_tracker():
    _tracker_context.set(None)

def track_latency(name: str, metadata: Optional[Dict[str, Any]] = None):
    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            tracker = get_tracker()
            tracker.start(name, metadata)
            try:
                return await func(*args, **kwargs)
            finally:
                tracker.stop(name)

        def sync_wrapper(*args, **kwargs):
            tracker = get_tracker()
            tracker.start(name, metadata)
            try:
                return func(*args, **kwargs)
            finally:
                tracker.stop(name)

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator
