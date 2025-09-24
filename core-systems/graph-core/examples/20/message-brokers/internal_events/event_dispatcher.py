# message-brokers/internal_events/event_dispatcher.py

import threading
import queue
import json
import logging
import re
from enum import Enum
from typing import Callable, Dict, List, Any, Union
from pydantic import BaseModel, Field

logger = logging.getLogger("event_dispatcher")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] [DISPATCH] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


class EventPriority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class InternalEvent(BaseModel):
    event_type: str
    payload: Dict[str, Any]
    source: str
    trace_id: str = Field(default_factory=lambda: "trace_" + threading.current_thread().name)
    priority: EventPriority = EventPriority.NORMAL


class EventDispatcher:
    def __init__(self):
        self.subscribers: Dict[str, List[Callable[[InternalEvent], None]]] = {}
        self.pattern_subscribers: List[Tuple[re.Pattern, Callable[[InternalEvent], None]]] = []
        self.queue = queue.PriorityQueue()
        self.lock = threading.Lock()
        self.running = False
        self.offline_buffer: List[InternalEvent] = []
        self.trusted_sources: List[str] = []  # Zero-Trust enforcement

    def start(self):
        self.running = True
        threading.Thread(target=self._process_loop, daemon=True).start()

    def stop(self):
        self.running = False

    def subscribe(self, event_type: str, handler: Callable[[InternalEvent], None]):
        with self.lock:
            if event_type not in self.subscribers:
                self.subscribers[event_type] = []
            self.subscribers[event_type].append(handler)

    def subscribe_pattern(self, pattern: str, handler: Callable[[InternalEvent], None]):
        compiled = re.compile(pattern)
        with self.lock:
            self.pattern_subscribers.append((compiled, handler))

    def trust_source(self, source: str):
        if source not in self.trusted_sources:
            self.trusted_sources.append(source)

    def emit(self, event: InternalEvent):
        if event.source not in self.trusted_sources:
            logger.warning(f"[BLOCKED] Untrusted event source: {event.source}")
            return

        priority_value = self._priority_to_int(event.priority)
        self.queue.put((priority_value, event))

    def _priority_to_int(self, priority: EventPriority) -> int:
        mapping = {
            EventPriority.CRITICAL: 0,
            EventPriority.HIGH: 1,
            EventPriority.NORMAL: 2,
            EventPriority.LOW: 3,
        }
        return mapping.get(priority, 2)

    def _process_loop(self):
        while self.running:
            try:
                _, event = self.queue.get(timeout=1)
                self._dispatch_event(event)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Event processing error: {e}")

    def _dispatch_event(self, event: InternalEvent):
        dispatched = False

        with self.lock:
            if event.event_type in self.subscribers:
                for handler in self.subscribers[event.event_type]:
                    try:
                        handler(event)
                        dispatched = True
                    except Exception as e:
                        logger.warning(f"Handler error for event {event.event_type}: {e}")

            for pattern, handler in self.pattern_subscribers:
                if pattern.match(event.event_type):
                    try:
                        handler(event)
                        dispatched = True
                    except Exception as e:
                        logger.warning(f"Pattern handler error for {event.event_type}: {e}")

        if not dispatched:
            logger.info(f"[UNHANDLED] No handler for event: {event.event_type}")
            self.offline_buffer.append(event)

    def get_offline_buffer(self) -> List[InternalEvent]:
        return self.offline_buffer.copy()

    def flush_offline_buffer(self):
        logger.info("[DISPATCHER] Flushing offline buffer...")
        for event in self.offline_buffer:
            self.emit(event)
        self.offline_buffer.clear()
