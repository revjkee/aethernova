import threading
import uuid
import time
from queue import PriorityQueue, Empty
from typing import Callable, Dict, Any, Optional


class Task:
    def __init__(self, priority: int, agent_name: str, payload: dict, callback: Optional[Callable] = None):
        self.id = str(uuid.uuid4())
        self.priority = priority
        self.agent_name = agent_name
        self.payload = payload
        self.callback = callback
        self.timestamp = time.time()

    def __lt__(self, other):
        return self.priority < other.priority


class TaskOrchestrator:
    """
    Центральный планировщик задач для мультиагентной среды TeslaAI Genesis.
    Поддерживает приоритеты, таймауты, динамическое распределение задач.
    """

    def __init__(self):
        self._queue = PriorityQueue()
        self._handlers: Dict[str, Callable[[dict], Any]] = {}
        self._lock = threading.Lock()
        self._running = False
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)

    def register_agent(self, name: str, handler: Callable[[dict], Any]):
        with self._lock:
            self._handlers[name] = handler

    def submit_task(self, agent_name: str, payload: dict, priority: int = 10, callback: Optional[Callable] = None):
        task = Task(priority=priority, agent_name=agent_name, payload=payload, callback=callback)
        self._queue.put(task)

    def start(self):
        if not self._running:
            self._running = True
            self._worker_thread.start()

    def stop(self):
        self._running = False
        self._worker_thread.join()

    def _worker_loop(self):
        while self._running:
            try:
                task = self._queue.get(timeout=0.2)
                handler = self._handlers.get(task.agent_name)
                if handler:
                    result = handler(task.payload)
                    if task.callback:
                        try:
                            task.callback(result)
                        except Exception as e:
                            print(f"[TaskOrchestrator] Callback error: {e}")
                else:
                    print(f"[TaskOrchestrator] No handler for agent: {task.agent_name}")
            except Empty:
                continue
            except Exception as e:
                print(f"[TaskOrchestrator] Task execution error: {e}")

    def list_registered_agents(self) -> list:
        with self._lock:
            return list(self._handlers.keys())
