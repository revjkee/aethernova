import asyncio
from typing import Callable, Dict, List, Any, Coroutine, Optional, Set

class AgentBus:
    """
    Асинхронная шина сообщений для межагентного взаимодействия.
    Поддерживает регистрацию агентов, подписку на типы сообщений,
    маршрутизацию и приоритеты обработки.
    """

    def __init__(self):
        # Подписчики: ключ — тип сообщения, значение — список корутин-обработчиков
        self._subscribers: Dict[str, List[Callable[[Any], Coroutine[Any, Any, None]]]] = {}

        # Зарегистрированные агенты: ключ — имя агента, значение — корутина обработки сообщений
        self._agents: Dict[str, Callable[[Any], Coroutine[Any, Any, None]]] = {}

        # Очередь сообщений (типа asyncio.Queue)
        self._message_queue: asyncio.Queue = asyncio.Queue()

        # Набор запущенных задач обработки сообщений
        self._worker_tasks: Set[asyncio.Task] = set()

        # Флаг остановки
        self._stopped: bool = False

    async def start_workers(self, worker_count: int = 5) -> None:
        """
        Запускает пул воркеров для обработки сообщений из очереди.
        """
        self._stopped = False
        for _ in range(worker_count):
            task = asyncio.create_task(self._worker_loop())
            self._worker_tasks.add(task)

    async def stop_workers(self) -> None:
        """
        Останавливает воркеров и очищает задачи.
        """
        self._stopped = True
        for task in self._worker_tasks:
            task.cancel()
        self._worker_tasks.clear()

    async def _worker_loop(self) -> None:
        """
        Цикл обработки сообщений из очереди.
        """
        while not self._stopped:
            try:
                message = await self._message_queue.get()
                await self._dispatch_message(message)
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Логировать ошибку (реализация логгера в проекте)
                print(f"AgentBus worker error: {e}")

    async def _dispatch_message(self, message: Dict[str, Any]) -> None:
        """
        Отправляет сообщение подписчикам по типу.
        message должен содержать ключ 'type'.
        """
        msg_type = message.get('type')
        if not msg_type:
            # Сообщение без типа игнорируем
            return

        subscribers = self._subscribers.get(msg_type, [])
        tasks = [subscriber(message) for subscriber in subscribers]
        if tasks:
            await asyncio.gather(*tasks)

    def register_agent(self, name: str, handler: Callable[[Any], Coroutine[Any, Any, None]]) -> None:
        """
        Регистрирует агента с именем и корутинным обработчиком сообщений.
        """
        if name in self._agents:
            raise ValueError(f"Agent with name '{name}' already registered.")
        self._agents[name] = handler

    def unregister_agent(self, name: str) -> None:
        """
        Удаляет зарегистрированного агента.
        """
        if name in self._agents:
            del self._agents[name]

    def subscribe(self, msg_type: str, handler: Callable[[Any], Coroutine[Any, Any, None]]) -> None:
        """
        Подписывает обработчик на сообщения указанного типа.
        """
        if msg_type not in self._subscribers:
            self._subscribers[msg_type] = []
        self._subscribers[msg_type].append(handler)

    def unsubscribe(self, msg_type: str, handler: Callable[[Any], Coroutine[Any, Any, None]]) -> None:
        """
        Отписывает обработчик от сообщений указанного типа.
        """
        if msg_type in self._subscribers:
            self._subscribers[msg_type].remove(handler)
            if not self._subscribers[msg_type]:
                del self._subscribers[msg_type]

    async def send_message(self, message: Dict[str, Any]) -> None:
        """
        Отправляет сообщение в очередь шины.
        """
        await self._message_queue.put(message)

    async def send_direct(self, agent_name: str, message: Dict[str, Any]) -> None:
        """
        Отправляет сообщение напрямую конкретному агенту.
        """
        handler = self._agents.get(agent_name)
        if handler:
            await handler(message)

    def get_registered_agents(self) -> List[str]:
        """
        Возвращает список имён зарегистрированных агентов.
        """
        return list(self._agents.keys())
