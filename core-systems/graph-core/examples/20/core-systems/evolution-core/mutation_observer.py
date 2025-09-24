import threading
from typing import Callable, Dict, List, Any

class MutationObserver:
    """
    Модуль слежения за изменениями агентов.
    Позволяет регистрировать коллбэки на события мутаций и отслеживать историю изменений.
    """

    def __init__(self):
        self._callbacks: List[Callable[[str, Dict[str, Any]], None]] = []
        self._mutation_log: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def register_callback(self, callback: Callable[[str, Dict[str, Any]], None]):
        """
        Регистрирует функцию обратного вызова, которая вызывается при мутации агента.

        :param callback: Функция с параметрами (agent_id, mutation_info)
        """
        with self._lock:
            self._callbacks.append(callback)

    def notify_mutation(self, agent_id: str, mutation_info: Dict[str, Any]):
        """
        Уведомляет все зарегистрированные коллбэки о произошедшей мутации.

        :param agent_id: Идентификатор агента.
        :param mutation_info: Информация о мутации (тип, параметры, время).
        """
        with self._lock:
            if agent_id not in self._mutation_log:
                self._mutation_log[agent_id] = []
            self._mutation_log[agent_id].append(mutation_info)

            for callback in self._callbacks:
                try:
                    callback(agent_id, mutation_info)
                except Exception:
                    pass  # Игнорировать ошибки в коллбэках

    def get_mutation_history(self, agent_id: str) -> List[Dict[str, Any]]:
        """
        Возвращает историю мутаций для данного агента.

        :param agent_id: Идентификатор агента.
        :return: Список словарей с информацией о мутациях.
        """
        with self._lock:
            return list(self._mutation_log.get(agent_id, []))

    def clear_history(self):
        """
        Очищает весь лог мутаций.
        """
        with self._lock:
            self._mutation_log.clear()
            self._callbacks.clear()
