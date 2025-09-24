import logging
import random
import threading
import time
from typing import Dict, List, Optional

MAX_EVENTS_PER_TRAP = 1000  # Ограничение для предотвращения DoS через логи
TRAP_EXPIRATION_SECONDS = 86400  # 1 день

class DeceptionEngine:
    """
    Модуль Deception Engine — система создания и управления многоуровневыми ловушками для атак.
    Отвлекает и анализирует злоумышленников, снижая риск успешных атак.
    """

    def __init__(self):
        self.logger = logging.getLogger("DeceptionEngine")
        self.logger.setLevel(logging.INFO)
        self.active_traps: Dict[str, Dict] = {}
        self.lock = threading.Lock()

    def deploy_trap(self, trap_id: str, trap_type: str, properties: Dict, owner_id: Optional[str] = None):
        """
        Разворачивает новую ловушку с заданными параметрами.
        trap_type: тип ловушки (фальшивый сервис, фейковый файл, DNS ловушка и т.п.)
        properties: параметры ловушки (например, IP, порты, имитация ответов)
        owner_id: кто поставил ловушку (для валидации доступа)
        """
        with self.lock:
            if trap_id in self.active_traps:
                self.logger.warning(f"Trap {trap_id} уже развернута")
                return

            responses = properties.get("responses")
            if responses and not isinstance(responses, list):
                self.logger.warning(f"Недопустимый формат responses у {trap_id}")
                return

            self.active_traps[trap_id] = {
                "type": trap_type,
                "properties": properties,
                "deployed_at": time.time(),
                "events": [],
                "owner_id": owner_id
            }
            self.logger.info(f"Trap {trap_id} типа {trap_type} развернута")

    def remove_trap(self, trap_id: str, requester_id: Optional[str] = None):
        """
        Удаляет ловушку из активных.
        """
        with self.lock:
            trap = self.active_traps.get(trap_id)
            if not trap:
                self.logger.warning(f"Trap {trap_id} не найдена")
                return

            if trap.get("owner_id") and trap["owner_id"] != requester_id:
                self.logger.warning(f"Запрет удаления ловушки {trap_id} пользователем {requester_id}")
                return

            del self.active_traps[trap_id]
            self.logger.info(f"Trap {trap_id} удалена")

    def log_event(self, trap_id: str, event: Dict):
        """
        Логирует событие атаки на ловушку.
        """
        with self.lock:
            trap = self.active_traps.get(trap_id)
            if not trap:
                self.logger.warning(f"Событие на несуществующую ловушку {trap_id}")
                return

            if len(trap["events"]) >= MAX_EVENTS_PER_TRAP:
                trap["events"].pop(0)
            trap["events"].append(event)
            self.logger.info(f"Лог события для ловушки {trap_id}: {event}")

    def simulate_interaction(self, trap_id: str, requester_id: Optional[str] = None):
        """
        Имитация взаимодействия злоумышленника с ловушкой.
        Возвращает случайный ответ, усиливая реалистичность ловушки.
        """
        with self.lock:
            trap = self.active_traps.get(trap_id)
            if not trap:
                self.logger.error(f"Trap {trap_id} не найдена для взаимодействия")
                return None

            if trap.get("owner_id") and trap["owner_id"] != requester_id:
                self.logger.warning(f"Пользователь {requester_id} не авторизован для ловушки {trap_id}")
                return None

            responses = trap["properties"].get("responses") or [
                "Error: Unknown command",
                "Access denied",
                "Connection timeout",
                "Service unavailable",
                "Command executed successfully"
            ]
            if not isinstance(responses, list):
                responses = ["Invalid trap configuration"]

            response = random.choice(responses)
            self.logger.info(f"Trap {trap_id} имитирует ответ: {response}")
            return response

    def get_trap_status(self, trap_id: str, requester_id: Optional[str] = None) -> Dict:
        """
        Возвращает статус ловушки и логи событий.
        """
        with self.lock:
            trap = self.active_traps.get(trap_id)
            if not trap:
                return {"error": "Trap not found"}

            if trap.get("owner_id") and trap["owner_id"] != requester_id:
                return {"error": "Access denied"}

            return {
                "type": trap["type"],
                "properties": trap["properties"],
                "deployed_at": trap["deployed_at"],
                "event_count": len(trap["events"]),
                "recent_events": trap["events"][-10:],
                "expired": self._is_expired(trap["deployed_at"])
            }

    def list_active_traps(self, requester_id: Optional[str] = None) -> List[str]:
        """
        Возвращает список всех активных ловушек для конкретного пользователя.
        """
        with self.lock:
            return [
                tid for tid, trap in self.active_traps.items()
                if trap.get("owner_id") is None or trap.get("owner_id") == requester_id
            ]

    def _is_expired(self, deployed_at: float) -> bool:
        return (time.time() - deployed_at) > TRAP_EXPIRATION_SECONDS
