import threading
import logging
from typing import Dict, Optional

class TunnelManager:
    """
    Управление VPN-туннелями и безопасными каналами для SASE.
    Обеспечивает создание, мониторинг, реконнект и завершение туннелей.
    """

    def __init__(self):
        self.tunnels: Dict[str, Dict] = {}  # tunnel_id -> tunnel_info
        self.lock = threading.Lock()
        self.logger = logging.getLogger("SASE.TunnelManager")
        self.logger.setLevel(logging.INFO)

    def create_tunnel(self, tunnel_id: str, config: Dict) -> bool:
        """
        Создает туннель с заданным ID и конфигурацией.
        :param tunnel_id: уникальный идентификатор туннеля
        :param config: параметры туннеля (endpoint, protocol, keys и т.д.)
        :return: True при успешном создании, False при ошибке
        """
        with self.lock:
            if tunnel_id in self.tunnels:
                self.logger.warning(f"Туннель {tunnel_id} уже существует.")
                return False
            # Симуляция создания туннеля
            self.tunnels[tunnel_id] = {
                "config": config,
                "status": "active"
            }
            self.logger.info(f"Туннель {tunnel_id} успешно создан.")
            return True

    def get_tunnel_status(self, tunnel_id: str) -> Optional[str]:
        """
        Возвращает статус туннеля по ID.
        :param tunnel_id: идентификатор туннеля
        :return: статус туннеля или None если не найден
        """
        with self.lock:
            tunnel = self.tunnels.get(tunnel_id)
            if tunnel:
                return tunnel.get("status")
            self.logger.warning(f"Туннель {tunnel_id} не найден.")
            return None

    def close_tunnel(self, tunnel_id: str) -> bool:
        """
        Закрывает туннель и удаляет его из списка.
        :param tunnel_id: идентификатор туннеля
        :return: True если закрытие прошло успешно, иначе False
        """
        with self.lock:
            if tunnel_id not in self.tunnels:
                self.logger.warning(f"Попытка закрыть несуществующий туннель {tunnel_id}.")
                return False
            # Симуляция закрытия
            self.tunnels[tunnel_id]["status"] = "closed"
            del self.tunnels[tunnel_id]
            self.logger.info(f"Туннель {tunnel_id} успешно закрыт.")
            return True

    def reconnect_tunnel(self, tunnel_id: str) -> bool:
        """
        Переустанавливает соединение туннеля.
        :param tunnel_id: идентификатор туннеля
        :return: True если реконнект успешен, иначе False
        """
        with self.lock:
            tunnel = self.tunnels.get(tunnel_id)
            if not tunnel:
                self.logger.warning(f"Туннель {tunnel_id} не найден для реконнекта.")
                return False
            if tunnel["status"] != "active":
                self.logger.warning(f"Туннель {tunnel_id} не активен для реконнекта.")
                return False
            # Симуляция реконнекта
            self.logger.info(f"Реконнект туннеля {tunnel_id} выполнен успешно.")
            return True
