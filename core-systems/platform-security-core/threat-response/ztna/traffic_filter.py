import ipaddress
import logging
from typing import Dict, Any, List

class TrafficFilter:
    """
    Модуль фильтрации сетевого трафика для Zero Trust Network Access.
    Обеспечивает контроль входящего и исходящего трафика на основе
    политик безопасности и анализа контекста запроса.
    """

    def __init__(self, allowed_ip_ranges: List[str], blocked_ports: List[int]):
        """
        Инициализация фильтра с разрешенными диапазонами IP и заблокированными портами.
        :param allowed_ip_ranges: Список CIDR-диапазонов разрешенных IP
        :param blocked_ports: Список портов, доступ к которым запрещен
        """
        self.allowed_networks = [ipaddress.ip_network(cidr) for cidr in allowed_ip_ranges]
        self.blocked_ports = set(blocked_ports)
        self.logger = logging.getLogger("ZTNA.TrafficFilter")
        self.logger.setLevel(logging.INFO)

    def is_ip_allowed(self, ip: str) -> bool:
        """
        Проверка, входит ли IP в разрешенные диапазоны.
        :param ip: IP-адрес для проверки
        :return: True если IP разрешен, False если нет
        """
        ip_obj = ipaddress.ip_address(ip)
        for network in self.allowed_networks:
            if ip_obj in network:
                return True
        self.logger.warning(f"IP {ip} не входит в разрешённые диапазоны.")
        return False

    def is_port_allowed(self, port: int) -> bool:
        """
        Проверка, не заблокирован ли порт.
        :param port: Номер порта
        :return: True если порт разрешён, False если заблокирован
        """
        if port in self.blocked_ports:
            self.logger.warning(f"Порт {port} заблокирован политикой фильтрации.")
            return False
        return True

    def filter_traffic(self, request: Dict[str, Any]) -> bool:
        """
        Основной метод фильтрации трафика.
        Проверяет IP, порт и дополнительные параметры запроса.
        :param request: Словарь с данными трафика, включает:
                        - src_ip: IP источника
                        - dst_ip: IP назначения
                        - dst_port: порт назначения
                        - protocol: протокол (TCP/UDP и т.д.)
                        - context: дополнительный контекст (опционально)
        :return: True, если трафик разрешён, иначе False
        """
        src_ip = request.get("src_ip")
        dst_ip = request.get("dst_ip")
        dst_port = request.get("dst_port")
        protocol = request.get("protocol", "").upper()

        self.logger.info(f"Фильтрация трафика: src_ip={src_ip}, dst_ip={dst_ip}, dst_port={dst_port}, protocol={protocol}")

        if not self.is_ip_allowed(src_ip):
            return False
        if not self.is_ip_allowed(dst_ip):
            return False
        if not self.is_port_allowed(dst_port):
            return False

        # Здесь можно добавить расширенные проверки по протоколу или контексту

        self.logger.info("Трафик разрешён по всем критериям.")
        return True
