import logging
from typing import List, Dict, Any

class PolicyEngine:
    """
    Класс для оценки и применения политик Zero Trust Network Access (ZTNA).
    Обеспечивает контроль доступа на основе динамических политик с учетом
    пользователей, устройств, контекста и сетевого поведения.
    """

    def __init__(self, policies: List[Dict[str, Any]]):
        """
        Инициализация движка с набором политик.
        :param policies: Список политик доступа, каждая политика — словарь с правилами.
        """
        self.policies = policies
        self.logger = logging.getLogger("ZTNA.PolicyEngine")
        self.logger.setLevel(logging.INFO)

    def evaluate_access(self, user: Dict[str, Any], device: Dict[str, Any], resource: str, context: Dict[str, Any]) -> bool:
        """
        Оценка доступа пользователя к ресурсу с учетом устройства и контекста.
        :param user: Информация о пользователе (id, роль, статус, группы)
        :param device: Характеристики устройства (id, тип, состояние безопасности)
        :param resource: Идентификатор ресурса или сервиса
        :param context: Дополнительный контекст (время, местоположение, сеть)
        :return: True если доступ разрешен, False — запрещен
        """
        self.logger.info(f"Оценка доступа: user={user['id']}, device={device['id']}, resource={resource}")

        for policy in self.policies:
            if not self._matches_policy(policy, user, device, resource, context):
                continue

            if policy.get("action") == "deny":
                self.logger.warning(f"Доступ запрещен политикой: {policy['id']}")
                return False
            elif policy.get("action") == "allow":
                self.logger.info(f"Доступ разрешен политикой: {policy['id']}")
                return True

        self.logger.warning("Доступ по умолчанию запрещен")
        return False

    def _matches_policy(self, policy: Dict[str, Any], user: Dict[str, Any], device: Dict[str, Any], resource: str, context: Dict[str, Any]) -> bool:
        """
        Проверка соответствия условий политики параметрам доступа.
        :param policy: Политика для проверки
        :return: True если условия совпадают, иначе False
        """
        # Проверка ресурса
        if "resources" in policy and resource not in policy["resources"]:
            return False

        # Проверка ролей пользователя
        if "roles" in policy:
            if user.get("role") not in policy["roles"]:
                return False

        # Проверка состояния устройства
        if "device_status" in policy:
            if device.get("status") not in policy["device_status"]:
                return False

        # Проверка времени доступа (например, рабочие часы)
        if "time_restrictions" in policy:
            current_hour = context.get("hour", -1)
            allowed_hours = policy["time_restrictions"]
            if not (allowed_hours[0] <= current_hour <= allowed_hours[1]):
                return False

        # Проверка IP или геолокации
        if "ip_ranges" in policy:
            client_ip = context.get("ip_address")
            if not self._ip_in_ranges(client_ip, policy["ip_ranges"]):
                return False

        return True

    def _ip_in_ranges(self, ip: str, ranges: List[str]) -> bool:
        """
        Проверка IP-адреса на вхождение в указанные диапазоны.
        :param ip: IP адрес клиента
        :param ranges: Список CIDR или диапазонов
        :return: True если IP входит в один из диапазонов
        """
        import ipaddress
        try:
            ip_addr = ipaddress.ip_address(ip)
            for cidr in ranges:
                if ip_addr in ipaddress.ip_network(cidr):
                    return True
            return False
        except ValueError:
            self.logger.error(f"Некорректный IP адрес: {ip}")
            return False
