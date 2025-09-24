import logging
from typing import Dict, Any

class PerimeterController:
    """
    Контроллер периметра для Zero Trust Architecture.
    Управляет проверкой и контролем всех входящих и исходящих сетевых запросов,
    обеспечивая выполнение принципов минимальных прав и непрерывной аутентификации.
    """

    def __init__(self, policy_engine):
        """
        Инициализация контроллера с движком политики.
        :param policy_engine: Экземпляр PolicyEngine для оценки доступа
        """
        self.policy_engine = policy_engine
        self.logger = logging.getLogger("ZTNA.PerimeterController")
        self.logger.setLevel(logging.INFO)

    def inspect_request(self, request: Dict[str, Any]) -> bool:
        """
        Проверка входящего сетевого запроса на соответствие политике доступа.
        :param request: Словарь с данными запроса, содержащий:
                        - user: данные пользователя
                        - device: данные устройства
                        - resource: целевой ресурс
                        - context: дополнительный контекст (IP, время и т.д.)
        :return: True, если доступ разрешен, иначе False
        """
        user = request.get("user")
        device = request.get("device")
        resource = request.get("resource")
        context = request.get("context", {})

        self.logger.info(f"Инспекция запроса: user={user.get('id')}, resource={resource}")

        access_granted = self.policy_engine.evaluate_access(user, device, resource, context)
        if access_granted:
            self.logger.info(f"Доступ разрешен для пользователя {user.get('id')} к ресурсу {resource}")
        else:
            self.logger.warning(f"Доступ запрещен для пользователя {user.get('id')} к ресурсу {resource}")

        return access_granted

    def enforce_perimeter(self, request: Dict[str, Any]) -> bool:
        """
        Принудительное применение политики безопасности на уровне периметра.
        Могут быть добавлены дополнительные проверки, например, анализ угроз или инъекций.
        :param request: Данные сетевого запроса
        :return: Результат проверки (True/False)
        """
        # Расширяемость: сюда можно добавить дополнительные слои защиты
        return self.inspect_request(request)
