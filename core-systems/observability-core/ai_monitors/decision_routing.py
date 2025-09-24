import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger("DecisionRouter")
logger.setLevel(logging.INFO)

class RoutePolicy:
    """
    Представляет маршрут и условие активации на основе правил, меток и уровня приоритета
    """
    def __init__(self, name: str, priority: int, match_tags: List[str], destination: str):
        self.name = name
        self.priority = priority
        self.match_tags = set(match_tags)
        self.destination = destination

    def matches(self, event_tags: List[str]) -> bool:
        return bool(self.match_tags.intersection(event_tags))

class DecisionRouter:
    """
    Интеллектуальный маршрутизатор решений:
    - Маршрутизирует алерты/события по приоритету, контексту, меткам
    - Позволяет динамически переопределять правила маршрутизации
    - Интегрируется с RBAC, AlertManager, EventBus, Slack, Webhook
    """
    def __init__(self):
        self.routes: List[RoutePolicy] = []
        self.default_destination = "alertmanager/main"

    def add_policy(self, name: str, priority: int, match_tags: List[str], destination: str):
        policy = RoutePolicy(name, priority, match_tags, destination)
        self.routes.append(policy)
        self.routes.sort(key=lambda x: x.priority, reverse=True)
        logger.info(f"[ROUTING] Policy added: {name} -> {destination}")

    def route(self, event: Dict[str, Any]) -> str:
        tags = event.get("tags", [])
        for policy in self.routes:
            if policy.matches(tags):
                logger.info(f"[ROUTE MATCH] {event.get('name')} matched policy {policy.name}")
                return policy.destination
        logger.warning(f"[DEFAULT ROUTE] {event.get('name')} routed to default")
        return self.default_destination

    def explain_routing(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Возвращает объяснение маршрута
        """
        tags = event.get("tags", [])
        for policy in self.routes:
            if policy.matches(tags):
                return {
                    "matched_policy": policy.name,
                    "destination": policy.destination,
                    "priority": policy.priority,
                    "matched_tags": list(policy.match_tags.intersection(tags))
                }
        return {
            "matched_policy": "default",
            "destination": self.default_destination,
            "matched_tags": [],
        }

    def list_routes(self) -> List[Dict[str, Any]]:
        return [{
            "name": route.name,
            "priority": route.priority,
            "match_tags": list(route.match_tags),
            "destination": route.destination
        } for route in self.routes]

    def remove_policy(self, name: str) -> bool:
        before = len(self.routes)
        self.routes = [r for r in self.routes if r.name != name]
        after = len(self.routes)
        if before > after:
            logger.info(f"[ROUTING] Policy {name} removed.")
            return True
        return False
