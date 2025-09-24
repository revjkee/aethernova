from typing import Dict, List, Callable, Any

class Route:
    def __init__(self, path: str, methods: List[str], handler: Callable[..., Any], tags: List[str], access_level: str):
        self.path = path
        self.methods = methods
        self.handler = handler
        self.tags = tags
        self.access_level = access_level

class RouterMap:
    def __init__(self):
        self.routes: Dict[str, Route] = {}

    def add_route(self, route_name: str, path: str, methods: List[str], handler: Callable[..., Any], tags: List[str], access_level: str):
        if route_name in self.routes:
            raise ValueError(f"Route {route_name} already exists")
        self.routes[route_name] = Route(path, methods, handler, tags, access_level)

    def get_route(self, route_name: str) -> Route:
        if route_name not in self.routes:
            raise KeyError(f"Route {route_name} not found")
        return self.routes[route_name]

    def get_routes_by_tag(self, tag: str) -> List[Route]:
        return [route for route in self.routes.values() if tag in route.tags]

    def get_routes_by_access(self, access_level: str) -> List[Route]:
        return [route for route in self.routes.values() if route.access_level == access_level]

# Пример инициализации роутов, реализация хендлеров в других модулях

router_map = RouterMap()

# Здесь примеры добавления маршрутов будут происходить в процессе запуска приложения
# router_map.add_route(
#     route_name="get_user",
#     path="/user/{user_id}",
#     methods=["GET"],
#     handler=get_user_handler,
#     tags=["user", "read"],
#     access_level="user"
# )

# router_map.add_route(
#     route_name="admin_dashboard",
#     path="/admin/dashboard",
#     methods=["GET"],
#     handler=admin_dashboard_handler,
#     tags=["admin", "dashboard"],
#     access_level="admin"
# )
