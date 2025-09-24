import pytest
from llmops.router import Router, RouteNotFoundError

@pytest.fixture
def router():
    r = Router()
    r.add_route("/home", lambda: "home page")
    r.add_route("/about", lambda: "about page")
    return r

def test_route_exists(router):
    handler = router.get_handler("/home")
    assert handler() == "home page"

def test_route_not_found(router):
    with pytest.raises(RouteNotFoundError):
        router.get_handler("/nonexistent")

def test_add_route_overwrites(router):
    router.add_route("/home", lambda: "new home page")
    handler = router.get_handler("/home")
    assert handler() == "new home page"

def test_remove_route(router):
    router.remove_route("/about")
    with pytest.raises(RouteNotFoundError):
        router.get_handler("/about")

def test_list_routes(router):
    routes = router.list_routes()
    assert "/home" in routes
    assert "/about" in routes

def test_route_handler_callable(router):
    handler = router.get_handler("/home")
    assert callable(handler)

