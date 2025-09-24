# automation-core/tests/unit/test_browser_automation.py
# -*- coding: utf-8 -*-
"""
Промышленный тест браузерной автоматизации на Playwright (pytest).

Факты и источники:
- Pytest: параметры, фикстуры, tmp_path, skip и маркеры описаны в официальной документации pytest.
  https://docs.pytest.org/en/stable/how-to/fixtures.html
  https://docs.pytest.org/en/stable/reference/reference.html#pytest.skip
- Playwright for Python: запуск браузера, контексты, страницы, route, console, screenshot, tracing, storage state.
  Запуск и базовый API: https://playwright.dev/python/docs/intro
  Контекст и куки/storageState: https://playwright.dev/python/docs/auth#global-setup-and-authentication
  Маршрутизация запросов: https://playwright.dev/python/docs/network#modify-requests
  Консольные события: https://playwright.dev/python/docs/api/class-page#page-on-console
  Снимки экрана: https://playwright.dev/python/docs/screenshots
  Трейсинг: https://playwright.dev/python/docs/trace-viewer
- Встроенный локальный HTTP-сервер Python: http.server
  https://docs.python.org/3/library/http.server.html

Не могу подтвердить наличие в вашем репозитории конкретного адаптера/обертки для браузера — тест автономен.
"""

import contextlib
import http.server
import os
import socket
import socketserver
import threading
import time
from pathlib import Path
from typing import Generator, Optional

import pytest

# Попытка импорта Playwright. При отсутствии зависимостей тесты будут помечены как SKIPPED.
with contextlib.suppress(Exception):
    from playwright.sync_api import sync_playwright, Browser, BrowserContext, Page


# ---------------------------
# Константы и утилиты
# ---------------------------

HEADLESS = os.environ.get("HEADLESS", "1") != "0"
BROWSER_NAME = os.environ.get("BROWSER", "chromium")  # chromium|firefox|webkit
TEST_TIMEOUT_SEC = int(os.environ.get("TEST_TIMEOUT_SEC", "30"))
NETWORK_IDLE_MS = int(os.environ.get("NETWORK_IDLE_MS", "1000"))


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _SilentHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    # Тихий лог, чтобы не засорять вывод pytest
    def log_message(self, format, *args):
        pass


@contextlib.contextmanager
def _serve_directory(directory: Path, host: str = "127.0.0.1") -> Generator[str, None, None]:
    handler = _SilentHTTPRequestHandler
    cwd = os.getcwd()
    os.chdir(str(directory))
    try:
        port = _free_tcp_port()
        httpd = socketserver.TCPServer((host, port), handler, bind_and_activate=True)
        httpd.timeout = 0.5
        th = threading.Thread(target=httpd.serve_forever, name="httpd", daemon=True)
        th.start()
        yield f"http://{host}:{port}"
    finally:
        with contextlib.suppress(Exception):
            httpd.shutdown()
            httpd.server_close()
        os.chdir(cwd)


# ---------------------------
# Фикстуры pytest
# ---------------------------

@pytest.fixture(scope="session")
def artifacts_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("artifacts")
    return d


@pytest.fixture(scope="session")
def test_site(tmp_path_factory: pytest.TempPathFactory) -> Generator[str, None, None]:
    """
    Локальный статический сайт для тестов:
    - index.html: базовая страница без ошибок
    - console_error.html: страница, генерирующая console.error
    - images/test.png: картинка для проверки блокировки запросов
    """
    root = tmp_path_factory.mktemp("site")
    (root / "images").mkdir(parents=True, exist_ok=True)

    # Минимальный PNG (1x1) — валидный заголовок + пустые данные, достаточно для проверки запроса
    (root / "images" / "test.png").write_bytes(
        bytes.fromhex(
            "89504E470D0A1A0A0000000D49484452000000010000000108020000009077053E0000000A4944"
            "4154789C6360000002000154A22A5D0000000049454E44AE426082"
        )
    )

    (root / "index.html").write_text(
        """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ok</title></head>
<body>
  <h1>Hello, automation-core</h1>
  <img src="/images/test.png" alt="img">
  <script>console.log("boot ok");</script>
</body></html>""",
        encoding="utf-8",
    )

    (root / "console_error.html").write_text(
        """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>err</title></head>
<body>
  <script>console.error("simulated error");</script>
</body></html>""",
        encoding="utf-8",
    )

    with _serve_directory(root) as base_url:
        yield base_url


@pytest.fixture(scope="session")
def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def browser(playwright_available: bool) -> Generator[Optional["Browser"], None, None]:
    """
    Запуск браузера. Если Playwright или браузеры не установлены, тесты будут пропущены корректно.

    Источник API: https://playwright.dev/python/docs/intro
    """
    if not playwright_available:
        pytest.skip("Playwright не установлен. См. https://playwright.dev/python/docs/intro")

    try:
        with sync_playwright() as p:
            browser_launcher = getattr(p, BROWSER_NAME, None)
            if browser_launcher is None:
                pytest.skip(f"Неизвестный браузер {BROWSER_NAME}")
            browser = browser_launcher.launch(headless=HEADLESS, args=["--no-sandbox"])
            yield browser
            with contextlib.suppress(Exception):
                browser.close()
    except Exception as e:
        pytest.skip(f"Браузер недоступен: {e}")


@pytest.fixture()
def context(browser: "Browser", artifacts_dir: Path) -> Generator["BrowserContext", None, None]:
    """
    Контекст страницы с включённым трейсингом и строгими таймаутами.
    Источник API: https://playwright.dev/python/docs/trace-viewer
    """
    ctx = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 800})
    trace_path = artifacts_dir / f"trace-{int(time.time()*1000)}.zip"
    with contextlib.suppress(Exception):
        ctx.tracing.start(screenshots=True, snapshots=True, sources=False)
    try:
        yield ctx
    finally:
        with contextlib.suppress(Exception):
            ctx.tracing.stop(path=str(trace_path))
        with contextlib.suppress(Exception):
            ctx.close()


@pytest.fixture()
def page(context: "BrowserContext") -> Generator["Page", None, None]:
    """
    Страница с базовой настройкой ожиданий.
    Источник API: https://playwright.dev/python/docs/api/class-page
    """
    p = context.new_page()
    p.set_default_timeout(TEST_TIMEOUT_SEC * 1000)
    yield p
    with contextlib.suppress(Exception):
        p.close()


# ---------------------------
# Тесты
# ---------------------------

def test_navigation_and_status_ok(page: "Page", test_site: str, artifacts_dir: Path):
    """
    Навигация на локальную страницу и проверка статуса загрузки.
    Источник API: https://playwright.dev/python/docs/api/class-page#page-goto
    """
    resp = page.goto(f"{test_site}/index.html", wait_until="load")
    # Playwright Response.ok() — true для статуса 2xx.
    # https://playwright.dev/python/docs/api/class-response#response-ok
    assert resp is not None and resp.ok, "Ожидается HTTP 2xx при загрузке index.html"

    # Дополнительное ожидание тишины сети
    page.wait_for_timeout(NETWORK_IDLE_MS)

    # Скриншот как артефакт
    shot = artifacts_dir / "index.png"
    page.screenshot(path=str(shot), full_page=True)  # https://playwright.dev/python/docs/screenshots
    assert shot.exists() and shot.stat().st_size > 0, "Скриншот должен быть создан"


def test_block_image_requests_with_route(page: "Page", test_site: str):
    """
    Блокировка запросов к изображениям через route.
    Источник API: https://playwright.dev/python/docs/network#modify-requests
    """
    blocked = {"count": 0}

    def _route(route, request):
        url = request.url
        if url.endswith(".png") or url.endswith(".jpg"):
            blocked["count"] += 1
            return route.abort()
        return route.continue_()

    page.route("**/*", _route)
    page.goto(f"{test_site}/index.html", wait_until="load")
    page.wait_for_timeout(NETWORK_IDLE_MS)
    assert blocked["count"] >= 1, "Должны быть заблокированы обращения к изображениям"


def test_console_should_not_have_errors(page: "Page", test_site: str):
    """
    Отслеживание console.error на странице без ошибок.
    Источник API: https://playwright.dev/python/docs/api/class-page#page-on-console
    """
    errors = []

    def _on_console(msg):
        if msg.type == "error":
            errors.append(msg.text)

    page.on("console", _on_console)
    page.goto(f"{test_site}/index.html", wait_until="load")
    page.wait_for_timeout(NETWORK_IDLE_MS)
    assert not errors, f"Не ожидаем console.error, получено: {errors}"


def test_console_should_capture_errors(page: "Page", test_site: str):
    """
    На странице с преднамеренной ошибкой ожидаем хотя бы один console.error.
    Источник API: https://playwright.dev/python/docs/api/class-page#page-on-console
    """
    errors = []

    def _on_console(msg):
        if msg.type == "error":
            errors.append(msg.text)

    page.on("console", _on_console)
    page.goto(f"{test_site}/console_error.html", wait_until="load")
    page.wait_for_timeout(NETWORK_IDLE_MS)
    assert any("simulated error" in e for e in errors), "Ожидаем 'simulated error' в console.error"


def test_storage_state_persistence(browser: "Browser", artifacts_dir: Path, test_site: str):
    """
    Проверяем, что cookie сохраняются и подхватываются новым контекстом через storage_state.
    Источники:
    - storageState: https://playwright.dev/python/docs/auth#global-setup-and-authentication
    - cookies API: https://playwright.dev/python/docs/api/class-browsercontext#browser-context-add-cookies
    """
    state_path = artifacts_dir / f"state-{int(time.time()*1000)}.json"

    # Первый контекст: устанавливаем cookie и сохраняем state
    ctx1 = browser.new_context()
    p1 = ctx1.new_page()
    p1.goto(f"{test_site}/index.html", wait_until="load")
    ctx1.add_cookies([{"name": "session", "value": "abc123", "domain": "127.0.0.1", "path": "/"}])
    # Сохранение storage state в файл
    ctx1.storage_state(path=str(state_path))
    ctx1.close()
    assert state_path.exists() and state_path.stat().st_size > 0, "Файл storage state должен существовать"

    # Второй контекст: подхватываем state и читаем cookie через evaluate
    ctx2 = browser.new_context(storage_state=str(state_path))
    p2 = ctx2.new_page()
    p2.goto(f"{test_site}/index.html", wait_until="load")
    cookies = ctx2.cookies()
    # https://playwright.dev/python/docs/api/class-browsercontext#browser-context-cookies
    assert any(c["name"] == "session" and c["value"] == "abc123" for c in cookies), "Куки должны сохраниться"
    ctx2.close()


@pytest.mark.timeout(TEST_TIMEOUT_SEC)
def test_page_close_and_context_close_are_clean(page: "Page", context: "BrowserContext"):
    """
    Корректное закрытие страницы и контекста без исключений.
    Источники:
    - Page.close: https://playwright.dev/python/docs/api/class-page#page-close
    - BrowserContext.close: https://playwright.dev/python/docs/api/class-browsercontext#browser-context-close
    """
    # Создаём дополнительную вкладку и закрываем
    p = context.new_page()
    p.goto("about:blank")
    p.close()
    # Базовая страница закроется в фикстуре; проверим, что контекст способен открывать новые страницы
    p2 = context.new_page()
    p2.goto("about:blank")
    assert p2.title() == "", "Ожидается пустой title у about:blank"
    p2.close()
