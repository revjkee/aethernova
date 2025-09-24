# automation-core/tests/fixtures/browser.py
# -*- coding: utf-8 -*-
"""
Pytest fixtures for Playwright (synchronous API).

Фикстуры:
- playwright_browser (session): запускает выбранный браузер (chromium/firefox/webkit).
- browser (alias)           (session): ссылка на playwright_browser.
- context                   (function): новый BrowserContext с опциями (video/trace/base_url/locale/timezone/...).
- page                      (function): новая страница в контексте.
- test_artifacts_dir        (function): директория артефактов для текущего теста.

Поведение:
- HEADLESS:      PW_HEADLESS=true|false (по умолчанию true)
- BROWSER:       PW_BROWSER=chromium|firefox|webkit (по умолчанию chromium)
- CHANNEL:       PW_CHANNEL=chrome|msedge|... (только для chromium, опционально)
- SLOWMO (мс):   PW_SLOWMO_MS=0
- PROXY:         PW_PROXY=http://host:port или socks5://host:port (опционально)
                 PW_PROXY_BYPASS=.example.com,localhost (опционально)
                 PW_PROXY_USERNAME / PW_PROXY_PASSWORD (опционально)
- BASE_URL:      PW_BASE_URL=https://example.local (используется new_context(base_url=...))
- LOCALE:        PW_LOCALE=ru-RU
- TIMEZONE:      PW_TIMEZONE=Europe/Stockholm
- USER_AGENT:    PW_USER_AGENT="MyAgent/1.0"
- VIEWPORT:      PW_VIEWPORT=1280x720 (или пусто для значения по умолчанию)
- IGNORE_HTTPS:  PW_IGNORE_HTTPS_ERRORS=true|false (по умолчанию true)
- ACCEPT_DL:     PW_ACCEPT_DOWNLOADS=true|false (по умолчанию true)
- DOWNLOADS_DIR: PW_DOWNLOADS_DIR=artifacts/playwright/downloads
- VIDEO:         PW_VIDEO=off|on|retain-on-failure (по умолчанию retain-on-failure)
- TRACE:         PW_TRACE=off|on|retain-on-failure (по умолчанию retain-on-failure)
- ARTIFACTS:     PW_ARTIFACTS=artifacts/playwright (корень для артефактов)

Примечания:
- Видео сохраняется при закрытии контекста; трассировка сохраняется в *.zip через context.tracing.stop(path=...).
- Для корректного статуса теста в teardown используется pytest hook pytest_runtest_makereport.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Generator, Optional, Tuple

import pytest
from playwright.sync_api import Browser, BrowserContext, Page, Playwright, sync_playwright


# -----------------------------
# Утилиты
# -----------------------------

def _bool_env(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}

def _int_env(name: str, default: int) -> int:
    v = os.getenv(name)
    if not v:
        return default
    try:
        return int(v)
    except ValueError:
        return default

def _parse_viewport(s: Optional[str]) -> Optional[Tuple[int, int]]:
    if not s:
        return None
    m = re.match(r"^\s*(\d+)\s*x\s*(\d+)\s*$", s)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))

def _now_stamp() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def _ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


# -----------------------------
# Pytest: статус теста в teardown
# (репорт прикрепляется к request.node)
# -----------------------------

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)


# -----------------------------
# Фикстуры артефактов
# -----------------------------

@pytest.fixture(scope="session")
def artifacts_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = Path(os.getenv("PW_ARTIFACTS", "artifacts/playwright"))
    # Сессия — отдельная подпапка по времени
    root = base / _now_stamp()
    return _ensure_dir(root)

@pytest.fixture
def test_artifacts_dir(artifacts_root: Path, request: pytest.FixtureRequest) -> Path:
    # nodeid подходит не всем ФС: заменим / и :: на _
    safe = re.sub(r"[\\/:\s]+", "_", request.node.nodeid)
    path = artifacts_root / safe
    return _ensure_dir(path)


# -----------------------------
# Playwright lifecycle
# -----------------------------

@pytest.fixture(scope="session")
def _playwright() -> Generator[Playwright, None, None]:
    with sync_playwright() as p:
        yield p  # p.stop() вызовется контекст-менеджером

def _launch_browser(p: Playwright) -> Browser:
    name = os.getenv("PW_BROWSER", "chromium").strip().lower()
    headless = _bool_env("PW_HEADLESS", True)
    slowmo = _int_env("PW_SLOWMO_MS", 0)

    proxy = None
    if os.getenv("PW_PROXY"):
        proxy = {
            "server": os.getenv("PW_PROXY"),
            "bypass": os.getenv("PW_PROXY_BYPASS") or None,
            "username": os.getenv("PW_PROXY_USERNAME") or None,
            "password": os.getenv("PW_PROXY_PASSWORD") or None,
        }

    launch_kw: Dict = {"headless": headless, "slow_mo": slowmo}
    if proxy:
        launch_kw["proxy"] = proxy

    if name == "chromium":
        channel = os.getenv("PW_CHANNEL")  # e.g., "chrome" or "msedge"
        if channel:
            launch_kw["channel"] = channel
        # Рекомендованные флаги для CI-контейнеров
        if os.getenv("CI"):
            launch_kw.setdefault("args", []).extend(["--no-sandbox", "--disable-dev-shm-usage"])
        return p.chromium.launch(**launch_kw)
    elif name == "firefox":
        return p.firefox.launch(**launch_kw)
    elif name == "webkit":
        return p.webkit.launch(**launch_kw)
    else:
        raise ValueError(f"Unsupported PW_BROWSER={name!r}")

@pytest.fixture(scope="session")
def playwright_browser(_playwright: Playwright) -> Generator[Browser, None, None]:
    browser = _launch_browser(_playwright)
    try:
        yield browser
    finally:
        browser.close()

# Alias для совместимости с привычным именем
@pytest.fixture(scope="session")
def browser(playwright_browser: Browser) -> Browser:
    return playwright_browser


# -----------------------------
# Context & Page
# -----------------------------

def _context_options(test_dir: Path) -> Dict:
    opts: Dict = {}
    # Базовые опции контекста
    base_url = os.getenv("PW_BASE_URL")
    if base_url:
        opts["base_url"] = base_url  # требует Playwright ≥1.20

    viewport = _parse_viewport(os.getenv("PW_VIEWPORT"))
    if viewport:
        opts["viewport"] = {"width": viewport[0], "height": viewport[1]}

    if _bool_env("PW_ACCEPT_DOWNLOADS", True):
        opts["accept_downloads"] = True
        downloads_dir = _ensure_dir(Path(os.getenv("PW_DOWNLOADS_DIR", str(test_dir / "downloads"))))
        opts["downloads_path"] = str(downloads_dir)

    if _bool_env("PW_IGNORE_HTTPS_ERRORS", True):
        opts["ignore_https_errors"] = True

    locale = os.getenv("PW_LOCALE")
    if locale:
        opts["locale"] = locale

    tz = os.getenv("PW_TIMEZONE")
    if tz:
        opts["timezone_id"] = tz

    ua = os.getenv("PW_USER_AGENT")
    if ua:
        opts["user_agent"] = ua

    # Видео
    video_mode = os.getenv("PW_VIDEO", "retain-on-failure").strip().lower()
    if video_mode in {"on", "retain-on-failure"}:
        video_dir = _ensure_dir(test_dir / "video")
        opts["record_video_dir"] = str(video_dir)

    # Доп. заголовки при необходимости:
    # if os.getenv("PW_EXTRA_HEADERS"):
    #     opts["extra_http_headers"] = json.loads(os.getenv("PW_EXTRA_HEADERS"))

    return opts

@pytest.fixture
def context(browser: Browser, request: pytest.FixtureRequest, test_artifacts_dir: Path) -> Generator[BrowserContext, None, None]:
    opts = _context_options(test_artifacts_dir)
    ctx = browser.new_context(**opts)

    # Трассировка
    trace_mode = os.getenv("PW_TRACE", "retain-on-failure").strip().lower()
    trace_path = test_artifacts_dir / f"trace-{_now_stamp()}.zip"
    if trace_mode in {"on", "retain-on-failure"}:
        ctx.tracing.start(screenshots=True, snapshots=True, sources=True)

    try:
        yield ctx
    finally:
        failed = bool(getattr(request.node, "rep_call", None) and request.node.rep_call.failed)

        # Снимок экрана при падении
        try:
            if failed:
                # Попытаться сделать скриншот с любой открытой страницы
                for pg in ctx.pages:
                    # сохраняем первый успешный
                    pg.screenshot(path=str(test_artifacts_dir / f"screenshot-fail-{_now_stamp()}.png"), full_page=True)
                    break
        except Exception:
            pass

        # Трассировка: сохраняем если включен режим on или retain-on-failure & тест упал
        try:
            if trace_mode == "on" or (trace_mode == "retain-on-failure" and failed):
                ctx.tracing.stop(path=str(trace_path))
            else:
                ctx.tracing.stop() if trace_mode in {"on", "retain-on-failure"} else None
        except Exception:
            pass

        # Важно: закрыть контекст, чтобы видео были записаны на диск
        ctx.close()

@pytest.fixture
def page(context: BrowserContext) -> Generator[Page, None, None]:
    pg = context.new_page()
    try:
        yield pg
    finally:
        # Закрытие страницы позволяет Playwright корректно завершить запись видео
        pg.close()
