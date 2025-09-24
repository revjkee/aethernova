# automation-core/src/automation_core/browser_automation/playwright_driver.py
# SPDX-License-Identifier: MIT
"""
Высокоуровневый асинхронный драйвер Playwright для промышленной автоматизации.

Ключевые возможности:
- Безопасный жизненный цикл: start() / close(), контексты по именам
- Поддержка chromium/firefox/webkit, headless/headful, slow_mo
- Прокси, локаль, таймзона, геолокация, разрешения, custom UA/headers, ignore_https_errors
- Папка для загрузок, запись видео, трассировка (start/stop, экспорт)
- Универсальные ретраи с экспоненциальным бэкоффом и настраиваемыми условиями
- Утилиты: goto, click, fill, type, press, select, check/uncheck, upload_files
- Ожидания: wait_for_selector, wait_network_idle, ожидание состояния
- Блокировка URL/паттернов, роутинг запросов
- Куки/StorageState: импорт/экспорт, сохранение/загрузка
- Скриншоты страницы/элементов, сохранение HTML

Зависимости:
    pip install playwright
    playwright install  # установка движков (однократно вне кода)

Примечание:
- Модуль использует исключительно публичные API Playwright и стандартную библиотеку.
- Для синхронного кода рекомендуется вызывать эти корутины через свой event loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import pathlib
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

from playwright.async_api import (  # type: ignore
    async_playwright,
    Browser,
    BrowserContext,
    Page,
    Playwright,
    Error as PWError,
    TimeoutError as PWTimeout,
    Request,
    Route,
)

# ------------------------------- Логирование -------------------------------

LOGGER = logging.getLogger("automation_core.playwright_driver")
if not LOGGER.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s :: %(message)s"))
    LOGGER.addHandler(_h)
    LOGGER.setLevel(logging.INFO)


# ------------------------------- Конфигурация ------------------------------

BrowserName = Literal["chromium", "firefox", "webkit"]


@dataclass(slots=True)
class RetryPolicy:
    """Политика ретраев для нестабильных операций UI/сети."""
    max_attempts: int = 3
    backoff_initial: float = 0.4  # секунды
    backoff_factor: float = 2.0
    backoff_max: float = 5.0
    retry_on_timeouts: bool = True
    retry_on_errors: bool = True

    def delay_for(self, attempt: int) -> float:
        base = self.backoff_initial * (self.backoff_factor ** max(0, attempt - 1))
        return min(self.backoff_max, base)


@dataclass(slots=True)
class BrowserConfig:
    """Единый конфиг браузера/контекста."""
    browser: BrowserName = "chromium"
    headless: bool = True
    slow_mo_ms: int = 0

    # Навигация/вьюпорт
    viewport: Optional[Tuple[int, int]] = (1366, 768)
    device_scale_factor: Optional[float] = None

    # Сеть/HTTPS/прокси
    proxy_server: Optional[str] = None               # "http://host:port" | "socks5://..."
    proxy_username: Optional[str] = None
    proxy_password: Optional[str] = None
    ignore_https_errors: bool = False

    # Идентификация
    user_agent: Optional[str] = None
    extra_headers: Dict[str, str] = field(default_factory=dict)
    base_url: Optional[str] = None
    locale: Optional[str] = None                     # например, "en-US"
    timezone_id: Optional[str] = None                # например, "Europe/Stockholm"

    # Гео/разрешения
    geolocation: Optional[Tuple[float, float]] = None  # (lat, lon)
    permissions: List[str] = field(default_factory=list)

    # Хранилище и загрузки
    storage_state_path: Optional[pathlib.Path] = None
    downloads_dir: Optional[pathlib.Path] = None
    record_video_dir: Optional[pathlib.Path] = None

    # Трассировка
    enable_tracing: bool = False
    trace_dir: Optional[pathlib.Path] = None         # куда экспортировать trace.zip

    # Таймауты
    navigation_timeout_ms: int = 30000
    action_timeout_ms: int = 15000

    # Политика ретраев по умолчанию
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)


# ------------------------------ Исключения ---------------------------------

class DriverError(RuntimeError):
    """Базовая ошибка драйвера."""


class ContextExistsError(DriverError):
    """Контекст с таким именем уже существует."""


class ContextNotFoundError(DriverError):
    """Контекст не найден."""


# ------------------------------ Вспомогательное ----------------------------

def _ensure_dir(p: Optional[pathlib.Path]) -> Optional[str]:
    if p is None:
        return None
    p.mkdir(parents=True, exist_ok=True)
    return str(p)


def _mk_proxy(cfg: BrowserConfig) -> Optional[Dict[str, str]]:
    if not cfg.proxy_server:
        return None
    proxy: Dict[str, str] = {"server": cfg.proxy_server}
    if cfg.proxy_username:
        proxy["username"] = cfg.proxy_username
    if cfg.proxy_password:
        proxy["password"] = cfg.proxy_password
    return proxy


async def _retry(
    op: Callable[[], Awaitable[Any]],
    *,
    policy: RetryPolicy,
    opname: str,
) -> Any:
    last_exc: Optional[BaseException] = None
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return await op()
        except PWTimeout as e:
            last_exc = e
            if not policy.retry_on_timeouts or attempt >= policy.max_attempts:
                break
        except PWError as e:
            last_exc = e
            if not policy.retry_on_errors or attempt >= policy.max_attempts:
                break
        delay = policy.delay_for(attempt)
        LOGGER.warning("Retrying %s (attempt %d/%d) after %.2fs due to %s",
                       opname, attempt, policy.max_attempts, delay, type(last_exc).__name__)
        await asyncio.sleep(delay)
    assert last_exc is not None
    raise last_exc


# -------------------------------- Драйвер ----------------------------------

class PlaywrightDriver:
    """
    Высокоуровневый асинхронный драйвер поверх Playwright.

    Жизненный цикл:
        driver = PlaywrightDriver(cfg)
        await driver.start()
        ... работа ...
        await driver.close()

    Контексты:
        await driver.new_context("auth", storage_state_path=Path("state.json"))
        page = await driver.new_page("auth")
    """

    def __init__(self, config: BrowserConfig) -> None:
        self.cfg = config
        self._plw: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._contexts: Dict[str, BrowserContext] = {}
        self._default_ctx_name = "_default"

    # -------- Контекст-менеджер --------

    async def __aenter__(self) -> "PlaywrightDriver":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    # -------- Жизненный цикл --------

    async def start(self) -> None:
        if self._plw is not None:
            return
        LOGGER.info("Starting Playwright (%s, headless=%s)", self.cfg.browser, self.cfg.headless)
        self._plw = await async_playwright().start()

        browser_launcher = {
            "chromium": self._plw.chromium,
            "firefox": self._plw.firefox,
            "webkit": self._plw.webkit,
        }[self.cfg.browser]

        self._browser = await browser_launcher.launch(
            headless=self.cfg.headless,
            slow_mo=self.cfg.slow_mo_ms or 0,
            proxy=_mk_proxy(self.cfg),
        )

        # Создаём базовый контекст
        await self.new_context(self._default_ctx_name, storage_state_path=self.cfg.storage_state_path)

    async def close(self) -> None:
        # Закрываем контексты
        for name in list(self._contexts.keys()):
            with contextlib.suppress(Exception):
                await self._close_context(name)
        self._contexts.clear()

        # Закрываем браузер и сам Playwright
        if self._browser is not None:
            with contextlib.suppress(Exception):
                await self._browser.close()
            self._browser = None

        if self._plw is not None:
            with contextlib.suppress(Exception):
                await self._plw.stop()
            self._plw = None
        LOGGER.info("Playwright stopped")

    # -------- Контексты --------

    async def new_context(
        self,
        name: str,
        *,
        storage_state_path: Optional[pathlib.Path] = None,
        downloads_dir: Optional[pathlib.Path] = None,
        record_video_dir: Optional[pathlib.Path] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        permissions: Optional[Sequence[str]] = None,
    ) -> BrowserContext:
        if name in self._contexts:
            raise ContextExistsError(f"context '{name}' already exists")
        if self._browser is None:
            raise DriverError("browser is not started")

        # Базовые опции контекста
        ctx_opts: Dict[str, Any] = dict(
            user_agent=self.cfg.user_agent,
            viewport={"width": self.cfg.viewport[0], "height": self.cfg.viewport[1]} if self.cfg.viewport else None,
            device_scale_factor=self.cfg.device_scale_factor,
            base_url=self.cfg.base_url,
            locale=self.cfg.locale,
            timezone_id=self.cfg.timezone_id,
            geolocation={"latitude": self.cfg.geolocation[0], "longitude": self.cfg.geolocation[1]}
            if self.cfg.geolocation else None,
            permissions=list(permissions) if permissions is not None else (self.cfg.permissions or None),
            record_video_dir=_ensure_dir(record_video_dir or self.cfg.record_video_dir),
            ignore_https_errors=self.cfg.ignore_https_errors,
            accept_downloads=True,
        )

        # Уберём None, чтобы не ломать дефолты Playwright
        ctx_opts = {k: v for k, v in ctx_opts.items() if v is not None}

        # Создание контекста
        ctx = await self._browser.new_context(**ctx_opts)

        # Заголовки
        merged_headers = dict(self.cfg.extra_headers or {})
        if extra_headers:
            merged_headers.update(extra_headers)
        if merged_headers:
            await ctx.set_extra_http_headers(merged_headers)

        # Папка загрузок
        dld_dir = downloads_dir or self.cfg.downloads_dir
        if dld_dir:
            dld_dir.mkdir(parents=True, exist_ok=True)
            # В Plawright для Python директория загрузок задаётся на уровне контекста через accept_downloads=True
            # и последующей обработкой события 'download'. Здесь настроим обработчик.
            @ctx.on("page")
            async def _on_page(page: Page) -> None:  # pragma: no cover - обработчик событий
                page.on("download", lambda dl: asyncio.create_task(dl.save_as(str(dld_dir / dl.suggested_filename))))

        # Таймауты
        ctx.set_default_navigation_timeout(self.cfg.navigation_timeout_ms)
        ctx.set_default_timeout(self.cfg.action_timeout_ms)

        # Storage state
        if storage_state_path and storage_state_path.exists():
            await ctx.add_cookies(json.loads(storage_state_path.read_text(encoding="utf-8")).get("cookies", []))

        # Трейс
        if self.cfg.enable_tracing:
            await ctx.tracing.start(screenshots=True, snapshots=True, sources=True)

        self._contexts[name] = ctx
        LOGGER.info("Created context '%s'", name)
        return ctx

    async def _close_context(self, name: str) -> None:
        ctx = self._contexts.get(name)
        if not ctx:
            return

        # Экспорт трейса, если включено
        if self.cfg.enable_tracing and self.cfg.trace_dir:
            self.cfg.trace_dir.mkdir(parents=True, exist_ok=True)
            trace_path = self.cfg.trace_dir / f"trace_{name}_{int(time.time())}.zip"
            with contextlib.suppress(Exception):
                await ctx.tracing.stop(path=str(trace_path))
                LOGGER.info("Trace exported: %s", trace_path)

        with contextlib.suppress(Exception):
            await ctx.close()
        self._contexts.pop(name, None)
        LOGGER.info("Closed context '%s'", name)

    def get_context(self, name: Optional[str] = None) -> BrowserContext:
        ctx = self._contexts.get(name or self._default_ctx_name)
        if not ctx:
            raise ContextNotFoundError(f"context '{name or self._default_ctx_name}' not found")
        return ctx

    async def close_context(self, name: str) -> None:
        await self._close_context(name)

    # -------- Страницы --------

    async def new_page(self, context_name: Optional[str] = None) -> Page:
        ctx = self.get_context(context_name)
        page = await ctx.new_page()
        return page

    # -------- Блокировка/роутинг --------

    async def block_urls(self, patterns: Sequence[str], *, context_name: Optional[str] = None) -> None:
        """
        Блокирует URL по паттернам (glob/regex поддерживает Playwright).
        """
        ctx = self.get_context(context_name)

        async def _route(route: Route, request: Request) -> None:
            await route.abort()

        for pat in patterns:
            await ctx.route(pat, _route)
        LOGGER.info("Blocked patterns on context '%s': %s", context_name or self._default_ctx_name, patterns)

    async def route(
        self,
        pattern: str,
        handler: Callable[[Route, Request], Awaitable[None]],
        *,
        context_name: Optional[str] = None,
    ) -> None:
        ctx = self.get_context(context_name)
        await ctx.route(pattern, handler)

    # -------- Навигация/действия (с ретраями) --------

    async def goto(
        self,
        page: Page,
        url: str,
        *,
        wait_until: Literal["load", "domcontentloaded", "networkidle", "commit"] = "networkidle",
        policy: Optional[RetryPolicy] = None,
        referer: Optional[str] = None,
    ) -> None:
        pol = policy or self.cfg.retry_policy

        async def _op():
            await page.goto(url, wait_until=wait_until, referer=referer)
        await _retry(_op, policy=pol, opname=f"goto({url})")

    async def wait_network_idle(self, page: Page, *, idle_ms: int = 500, timeout_ms: Optional[int] = None) -> None:
        """
        Ожидает относительную сетевую тишину: навигация + небольшой idle.
        """
        await page.wait_for_load_state("networkidle", timeout=timeout_ms or self.cfg.navigation_timeout_ms)
        await asyncio.sleep(idle_ms / 1000.0)

    async def click(self, page: Page, selector: str, *, policy: Optional[RetryPolicy] = None) -> None:
        pol = policy or self.cfg.retry_policy

        async def _op():
            await page.click(selector)
        await _retry(_op, policy=pol, opname=f"click({selector})")

    async def fill(self, page: Page, selector: str, value: str, *, policy: Optional[RetryPolicy] = None) -> None:
        pol = policy or self.cfg.retry_policy

        async def _op():
            await page.fill(selector, value)
        await _retry(_op, policy=pol, opname=f"fill({selector})")

    async def type(self, page: Page, selector: str, text: str, *, delay_ms: int = 0) -> None:
        await page.type(selector, text, delay=delay_ms)

    async def press(self, page: Page, selector: str, key: str) -> None:
        await page.press(selector, key)

    async def select(self, page: Page, selector: str, values: Sequence[str]) -> None:
        await page.select_option(selector, values)

    async def check(self, page: Page, selector: str, *, checked: bool = True) -> None:
        if checked:
            await page.check(selector)
        else:
            await page.uncheck(selector)

    async def upload_files(self, page: Page, selector: str, paths: Sequence[pathlib.Path]) -> None:
        files = [str(p) for p in paths]
        await page.set_input_files(selector, files)

    async def wait_for_selector(
        self,
        page: Page,
        selector: str,
        *,
        state: Literal["attached", "detached", "visible", "hidden"] = "visible",
        timeout_ms: Optional[int] = None,
    ) -> None:
        await page.wait_for_selector(selector, state=state, timeout=timeout_ms or self.cfg.action_timeout_ms)

    async def eval_js(self, page: Page, expression: str, *args: Any) -> Any:
        return await page.evaluate(expression, *args)

    # -------- Скриншоты/HTML --------

    async def screenshot_page(
        self,
        page: Page,
        path: pathlib.Path,
        *,
        full_page: bool = True,
        quality: Optional[int] = None,  # для JPEG
        omit_background: bool = False,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        await page.screenshot(path=str(path), full_page=full_page, quality=quality, omit_background=omit_background)

    async def screenshot_element(self, page: Page, selector: str, path: pathlib.Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        el = await page.wait_for_selector(selector, state="visible", timeout=self.cfg.action_timeout_ms)
        await el.screenshot(path=str(path))

    async def save_html(self, page: Page, path: pathlib.Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        html = await page.content()
        path.write_text(html, encoding="utf-8")

    # -------- Куки/Storage State --------

    async def export_storage_state(self, context_name: Optional[str], path: pathlib.Path) -> None:
        ctx = self.get_context(context_name)
        state = await ctx.storage_state()
        path.parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(path).write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

    async def import_cookies(self, context_name: Optional[str], cookies: Iterable[Dict[str, Any]]) -> None:
        ctx = self.get_context(context_name)
        await ctx.add_cookies(list(cookies))

    async def clear_cookies(self, context_name: Optional[str]) -> None:
        ctx = self.get_context(context_name)
        await ctx.clear_cookies()

    # -------- Таймауты по умолчанию --------

    def set_timeouts(self, *, navigation_ms: Optional[int] = None, action_ms: Optional[int] = None,
                     context_name: Optional[str] = None) -> None:
        ctx = self.get_context(context_name)
        if navigation_ms:
            ctx.set_default_navigation_timeout(navigation_ms)
        if action_ms:
            ctx.set_default_timeout(action_ms)

    # -------- Утилиты --------

    async def open_new_tab(self, context_name: Optional[str] = None) -> Page:
        ctx = self.get_context(context_name)
        return await ctx.new_page()

    async def close_all_pages(self, context_name: Optional[str] = None) -> None:
        ctx = self.get_context(context_name)
        for p in list(ctx.pages):
            with contextlib.suppress(Exception):
                await p.close()

    async def pages(self, context_name: Optional[str] = None) -> List[Page]:
        ctx = self.get_context(context_name)
        return list(ctx.pages)
