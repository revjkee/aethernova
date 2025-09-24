from __future__ import annotations

"""
automation_core.browser_automation.base

Промышленная, безопасная и расширяемая основа для автоматизации браузера.

Цели:
- Стабильный интерфейс поверх конкретных реализаций (Playwright, Selenium, CDP и т. п.).
- Асинхронная модель с таймаутами, ожиданиями и ретраями.
- Минимальные гарантии безопасности: ограничение домена, запрет сетевых побочных эффектов в Null-движке.
- Структурированное JSON-логирование для трассировки в CI/observability.
- Возможность офлайн-тестов без реального браузера (NullBrowserEngine).
- Детальные типы и ошибки высокого уровня.

Зависимости: только стандартная библиотека Python 3.11+.
Реальные интеграции размещайте в отдельных модулях-адаптерах, реализующих интерфейсы ниже.

Пример (псевдокод, адаптер Playwright):
    from .base import BrowserEngine, BrowserLaunchOptions, register_engine

    class PlaywrightEngine(BrowserEngine): ...
    register_engine("playwright", PlaywrightEngine)

    # где-то в приложении:
    engine = get_engine("playwright")(launch_opts)
    async with engine as ctx:
        page = await ctx.new_page()
        await page.goto("https://example.com")
        txt = await page.text_content("h1")
        await page.screenshot(path=Path("./shot.png"))

Лицензия: MIT
"""

import abc
import asyncio
import base64
import contextlib
import dataclasses
import hashlib
import json
import os
import random
import re
import secrets
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from pathlib import Path
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
)

# ============================================================
# ЛОГИРОВАНИЕ
# ============================================================

class JsonLogger:
    """
    Лаконичный JSONL-логгер: пишет в stdout и, опционально, в файл.
    """
    def __init__(self, file: Optional[Path] = None) -> None:
        self._fp = None
        if file:
            file.parent.mkdir(parents=True, exist_ok=True)
            self._fp = file.open("a", encoding="utf-8")

    def emit(self, level: str, event: str, **fields: Any) -> None:
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level.upper(),
            "event": event,
            **fields,
        }
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
        print(line, flush=True)
        if self._fp:
            self._fp.write(line + "\n")
            self._fp.flush()

    def info(self, event: str, **fields: Any) -> None:
        self.emit("INFO", event, **fields)

    def warn(self, event: str, **fields: Any) -> None:
        self.emit("WARN", event, **fields)

    def error(self, event: str, **fields: Any) -> None:
        self.emit("ERROR", event, **fields)

    def close(self) -> None:
        if self._fp:
            self._fp.close()


# ============================================================
# ОШИБКИ
# ============================================================

class BrowserError(RuntimeError):
    pass

class NavigationError(BrowserError):
    pass

class TimeoutError_(BrowserError):  # чтобы не конфликтовать с asyncio.TimeoutError
    pass

class SelectorError(BrowserError):
    pass

class DownloadError(BrowserError):
    pass

class SecurityError(BrowserError):
    pass


# ============================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И ТИПЫ
# ============================================================

def _now_ms() -> int:
    return int(time.time() * 1000)

def _sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def _truncate(s: str, limit: int = 2048) -> str:
    if len(s) <= limit:
        return s
    return s[:limit] + f"...[+{len(s)-limit}]"

def _as_bool(x: Union[bool, str, int]) -> bool:
    if isinstance(x, bool):
        return x
    if isinstance(x, int):
        return x != 0
    s = str(x).strip().lower()
    return s in {"1", "true", "yes", "y", "on"}

T = TypeVar("T")


# ============================================================
# РЕТРАИ/ОЖИДАНИЯ (локальная мини-реализация)
# ============================================================

async def retry_async(
    op: Callable[[], Awaitable[T]],
    *,
    attempts: int = 3,
    initial_delay: float = 0.2,
    mult: float = 2.0,
    max_delay: float = 5.0,
    jitter: Literal["none", "full", "equal", "decorrelated"] = "full",
    timeout: Optional[float] = None,
    on_retry: Optional[Callable[[int, BaseException, float], None]] = None,
) -> T:
    """
    Универсальный async-ретрай с экспоненциальной задержкой.
    """
    if attempts < 1:
        raise ValueError("attempts must be >= 1")
    delay = initial_delay
    last_exc: Optional[BaseException] = None

    for i in range(1, attempts + 1):
        try:
            if timeout is None:
                return await op()
            return await asyncio.wait_for(op(), timeout=timeout)
        except asyncio.CancelledError:
            raise
        except BaseException as e:
            last_exc = e
            if i >= attempts:
                break
            # compute sleep
            base = min(delay, max_delay)
            if jitter == "none":
                sleep_for = base
            elif jitter == "full":
                sleep_for = random.uniform(0.0, base)
            elif jitter == "equal":
                sleep_for = base * 0.5 + random.uniform(0.0, base * 0.5)
            else:  # decorrelated
                lo = initial_delay
                hi = max(base * 3.0, lo)
                sleep_for = min(random.uniform(lo, hi), max_delay)

            if on_retry:
                try:
                    on_retry(i, e, sleep_for)
                except Exception:
                    pass

            await asyncio.sleep(sleep_for)
            delay = min(delay * mult, max_delay)
    assert last_exc is not None
    raise last_exc


async def wait_for_predicate(
    predicate: Callable[[], Awaitable[bool]],
    *,
    timeout: float,
    interval: float = 0.05,
) -> None:
    """
    Поллинговое ожидание до тех пор, пока predicate() не вернет True, либо истечет timeout.
    """
    start = time.monotonic()
    while True:
        if await predicate():
            return
        if time.monotonic() - start > timeout:
            raise TimeoutError_(f"predicate timeout after {timeout}s")
        await asyncio.sleep(interval)


# ============================================================
# КОНФИГУРАЦИИ И ОПЦИИ
# ============================================================

@dataclass(frozen=True)
class ProxyConfig:
    server: Optional[str] = None           # "http://host:port" | "socks5://..."
    username: Optional[str] = None
    password: Optional[str] = None
    bypass: Optional[str] = None           # "localhost,127.0.0.1"

@dataclass(frozen=True)
class Viewport:
    width: int = 1280
    height: int = 800
    device_scale_factor: float = 1.0

class Permission(str, Enum):
    GEOLOCATION = "geolocation"
    CLIPBOARD_READ = "clipboard-read"
    CLIPBOARD_WRITE = "clipboard-write"
    NOTIFICATIONS = "notifications"
    CAMERA = "camera"
    MICROPHONE = "microphone"

@dataclass(frozen=True)
class BrowserLaunchOptions:
    headless: bool = True
    viewport: Viewport = field(default_factory=Viewport)
    user_agent: Optional[str] = None
    locale: Optional[str] = None
    timezone_id: Optional[str] = None
    proxy: Optional[ProxyConfig] = None
    accept_downloads: bool = False
    permissions: Tuple[Permission, ...] = tuple()
    extra_args: Tuple[str, ...] = tuple()
    env: Mapping[str, str] = field(default_factory=dict)
    slow_mo_ms: int = 0                     # задержка для визуализации (если движок поддерживает)
    video_enabled: bool = False             # запись видео, если поддерживает адаптер
    har_enabled: bool = False               # запись HAR, если поддерживает адаптер

@dataclass(frozen=True)
class NavigationOptions:
    timeout_sec: float = 30.0
    wait_until: Literal["load", "domcontentloaded", "networkidle"] = "load"
    referer: Optional[str] = None

@dataclass(frozen=True)
class ScreenshotOptions:
    path: Optional[Path] = None
    full_page: bool = False
    quality: Optional[int] = None           # для JPEG/WebP
    type: Literal["png", "jpeg", "webp"] = "png"
    omit_background: bool = True

@dataclass(frozen=True)
class DownloadOptions:
    timeout_sec: float = 60.0
    suggested_name: Optional[str] = None
    accept_dialogs: bool = True

@dataclass(frozen=True)
class EvaluateOptions:
    timeout_sec: float = 5.0
    arg: Any = None


# ============================================================
# БАЗОВЫЕ ИНТЕРФЕЙСЫ (ABC)
# ============================================================

class Page(abc.ABC):
    """
    Абстракция вкладки/страницы.
    """
    @abc.abstractmethod
    async def goto(self, url: str, opts: NavigationOptions = NavigationOptions()) -> None: ...

    @abc.abstractmethod
    async def wait_for_selector(self, selector: str, *, timeout_sec: float = 10.0) -> None: ...

    @abc.abstractmethod
    async def click(self, selector: str, *, timeout_sec: float = 10.0) -> None: ...

    @abc.abstractmethod
    async def type(self, selector: str, text: str, *, delay_ms: int = 0, timeout_sec: float = 10.0) -> None: ...

    @abc.abstractmethod
    async def fill(self, selector: str, text: str, *, timeout_sec: float = 10.0, clear: bool = True) -> None: ...

    @abc.abstractmethod
    async def text_content(self, selector: str, *, timeout_sec: float = 10.0) -> str: ...

    @abc.abstractmethod
    async def inner_html(self, selector: str, *, timeout_sec: float = 10.0) -> str: ...

    @abc.abstractmethod
    async def evaluate(self, expression: str, opts: EvaluateOptions = EvaluateOptions()) -> Any: ...

    @abc.abstractmethod
    async def screenshot(self, opts: ScreenshotOptions = ScreenshotOptions()) -> bytes: ...

    @abc.abstractmethod
    async def url(self) -> str: ...

    @abc.abstractmethod
    async def close(self) -> None: ...


class BrowserContext(abc.ABC):
    """
    Изолированная среда (cookie jar, localStorage и пр.).
    """
    @abc.abstractmethod
    async def new_page(self) -> Page: ...

    @abc.abstractmethod
    async def grant_permissions(self, permissions: Sequence[Permission]) -> None: ...

    @abc.abstractmethod
    async def set_cookies(self, cookies: Sequence[Mapping[str, Any]]) -> None: ...

    @abc.abstractmethod
    async def get_cookies(self) -> List[Mapping[str, Any]]: ...

    @abc.abstractmethod
    async def close(self) -> None: ...


class BrowserEngine(abc.ABC):
    """
    Жизненный цикл браузера и контексты.
    """
    def __init__(self, launch: BrowserLaunchOptions, *, logger: Optional[JsonLogger] = None) -> None:
        self.launch = launch
        self.logger = logger or JsonLogger()

    async def __aenter__(self) -> BrowserContext:
        await self.start()
        return await self.new_context()

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()

    @abc.abstractmethod
    async def start(self) -> None: ...

    @abc.abstractmethod
    async def stop(self) -> None: ...

    @abc.abstractmethod
    async def new_context(self) -> BrowserContext: ...


# ============================================================
# РЕЕСТР ДВИЖКОВ
# ============================================================

_ENGINE_REGISTRY: Dict[str, Type[BrowserEngine]] = {}

def register_engine(name: str, cls: Type[BrowserEngine]) -> None:
    if not re.fullmatch(r"[a-z][a-z0-9_-]{1,32}", name):
        raise ValueError("invalid engine name")
    _ENGINE_REGISTRY[name] = cls

def get_engine(name: str) -> Type[BrowserEngine]:
    if name not in _ENGINE_REGISTRY:
        raise KeyError(f"engine not registered: {name}")
    return _ENGINE_REGISTRY[name]

def list_engines() -> List[str]:
    return sorted(_ENGINE_REGISTRY.keys())


# ============================================================
# ПСЕВДО-ДВИЖОК (NULL): безопасный для офлайна/CI
# ============================================================

@dataclass
class _NullPageState:
    url: str = "about:blank"
    dom: Dict[str, str] = field(default_factory=dict)  # selector -> text
    html: Dict[str, str] = field(default_factory=dict) # selector -> innerHTML

class NullPage(Page):
    """
    Безопасная in-memory реализация. Полезна для юнит-тестов без браузера.
    """
    def __init__(self, logger: JsonLogger, state: Optional[_NullPageState] = None) -> None:
        self._logger = logger
        self._state = state or _NullPageState()
        self._closed = False

    async def goto(self, url: str, opts: NavigationOptions = NavigationOptions()) -> None:
        if self._closed:
            raise BrowserError("page closed")
        # Допустим только http(s) и about:
        if not (url.startswith("http://") or url.startswith("https://") or url.startswith("about:")):
            raise SecurityError("unsupported protocol")
        self._state.url = url
        self._logger.info("null.goto", url=url, wait_until=opts.wait_until, timeout=opts.timeout_sec)

    async def wait_for_selector(self, selector: str, *, timeout_sec: float = 10.0) -> None:
        if self._closed:
            raise BrowserError("page closed")
        async def ok() -> bool:
            return selector in self._state.dom or selector in self._state.html
        await wait_for_predicate(ok, timeout=timeout_sec, interval=0.02)
        self._logger.info("null.wait_for_selector", selector=selector)

    async def click(self, selector: str, *, timeout_sec: float = 10.0) -> None:
        await self.wait_for_selector(selector, timeout_sec=timeout_sec)
        self._logger.info("null.click", selector=selector)

    async def type(self, selector: str, text: str, *, delay_ms: int = 0, timeout_sec: float = 10.0) -> None:
        await self.wait_for_selector(selector, timeout_sec=timeout_sec)
        # эмулируем набор
        if delay_ms > 0:
            await asyncio.sleep(min(delay_ms / 1000.0, 0.2))
        self._state.dom[selector] = self._state.dom.get(selector, "") + text
        self._logger.info("null.type", selector=selector, text=_truncate(text, 128))

    async def fill(self, selector: str, text: str, *, timeout_sec: float = 10.0, clear: bool = True) -> None:
        await self.wait_for_selector(selector, timeout_sec=timeout_sec)
        self._state.dom[selector] = "" if clear else self._state.dom.get(selector, "")
        self._state.dom[selector] += text
        self._logger.info("null.fill", selector=selector, text=_truncate(text, 128), clear=clear)

    async def text_content(self, selector: str, *, timeout_sec: float = 10.0) -> str:
        await self.wait_for_selector(selector, timeout_sec=timeout_sec)
        txt = self._state.dom.get(selector) or ""
        self._logger.info("null.text_content", selector=selector, result=_truncate(txt, 128))
        return txt

    async def inner_html(self, selector: str, *, timeout_sec: float = 10.0) -> str:
        await self.wait_for_selector(selector, timeout_sec=timeout_sec)
        html = self._state.html.get(selector) or ""
        self._logger.info("null.inner_html", selector=selector, result_len=len(html))
        return html

    async def evaluate(self, expression: str, opts: EvaluateOptions = EvaluateOptions()) -> Any:
        # В null-режиме ничего не исполняем; возвращаем echo.
        self._logger.info("null.evaluate", expr=_truncate(expression, 256), timeout=opts.timeout_sec)
        return {"echo": expression, "arg": opts.arg}

    async def screenshot(self, opts: ScreenshotOptions = ScreenshotOptions()) -> bytes:
        # Генерируем «пустой» PNG-заглушку 1x1 (валидный PNG header + IHDR + IDAT + IEND)
        # Это безопасно и детерминировано.
        png_1x1 = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAObJ9d8AAAAASUVORK5CYII="
        )
        data = png_1x1 if opts.type == "png" else png_1x1  # простая заглушка
        if opts.path:
            opts.path.parent.mkdir(parents=True, exist_ok=True)
            opts.path.write_bytes(data)
            self._logger.info("null.screenshot.saved", path=str(opts.path), bytes=len(data))
        else:
            self._logger.info("null.screenshot.bytes", bytes=len(data))
        return data

    async def url(self) -> str:
        return self._state.url

    async def close(self) -> None:
        self._closed = True
        self._logger.info("null.page.close")


class NullBrowserContext(BrowserContext):
    def __init__(self, logger: JsonLogger, launch: BrowserLaunchOptions) -> None:
        self._logger = logger
        self._launch = launch
        self._pages: List[NullPage] = []
        self._closed = False

    async def new_page(self) -> Page:
        if self._closed:
            raise BrowserError("context closed")
        p = NullPage(self._logger)
        self._pages.append(p)
        self._logger.info("null.context.new_page", count=len(self._pages))
        return p

    async def grant_permissions(self, permissions: Sequence[Permission]) -> None:
        self._logger.info("null.context.grant_permissions", permissions=[p.value for p in permissions])

    async def set_cookies(self, cookies: Sequence[Mapping[str, Any]]) -> None:
        # Ничего не делаем, только лог
        self._logger.info("null.context.set_cookies", count=len(cookies))

    async def get_cookies(self) -> List[Mapping[str, Any]]:
        self._logger.info("null.context.get_cookies")
        return []

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._logger.info("null.context.close", open_pages=sum(1 for p in self._pages if getattr(p, "_closed", False) is False))
        for p in self._pages:
            with contextlib.suppress(Exception):
                await p.close()


class NullBrowserEngine(BrowserEngine):
    """
    Безопасный движок, не открывающий реальный браузер. Подходит для юнит-тестов и офлайна.
    """
    def __init__(self, launch: BrowserLaunchOptions, *, logger: Optional[JsonLogger] = None) -> None:
        super().__init__(launch, logger=logger)
        self._started = False
        self._contexts: List[NullBrowserContext] = []

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        self.logger.info("null.engine.start", headless=self.launch.headless, viewport=dataclasses.asdict(self.launch.viewport))

    async def stop(self) -> None:
        if not self._started:
            return
        self.logger.info("null.engine.stop", open_contexts=len(self._contexts))
        for ctx in list(self._contexts):
            with contextlib.suppress(Exception):
                await ctx.close()
        self._started = False

    async def new_context(self) -> BrowserContext:
        if not self._started:
            await self.start()
        ctx = NullBrowserContext(self.logger, self.launch)
        self._contexts.append(ctx)
        self.logger.info("null.engine.new_context", total=len(self._contexts))
        return ctx


# Регистрируем Null-движок как «null»
register_engine("null", NullBrowserEngine)


# ============================================================
# УТИЛИТЫ HAR (минимальный нейтральный дамп)
# ============================================================

def build_minimal_har(
    *,
    started_ms: int,
    finished_ms: int,
    pages: Sequence[Mapping[str, Any]],
    entries: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """
    Минимальный валидный HAR 1.2 для базовой трассировки.
    """
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "automation-core", "version": "0.1"},
            "pages": list(pages),
            "entries": list(entries),
            "comment": f"elapsed_ms={max(0, finished_ms - started_ms)}",
        }
    }


# ============================================================
# HIGH-LEVEL ВСПОМОГАТЕЛЬНЫЕ ОБЕРТКИ
# ============================================================

class BrowserSession:
    """
    Высокоуровневая обертка жизненного цикла: engine -> context -> single page.
    Удобна для простых сценариев.
    """
    def __init__(
        self,
        engine: BrowserEngine,
        *,
        create_page: bool = True,
    ) -> None:
        self._engine = engine
        self._ctx: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._create_page = create_page

    async def __aenter__(self) -> "BrowserSession":
        self._ctx = await self._engine.new_context()
        if self._create_page:
            self._page = await self._ctx.new_page()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._page:
            with contextlib.suppress(Exception):
                await self._page.close()
        if self._ctx:
            with contextlib.suppress(Exception):
                await self._ctx.close()
        with contextlib.suppress(Exception):
            await self._engine.stop()

    @property
    def page(self) -> Page:
        if not self._page:
            raise BrowserError("session has no page")
        return self._page

    @property
    def context(self) -> BrowserContext:
        if not self._ctx:
            raise BrowserError("session has no context")
        return self._ctx


# ============================================================
# «БЕЗОПАСНЫЕ» ВСПОМОГАТЕЛЬНЫЕ ДЕЙСТВИЯ ДЛЯ СТРАНИЦЫ
# ============================================================

async def safe_goto(page: Page, url: str, *, timeout_sec: float = 30.0, wait_until: NavigationOptions["wait_until"]="load") -> None:
    """
    Переход с ретраями по навигационным ошибкам.
    """
    async def op():
        await page.goto(url, NavigationOptions(timeout_sec=timeout_sec, wait_until=wait_until))
    await retry_async(op, attempts=3, initial_delay=0.2, mult=2.0, timeout=timeout_sec)

async def safe_click(page: Page, selector: str, *, timeout_sec: float = 10.0) -> None:
    async def op():
        await page.click(selector, timeout_sec=timeout_sec)
    await retry_async(op, attempts=2, initial_delay=0.1, mult=1.5, timeout=timeout_sec)

async def safe_fill(page: Page, selector: str, text: str, *, timeout_sec: float = 10.0, clear: bool = True) -> None:
    async def op():
        await page.fill(selector, text, timeout_sec=timeout_sec, clear=clear)
    await retry_async(op, attempts=2, initial_delay=0.1, mult=1.5, timeout=timeout_sec)


# ============================================================
# ОБЩЕДОСТУПНЫЕ API
# ============================================================

__all__ = [
    # Логирование
    "JsonLogger",
    # Ошибки
    "BrowserError", "NavigationError", "TimeoutError_", "SelectorError", "DownloadError", "SecurityError",
    # Опции
    "ProxyConfig", "Viewport", "Permission", "BrowserLaunchOptions", "NavigationOptions",
    "ScreenshotOptions", "DownloadOptions", "EvaluateOptions",
    # Интерфейсы
    "Page", "BrowserContext", "BrowserEngine",
    # Реестр
    "register_engine", "get_engine", "list_engines",
    # Null implementation
    "NullBrowserEngine", "NullBrowserContext", "NullPage",
    # HAR
    "build_minimal_har",
    # High-level session and helpers
    "BrowserSession", "safe_goto", "safe_click", "safe_fill",
]
