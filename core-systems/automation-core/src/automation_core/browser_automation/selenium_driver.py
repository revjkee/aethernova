# automation-core/src/automation_core/browser_automation/selenium_driver.py
# -*- coding: utf-8 -*-
"""
Промышленная обертка над Selenium WebDriver (Python, Selenium 4).

Подтвержденные факты:
- Explicit Waits (WebDriverWait + Expected Conditions) — рекомендуемая стратегия ожиданий.  # :contentReference[oaicite:1]{index=1}
- В Selenium 4 капабилити задаются через Options-классы; DesiredCapabilities устарели.       # :contentReference[oaicite:2]{index=2}
- Selenium Manager автоматически управляет драйверами (без ручной установки).               # :contentReference[oaicite:3]{index=3}
- Стратегия загрузки страниц задается как W3C capability `pageLoadStrategy`.                 # :contentReference[oaicite:4]{index=4}
- Для управления загрузками в Chromium доступен CDP `Browser.setDownloadBehavior`.           # :contentReference[oaicite:5]{index=5}

Ограничения:
- Настройка каталога загрузок реализована для Chromium-браузеров через CDP.
- Для Firefox/Gecko настройка загрузок завязана на профиль/преференсы; официальный
  универсальный API в Selenium отсутствует. Здесь намеренно не реализовано, чтобы
  не опираться на непроверенные источники. Не могу подтвердить это для кросс-браузерного API.

Использование:
    cfg = SeleniumConfig(browser="chrome", headless=True, download_dir="/tmp/dl")
    with SeleniumDriver(cfg) as d:
        d.get("https://example.org")
        el = d.wait_visible((By.CSS_SELECTOR, "h1"))
        print(el.text)
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import pathlib
import typing as t

from dataclasses import dataclass, field

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.support.ui import WebDriverWait   # :contentReference[oaicite:6]{index=6}
from selenium.webdriver.support import expected_conditions as EC  # :contentReference[oaicite:7]{index=7}
from selenium.webdriver.common.proxy import Proxy, ProxyType      # :contentReference[oaicite:8]{index=8}

# Публичный интерфейс
__all__ = [
    "SeleniumConfig",
    "Timeouts",
    "ProxyConfig",
    "SeleniumDriver",
    "By",
]

# -----------------------------
# Модели конфигурации
# -----------------------------

@dataclass(slots=True)
class Timeouts:
    """Таймауты драйвера."""
    implicit: float = 0.0           # сек; 0 = выключено (рекомендуется explicit waits).  # :contentReference[oaicite:9]{index=9}
    page_load: float = 60.0         # сек
    script: float = 30.0            # сек


@dataclass(slots=True)
class ProxyConfig:
    """Прокси-настройки (MANUAL)."""
    http: str | None = None
    https: str | None = None
    no_proxy: str | None = None     # список исключений через запятую


@dataclass(slots=True)
class SeleniumConfig:
    browser: str = "chrome"         # chrome | firefox | edge
    headless: bool = False
    window_size: tuple[int, int] = (1280, 800)
    user_agent: str | None = None
    accept_insecure_certs: bool = False

    # Стратегия загрузки страниц (W3C): normal | eager | none
    # Передается как capability pageLoadStrategy.                                          # :contentReference[oaicite:10]{index=10}
    page_load_strategy: str = "normal"

    # Директория загрузок (только Chromium через CDP Browser.setDownloadBehavior).         # :contentReference[oaicite:11]{index=11}
    download_dir: str | None = None

    timeouts: Timeouts = field(default_factory=Timeouts)
    proxy: ProxyConfig | None = None

    # Доп. аргументы браузера
    extra_args: list[str] = field(default_factory=list)

# -----------------------------
# Фабрика драйверов
# -----------------------------

class SeleniumDriver:
    """Контекстный менеджер и фасад над Selenium WebDriver."""

    def __init__(self, cfg: SeleniumConfig) -> None:
        self.cfg = cfg
        self.driver: WebDriver | None = None

    # -- публичные утилиты ожиданий --

    def wait(self, timeout: float | None = None, poll_frequency: float = 0.5) -> WebDriverWait:
        """Создать WebDriverWait (Explicit Wait)."""  # :contentReference[oaicite:12]{index=12}
        d = self._need_driver()
        to = timeout if timeout is not None else self.cfg.timeouts.page_load
        return WebDriverWait(d, to, poll_frequency=poll_frequency)

    def wait_visible(self, locator: tuple[str, str], timeout: float | None = None):
        """Дождаться видимости элемента по локатору."""
        return self.wait(timeout).until(EC.visibility_of_element_located(locator))  # :contentReference[oaicite:13]{index=13}

    def wait_clickable(self, locator: tuple[str, str], timeout: float | None = None):
        """Дождаться кликабельности элемента по локатору."""
        return self.wait(timeout).until(EC.element_to_be_clickable(locator))  # :contentReference[oaicite:14]{index=14}

    # -- жизненный цикл --

    def start(self) -> WebDriver:
        if self.driver:
            return self.driver

        browser = self.cfg.browser.lower()
        if browser == "chrome":
            self.driver = self._start_chrome()
        elif browser == "firefox":
            self.driver = self._start_firefox()
        elif browser == "edge":
            self.driver = self._start_edge()
        else:
            raise ValueError(f"Unsupported browser: {self.cfg.browser}")

        # Таймауты сеанса
        self._apply_timeouts(self.driver, self.cfg.timeouts)

        # Настроить загрузки (только Chromium через CDP)
        if self.cfg.download_dir and browser in ("chrome", "edge"):
            self._enable_chromium_downloads(self.driver, self.cfg.download_dir)

        return self.driver

    def quit(self) -> None:
        if self.driver:
            with contextlib.suppress(Exception):
                self.driver.quit()
        self.driver = None

    # -- контекст-менеджер --

    def __enter__(self) -> WebDriver:
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.quit()

    # -----------------------------
    # Внутренние реализации
    # -----------------------------

    def _need_driver(self) -> WebDriver:
        if not self.driver:
            raise RuntimeError("Driver is not started. Call start() or use context manager.")
        return self.driver

    def _build_proxy(self) -> Proxy | None:
        if not self.cfg.proxy:
            return None
        p = Proxy()
        p.proxy_type = ProxyType.MANUAL  # MANUAL proxy mode                                     # :contentReference[oaicite:15]{index=15}
        if self.cfg.proxy.http:
            p.http_proxy = self.cfg.proxy.http
        if self.cfg.proxy.https:
            p.ssl_proxy = self.cfg.proxy.https
        if self.cfg.proxy.no_proxy:
            p.no_proxy = self.cfg.proxy.no_proxy
        return p

    def _start_chrome(self) -> WebDriver:
        from selenium.webdriver.chrome.options import Options as ChromeOptions
        # Сборка опций согласно Selenium 4 (options-классы вместо DesiredCapabilities).        # :contentReference[oaicite:16]{index=16}
        options = ChromeOptions()
        options.page_load_strategy = self.cfg.page_load_strategy  # W3C pageLoadStrategy.       # :contentReference[oaicite:17]{index=17}

        if self.cfg.headless:
            options.add_argument("--headless")  # headless режим поддерживается Chrome/Edge

        w, h = self.cfg.window_size
        options.add_argument(f"--window-size={w},{h}")

        if self.cfg.user_agent:
            options.add_argument(f"--user-agent={self.cfg.user_agent}")

        for arg in self.cfg.extra_args:
            options.add_argument(arg)

        if self.cfg.accept_insecure_certs:
            options.set_capability("acceptInsecureCerts", True)

        proxy = self._build_proxy()
        if proxy:
            options.proxy = proxy  # официальный способ задать прокси                           # :contentReference[oaicite:18]{index=18}

        # Selenium Manager: webdriver.Chrome(options=...) автоматически решит драйвер.          # :contentReference[oaicite:19]{index=19}
        driver = webdriver.Chrome(options=options)
        return driver

    def _start_edge(self) -> WebDriver:
        from selenium.webdriver.edge.options import Options as EdgeOptions
        options = EdgeOptions()
        options.page_load_strategy = self.cfg.page_load_strategy                                     # :contentReference[oaicite:20]{index=20}
        if self.cfg.headless:
            options.add_argument("--headless=new" if "new" in "new" else "--headless")
        w, h = self.cfg.window_size
        options.add_argument(f"--window-size={w},{h}")
        if self.cfg.user_agent:
            options.add_argument(f"--user-agent={self.cfg.user_agent}")
        for arg in self.cfg.extra_args:
            options.add_argument(arg)
        if self.cfg.accept_insecure_certs:
            options.set_capability("acceptInsecureCerts", True)

        proxy = self._build_proxy()
        if proxy:
            options.proxy = proxy                                                                     # :contentReference[oaicite:21]{index=21}

        driver = webdriver.Edge(options=options)  # Selenium Manager                               # :contentReference[oaicite:22]{index=22}
        return driver

    def _start_firefox(self) -> WebDriver:
        from selenium.webdriver.firefox.options import Options as FirefoxOptions
        options = FirefoxOptions()
        options.page_load_strategy = self.cfg.page_load_strategy                                      # :contentReference[oaicite:23]{index=23}
        if self.cfg.headless:
            options.add_argument("-headless")
        if self.cfg.user_agent:
            options.set_preference("general.useragent.override", self.cfg.user_agent)
        if self.cfg.accept_insecure_certs:
            options.set_capability("acceptInsecureCerts", True)
        # Прокси — через Proxy (как и у других браузеров)
        proxy = self._build_proxy()
        if proxy:
            options.proxy = proxy                                                                     # :contentReference[oaicite:24]{index=24}
        # Selenium Manager поднимет geckodriver автоматически
        driver = webdriver.Firefox(options=options)                                                   # :contentReference[oaicite:25]{index=25}
        # Размер окна приведем к конфигу
        w, h = self.cfg.window_size
        try:
            driver.set_window_size(w, h)
        except Exception:
            pass
        return driver

    @staticmethod
    def _apply_timeouts(driver: WebDriver, tmo: Timeouts) -> None:
        # Имплицитные ожидания — по умолчанию 0, explicit waits предпочтительнее.                # :contentReference[oaicite:26]{index=26}
        if tmo.implicit and tmo.implicit > 0:
            driver.implicitly_wait(tmo.implicit)  # метод драйвера                                # :contentReference[oaicite:27]{index=27}
        # Таймауты загрузки страниц и скриптов
        try:
            driver.set_page_load_timeout(tmo.page_load)
        except Exception:
            pass
        try:
            driver.set_script_timeout(tmo.script)
        except Exception:
            pass

    @staticmethod
    def _enable_chromium_downloads(driver: WebDriver, download_dir: str) -> None:
        """
        Разрешить загрузки и выставить папку скачивания для Chromium через CDP:
        Browser.setDownloadBehavior(behavior='allow', downloadPath=<abs>).
        Требует абсолютного пути.                                                                # :contentReference[oaicite:28]{index=28}
        """
        p = pathlib.Path(download_dir).absolute()
        p.mkdir(parents=True, exist_ok=True)
        try:
            # Новый API (Selenium 4+): driver.execute_cdp_cmd доступен в Python-клиенте.
            driver.execute_cdp_cmd(
                "Browser.setDownloadBehavior",
                {"behavior": "allow", "downloadPath": str(p)},
            )  # :contentReference[oaicite:29]{index=29}
        except Exception as e:
            # Не критично для общего запуска; оставим сообщение для журнала пользователя.
            # Здесь нет глобального логгера — выбрасывать исключение нельзя, чтобы не
            # ломать общую логику запуска.
            _ = e  # no-op

# Константы локаторов доступны как Selenium By:
# from selenium.webdriver.common.by import By
