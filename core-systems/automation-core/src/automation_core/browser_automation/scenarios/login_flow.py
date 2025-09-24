# automation-core/src/automation_core/browser_automation/scenarios/login_flow.py
# -*- coding: utf-8 -*-
"""
Промышленный сценарий логина в веб-приложение на Playwright (Python, async).

Возможности:
- Надежные Locators с автожданием (actionability), явные ожидания видимости.
- Управляемые таймауты и ретраи шага входа.
- Навигация с контролем "wait_until" и проверкой удачи по селектору.
- Опциональный ввод TOTP (RFC 6238) через PyOTP.
- Трассировка действий (Trace Viewer) и снимки экрана при сбое.
- Экспорт storage_state для повторного использования сессии.

Требования:
- Python 3.9+
- pip install playwright
- playwright install
- Опционально для TOTP: pip install pyotp

Документация Playwright и стандарты указаны в конце файла.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

try:
    import pyotp  # RFC 6238 TOTP
except Exception:  # модуль не обязателен
    pyotp = None

from playwright.async_api import (
    async_playwright,
    TimeoutError as PlaywrightTimeoutError,
    Page,
    BrowserContext,
)


# ------------------------------- конфиг ---------------------------------

@dataclass
class LoginConfig:
    login_url: str
    username: str
    password: str

    # Селекторы можно переопределять под продукт
    sel_username: Sequence[str] = field(default_factory=lambda: [
        'input[name="username"]',
        'input#username',
        'input[type="email"]',
    ])
    sel_password: Sequence[str] = field(default_factory=lambda: [
        'input[name="password"]',
        'input#password',
        'input[type="password"]',
    ])
    sel_submit: Sequence[str] = field(default_factory=lambda: [
        'button[type="submit"]',
        'button:has-text("Sign in")',
        'button:has-text("Log in")',
        'input[type="submit"]',
    ])
    # Опциональные селекторы для TOTP/OTP и подтверждения успеха
    sel_otp: Sequence[str] = field(default_factory=lambda: [
        'input[name="otp"]',
        'input[name="totp"]',
        'input#otp',
        'input#totp',
    ])
    sel_success: str = '[data-test-id="app-root"], header:has-text("Dashboard"), nav[role="navigation"]'
    sel_error: Sequence[str] = field(default_factory=lambda: [
        '[data-test-id="login-error"]',
        '.alert-error',
        '.error, .error-message',
    ])

    # Параметры выполнения
    headless: bool = True
    slow_mo_ms: int = 0
    timeout_ms: int = 15000
    navigation_wait: str = "load"  # "load" | "domcontentloaded" | "networkidle"
    retries: int = 2

    # TOTP
    totp_secret: Optional[str] = None

    # Артефакты
    storage_state_path: Optional[Path] = None
    trace_zip_path: Optional[Path] = None
    screenshot_on_fail_path: Optional[Path] = None

    # Дополнительно
    base_url: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class LoginResult:
    success: bool
    final_url: Optional[str]
    storage_state_path: Optional[str]
    trace_zip_path: Optional[str]
    error: Optional[str]


# ----------------------------- утилиты ----------------------------------

async def _first_visible_fill(page: Page, selectors: Sequence[str], value: str) -> bool:
    """
    Пытается найти первый видимый элемент по списку селекторов и заполнить его значением.
    Возвращает True при успехе, иначе False.
    """
    for css in selectors:
        loc = page.locator(css)
        try:
            await loc.wait_for(state="visible")
            await loc.fill(value)  # Locators имеют автождание и actionability
            return True
        except PlaywrightTimeoutError:
            continue
    return False


async def _first_visible_click(page: Page, selectors: Sequence[str]) -> bool:
    for css in selectors:
        loc = page.locator(css)
        try:
            await loc.wait_for(state="visible")
            await loc.click()
            return True
        except PlaywrightTimeoutError:
            continue
    return False


def _compute_totp(secret: str) -> str:
    if pyotp is None:
        raise RuntimeError("PyOTP не установлен; невозможно сгенерировать TOTP.")
    # RFC 6238: 30-секундные временные шаги по умолчанию
    return pyotp.TOTP(secret).now()


# ----------------------------- основной сценарий -----------------------

class LoginFlow:
    def __init__(self, cfg: LoginConfig) -> None:
        self.cfg = cfg

    async def run(self) -> LoginResult:
        trace_zip_path = str(self.cfg.trace_zip_path) if self.cfg.trace_zip_path else None
        storage_state_path = str(self.cfg.storage_state_path) if self.cfg.storage_state_path else None

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self.cfg.headless, slow_mo=self.cfg.slow_mo_ms)
            context_kwargs = dict()
            if self.cfg.base_url:
                context_kwargs["base_url"] = self.cfg.base_url
            if self.cfg.user_agent:
                context_kwargs["user_agent"] = self.cfg.user_agent

            context: BrowserContext = await browser.new_context(**context_kwargs)
            # Включаем трассировку до действий
            if trace_zip_path:
                await context.tracing.start(screenshots=True, snapshots=True, sources=True)

            page = await context.new_page()
            page.set_default_timeout(self.cfg.timeout_ms)

            error_text: Optional[str] = None
            success = False

            try:
                for attempt in range(self.cfg.retries + 1):
                    try:
                        await page.goto(self.cfg.login_url, wait_until=self.cfg.navigation_wait)
                        # Вводим логин/пароль
                        if not await _first_visible_fill(page, self.cfg.sel_username, self.cfg.username):
                            raise RuntimeError("Поле username не найдено или невидимо.")
                        if not await _first_visible_fill(page, self.cfg.sel_password, self.cfg.password):
                            raise RuntimeError("Поле password не найдено или невидимо.")

                        # Отправляем форму
                        if not await _first_visible_click(page, self.cfg.sel_submit):
                            # если кнопка не найдена, пробуем Enter
                            await page.keyboard.press("Enter")

                        # Если требуется TOTP
                        if self.cfg.totp_secret:
                            # Дождаться появления поля и ввести код
                            for css in self.cfg.sel_otp:
                                loc = page.locator(css)
                                try:
                                    await loc.wait_for(state="visible", timeout=5000)
                                    code = _compute_totp(self.cfg.totp_secret)
                                    await loc.fill(code)
                                    # Пробуем отправку
                                    await page.keyboard.press("Enter")
                                    break
                                except PlaywrightTimeoutError:
                                    continue

                        # Ожидание успеха: элемент интерфейса приложения
                        await page.locator(self.cfg.sel_success).wait_for(state="visible", timeout=self.cfg.timeout_ms)
                        success = True
                        break

                    except Exception as e:
                        error_text = f"Попытка {attempt + 1} из {self.cfg.retries + 1} неудачна: {e}"
                        if attempt < self.cfg.retries:
                            continue
                        raise

                # Сохраняем storage_state после успешного входа
                if success and storage_state_path:
                    await context.storage_state(path=storage_state_path)

                return LoginResult(
                    success=success,
                    final_url=page.url if success else None,
                    storage_state_path=storage_state_path if success else None,
                    trace_zip_path=trace_zip_path,
                    error=None if success else error_text,
                )

            except Exception as e:
                # Скриншот на сбое
                if self.cfg.screenshot_on_fail_path:
                    try:
                        await page.screenshot(path=str(self.cfg.screenshot_on_fail_path))
                    except Exception:
                        pass
                return LoginResult(
                    success=False,
                    final_url=page.url if page else None,
                    storage_state_path=None,
                    trace_zip_path=trace_zip_path,
                    error=str(e),
                )

            finally:
                # Останавливаем трассировку и пишем zip
                if trace_zip_path:
                    try:
                        await context.tracing.stop(path=trace_zip_path)
                    except Exception:
                        pass
                await context.close()
                await browser.close()


# ----------------------------- CLI -------------------------------------

def _env_or(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if v is not None else default

def build_config_from_args(argv: Sequence[str]) -> LoginConfig:
    p = argparse.ArgumentParser(description="Playwright login flow (async)")
    p.add_argument("--login-url", required=True)
    p.add_argument("--username", default=_env_or("LOGIN_USERNAME"))
    p.add_argument("--password", default=_env_or("LOGIN_PASSWORD"))
    p.add_argument("--totp-secret", default=_env_or("LOGIN_TOTP_SECRET"))
    p.add_argument("--headless", action="store_true", default=True)
    p.add_argument("--headed", dest="headless", action="store_false")
    p.add_argument("--timeout-ms", type=int, default=int(_env_or("LOGIN_TIMEOUT_MS", "15000")))
    p.add_argument("--retries", type=int, default=int(_env_or("LOGIN_RETRIES", "2")))
    p.add_argument("--navigation-wait", choices=["load", "domcontentloaded", "networkidle"], default=_env_or("LOGIN_NAV_WAIT", "load"))
    p.add_argument("--storage-state", type=Path, default=_env_or("LOGIN_STORAGE_STATE") and Path(_env_or("LOGIN_STORAGE_STATE")))
    p.add_argument("--trace-zip", type=Path, default=_env_or("LOGIN_TRACE_ZIP") and Path(_env_or("LOGIN_TRACE_ZIP")))
    p.add_argument("--screenshot-on-fail", type=Path, default=_env_or("LOGIN_SCREENSHOT") and Path(_env_or("LOGIN_SCREENSHOT")))
    p.add_argument("--base-url", default=_env_or("LOGIN_BASE_URL"))
    p.add_argument("--user-agent", default=_env_or("LOGIN_USER_AGENT"))
    p.add_argument("--slow-mo-ms", type=int, default=int(_env_or("LOGIN_SLOW_MO_MS", "0")))
    args = p.parse_args(argv)

    if not args.username or not args.password:
        p.error("Не заданы --username/--password (или переменные окружения LOGIN_USERNAME/LOGIN_PASSWORD).")

    return LoginConfig(
        login_url=args.login_url,
        username=args.username,
        password=args.password,
        totp_secret=args.totp_secret,
        headless=args.headless,
        slow_mo_ms=args.slow_mo_ms,
        timeout_ms=args.timeout_ms,
        retries=args.retries,
        navigation_wait=args.navigation_wait,
        storage_state_path=args.storage_state,
        trace_zip_path=args.trace_zip,
        screenshot_on_fail_path=args.screenshot_on_fail,
        base_url=args.base_url,
        user_agent=args.user_agent,
    )

async def _amain(argv: Sequence[str]) -> int:
    cfg = build_config_from_args(argv)
    flow = LoginFlow(cfg)
    result = await flow.run()
    print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))
    return 0 if result.success else 1

def main() -> None:
    exit_code = asyncio.run(_amain(sys.argv[1:]))
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
