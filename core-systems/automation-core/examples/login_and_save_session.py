#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
login_and_save_session.py — промышленный пример логина к HTTP-сервису
и сохранения сессии на диск в формате MozillaCookieJar с безопасными правами.

Размещение: automation-core/examples/login_and_save_session.py

Особенности:
- Строгие таймауты и ретраи (urllib3 Retry) с экспоненциальным backoff.
- Поддержка .env (если установлен python-dotenv), а также переменных окружения.
- Маскирование секретов в логах; структурные логи.
- Префлайт для извлечения CSRF (HTML <meta name="csrf-token"> или cookie).
- Извлечение токенов из JSON-ответа (опционально через JMESPath, если установлен).
- TLS-валидация с возможностью отключения (не рекомендуется).
- Прокси, настраиваемые заголовки, форматы логина: form/json.
- Сохранение cookiejar (0600) и сопутствующего session.json (метаданные).
- Явный код возврата: 0 — успех, 2 — ошибочные аргументы, 3 — сетевые/протокольные ошибки, 4 — политика успеха не выполнена.

Совместимость:
- Рассчитан на Python 3.8+.
- Внешние пакеты опциональны: python-dotenv, jmespath, beautifulsoup4.

Примеры:
  python3 login_and_save_session.py \
    --base-url https://example.com \
    --login-endpoint /api/login \
    --username "$USER" --password "$PASS" \
    --payload-format json \
    --success-json-jmespath "status" --success-json-expect "ok" \
    --cookie-file ../artifacts/sessions/example.cookiejar \
    --session-file ../artifacts/sessions/example.session.json

  # Префлайт CSRF из HTML и cookie:
  python3 login_and_save_session.py \
    --base-url https://example.com \
    --prefetch-path /login \
    --csrf-meta-name csrf-token \
    --csrf-header X-CSRF-Token

Примечание: Скрипт не делает предположений о конкретном API; поля можно настроить аргументами.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from requests import Session
from requests.adapters import HTTPAdapter
from requests.cookies import RequestsCookieJar
from urllib3.util.retry import Retry

# Опциональные зависимости
with contextlib.suppress(ImportError):
    from dotenv import load_dotenv  # type: ignore
with contextlib.suppress(ImportError):
    import jmespath  # type: ignore
with contextlib.suppress(ImportError):
    from bs4 import BeautifulSoup  # type: ignore

# ------------------------------ Константы/дефолты ------------------------------

DEFAULT_TIMEOUT = 15  # seconds per request
DEFAULT_TOTAL_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 0.5
DEFAULT_ALLOWED_METHODS = frozenset(["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"])
DEFAULT_STATUS_FORCELIST = (429, 500, 502, 503, 504)

# ------------------------------ Утилиты ------------------------------

def mask_secret(s: Optional[str]) -> str:
    if not s:
        return ""
    if len(s) <= 6:
        return "*" * len(s)
    return s[:2] + "*" * (len(s) - 4) + s[-2:]


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def chmod_600(path: Path) -> None:
    # На Windows права не применяются так же; просто тихо продолжаем.
    with contextlib.suppress(Exception):
        os.chmod(path, 0o600)


def now_ts() -> int:
    return int(time.time())


# ------------------------------ Логирование ------------------------------

def setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
    )


log = logging.getLogger("login")


# ------------------------------ Конфиг CLI ------------------------------

@dataclass
class Config:
    base_url: str
    login_endpoint: str
    method: str
    username: str
    password: str
    otp: Optional[str]
    payload_format: str  # "form" | "json"
    user_field: str
    pass_field: str
    otp_field: Optional[str]
    extra_fields: Dict[str, Any]
    headers: Dict[str, str]
    timeout: int
    retries: int
    backoff: float
    verify_tls: bool
    proxies: Optional[Dict[str, str]]
    cookie_file: Path
    session_file: Path
    prefetch_path: Optional[str]
    csrf_cookie_name: Optional[str]
    csrf_meta_name: Optional[str]
    csrf_header: Optional[str]
    success_http_min: int
    success_http_max: int
    success_json_jmespath: Optional[str]
    success_json_expect: Optional[str]
    allow_redirects: bool


def parse_args(argv: Optional[list[str]] = None) -> Config:
    p = argparse.ArgumentParser(
        description="Generic login + save session cookiejar (industrial-grade).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Основные параметры логина
    p.add_argument("--base-url", required=True, help="Базовый URL сервиса, например https://example.com")
    p.add_argument("--login-endpoint", default="/api/login", help="Путь логина относительно base-url")
    p.add_argument("--method", default="POST", choices=["POST", "GET"], help="HTTP метод для логина")

    # Учетные данные
    p.add_argument("--username", default=os.getenv("LOGIN_USERNAME"), help="Имя пользователя (или переменная окружения LOGIN_USERNAME)")
    p.add_argument("--password", default=os.getenv("LOGIN_PASSWORD"), help="Пароль (или переменная окружения LOGIN_PASSWORD)")
    p.add_argument("--otp", default=os.getenv("LOGIN_OTP"), help="Одноразовый код (2FA), опционально")

    # Формат и поля
    p.add_argument("--payload-format", default="json", choices=["json", "form"], help="Формат логин-пэйлоада")
    p.add_argument("--user-field", default="username", help="Имя поля логина")
    p.add_argument("--pass-field", default="password", help="Имя поля пароля")
    p.add_argument("--otp-field", default=None, help="Имя поля OTP (если требуется)")
    p.add_argument("--extra", default="{}", help="Дополнительные поля JSON (строка JSON)")

    # Заголовки/таймауты/ретраи/TLS/прокси
    p.add_argument("--headers", default="{}", help="Дополнительные заголовки (JSON)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Таймаут запроса, сек")
    p.add_argument("--retries", type=int, default=DEFAULT_TOTAL_RETRIES, help="Количество ретраев")
    p.add_argument("--backoff", type=float, default=DEFAULT_BACKOFF_FACTOR, help="Фактор backoff (экспоненциальный)")
    p.add_argument("--no-verify-tls", action="store_true", help="Отключить проверку TLS (не рекомендуется)")
    p.add_argument("--proxy", default=None, help='HTTP(S) proxy, например "http://127.0.0.1:8080"')

    # Файлы вывода
    p.add_argument("--cookie-file", default="../artifacts/sessions/session.cookiejar", help="Путь для сохранения cookiejar")
    p.add_argument("--session-file", default="../artifacts/sessions/session.json", help="Путь для сохранения метаданных сессии")

    # Префлайт/CSRF
    p.add_argument("--prefetch-path", default=None, help="Путь для префлайта (GET), чтобы получить CSRF/cookie")
    p.add_argument("--csrf-cookie-name", default=None, help="Имя cookie с CSRF токеном (если таковой используется)")
    p.add_argument("--csrf-meta-name", default=None, help="Имя HTML meta с CSRF токеном (например, csrf-token)")
    p.add_argument("--csrf-header", default=None, help="Имя заголовка, в который помещать CSRF токен")

    # Политики успеха
    p.add_argument("--success-http-min", type=int, default=200, help="Минимум успешного HTTP кода")
    p.add_argument("--success-http-max", type=int, default=299, help="Максимум успешного HTTP кода")
    p.add_argument("--success-json-jmespath", default=None, help='JMESPath выражение для проверки JSON ответа (например, "status")')
    p.add_argument("--success-json-expect", default=None, help='Ожидаемое строковое значение по JMESPath (например, "ok")')

    # Дополнительное поведение
    p.add_argument("--allow-redirects", action="store_true", help="Разрешить редиректы при логине")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Подробность логов (-v|-vv)")

    args = p.parse_args(argv)

    # Подгружаем .env если доступен dotenv
    if "load_dotenv" in globals():
        load_dotenv()  # type: ignore

    # Валидации
    if not args.username or not args.password:
        print("Требуются --username и --password (или переменные окружения LOGIN_USERNAME/LOGIN_PASSWORD).", file=sys.stderr)
        sys.exit(2)

    # Разбор JSON строк
    try:
        headers = json.loads(args.headers) if args.headers else {}
        if not isinstance(headers, dict):
            raise ValueError("headers must be a JSON object")
    except Exception as e:
        print(f"Некорректный JSON в --headers: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        extra = json.loads(args.extra) if args.extra else {}
        if not isinstance(extra, dict):
            raise ValueError("extra must be a JSON object")
    except Exception as e:
        print(f"Некорректный JSON в --extra: {e}", file=sys.stderr)
        sys.exit(2)

    proxies: Optional[Dict[str, str]] = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    cfg = Config(
        base_url=args.base_url.rstrip("/"),
        login_endpoint=args.login_endpoint,
        method=args.method.upper(),
        username=args.username,
        password=args.password,
        otp=args.otp,
        payload_format=args.payload_format,
        user_field=args.user_field,
        pass_field=args.pass_field,
        otp_field=args.otp_field,
        extra_fields=extra,
        headers=headers,
        timeout=int(args.timeout),
        retries=int(args.retries),
        backoff=float(args.backoff),
        verify_tls=(not args.no_verify_tls),
        proxies=proxies,
        cookie_file=Path(args.cookie_file),
        session_file=Path(args.session_file),
        prefetch_path=args.prefetch_path,
        csrf_cookie_name=args.csrf_cookie_name,
        csrf_meta_name=args.csrf_meta_name,
        csrf_header=args.csrf_header,
        success_http_min=int(args.success_http_min),
        success_http_max=int(args.success_http_max),
        success_json_jmespath=args.success_json_jmespath,
        success_json_expect=args.success_json_expect,
        allow_redirects=bool(args.allow_redirects),
    )

    setup_logging(args.verbose)
    return cfg


# ------------------------------ HTTP сессия и ретраи ------------------------------

def build_session(cfg: Config) -> Session:
    s = requests.Session()

    # Заголовки по умолчанию
    s.headers.update({
        "User-Agent": "automation-core-login/1.0 (+https://aethernova.local)",
        "Accept": "application/json, text/plain, */*",
    })
    # Пользовательские заголовки
    s.headers.update(cfg.headers)

    # Ретраи
    retry = Retry(
        total=cfg.retries,
        read=cfg.retries,
        connect=cfg.retries,
        backoff_factor=cfg.backoff,
        status_forcelist=DEFAULT_STATUS_FORCELIST,
        allowed_methods=DEFAULT_ALLOWED_METHODS,  # POST будет ретраиться только при сетевых ошибках
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=32, pool_maxsize=64)
    s.mount("http://", adapter)
    s.mount("https://", adapter)

    # Прокси
    if cfg.proxies:
        s.proxies.update(cfg.proxies)

    return s


# ------------------------------ CSRF / префлайт ------------------------------

def prefetch_csrf(session: Session, cfg: Config) -> Optional[str]:
    if not cfg.prefetch_path:
        return None

    url = f"{cfg.base_url}{cfg.prefetch_path}"
    log.info("Префлайт GET %s", url)
    try:
        r = session.get(url, timeout=cfg.timeout, verify=cfg.verify_tls, allow_redirects=True)
    except Exception as e:
        log.warning("Префлайт не удался: %s", e)
        return None

    token: Optional[str] = None

    # 1) Cookie
    if cfg.csrf_cookie_name:
        token = r.cookies.get(cfg.csrf_cookie_name)
        if token:
            log.debug("CSRF из cookie '%s' получен.", cfg.csrf_cookie_name)

    # 2) HTML meta
    if not token and cfg.csrf_meta_name:
        html = r.text or ""
        token = extract_meta_csrf(html, cfg.csrf_meta_name)

    return token


def extract_meta_csrf(html: str, meta_name: str) -> Optional[str]:
    # Если есть BeautifulSoup — используем его, иначе — fallback на regex.
    if "BeautifulSoup" in globals():
        soup = BeautifulSoup(html, "html.parser")  # type: ignore
        tag = soup.find("meta", attrs={"name": meta_name})
        if tag and tag.get("content"):
            return tag.get("content")
        return None
    # Простой безопасный regex на meta name/content
    pattern = re.compile(rf'<meta\s+[^>]*name=["\']{re.escape(meta_name)}["\'][^>]*content=["\']([^"\']+)["\']', re.I)
    m = pattern.search(html)
    return m.group(1) if m else None


# ------------------------------ Логин ------------------------------

def build_payload(cfg: Config, csrf_token: Optional[str]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    payload: Dict[str, Any] = {}
    headers: Dict[str, str] = {}

    payload[cfg.user_field] = cfg.username
    payload[cfg.pass_field] = cfg.password

    if cfg.otp and cfg.otp_field:
        payload[cfg.otp_field] = cfg.otp

    # Дополнительные поля
    for k, v in (cfg.extra_fields or {}).items():
        payload[k] = v

    # CSRF в заголовок (если указали имя)
    if csrf_token and cfg.csrf_header:
        headers[cfg.csrf_header] = csrf_token

    return payload, headers


def do_login(session: Session, cfg: Config, csrf_token: Optional[str]) -> requests.Response:
    url = f"{cfg.base_url}{cfg.login_endpoint}"
    payload, csrf_headers = build_payload(cfg, csrf_token)

    log.info("Логин %s %s", cfg.method, url)
    safe_payload = dict(payload)
    # Маскируем секреты
    if cfg.pass_field in safe_payload:
        safe_payload[cfg.pass_field] = "***"
    if cfg.otp_field and cfg.otp_field in safe_payload:
        safe_payload[cfg.otp_field] = "***"
    log.debug("payload=%s", safe_payload)

    headers = dict(session.headers)
    headers.update(csrf_headers)

    if cfg.method == "GET":
        r = session.get(
            url,
            params=payload,
            headers=headers,
            timeout=cfg.timeout,
            verify=cfg.verify_tls,
            allow_redirects=cfg.allow_redirects,
        )
        return r

    # POST
    if cfg.payload_format == "json":
        r = session.post(
            url,
            json=payload,
            headers=headers,
            timeout=cfg.timeout,
            verify=cfg.verify_tls,
            allow_redirects=cfg.allow_redirects,
        )
    else:
        r = session.post(
            url,
            data=payload,
            headers=headers,
            timeout=cfg.timeout,
            verify=cfg.verify_tls,
            allow_redirects=cfg.allow_redirects,
        )
    return r


def success_policy(cfg: Config, resp: requests.Response) -> bool:
    # HTTP диапазон
    if not (cfg.success_http_min <= resp.status_code <= cfg.success_http_max):
        log.warning("HTTP статус вне диапазона успеха: %s", resp.status_code)
        return False

    # JSON политика
    if cfg.success_json_jmespath:
        try:
            data = resp.json()
        except Exception as e:
            log.warning("Ожидался JSON для проверки JMESPath: %s", e)
            return False

        value: Any
        if "jmespath" in globals():
            value = jmespath.search(cfg.success_json_jmespath, data)  # type: ignore
        else:
            # Простейший «dot» навигатор в отсутствие jmespath: key1.key2
            value = data
            for part in cfg.success_json_jmespath.split("."):
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    value = None
                    break

        if cfg.success_json_expect is not None:
            ok = (str(value) == str(cfg.success_json_expect))
            if not ok:
                log.warning("JSON политика не выполнена: %r != %r", value, cfg.success_json_expect)
                return False

    return True


# ------------------------------ Сохранение сессии ------------------------------

def save_cookiejar(cookie_file: Path, jar: RequestsCookieJar) -> None:
    from http.cookiejar import MozillaCookieJar

    ensure_parent_dir(cookie_file)
    tmp = cookie_file.with_suffix(cookie_file.suffix + ".tmp")
    cj = MozillaCookieJar(str(tmp))

    # Переносим из requests.jar
    for c in jar:
        # Учитываем, что MozillaCookieJar требует ключевые поля
        cj.set_cookie(c)

    cj.save(ignore_discard=True, ignore_expires=True)
    chmod_600(tmp)
    tmp.replace(cookie_file)
    log.info("CookieJar сохранён: %s", cookie_file)


def save_session_meta(session_file: Path, cfg: Config, resp: requests.Response) -> None:
    ensure_parent_dir(session_file)
    meta = {
        "saved_at": now_ts(),
        "base_url": cfg.base_url,
        "login_endpoint": cfg.login_endpoint,
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "cookies": [c.name for c in resp.cookies],  # названия, без значений
        "verify_tls": cfg.verify_tls,
        "proxies": bool(cfg.proxies),
    }
    tmp = session_file.with_suffix(session_file.suffix + ".tmp")
    tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    chmod_600(tmp)
    tmp.replace(session_file)
    log.info("Метаданные сессии сохранены: %s", session_file)


# ------------------------------ main ------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    cfg = parse_args(argv)

    log.info("Старт. base_url=%s, user=%s", cfg.base_url, cfg.username)
    log.debug("Пароль=%s, OTP=%s", mask_secret(cfg.password), mask_secret(cfg.otp or ""))

    s = build_session(cfg)

    # Префлайт/CSRF
    csrf_token = prefetch_csrf(s, cfg)
    if csrf_token and cfg.csrf_header:
        log.info("CSRF токен получен и будет добавлен в заголовок %s", cfg.csrf_header)

    try:
        resp = do_login(s, cfg, csrf_token)
    except requests.RequestException as e:
        log.error("Ошибка сети/запроса: %s", e)
        return 3

    log.info("Ответ логина: HTTP %s", resp.status_code)
    # Масштабный отладочный вывод по желанию
    log.debug("Resp headers: %s", dict(resp.headers))
    with contextlib.suppress(Exception):
        log.debug("Resp JSON: %s", resp.json())

    if not success_policy(cfg, resp):
        log.error("Политика успеха не выполнена.")
        return 4

    # Сохраняем cookiejar и метаданные
    try:
        save_cookiejar(Path(cfg.cookie_file), s.cookies)
        save_session_meta(Path(cfg.session_file), cfg, resp)
    except Exception as e:
        log.error("Ошибка сохранения сессии: %s", e)
        return 3

    log.info("Готово.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
