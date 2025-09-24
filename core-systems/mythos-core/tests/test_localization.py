# mythos-core/tests/unit/test_localization.py
# -*- coding: utf-8 -*-
"""
Промышленный тестовый модуль для mythos_core.localization.

ОЖИДАЕМЫЙ КОНТРАКТ API (минимум):
- class Localizer:
    @classmethod
    def from_path(path: str | pathlib.Path,
                  default_locale: str = "en",
                  fallback_locales: list[str] | None = None,
                  cache: bool = True) -> "Localizer"

    def t(self, key: str, /, **params) -> str
    def exists(self, key: str) -> bool
    def set_locale(self, locale: str) -> None
    def get_locale(self) -> str
    # Контекстный менеджер, меняющий локаль в рамках with-блока (обязателен для потоковой изоляции)
    def with_locale(self, locale: str):
        ...

    # Опционально (если реализовано — тесты пройдут; если нет — будут помечены xfail/skip):
    def format_date(self, dt, format: str = "medium") -> str
    def format_number(self, number) -> str
    def format_currency(self, amount, currency: str) -> str

МОДУЛЬНЫЕ ФУНКЦИИ (опционально):
- def detect_locale_from_headers(headers: dict, supported: list[str], default: str) -> str

КАТАЛОГИ ПЕРЕВОДОВ:
Тесты создают временные JSON-файлы: en.json, ru.json, ar.json с полями: locale, messages.
ICU-плюрализация используется в значениях "apples".

Если часть API не реализована, соответствующие тесты будут помечены как xfail/skip с четким пояснением.
"""

from __future__ import annotations

import importlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import pytest


# --------------------------
# Вспомогательные заготовки
# --------------------------

EN_CATALOG = {
    "locale": "en",
    "messages": {
        "greet": "Hello, {name}.",
        "apples": "{count, plural, one {# apple} other {# apples}}",
        "nested.key.value": "Deep value",
        "needs_param": "Param is {p}",
        "dangerous": "Literal braces {{not a placeholder}} and {param}",
        "date_example": "Today is {date}",
        "fallback_only": "Only in EN"
    },
    "metadata": {"version": "1.0.0"}
}

RU_CATALOG = {
    "locale": "ru",
    "messages": {
        "greet": "Привет, {name}.",
        # Русская ICU-плюрализация: one, few, many, other
        "apples": "{count, plural, one {# яблоко} few {# яблока} many {# яблок} other {# яблока}}",
        "nested.key.value": "Глубокое значение",
        "needs_param": "Параметр {p}",
        "date_example": "Сегодня {date}"
    },
    "metadata": {"version": "1.0.0"}
}

AR_CATALOG = {
    "locale": "ar",
    "messages": {
        "greet": "مرحبا، {name}.",
        "apples": "{count, plural, one {# تفاحة} other {# تفاحات}}",
        # отсутсвует nested.key.value — проверим fallback в EN
    },
    "metadata": {"version": "1.0.0", "rtl": True}
}


def _write_catalogs(tmp_path: Path) -> Path:
    (tmp_path / "en.json").write_text(json.dumps(EN_CATALOG, ensure_ascii=False, indent=2), encoding="utf-8")
    (tmp_path / "ru.json").write_text(json.dumps(RU_CATALOG, ensure_ascii=False, indent=2), encoding="utf-8")
    (tmp_path / "ar.json").write_text(json.dumps(AR_CATALOG, ensure_ascii=False, indent=2), encoding="utf-8")
    return tmp_path


def _import_localizer():
    try:
        mod = importlib.import_module("mythos_core.localization")
    except ModuleNotFoundError as e:
        pytest.skip(f"Модуль mythos_core.localization не найден: {e}")
    L = getattr(mod, "Localizer", None)
    if L is None:
        pytest.skip("Класс Localizer не найден в mythos_core.localization")
    return mod, L


def _build_localizer(catalog_dir: Path,
                     default_locale: str = "en",
                     fallbacks: Optional[list[str]] = None):
    mod, Localizer = _import_localizer()
    fallbacks = fallbacks or ["en"]
    if hasattr(Localizer, "from_path") and callable(Localizer.from_path):
        return Localizer.from_path(catalog_dir, default_locale=default_locale, fallback_locales=fallbacks, cache=True)
    # Если from_path не реализован — пробуем конструктор с типичными параметрами
    try:
        return Localizer(catalog_dir, default_locale=default_locale, fallback_locales=fallbacks)
    except TypeError:
        return Localizer(catalog_dir, default_locale=default_locale)


def _has_attr(obj: Any, name: str) -> bool:
    return hasattr(obj, name) and callable(getattr(obj, name))


# --------------------------
# Тесты API поверхности
# --------------------------

@pytest.mark.localization
def test_api_surface_minimal(tmp_path: Path):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path)

    assert _has_attr(loc, "t"), "Ожидается метод t(key, **params)"
    assert _has_attr(loc, "set_locale"), "Ожидается метод set_locale(locale)"
    assert _has_attr(loc, "get_locale"), "Ожидается метод get_locale()"
    assert _has_attr(loc, "with_locale"), "Ожидается контекстный менеджер with_locale(locale)"
    assert _has_attr(loc, "exists"), "Ожидается метод exists(key)"


# --------------------------
# Базовая загрузка и перевод
# --------------------------

@pytest.mark.localization
def test_basic_loading_and_translation(tmp_path: Path):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path, default_locale="en", fallbacks=["en"])

    assert loc.get_locale() in {"en", "en_US", "en-001", "en_GB", "en-GB", "en-US"}
    assert loc.t("greet", name="World") == "Hello, World."
    assert loc.t("nested.key.value") == "Deep value"

    loc.set_locale("ru")
    assert loc.get_locale().startswith("ru")
    assert loc.t("greet", name="Мир") == "Привет, Мир."
    assert loc.t("nested.key.value") == "Глубокое значение"


@pytest.mark.localization
def test_interpolation_and_missing_params(tmp_path: Path):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path)

    # Успешная интерполяция
    assert loc.t("needs_param", p=42) in {"Param is 42", "Параметр 42"}

    # Отсутствующий параметр — ожидаем управляемую ошибку или диагностический текст
    with pytest.raises(Exception, match="p|param|missing|KeyError"):
        loc.t("needs_param")  # без p

    # Экранированные фигурные скобки должны оставаться буквальными
    txt = loc.t("dangerous", param="ok")
    assert "{" in txt and "}" in txt and "ok" in txt
    assert "{{" not in txt and "}}" not in txt, "Двойные скобки должны интерпретироваться как литералы"


# --------------------------
# ICU-плюрализация
# --------------------------

@pytest.mark.localization
def test_pluralization_en(tmp_path: Path):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path, default_locale="en")

    assert loc.t("apples", count=1) == "1 apple"
    assert loc.t("apples", count=2) == "2 apples"
    assert loc.t("apples", count=0) == "0 apples"


@pytest.mark.localization
def test_pluralization_ru(tmp_path: Path):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path, default_locale="ru")

    cases = {
        1: "1 яблоко",
        2: "2 яблока",
        5: "5 яблок",
        21: "21 яблоко",
        22: "22 яблока",
        25: "25 яблок",
        111: "111 яблок",
    }
    for n, expected in cases.items():
        got = loc.t("apples", count=n)
        assert got == expected, f"ru plural failed for {n}: got '{got}', expected '{expected}'"


# --------------------------
# Fallback-цепочки и отсутствие ключей
# --------------------------

@pytest.mark.localization
def test_fallback_chain(tmp_path: Path):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path, default_locale="ar", fallbacks=["ru", "en"])

    # В ar отсутствует nested.key.value → берем из ru? там есть → да.
    # Если реализация предпочитает непосредственный fallback к en, важен порядок ["ru", "en"].
    got = loc.t("nested.key.value")
    assert got in {"Глубокое значение", "Deep value"}, "Должен сработать fallback ru → en"

    # Ключ существует только в EN
    got2 = loc.t("fallback_only")
    assert got2 == "Only in EN", "Fallback до EN для ключа fallback_only"


@pytest.mark.localization
def test_missing_key_behavior(tmp_path: Path):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path)

    # exists должен корректно отражать наличие ключа
    assert loc.exists("greet") is True
    assert loc.exists("no.such.key") is False

    # Для отсутствующего ключа — либо понятная ошибка, либо диагностический маркер
    with pytest.raises(Exception):
        _ = loc.t("no.such.key")


# --------------------------
# Контекстная локаль и потоки
# --------------------------

@pytest.mark.localization
def test_with_locale_context_manager(tmp_path: Path):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path, default_locale="en")

    assert loc.t("greet", name="User") == "Hello, User."
    with loc.with_locale("ru"):
        assert loc.get_locale().startswith("ru")
        assert loc.t("greet", name="Пользователь") == "Привет, Пользователь."
    # после выхода из with локаль возвращается
    assert loc.t("greet", name="User") == "Hello, User."


@pytest.mark.localization
def test_locale_is_thread_isolated(tmp_path: Path):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path, default_locale="en")

    results = []

    def worker(locale: str, name: str):
        with loc.with_locale(locale):
            results.append(loc.t("greet", name=name))

    t1 = threading.Thread(target=worker, args=("en", "Alice"))
    t2 = threading.Thread(target=worker, args=("ru", "Алиса"))
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert "Hello, Alice." in results
    assert "Привет, Алиса." in results


# --------------------------
# Форматирование дат/чисел/валют (опционально)
# --------------------------

@pytest.mark.localization
@pytest.mark.parametrize("locale,expected_substr", [
    ("en", "2024"),  # строка должна содержать год
    ("ru", "2024"),
])
def test_format_date_if_available(tmp_path: Path, locale: str, expected_substr: str):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path, default_locale=locale)

    if not _has_attr(loc, "format_date"):
        pytest.xfail("format_date не реализован")

    dt = datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    s = loc.format_date(dt, format="long")
    assert isinstance(s, str) and expected_substr in s


@pytest.mark.localization
def test_format_currency_if_available(tmp_path: Path):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path, default_locale="en")

    if not _has_attr(loc, "format_currency"):
        pytest.xfail("format_currency не реализован")

    s = loc.format_currency(1234.56, "USD")
    assert isinstance(s, str) and ("USD" in s or "$" in s)


@pytest.mark.localization
def test_format_number_if_available(tmp_path: Path):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path, default_locale="ru")

    if not _has_attr(loc, "format_number"):
        pytest.xfail("format_number не реализован")

    s = loc.format_number(1000000.5)
    assert isinstance(s, str) and any(ch in s for ch in [",", " ", " ", "."])


# --------------------------
# Детекция локали из заголовков (опционально)
# --------------------------

@pytest.mark.localization
def test_detect_locale_from_headers_if_available(tmp_path: Path):
    mod, _ = _import_localizer()
    detector = getattr(mod, "detect_locale_from_headers", None)
    if detector is None or not callable(detector):
        pytest.xfail("detect_locale_from_headers не реализован")

    headers = {"Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8"}
    supported = ["en", "ru", "ar"]
    assert detector(headers, supported, default="en").startswith("ru")

    headers2 = {"Accept-Language": "fr-CA,fr;q=0.9"}
    assert detector(headers2, supported, default="en").startswith("en")


# --------------------------
# Валидация схемы каталога
# --------------------------

@pytest.mark.localization
def test_catalog_schema_validation(tmp_path: Path):
    # пишем корректные каталоги и один некорректный
    _write_catalogs(tmp_path)
    bad = {
        # "locale": "xx",  # отсутствует
        "messages": {"key": "value"}
    }
    (tmp_path / "bad.json").write_text(json.dumps(bad, ensure_ascii=False), encoding="utf-8")

    # Ожидается, что при загрузке каталогов будет поднято исключение/диагностика
    with pytest.raises(Exception):
        _build_localizer(tmp_path)


# --------------------------
# Безопасность форматирования
# --------------------------

@pytest.mark.localization
def test_no_code_injection_in_messages(tmp_path: Path):
    # Сообщения не должны исполнять код; фигурные скобки — лишь плейсхолдеры.
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path)

    payload = "{__import__('os').system('echo hacked')}"
    # Передаем как текстовый параметр — ожидаем безопасный вывод, а не выполнение
    out = loc.t("dangerous", param=payload)
    assert payload in out
    # Косвенная проверка: если бы код выполнялся, след теста был бы иным; здесь фиксируем только строковый вывод.


# --------------------------
# Дата встраивается через t() (составной кейс)
# --------------------------

@pytest.mark.localization
def test_date_interpolation_via_t(tmp_path: Path):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path, default_locale="ru")

    today_fmt = "2024-12-31"
    out = loc.t("date_example", date=today_fmt)
    assert "2024" in out and any(substr in out for substr in ["Сегодня", "Today"])


# --------------------------
# Диагностика ошибок — сообщения понятны
# --------------------------

@pytest.mark.localization
def test_error_messages_are_informative(tmp_path: Path):
    _write_catalogs(tmp_path)
    loc = _build_localizer(tmp_path)

    with pytest.raises(Exception) as ei:
        loc.t("needs_param")  # нет p
    msg = str(ei.value)
    # Ошибка должна содержать имя ключа/параметра, чтобы разработчик быстро нашел причину
    assert any(token in msg for token in ["needs_param", "p", "param", "missing"])
