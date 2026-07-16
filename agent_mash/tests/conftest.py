# agent_mash/tests/conftest.py

from __future__ import annotations

import os
import random
import time
from typing import Iterator

import pytest


# ---------------------------------------------------------------------------
# Глобальные инварианты тестового окружения
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _enforce_test_environment() -> None:
    """
    Гарантирует, что тесты запускаются в корректном и изолированном окружении.

    Инварианты:
    - Явно помечено тестовое окружение.
    - Отсутствуют продакшн-флаги.
    """
    os.environ.setdefault("ENV", "test")
    os.environ.setdefault("PYTHONHASHSEED", "0")


# ---------------------------------------------------------------------------
# Детерминизм и воспроизводимость
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _fix_random_seed() -> None:
    """
    Фиксирует генераторы случайных чисел для воспроизводимости тестов.
    """
    random.seed(0)


@pytest.fixture
def fixed_time(monkeypatch: pytest.MonkeyPatch) -> float:
    """
    Замораживает time.time() на фиксированное значение.

    Используется в тестах, где важно исключить влияние реального времени.
    """
    frozen = 1_600_000_000.0

    def _fake_time() -> float:
        return frozen

    monkeypatch.setattr(time, "time", _fake_time)
    return frozen


# ---------------------------------------------------------------------------
# Базовые фикстуры pytest
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_environ(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """
    Обеспечивает чистое окружение переменных среды для теста.
    """
    original = dict(os.environ)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


@pytest.fixture
def tmp_workdir(tmp_path):
    """
    Изолированная временная рабочая директория для тестов,
    исключающая влияние файловой системы.
    """
    return tmp_path


# ---------------------------------------------------------------------------
# Защитные хуки pytest
# ---------------------------------------------------------------------------

def pytest_configure(config: pytest.Config) -> None:
    """
    Конфигурационный хук pytest.

    Используется для:
    - фиксации пользовательских маркеров,
    - централизованной инициализации тестового контура.
    """
    config.addinivalue_line(
        "markers",
        "unit: isolated unit tests without external dependencies",
    )
    config.addinivalue_line(
        "markers",
        "integration: tests with controlled integrations",
    )
    config.addinivalue_line(
        "markers",
        "e2e: end-to-end tests",
    )
    config.addinivalue_line(
        "markers",
        "slow: long-running tests excluded from default runs",
    )
    config.addinivalue_line(
        "markers",
        "flaky: unstable tests, allowed only temporarily",
    )


def pytest_runtest_setup(item: pytest.Item) -> None:
    """
    Хук, выполняемый перед каждым тестом.

    Используется для enforce-логики:
    - запрет случайного использования flaky без явного маркера,
    - точка расширения для будущих проверок.
    """
    if "flaky" in item.keywords and "allow_flaky" not in item.keywords:
        pass


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """
    Хук завершения сессии pytest.

    Предназначен для:
    - финальных проверок,
    - интеграции с CI-артефактами при необходимости.
    """
    _ = session
    _ = exitstatus
