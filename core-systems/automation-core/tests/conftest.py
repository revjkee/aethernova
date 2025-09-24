# automation-core/tests/conftest.py
from __future__ import annotations

import asyncio
import logging
import os
import random
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

import pytest

try:
    # Не требуем обязательно python-dotenv, но используем если установлен
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None  # type: ignore[assignment]

# Автоматически подключаем доп. фикстуры, если они присутствуют в проекте
# (см. дерево: tests/fixtures/{db.py,http.py,browser.py})
pytest_plugins = (
    "tests.fixtures.db",
    "tests.fixtures.http",
    "tests.fixtures.browser",
)

# ---------- Константы и утилиты ----------

DEFAULT_DOTENV_FILES = (".env.test", ".env.ci", ".env")
LOG_FORMAT = (
    "%(asctime)s.%(msecs)03dZ "
    "%(levelname)s "
    "%(name)s "
    "%(filename)s:%(lineno)d "
    "%(message)s"
)


@contextmanager
def _chdir(path: Path) -> Iterator[None]:
    """Контекстный менеджер для смены текущего рабочей директории с возвратом назад."""
    prev = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(prev)


def _load_first_existing_env(root: Path) -> Optional[Path]:
    """Подхватывает первый существующий .env из предопределённого списка."""
    for name in DEFAULT_DOTENV_FILES:
        p = root / name
        if p.exists():
            return p
    return None


# ---------- Pytest hooks ----------

def pytest_addoption(parser: pytest.Parser) -> None:
    """Регистрируем CLI-флаги для управления прогоном."""
    group = parser.getgroup("run-control")
    group.addoption(
        "--runslow",
        action="store_true",
        default=False,
        help="Run tests marked as 'slow'.",
    )
    group.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="Run tests marked as 'integration'.",
    )
    group.addoption(
        "--e2e",
        action="store_true",
        default=False,
        help="Run tests marked as 'e2e'.",
    )
    parser.addini("markers", "slow: mark tests as slow")
    parser.addini("markers", "integration: mark tests as integration")
    parser.addini("markers", "e2e: mark tests as end-to-end")
    parser.addini("markers", "db: tests requiring database access")
    parser.addini("markers", "http: tests requiring HTTP/network")
    parser.addini("markers", "browser: tests requiring browser automation")


def pytest_configure(config: pytest.Config) -> None:
    """Регистрируем маркеры (для Pytest>=7 предупреждения не выводятся)."""
    markers = [
        "slow: mark tests as slow",
        "integration: mark tests as integration",
        "e2e: mark tests as end-to-end",
        "db: tests requiring database access",
        "http: tests requiring HTTP/network",
        "browser: tests requiring browser automation",
        "security: tests related to security flows",
    ]
    for m in markers:
        config.addinivalue_line("markers", m)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Управляем пропусками тестов на основе флагов командной строки."""
    run_slow = config.getoption("--runslow")
    run_integration = config.getoption("--integration")
    run_e2e = config.getoption("--e2e")

    skip_slow = pytest.mark.skip(reason="need --runslow to run")
    skip_integration = pytest.mark.skip(reason="need --integration to run")
    skip_e2e = pytest.mark.skip(reason="need --e2e to run")

    for item in items:
        if "slow" in item.keywords and not run_slow:
            item.add_marker(skip_slow)
        if "integration" in item.keywords and not run_integration:
            item.add_marker(skip_integration)
        if "e2e" in item.keywords and not run_e2e:
            item.add_marker(skip_e2e)


# ---------- Фикстуры верхнего уровня ----------

@pytest.fixture(scope="session", autouse=True)
def _env_loaded() -> Optional[Path]:
    """
    Автозагрузка переменных окружения из .env.{test|ci|default}, если доступен python-dotenv.
    Приоритет: .env.test > .env.ci > .env.
    """
    project_root = Path(__file__).resolve().parents[1]
    env_path = _load_first_existing_env(project_root)
    if load_dotenv and env_path:
        load_dotenv(dotenv_path=env_path, override=False)
        os.environ.setdefault("ENV", "test")
        return env_path
    # Если dotenv не установлен — пропускаем бесшумно.
    os.environ.setdefault("ENV", "test")
    return None


@pytest.fixture(scope="session", autouse=True)
def _configure_logging() -> None:
    """
    Единообразное логирование для тестов: UTC-таймстемпы, единый формат, INFO по умолчанию.
    Можно усилить через переменную LOG_LEVEL.
    """
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    # Гарантируем отсутствие дублирующих хендлеров при повторных вызовах
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt="%Y-%m-%dT%H:%M:%S"))
    root.addHandler(handler)
    root.setLevel(level)


@pytest.fixture(scope="session")
def event_loop() -> asyncio.AbstractEventLoop:
    """
    Глобальный event loop уровня session.
    В проекте используется только асинхронная SQLAlchemy-сессия — держим один loop.
    """
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        # Осторожное завершение всех оставшихся задач
        pending = asyncio.all_tasks(loop=loop)
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Корень проекта (папка automation-core/)."""
    return Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def tests_root() -> Path:
    """Корень каталога с тестами."""
    return Path(__file__).resolve().parent


@pytest.fixture(scope="function")
def temp_workdir(tmp_path: Path) -> Iterator[Path]:
    """
    Изолированный рабочий каталог на время теста (chdir).
    Полезно для тестов, создающих временные файлы/директории.
    """
    with _chdir(tmp_path):
        yield tmp_path


@pytest.fixture(scope="session")
def random_seed() -> int:
    """
    Фиксированный seed для воспроизводимости.
    Значение можно переопределить через переменную окружения TEST_SEED.
    """
    seed_env = os.getenv("TEST_SEED")
    seed = int(seed_env) if seed_env and seed_env.isdigit() else 1337
    random.seed(seed)
    try:
        import numpy as np  # type: ignore
        np.random.seed(seed)  # pragma: no cover
    except Exception:
        pass
    return seed


@pytest.fixture(scope="session")
def has_playwright() -> bool:
    """Есть ли playwright в зависимостях (для условных e2e-тестов браузера)."""
    try:
        import importlib.util

        return importlib.util.find_spec("playwright") is not None
    except Exception:  # pragma: no cover
        return False


@pytest.fixture(scope="session")
def has_psycopg() -> bool:
    """Есть ли psycopg2/psycopg (для PostgreSQL-интеграций)."""
    try:
        import importlib.util

        return any(
            importlib.util.find_spec(m) is not None
            for m in ("psycopg2", "psycopg")
        )
    except Exception:  # pragma: no cover
        return False


# ---------- Политики пропуска в рантайме (доп. защита) ----------

@pytest.fixture(autouse=True)
def _skip_if_browser_marker_without_flag(
    request: pytest.FixtureRequest, has_playwright: bool
) -> None:
    """
    Если тест помечен @pytest.mark.browser, но playwright отсутствует — пропускаем.
    """
    if "browser" in request.keywords and not has_playwright:
        pytest.skip("Playwright is not available; skipping browser-marked test.")


@pytest.fixture(autouse=True)
def _skip_if_db_marker_without_driver(
    request: pytest.FixtureRequest, has_psycopg: bool
) -> None:
    """
    Если тест помечен @pytest.mark.db и требуется PostgreSQL-драйвер, но его нет — пропускаем.
    (Unit-тесты SQLite не затрагивает.)
    """
    if "db" in request.keywords and not has_psycopg:
        # Это условие действует, когда тест явно требует PG.
        # Для SQLite-тестов используйте отдельные маркеры/фикстуры.
        pass
