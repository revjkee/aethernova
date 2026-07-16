"""
agent_mash.tests.performance

Пакет для performance и load тестов.

Цели:
- Явное включение perf-тестов через переменные окружения (чтобы не запускались случайно в CI/локально).
- Единый конфиг и утилиты, пригодные для промышленного пайплайна.
- Нулевые побочные эффекты при импорте (только определения).

Принципы:
- Safe-by-default: perf-тесты выключены по умолчанию.
- Reproducibility: конфиг читается из окружения, значения нормализуются.
- Explicitness: публичный API пакета фиксирован через __all__.
"""

from __future__ import annotations

from dataclasses import dataclass
from os import getenv
from typing import Final, Optional

__all__ = [
    "PERF_ENV_ENABLE",
    "PERF_ENV_SEED",
    "PERF_ENV_DURATION_S",
    "PERF_ENV_WARMUP_S",
    "PERF_ENV_THREADS",
    "PERF_ENV_TARGET_RPS",
    "PerfConfig",
    "get_perf_config",
    "is_perf_enabled",
    "require_perf",
]


PERF_ENV_ENABLE: Final[str] = "AETHERNOVA_RUN_PERF"
PERF_ENV_SEED: Final[str] = "AETHERNOVA_PERF_SEED"
PERF_ENV_DURATION_S: Final[str] = "AETHERNOVA_PERF_DURATION_S"
PERF_ENV_WARMUP_S: Final[str] = "AETHERNOVA_PERF_WARMUP_S"
PERF_ENV_THREADS: Final[str] = "AETHERNOVA_PERF_THREADS"
PERF_ENV_TARGET_RPS: Final[str] = "AETHERNOVA_PERF_TARGET_RPS"


_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "y", "on"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "no", "n", "off"}


def _parse_bool(value: Optional[str], *, default: bool = False) -> bool:
    if value is None:
        return default
    v = value.strip().lower()
    if v in _TRUE_VALUES:
        return True
    if v in _FALSE_VALUES:
        return False
    return default


def _parse_int(value: Optional[str], *, default: int, min_value: int, max_value: int) -> int:
    if value is None:
        return default
    try:
        n = int(value.strip())
    except Exception:
        return default
    if n < min_value:
        return min_value
    if n > max_value:
        return max_value
    return n


@dataclass(frozen=True, slots=True)
class PerfConfig:
    """
    Единый конфиг perf-тестов.

    enabled: включение perf-режима
    seed: сид для воспроизводимости (если применимо)
    duration_s: основная длительность прогона
    warmup_s: прогрев перед замерами
    threads: условный уровень параллелизма для тестов, где применимо
    target_rps: целевая нагрузка (RPS), если сценарий ее поддерживает
    """

    enabled: bool
    seed: int
    duration_s: int
    warmup_s: int
    threads: int
    target_rps: int


def get_perf_config() -> PerfConfig:
    """
    Читает конфиг perf-тестов из окружения и возвращает нормализованный PerfConfig.
    """
    enabled = _parse_bool(getenv(PERF_ENV_ENABLE), default=False)

    seed = _parse_int(getenv(PERF_ENV_SEED), default=42, min_value=0, max_value=2_147_483_647)
    duration_s = _parse_int(getenv(PERF_ENV_DURATION_S), default=30, min_value=1, max_value=24 * 60 * 60)
    warmup_s = _parse_int(getenv(PERF_ENV_WARMUP_S), default=5, min_value=0, max_value=60 * 60)
    threads = _parse_int(getenv(PERF_ENV_THREADS), default=4, min_value=1, max_value=1024)
    target_rps = _parse_int(getenv(PERF_ENV_TARGET_RPS), default=50, min_value=1, max_value=10_000_000)

    if warmup_s >= duration_s:
        warmup_s = max(0, duration_s - 1)

    return PerfConfig(
        enabled=enabled,
        seed=seed,
        duration_s=duration_s,
        warmup_s=warmup_s,
        threads=threads,
        target_rps=target_rps,
    )


def is_perf_enabled() -> bool:
    """
    Быстрая проверка, включены ли perf-тесты.
    """
    return get_perf_config().enabled


def require_perf(*, reason: str = "performance tests are disabled by default") -> None:
    """
    Гейт для perf-тестов.

    Использование внутри теста:
        from agent_mash.tests.performance import require_perf
        require_perf()

    Если perf-режим не включен, тест корректно пропускается через pytest.skip.
    """
    if is_perf_enabled():
        return

    try:
        import pytest  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "Perf tests are disabled and pytest is unavailable to skip. "
            f"Set {PERF_ENV_ENABLE}=1 to enable performance tests."
        ) from exc

    pytest.skip(f"{reason}. Set {PERF_ENV_ENABLE}=1 to enable.")
