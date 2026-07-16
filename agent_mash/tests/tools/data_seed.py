# agent_mash/tests/tools/data_seed.py
from __future__ import annotations

import os
import random
import secrets
import typing as t
from dataclasses import dataclass

__all__ = [
    "SeedConfig",
    "get_seed",
    "init_global_seed",
    "rng",
]

DEFAULT_TEST_SEED = 1337
ENV_SEED_KEY = "TEST_DATA_SEED"


@dataclass(frozen=True, slots=True)
class SeedConfig:
    """
    Конфигурация seed для тестовых данных.

    seed:
        Целочисленный seed, используемый для всех генераторов.
    source:
        Источник значения seed (env, default, explicit).
    """

    seed: int
    source: str


def _parse_seed(value: str) -> int:
    """
    Преобразует строковое значение seed в int.
    """
    value = value.strip()
    try:
        return int(value)
    except ValueError:
        raise ValueError(
            f"Invalid seed value '{value}'. "
            f"{ENV_SEED_KEY} must be an integer."
        )


def get_seed(explicit: int | None = None) -> SeedConfig:
    """
    Определяет seed для тестовых данных.

    Приоритет:
    1. Явно переданный seed
    2. Переменная окружения TEST_DATA_SEED
    3. DEFAULT_TEST_SEED
    """
    if explicit is not None:
        return SeedConfig(seed=int(explicit), source="explicit")

    env_value = os.environ.get(ENV_SEED_KEY)
    if env_value is not None:
        return SeedConfig(seed=_parse_seed(env_value), source="env")

    return SeedConfig(seed=DEFAULT_TEST_SEED, source="default")


def init_global_seed(explicit: int | None = None) -> SeedConfig:
    """
    Инициализирует глобальный random.seed.

    Вызывается один раз на старте тестов.
    """
    config = get_seed(explicit)
    random.seed(config.seed)
    return config


class _RNGProxy:
    """
    Обёртка над random.Random для централизованного доступа.

    Используется вместо прямого random.* в тестах.
    """

    def __init__(self) -> None:
        self._rng: random.Random | None = None

    def init(self, seed: int) -> None:
        self._rng = random.Random(seed)

    def _get(self) -> random.Random:
        if self._rng is None:
            raise RuntimeError(
                "RNG is not initialized. "
                "Call init_global_seed() before using rng."
            )
        return self._rng

    def randint(self, a: int, b: int) -> int:
        return self._get().randint(a, b)

    def choice(self, seq: t.Sequence[t.Any]) -> t.Any:
        return self._get().choice(seq)

    def random(self) -> float:
        return self._get().random()

    def sample(self, population: t.Sequence[t.Any], k: int) -> list[t.Any]:
        return self._get().sample(population, k)

    def token_hex(self, nbytes: int = 8) -> str:
        """
        Детерминированный hex-токен.
        """
        value = self._get().getrandbits(nbytes * 8)
        return f"{value:0{nbytes * 2}x}"


rng = _RNGProxy()
