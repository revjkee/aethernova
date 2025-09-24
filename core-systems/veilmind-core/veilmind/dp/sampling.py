# -*- coding: utf-8 -*-
"""
veilmind.dp.sampling
====================

Промышленные примитивы сэмплинга и утилиты дифференциальной приватности.

Возможности:
- RNG: крипто-стойкий (SystemPRNG) и детерминированный (DeterministicPRNG на Blake2b‑PRF).
- Подвыборка: Poisson (включение с вероятностью p), равномерная без возвращения (Floyd), с возвращением.
- Резервуарное сэмплирование для потоков (Reservoir L; неизвестный N).
- Потоковые генераторы индексов без аллокаций на N.
- Шум Laplace/Gaussian + калибровка σ для (ε,δ)‑DP (классическая оценка).
- Усиление приватности подвыборкой: ε' = ln(1 + q * (e^ε - 1)), δ' = q * δ (Poisson).
- Композиция механизмов: базовая (суммы) и «advanced» (Dwork et al., ε_total и δ_total).

Зависимости: только стандартная библиотека Python.

ВНИМАНИЕ:
- Детерминированный PRNG предназначен для воспроизводимости экспериментов, не для криптографии.
- Для критичных к атакующему сценариев используйте SystemPRNG.
"""

from __future__ import annotations

import base64
import itertools
import math
import os
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Any, Dict, Generator, Iterable, Iterator, List, Optional, Sequence, Tuple, TypeVar

import hashlib
import hmac
import random

__all__ = [
    "SystemPRNG",
    "DeterministicPRNG",
    "get_rng",
    "poisson_subsample_indices",
    "uniform_without_replacement",
    "uniform_with_replacement",
    "reservoir_sample",
    "iter_poisson_mask",
    "iter_uniform_without_replacement",
    "laplace_noise",
    "gaussian_noise",
    "calibrate_gaussian_sigma",
    "amplify_eps_delta_poisson",
    "compose_basic",
    "compose_advanced",
]

T = TypeVar("T")

# =============================================================================
# RNGs
# =============================================================================

class SystemPRNG:
    """
    Криптографически стойкий генератор на основе secrets.SystemRandom.
    Не детерминирован. Подходит для продакшна там, где воспроизводимость не требуется.
    """
    def __init__(self) -> None:
        self._sys = secrets.SystemRandom()

    # Совместимый интерфейс
    def random(self) -> float:
        return self._sys.random()

    def randrange(self, start: int, stop: Optional[int] = None) -> int:
        if stop is None:
            return self._sys.randrange(start)
        return self._sys.randrange(start, stop)

    def randint(self, a: int, b: int) -> int:
        return self._sys.randint(a, b)

    def choice(self, seq: Sequence[T]) -> T:
        if not seq:
            raise IndexError("cannot choose from an empty sequence")
        return seq[self._sys.randrange(0, len(seq))]

    def shuffle(self, x: List[T]) -> None:
        self._sys.shuffle(x)

    def randbits(self, k: int) -> int:
        return self._sys.getrandbits(k)

    def bytes(self, n: int) -> bytes:
        return secrets.token_bytes(n)


class DeterministicPRNG:
    """
    Детерминированный PRNG на основе блочного счётчика и Blake2b (PRF).
    Подходит для воспроизводимых экспериментов и оффлайн-оценок.

    Конструкция:
        R[i] = blake2b(key=kdf(seed, label, salt), data=uint64_le(counter=i)) -> 64 байт
    Из блока извлекаем 64-битные слова для randrange/random.

    ВАЖНО: это *не* криптографический DRBG, хотя построен на криптографической хеш‑функции.
    Для продакшн‑секьюрности используйте SystemPRNG.
    """
    def __init__(self, seed: bytes | str | int, label: str = "veilmind.dp", salt: bytes | None = None) -> None:
        self._key = self._kdf(seed, label, salt)
        self._counter = 0
        self._pool = b""
        self._pool_pos = 0

    @staticmethod
    def _kdf(seed: bytes | str | int, label: str, salt: Optional[bytes]) -> bytes:
        if isinstance(seed, int):
            seed_b = seed.to_bytes(32, "big", signed=False)
        elif isinstance(seed, str):
            seed_b = seed.encode("utf-8")
        else:
            seed_b = seed
        salt_b = salt if salt is not None else b""
        # HKDF-подобная конструкция на BLAKE2b (без внешних зависимостей)
        prk = hmac.new(salt_b, seed_b, hashlib.blake2b).digest()
        okm = hmac.new(prk, b"key|" + label.encode("utf-8"), hashlib.blake2b).digest()
        return okm

    def _refill(self) -> None:
        block = hashlib.blake2b(struct.pack("<Q", self._counter), key=self._key, digest_size=64).digest()
        self._counter += 1
        self._pool = block
        self._pool_pos = 0

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while n > 0:
            if self._pool_pos >= len(self._pool):
                self._refill()
            take = min(n, len(self._pool) - self._pool_pos)
            out += self._pool[self._pool_pos : self._pool_pos + take]
            self._pool_pos += take
            n -= take
        return bytes(out)

    def randbits(self, k: int) -> int:
        nbytes = (k + 7) // 8
        b = self.bytes(nbytes)
        # Маскируем старшие биты
        val = int.from_bytes(b, "big")
        val &= (1 << k) - 1
        return val

    def random(self) -> float:
        # 53 случайных бита для double в [0,1)
        return self.randbits(53) / (1 << 53)

    def randrange(self, start: int, stop: Optional[int] = None) -> int:
        if stop is None:
            stop = start
            start = 0
        if stop <= start:
            raise ValueError("empty range")
        width = stop - start
        # Без смещения: отбрасывание по модулю для равномерности
        k = width.bit_length()
        while True:
            r = self.randbits(k)
            if r < width:
                return start + r

    def randint(self, a: int, b: int) -> int:
        if b < a:
            raise ValueError("b < a")
        return a + self.randrange(b - a + 1)

    def choice(self, seq: Sequence[T]) -> T:
        if not seq:
            raise IndexError("cannot choose from an empty sequence")
        return seq[self.randrange(0, len(seq))]

    def shuffle(self, x: List[T]) -> None:
        # Fisher–Yates
        n = len(x)
        for i in range(n - 1, 0, -1):
            j = self.randrange(i + 1)
            x[i], x[j] = x[j], x[i]


def get_rng(mode: str = "secure", *, seed: bytes | str | int | None = None, label: str = "veilmind.dp") -> SystemPRNG | DeterministicPRNG:
    """
    Получить RNG.
    mode="secure" — SystemPRNG (по умолчанию).
    mode="deterministic" — DeterministicPRNG (требует seed).
    """
    if mode == "secure":
        return SystemPRNG()
    if mode == "deterministic":
        if seed is None:
            raise ValueError("deterministic mode requires 'seed'")
        return DeterministicPRNG(seed=seed, label=label)
    raise ValueError("mode must be 'secure' or 'deterministic'")

# =============================================================================
# Сэмплинг
# =============================================================================

def poisson_subsample_indices(n: int, p: float, *, rng: SystemPRNG | DeterministicPRNG) -> List[int]:
    """
    Poisson-подвыборка: каждый индекс включается независимо с вероятностью p.
    Возвращает отсортированный список индексов в [0, n).
    """
    if not (0.0 <= p <= 1.0):
        raise ValueError("p must be in [0,1]")
    if n < 0:
        raise ValueError("n must be non-negative")
    out: List[int] = []
    # Векторизация без numpy: случай независимостей
    # Оптимизация: геометрические пропуски
    if p == 0.0 or n == 0:
        return out
    if p == 1.0:
        return list(range(n))
    # Алгоритм пропуска: генерируем длины пробелов по геометрическому распределению
    # P(gap = k) = (1-p)^k * p, выбираем следующий «успех»
    log1m_p = math.log1p(-p)
    i = 0
    while i < n:
        # U ~ Uniform(0,1), gap = floor(log(U)/log(1-p))
        u = max(rng.random(), 1e-16)
        gap = int(math.floor(math.log(u) / log1m_p))
        i += gap
        if i >= n:
            break
        out.append(i)
        i += 1
    return out


def uniform_without_replacement(n: int, k: int, *, rng: SystemPRNG | DeterministicPRNG, sorted_output: bool = False) -> List[int]:
    """
    Равномерная выборка k уникальных индексов из [0,n) без возвращения.
    Реализация Floyd's algorithm (O(k) память, O(k) ожидание).
    """
    if k < 0 or n < 0:
        raise ValueError("n, k must be non-negative")
    if k > n:
        raise ValueError("k cannot exceed n for sampling without replacement")
    selected: Dict[int, int] = {}
    # Идем с конца диапазона: i = n-k .. n-1
    for i in range(n - k, n):
        t = rng.randrange(0, i + 1)
        # если t уже выбран, используем его значение; иначе t
        x = selected.get(t, t)
        selected[i] = x
    result = list(selected.values())
    if sorted_output:
        result.sort()
    else:
        rng.shuffle(result)
    return result


def uniform_with_replacement(n: int, k: int, *, rng: SystemPRNG | DeterministicPRNG) -> List[int]:
    """
    Равномерная выборка k индексов из [0,n) с возвращением.
    """
    if k < 0 or n <= 0:
        if k == 0:
            return []
        raise ValueError("n must be positive and k >= 0")
    return [rng.randrange(0, n) for _ in range(k)]


def reservoir_sample(stream: Iterable[T], k: int, *, rng: SystemPRNG | DeterministicPRNG) -> List[T]:
    """
    Резервуарное сэмплирование (Algorithm R): равномерно выбирает k элементов из потока неизвестной длины.
    """
    if k < 0:
        raise ValueError("k must be non-negative")
    it = iter(stream)
    reservoir: List[T] = []
    try:
        for _ in range(k):
            reservoir.append(next(it))
    except StopIteration:
        return reservoir  # поток короче k
    # i — индекс (начиная с k)
    for i, item in enumerate(it, start=k):
        j = rng.randrange(0, i + 1)
        if j < k:
            reservoir[j] = item
    return reservoir


# -------------------- Потоковые генераторы индексов --------------------

def iter_poisson_mask(n: int, p: float, *, rng: SystemPRNG | DeterministicPRNG) -> Iterator[bool]:
    """
    Потоковый Poisson-маск: для i=0..n-1 выдаёт True с вероятностью p независимо.
    """
    if not (0.0 <= p <= 1.0):
        raise ValueError("p must be in [0,1]")
    for _ in range(n):
        yield rng.random() < p


def iter_uniform_without_replacement(n: int, k: int, *, rng: SystemPRNG | DeterministicPRNG) -> Iterator[int]:
    """
    Потоковый вариант: выдаёт k уникальных индексов (порядок случайный).
    """
    return iter(uniform_without_replacement(n, k, rng=rng, sorted_output=False))

# =============================================================================
# Дифференциальная приватность: шум и учёт
# =============================================================================

def laplace_noise(scale: float, *, rng: SystemPRNG | DeterministicPRNG) -> float:
    """
    Шум Лапласа с параметром scale=b (плотность ~ exp(-|x|/b)/(2b)).
    """
    if scale <= 0:
        raise ValueError("scale must be positive")
    # Inverse CDF: draw U~Uniform(-0.5, 0.5), noise = -b * sgn(U) * ln(1 - 2|U|)
    u = rng.random() - 0.5
    return -scale * math.copysign(1.0, u) * math.log(1.0 - 2.0 * abs(u))


def gaussian_noise(sigma: float, *, rng: SystemPRNG | DeterministicPRNG) -> float:
    """
    Шум Гаусса N(0, sigma^2) — Box–Muller без зависимости от внешних библиотек.
    """
    if sigma <= 0:
        raise ValueError("sigma must be positive")
    # Генерируем два независимых N(0,1) и используем один
    while True:
        u1 = rng.random()
        u2 = rng.random()
        if u1 <= 1e-16:
            continue
        z0 = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
        return z0 * sigma


def calibrate_gaussian_sigma(epsilon: float, delta: float, *, sensitivity_l2: float = 1.0) -> float:
    """
    Калибровка σ для механизма Гаусса (ε,δ)-DP с L2-чувствительностью.
    Классическая оценка (Dwork–Roth): sigma >= sqrt(2 ln(1.25/δ)) * S / ε для ε∈(0,1).
    """
    if epsilon <= 0 or delta <= 0 or delta >= 1:
        raise ValueError("epsilon>0, delta in (0,1)")
    return (math.sqrt(2.0 * math.log(1.25 / delta)) * sensitivity_l2) / epsilon


def amplify_eps_delta_poisson(epsilon: float, delta: float, q: float) -> Tuple[float, float]:
    """
    Усиление приватности подвыборкой (Poisson rate = q).
    Для механизма с (ε,δ)-DP:
        ε' = ln(1 + q * (exp(ε) - 1))
        δ' = q * δ
    """
    if not (0.0 <= q <= 1.0):
        raise ValueError("q must be in [0,1]")
    if epsilon < 0 or delta < 0:
        raise ValueError("epsilon, delta must be non-negative")
    eps_prime = math.log1p(q * (math.exp(epsilon) - 1.0))
    delta_prime = q * delta
    return eps_prime, delta_prime


def compose_basic(parts: Sequence[Tuple[float, float]]) -> Tuple[float, float]:
    """
    Базовая композиция: (ε,δ) суммируются по компонентам.
    """
    eps = sum(e for e, _ in parts)
    delt = sum(d for _, d in parts)
    return eps, delt


def compose_advanced(epsilon: float, delta: float, k: int, *, delta_prime: float) -> Tuple[float, float]:
    """
    «Advanced composition» (Dwork et al., 2010) для k одинаковых (ε,δ)-механизмов.
    Для любого δ'∈(0,1):
        ε_total = sqrt(2k ln(1/δ')) * ε + k * ε * (e^ε - 1)
        δ_total = k*δ + δ'
    Примечание: формула даёт верхнюю границу, особенно полезна при малых ε.
    """
    if k < 1:
        raise ValueError("k >= 1 required")
    if not (0.0 < delta_prime < 1.0):
        raise ValueError("delta_prime must be in (0,1)")
    eps_total = math.sqrt(2.0 * k * math.log(1.0 / delta_prime)) * epsilon + k * epsilon * (math.exp(epsilon) - 1.0)
    delta_total = k * delta + delta_prime
    return eps_total, delta_total

# =============================================================================
# Вспомогательное: выборка по произвольной коллекции / батчирование
# =============================================================================

def sample_items_without_replacement(items: Sequence[T], k: int, *, rng: SystemPRNG | DeterministicPRNG) -> List[T]:
    """
    Выборка k элементов из последовательности items без возвращения.
    """
    n = len(items)
    idx = uniform_without_replacement(n, min(k, n), rng=rng, sorted_output=False)
    return [items[i] for i in idx]


def sample_items_with_replacement(items: Sequence[T], k: int, *, rng: SystemPRNG | DeterministicPRNG) -> List[T]:
    """
    Выборка k элементов из последовательности items с возвращением.
    """
    n = len(items)
    if n == 0 and k > 0:
        raise ValueError("cannot sample from empty sequence")
    return [items[rng.randrange(0, n)] for _ in range(k)]


def batch_iter_indices(n: int, batch_size: int, *, rng: SystemPRNG | DeterministicPRNG, shuffle: bool = True) -> Iterator[List[int]]:
    """
    Итератор по батчам индексов [0..n), размер батча фиксированный, последний — возможно короче.
    При shuffle=True используется детерминированная/крипто стойкая перетасовка в зависимости от RNG.
    """
    if n < 0 or batch_size <= 0:
        raise ValueError("n>=0 and batch_size>0 required")
    idx = list(range(n))
    if shuffle:
        rng.shuffle(idx)
    for i in range(0, n, batch_size):
        yield idx[i : i + batch_size]

# =============================================================================
# Примеры использования (доктесты)
# =============================================================================
if __name__ == "__main__":
    # Демонстрация корректности интерфейса — не юнит‑тесты.
    rng_sec = get_rng("secure")
    rng_det = get_rng("deterministic", seed=42)

    # Poisson
    sel = poisson_subsample_indices(1000, p=0.05, rng=rng_sec)
    print(f"Poisson selected ~{len(sel)} indices (expected ~50)")

    # Без возвращения
    s1 = uniform_without_replacement(100, 10, rng=rng_det)
    assert len(s1) == 10 and len(set(s1)) == 10

    # С возвращением
    s2 = uniform_with_replacement(100, 10, rng=rng_det)
    assert len(s2) == 10

    # Резервуар
    res = reservoir_sample(range(1000), 7, rng=rng_det)
    assert len(res) == 7

    # Шумы
    lap = laplace_noise(1.0, rng=rng_det)
    gau = gaussian_noise(1.0, rng=rng_det)
    print("Laplace:", lap, "Gaussian:", gau)

    # Калибровка σ для ε=1, δ=1e-5
    sigma = calibrate_gaussian_sigma(1.0, 1e-5)
    print("sigma:", sigma)

    # Усиление подвыборкой
    e2, d2 = amplify_eps_delta_poisson(1.0, 1e-5, q=0.1)
    print("amplified:", e2, d2)

    # Композиция
    eps_tot, del_tot = compose_basic([(0.1, 1e-6)] * 10)
    print("basic compose:", eps_tot, del_tot)

    eps_adv, del_adv = compose_advanced(0.1, 1e-6, 10, delta_prime=1e-6)
    print("advanced compose:", eps_adv, del_adv)
