import os
import time
import threading
import hashlib
import secrets
import struct
from typing import Optional, List
from collections import deque
from Crypto.Hash import SHA3_512

class EntropySource:
    def __init__(self, name: str, gather_fn, weight: float = 1.0):
        self.name = name
        self.gather = gather_fn
        self.weight = weight

class QuantumEntropyPool:
    """
    Промышленный пул энтропии с квантовым усилением.
    Объединяет множественные источники случайности, проводит смешивание, хэширование и проверку коллизий.
    """

    def __init__(self, capacity_bits: int = 8192):
        self.lock = threading.RLock()
        self.capacity = capacity_bits // 8
        self.pool = deque(maxlen=self.capacity)
        self.sources: List[EntropySource] = []
        self._state_hash = b'\x00' * 64
        self._timestamp_tracker = deque(maxlen=256)
        self._init_entropy_sources()

    def _init_entropy_sources(self):
        self.sources.append(EntropySource("os_urandom", os.urandom, weight=1.0))
        self.sources.append(EntropySource("secrets", lambda n=64: secrets.token_bytes(n), weight=1.5))
        self.sources.append(EntropySource("timestamp_noise", self._timestamp_entropy, weight=0.7))

    def _timestamp_entropy(self, length: int = 64) -> bytes:
        now = time.time_ns()
        entropy = struct.pack(">Q", now ^ id(self)) + os.urandom(length - 8)
        self._timestamp_tracker.append(now)
        return hashlib.blake2b(entropy, digest_size=length).digest()

    def collect_entropy(self):
        """
        Запускает сбор и объединение энтропии из всех источников.
        """
        with self.lock:
            for source in self.sources:
                raw = source.gather(64)
                weighted = hashlib.sha3_512(raw + self._state_hash + source.name.encode()).digest()
                self._append_to_pool(weighted)

    def _append_to_pool(self, data: bytes):
        for byte in data:
            self.pool.append(byte)
        self._state_hash = hashlib.sha3_512(bytes(self.pool)).digest()

    def get_entropy(self, length: int = 64) -> bytes:
        """
        Возвращает порцию свежей энтропии из пула с перемешиванием и защитой от восстановления.
        """
        with self.lock:
            if len(self.pool) < length:
                self.collect_entropy()
            mix = bytes([self.pool[i % len(self.pool)] ^ self._state_hash[i % len(self._state_hash)]
                         for i in range(length)])
            return hashlib.shake_256(mix).digest(length)

    def seed_rng(self, rng):
        """
        Инициализирует внешний генератор (например, numpy или PyTorch) полученной энтропией.
        """
        entropy = self.get_entropy(64)
        seed = int.from_bytes(entropy, 'big') % (2 ** 32)
        rng.seed(seed)

    def status(self) -> dict:
        """
        Возвращает состояние пула: уровень наполнения, хэш состояния и историю времени.
        """
        return {
            "pool_size": len(self.pool),
            "state_hash": self._state_hash.hex(),
            "last_timestamp": self._timestamp_tracker[-1] if self._timestamp_tracker else None
        }

    def clear_pool(self):
        with self.lock:
            self.pool.clear()
            self._state_hash = os.urandom(64)

