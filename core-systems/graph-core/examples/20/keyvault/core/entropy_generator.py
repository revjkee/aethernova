# keyvault/core/entropy_generator.py
"""
TeslaAI Genesis — Entropy Generator v4.7
Генерация устойчивой, измеримой, криптостойкой энтропии для ключей и операций.
Поддержка ZK-ready seed-потоков, аудит, контроль качества, многоисточниковая энтропия.
"""

import os
import time
import secrets
import hashlib
import random
import base64
import logging
from typing import List, Tuple

logger = logging.getLogger("teslaai.entropy_generator")
logger.setLevel(logging.INFO)

class EntropyGenerator:
    def __init__(self):
        self.sources = [
            self._os_random,
            self._secrets_random,
            self._timed_jitter_source,
            self._environment_noise
        ]
        logger.info("[EntropyGenerator] Initialized with multi-source entropy model")

    def generate_seed(self, size: int = 32) -> bytes:
        entropy_chunks = [source(size) for source in self.sources]
        combined = b"".join(entropy_chunks)
        seed = hashlib.sha3_512(combined).digest()[:size]
        logger.info(f"[EntropyGenerator] Generated seed of {size} bytes")
        return seed

    def estimate_entropy(self, data: bytes) -> float:
        # Наивная оценка энтропии на основе распределения байтов
        freq = {b: data.count(b) for b in set(data)}
        prob = [f / len(data) for f in freq.values()]
        entropy = -sum(p * (p and (p).bit_length()) for p in prob)
        score = round(entropy / 8, 3)
        logger.debug(f"[EntropyGenerator] Entropy score: {score}")
        return score

    def generate_entropy_block(self, block_size: int = 64, mix_rounds: int = 4) -> bytes:
        entropy = self.generate_seed(block_size)
        for _ in range(mix_rounds):
            entropy = hashlib.shake_256(entropy).digest(block_size)
        logger.info(f"[EntropyGenerator] Generated mixed entropy block ({block_size}B, {mix_rounds} rounds)")
        return entropy

    def zk_seed_with_context(self, context: str) -> bytes:
        base = self.generate_seed()
        mix = base + context.encode()
        seed = hashlib.sha3_512(mix).digest()
        logger.info("[EntropyGenerator] ZK-contextual seed derived")
        return seed

    def _os_random(self, size: int) -> bytes:
        return os.urandom(size)

    def _secrets_random(self, size: int) -> bytes:
        return bytes([secrets.randbelow(256) for _ in range(size)])

    def _timed_jitter_source(self, size: int) -> bytes:
        buffer = bytearray()
        for _ in range(size):
            t = time.perf_counter_ns()
            r = int((t * random.random()) % 256)
            buffer.append(r)
        return bytes(buffer)

    def _environment_noise(self, size: int) -> bytes:
        env_data = f"{os.getpid()}{os.urandom(1)}{time.time_ns()}".encode()
        hash_digest = hashlib.blake2b(env_data, digest_size=size).digest()
        return hash_digest

    def audit_entropy_hash(self, data: bytes) -> str:
        fingerprint = hashlib.sha3_512(data).hexdigest()
        logger.debug(f"[EntropyGenerator] Entropy audit hash: {fingerprint}")
        return fingerprint
