# forgemind-core/payload_lab/payload_optimizer.py

import os
import json
import hashlib
import tempfile
import logging
from typing import List, Dict, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("payload_optimizer")
logger.setLevel(logging.DEBUG)

@dataclass
class PayloadVariant:
    id: str
    code: bytes
    size: int
    exec_time: float
    memory_usage: float
    entropy: float
    heuristic_score: float
    passed_tests: bool

    def metrics(self) -> Dict:
        return {
            "id": self.id,
            "size": self.size,
            "exec_time": self.exec_time,
            "memory_usage": self.memory_usage,
            "entropy": self.entropy,
            "heuristic_score": self.heuristic_score,
            "passed_tests": self.passed_tests
        }

class PayloadOptimizer:
    def __init__(self, heuristics_model_path: str = None):
        self.variants: List[PayloadVariant] = []
        self.heuristics_model_path = heuristics_model_path
        self.entropy_threshold = 6.5  # adjustable

    def _calculate_entropy(self, data: bytes) -> float:
        from math import log2
        if not data:
            return 0.0
        freq = {b: data.count(b) / len(data) for b in set(data)}
        entropy = -sum(p * log2(p) for p in freq.values())
        return round(entropy, 3)

    def _simulate_exec(self, code: bytes) -> Tuple[float, float]:
        # Simulation stub: should integrate with sandbox
        import random
        return round(random.uniform(0.01, 0.2), 4), round(random.uniform(5.0, 15.0), 2)

    def _estimate_heuristics(self, code: bytes) -> float:
        if self.heuristics_model_path and os.path.exists(self.heuristics_model_path):
            # Future integration point
            return 0.0
        else:
            return round(self._calculate_entropy(code) * 1.3, 3)

    def register_payload(self, code: bytes) -> PayloadVariant:
        pid = hashlib.sha256(code).hexdigest()[:10]
        size = len(code)
        exec_time, mem_use = self._simulate_exec(code)
        entropy = self._calculate_entropy(code)
        heur_score = self._estimate_heuristics(code)
        passed = heur_score < 9.0 and entropy < self.entropy_threshold
        variant = PayloadVariant(
            id=pid,
            code=code,
            size=size,
            exec_time=exec_time,
            memory_usage=mem_use,
            entropy=entropy,
            heuristic_score=heur_score,
            passed_tests=passed
        )
        self.variants.append(variant)
        logger.debug(f"Registered payload {pid}: {variant.metrics()}")
        return variant

    def optimize(self, top_n: int = 3, strategy: str = "multi-objective") -> List[PayloadVariant]:
        if not self.variants:
            return []

        if strategy == "size":
            sorted_variants = sorted(self.variants, key=lambda x: x.size)
        elif strategy == "speed":
            sorted_variants = sorted(self.variants, key=lambda x: x.exec_time)
        elif strategy == "stealth":
            sorted_variants = sorted(self.variants, key=lambda x: x.heuristic_score)
        elif strategy == "multi-objective":
            sorted_variants = sorted(self.variants, key=lambda x: (
                x.heuristic_score + x.entropy + x.exec_time + x.memory_usage + x.size
            ))
        else:
            sorted_variants = self.variants

        top_variants = sorted_variants[:top_n]
        for v in top_variants:
            logger.info(f"[Optimizer] Selected variant {v.id}: {v.metrics()}")
        return top_variants

    def export_report_
