# observability/dashboards/processors/inference_gateway.py

import logging
import random
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class InferenceBackend:
    def __init__(self, name: str, infer_fn: Callable[[Any], Any], weight: float = 1.0):
        self.name = name
        self.infer_fn = infer_fn
        self.weight = weight
        self.success_count = 0
        self.error_count = 0

    async def infer(self, input_data: Any) -> Any:
        try:
            result = await self.infer_fn(input_data)
            self.success_count += 1
            logger.debug(f"Inference successful on backend: {self.name}")
            return result
        except Exception as e:
            self.error_count += 1
            logger.warning(f"Inference failed on backend {self.name}: {e}")
            raise


class InferenceGateway:
    """
    Асинхронный маршрутизатор инференции AI:
    - Поддерживает множество бэкендов с весами.
    - Автоматически переключается при сбоях.
    - Интегрируется с логированием и трассировкой.
    """

    def __init__(self):
        self.backends: list[InferenceBackend] = []

    def register_backend(self, name: str, infer_fn: Callable[[Any], Any], weight: float = 1.0):
        if weight <= 0:
            raise ValueError("weight must be greater than zero")
        self.backends.append(InferenceBackend(name, infer_fn, weight))
        logger.info(f"Registered inference backend: {name} (weight={weight})")

    async def route(self, input_data: Any) -> Any | None:
        if not self.backends:
            logger.error("No inference backends registered.")
            raise RuntimeError("No backends available")

        backends = self._weighted_shuffle()
        for backend in backends:
            try:
                return await backend.infer(input_data)
            except Exception:
                continue

        logger.error("All inference backends failed.")
        return None

    def _weighted_shuffle(self) -> list[InferenceBackend]:
        remaining = [backend for backend in self.backends if backend.weight > 0]
        ordered: list[InferenceBackend] = []
        while remaining:
            selected = random.choices(
                remaining,
                weights=[backend.weight for backend in remaining],
                k=1,
            )[0]
            ordered.append(selected)
            remaining.remove(selected)
        return ordered
