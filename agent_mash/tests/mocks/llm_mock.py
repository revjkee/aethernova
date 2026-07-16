# agent_mash/tests/mocks/llm_mock.py
from __future__ import annotations

import asyncio
import json
import random
import time
import typing as t
from dataclasses import dataclass, field

Json = dict[str, t.Any]


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclass(frozen=True, slots=True)
class LLMCall:
    timestamp_ms: int
    prompt: str
    temperature: float
    max_tokens: int
    response: str
    metadata: Json = field(default_factory=dict)


class LLMProtocol(t.Protocol):
    """
    Минимальный протокол LLM для тестов.
    Совместим по смыслу с большинством async LLM SDK.
    """

    async def acomplete(
        self,
        prompt: str,
        *,
        temperature: float = 0.0,
        max_tokens: int = 256,
        **kwargs: t.Any,
    ) -> str:
        ...


class DeterministicLLMMock:
    """
    Промышленный mock LLM.

    Свойства:
    - Полный детерминизм (seed).
    - Async интерфейс.
    - Отсутствие сетевых вызовов.
    - Трассировка всех обращений.
    - Возможность сценарных ответов.
    """

    def __init__(
        self,
        *,
        seed: int = 1337,
        model_name: str = "mock-llm",
        latency_ms: int = 0,
        scripted_responses: list[str] | None = None,
    ) -> None:
        self._rng = random.Random(seed)
        self.model_name = model_name
        self.latency_ms = max(0, int(latency_ms))
        self._scripted = list(scripted_responses or [])
        self.calls: list[LLMCall] = []

    def reset(self) -> None:
        """
        Полный сброс состояния mock.
        """
        self.calls.clear()

    def _generate_response(self, prompt: str, temperature: float, max_tokens: int) -> str:
        """
        Генерация детерминированного ответа.
        """
        if self._scripted:
            return self._scripted.pop(0)

        token = self._rng.randint(100000, 999999)
        base = {
            "model": self.model_name,
            "prompt": prompt,
            "token": token,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        return json.dumps(base, ensure_ascii=False, sort_keys=True)

    async def acomplete(
        self,
        prompt: str,
        *,
        temperature: float = 0.0,
        max_tokens: int = 256,
        **kwargs: t.Any,
    ) -> str:
        """
        Асинхронное завершение prompt.
        """
        if self.latency_ms > 0:
            await asyncio.sleep(self.latency_ms / 1000.0)

        response = self._generate_response(prompt, temperature, max_tokens)

        call = LLMCall(
            timestamp_ms=_now_ms(),
            prompt=prompt,
            temperature=float(temperature),
            max_tokens=int(max_tokens),
            response=response,
            metadata=dict(kwargs),
        )
        self.calls.append(call)

        return response

    def last_call(self) -> LLMCall:
        if not self.calls:
            raise AssertionError("LLM was not called")
        return self.calls[-1]

    def assert_called(self) -> None:
        if not self.calls:
            raise AssertionError("Expected LLM to be called at least once")

    def assert_called_times(self, n: int) -> None:
        actual = len(self.calls)
        if actual != n:
            raise AssertionError(f"Expected {n} LLM calls, got {actual}")

    def dump_calls(self) -> list[Json]:
        """
        Возвращает сериализуемое представление всех вызовов.
        """
        out: list[Json] = []
        for c in self.calls:
            out.append(
                {
                    "timestamp_ms": c.timestamp_ms,
                    "prompt": c.prompt,
                    "temperature": c.temperature,
                    "max_tokens": c.max_tokens,
                    "response": c.response,
                    "metadata": c.metadata,
                }
            )
        return out


class StrictLLMMock(DeterministicLLMMock):
    """
    Более строгая версия mock:
    - запрещает пустые prompt
    - запрещает max_tokens <= 0
    """

    async def acomplete(
        self,
        prompt: str,
        *,
        temperature: float = 0.0,
        max_tokens: int = 256,
        **kwargs: t.Any,
    ) -> str:
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Prompt must be a non-empty string")

        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")

        return await super().acomplete(
            prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )
