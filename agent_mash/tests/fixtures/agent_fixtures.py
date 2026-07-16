# agent_mash/tests/fixtures/agent_fixtures.py
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import os
import random
import time
import typing as t
import uuid

import pytest

try:
    import pytest_asyncio  # type: ignore
except Exception:  # pragma: no cover
    pytest_asyncio = None  # type: ignore


T = t.TypeVar("T")


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclasses.dataclass(frozen=True, slots=True)
class AgentIdentity:
    agent_id: str
    name: str
    role: str


@dataclasses.dataclass(slots=True)
class AgentState:
    identity: AgentIdentity
    created_at_ms: int
    meta: dict[str, t.Any] = dataclasses.field(default_factory=dict)


class FakeLLM:
    """
    Безопасная детерминированная заглушка LLM для тестов.
    Не делает сетевых запросов и не зависит от внешних API.
    """

    def __init__(self, *, seed: int = 0, model: str = "fake-llm", latency_ms: int = 0) -> None:
        self._rng = random.Random(seed)
        self.model = model
        self.latency_ms = max(0, int(latency_ms))
        self.calls: list[dict[str, t.Any]] = []

    async def acomplete(self, prompt: str, *, temperature: float = 0.0, max_tokens: int = 256) -> str:
        if self.latency_ms:
            await asyncio.sleep(self.latency_ms / 1000.0)

        token = self._rng.randint(100000, 999999)
        text = f"[{self.model}] {prompt} :: {token}"

        self.calls.append(
            {
                "prompt": prompt,
                "temperature": float(temperature),
                "max_tokens": int(max_tokens),
                "response": text,
            }
        )
        return text


class FakeHTTPClient:
    """
    Заглушка HTTP-клиента.
    Любая попытка реального запроса считается ошибкой теста, если не зарегистрирован маршрут.
    """

    def __init__(self) -> None:
        self._routes: dict[tuple[str, str], dict[str, t.Any]] = {}
        self.calls: list[dict[str, t.Any]] = []

    def register(
        self,
        method: str,
        url: str,
        *,
        status_code: int = 200,
        json: t.Any = None,
        text: str | None = None,
        headers: dict[str, str] | None = None,
        delay_ms: int = 0,
    ) -> None:
        key = (method.upper(), url)
        self._routes[key] = {
            "status_code": int(status_code),
            "json": json,
            "text": text,
            "headers": dict(headers or {}),
            "delay_ms": max(0, int(delay_ms)),
        }

    async def request(self, method: str, url: str, **kwargs: t.Any) -> "FakeHTTPResponse":
        key = (method.upper(), url)
        self.calls.append({"method": method.upper(), "url": url, "kwargs": kwargs})

        if key not in self._routes:
            raise AssertionError(
                f"Unexpected HTTP call: {method.upper()} {url}. "
                f"Register route via FakeHTTPClient.register()."
            )

        route = self._routes[key]
        if route["delay_ms"]:
            await asyncio.sleep(route["delay_ms"] / 1000.0)

        return FakeHTTPResponse(
            status_code=route["status_code"],
            json_data=route["json"],
            text_data=route["text"],
            headers=route["headers"],
        )

    async def get(self, url: str, **kwargs: t.Any) -> "FakeHTTPResponse":
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: t.Any) -> "FakeHTTPResponse":
        return await self.request("POST", url, **kwargs)


@dataclasses.dataclass(frozen=True, slots=True)
class FakeHTTPResponse:
    status_code: int
    json_data: t.Any = None
    text_data: str | None = None
    headers: dict[str, str] = dataclasses.field(default_factory=dict)

    def json(self) -> t.Any:
        return self.json_data

    @property
    def text(self) -> str:
        return self.text_data or ""


class InMemoryKV:
    """
    Простейшее in-memory KV-хранилище для тестов (под Redis-like паттерн).
    """

    def __init__(self) -> None:
        self._store: dict[str, t.Any] = {}

    def get(self, key: str, default: t.Any = None) -> t.Any:
        return self._store.get(key, default)

    def set(self, key: str, value: t.Any) -> None:
        self._store[key] = value

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()

    def snapshot(self) -> dict[str, t.Any]:
        return dict(self._store)


@contextlib.contextmanager
def _patched_environ(patches: dict[str, str | None]) -> t.Iterator[None]:
    old = dict(os.environ)
    try:
        for k, v in patches.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        os.environ.clear()
        os.environ.update(old)


@pytest.fixture(scope="session")
def test_seed() -> int:
    """
    Единый seed для детерминизма. Можно переопределять через env TEST_SEED.
    """
    raw = os.environ.get("TEST_SEED", "1337").strip()
    try:
        return int(raw)
    except Exception:
        return 1337


@pytest.fixture()
def rng(test_seed: int) -> random.Random:
    """
    Детерминированный RNG на тест.
    """
    return random.Random(test_seed)


@pytest.fixture()
def unique_id(rng: random.Random) -> str:
    """
    Уникальный, но детерминированный идентификатор на тест.
    """
    # uuid5 даёт детерминированность при одинаковом seed.
    namespace = uuid.UUID(int=rng.getrandbits(128))
    return str(uuid.uuid5(namespace, "agent_mash_test"))


@pytest.fixture()
def env_isolation() -> t.Iterator[None]:
    """
    Изоляция переменных окружения внутри теста.
    """
    with _patched_environ({}):
        yield


@pytest.fixture()
def app_env(env_isolation: None) -> t.Iterator[None]:
    """
    Базовые переменные окружения для тестов.
    """
    patches = {
        "APP_ENV": "test",
        "PYTHONASYNCIODEBUG": "1",
        "NO_NETWORK": "1",
    }
    with _patched_environ(patches):
        yield


@pytest.fixture()
def caplog_debug(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level("DEBUG")
    return caplog


@pytest.fixture()
def kv_store() -> InMemoryKV:
    return InMemoryKV()


@pytest.fixture()
def fake_http() -> FakeHTTPClient:
    return FakeHTTPClient()


@pytest.fixture()
def fake_llm(test_seed: int) -> FakeLLM:
    return FakeLLM(seed=test_seed, model="fake-llm", latency_ms=0)


@pytest.fixture()
def agent_factory(rng: random.Random) -> t.Callable[..., AgentState]:
    """
    Фабрика тест-агентов. Не зависит от внутренних классов проекта.
    """
    counter = {"n": 0}

    def _make(
        *,
        name: str | None = None,
        role: str = "test-agent",
        agent_id: str | None = None,
        meta: dict[str, t.Any] | None = None,
    ) -> AgentState:
        counter["n"] += 1
        idx = counter["n"]

        resolved_name = name or f"agent-{idx}"
        resolved_id = agent_id or f"a_{rng.randint(100000, 999999)}_{idx}"

        identity = AgentIdentity(agent_id=resolved_id, name=resolved_name, role=role)
        state = AgentState(identity=identity, created_at_ms=_now_ms(), meta=dict(meta or {}))
        return state

    return _make


@pytest.fixture()
def agent(agent_factory: t.Callable[..., AgentState]) -> AgentState:
    return agent_factory()


@pytest.fixture()
def agents(agent_factory: t.Callable[..., AgentState]) -> list[AgentState]:
    return [
        agent_factory(name="planner", role="planner"),
        agent_factory(name="executor", role="executor"),
        agent_factory(name="critic", role="critic"),
    ]


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    """
    Для совместимости с anyio, если проект использует httpx/starlette/fastapi тесты.
    """
    return "asyncio"


@pytest.fixture(scope="session")
def event_loop_policy() -> t.Iterator[asyncio.AbstractEventLoopPolicy]:
    """
    Единая политика event loop на сессию.
    """
    policy = asyncio.get_event_loop_policy()
    yield policy


@pytest.fixture()
def event_loop(event_loop_policy: asyncio.AbstractEventLoopPolicy) -> t.Iterator[asyncio.AbstractEventLoop]:
    """
    Отдельный loop на тест, чтобы не было протечек задач.
    """
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        yield loop
    finally:
        try:
            _cancel_all_tasks(loop)
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            asyncio.set_event_loop(None)
            loop.close()


def _cancel_all_tasks(loop: asyncio.AbstractEventLoop) -> None:
    pending = asyncio.all_tasks(loop=loop)
    if not pending:
        return
    for task in pending:
        task.cancel()
    with contextlib.suppress(Exception):
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))


def pytest_configure(config: pytest.Config) -> None:
    """
    Жёсткая защита от случайных сетевых тестов через env-флаг.
    Сам по себе файл не блокирует сеть на уровне ОС, но позволяет проекту проверять NO_NETWORK=1.
    """
    os.environ.setdefault("NO_NETWORK", "1")
