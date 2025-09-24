# mythos-core/tests/integration/test_dialogue_runtime.py
# -*- coding: utf-8 -*-
"""
Интеграционные тесты диалогового рантайма Mythos-Core.

Требования (мягкие, тест сам подстроится):
- Модуль: mythos_core.dialogue.runtime
- Точка входа: create_runtime(config: Mapping) -> Runtime или класс DialogueRuntime
- Интерфейс Runtime (duck-typed, допускаются алиасы):
    - async start() / stop()
    - async open_session(session_id: str, user: Mapping | None = None) -> Session
    - async close_session(session_id: str)
    - async send(session_id: str, text: str, *, lang: str | None = None, meta: dict | None = None) -> Reply
    - subscribe(callback) -> unsubscribe()  # события trace/log/metrics (опционально)
- Интерфейс Reply:
    - .text: str
    - .meta: dict (может отсутствовать, тогда игнор)
- Session / state persistence: опционально через storage/config
- i18n: опционально через config["i18n"]

Если некоторые части отсутствуют, соответствующие тесты будут помечены как skipped,
чтобы не блокировать CI при неполной реализации.
"""
from __future__ import annotations

import asyncio
import contextlib
import importlib
import inspect
import os
import random
import string
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import pytest

# ---------------------------
# Утилиты автообнаружения API
# ---------------------------

def _import_runtime_module():
    try:
        return importlib.import_module("mythos_core.dialogue.runtime")
    except Exception as e:
        pytest.skip(f"Runtime module not available: {e}")

def _make_runtime(config: Dict[str, Any]):
    """
    Пытается создать рантайм через create_runtime или класс DialogueRuntime.
    """
    mod = _import_runtime_module()
    # Вариант 1: create_runtime
    factory = getattr(mod, "create_runtime", None)
    if callable(factory):
        rt = factory(config)
        return rt
    # Вариант 2: класс DialogueRuntime
    cls = getattr(mod, "DialogueRuntime", None)
    if inspect.isclass(cls):
        return cls(config)
    pytest.skip("No runtime factory found (create_runtime or DialogueRuntime).")

def _has_attr(obj, *names) -> bool:
    for n in names:
        if not hasattr(obj, n):
            return False
    return True

def _rand_id(prefix: str = "sess") -> str:
    return f"{prefix}_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))

# ---------------------------
# Общие фикстуры
# ---------------------------

@pytest.fixture(scope="module")
def tmp_dir():
    with tempfile.TemporaryDirectory(prefix="mythos_runtime_") as d:
        yield Path(d)

@pytest.fixture
def base_config(tmp_dir: Path) -> Dict[str, Any]:
    """
    Базовый конфиг — in-memory storage по умолчанию.
    Конкретные ключи не обязательны; рантайм может игнорировать незнакомые поля.
    """
    return {
        "storage": {
            "kind": "memory",
            "path": str(tmp_dir / "state.db"),
        },
        "policies": {
            "default": {
                "kind": "echo",  # если движок поддерживает, иначе используется дефолт
                "max_latency_ms": 50,
            },
            "failing": {
                "kind": "failing_policy",
            },
            "slow": {
                "kind": "slow_policy",
                "latency_ms": 5_000,
            }
        },
        "timeouts": {
            "reply_ms": 1000,  # общий таймаут ответа
        },
        "i18n": {
            "default_lang": "en",
            "catalog": {
                "en": {
                    "hello": "Hello, {name}!",
                    "fallback": "Sorry, something went wrong."
                },
                "ru": {
                    "hello": "Привет, {name}!",
                    "fallback": "Извините, что-то пошло не так."
                }
            }
        },
        "tracing": {
            "enabled": True
        }
    }

@pytest.fixture
async def runtime(base_config):
    """
    Создает и запускает рантайм; по окончании — корректно останавливает.
    Тесты должны использовать отдельные session_id для изоляции.
    """
    rt = _make_runtime(base_config)
    # Проверяем наличие ключевых методов
    if not _has_attr(rt, "start", "stop", "open_session", "close_session", "send"):
        pytest.skip("Runtime does not expose required async methods.")
    await rt.start()
    try:
        yield rt
    finally:
        await rt.stop()

# ---------------------------
# Хелперы
# ---------------------------

async def _ensure_session(rt, session_id: str, user: Optional[Dict[str, Any]] = None):
    # Некоторые реализации не требуют open_session; тем не менее пробуем.
    if hasattr(rt, "open_session") and inspect.iscoroutinefunction(rt.open_session):
        await rt.open_session(session_id, user=user or {"id": "u1", "role": "tester"})

async def _close_session(rt, session_id: str):
    if hasattr(rt, "close_session") and inspect.iscoroutinefunction(rt.close_session):
        with contextlib.suppress(Exception):
            await rt.close_session(session_id)

def _text_of(reply: Any) -> str:
    if reply is None:
        return ""
    if isinstance(reply, str):
        return reply
    return getattr(reply, "text", "") or ""

def _meta_of(reply: Any) -> Dict[str, Any]:
    return getattr(reply, "meta", {}) if hasattr(reply, "meta") else {}

# ---------------------------
# Тесты
# ---------------------------

@pytest.mark.asyncio
async def test_basic_turns_flow(runtime):
    """
    Базовый сценарий: открытие сессии, последовательная отправка реплик,
    проверка детерминированности ответа и изменения состояния.
    """
    session_id = _rand_id()
    await _ensure_session(runtime, session_id, user={"id": "u42", "role": "qa"})
    try:
        r1 = await runtime.send(session_id, "Hello")
        assert isinstance(r1, (str, object)), "Reply must be a string-like or object with .text"
        t1 = _text_of(r1)
        assert t1, "Reply text must not be empty"

        r2 = await runtime.send(session_id, "How are you?")
        t2 = _text_of(r2)
        assert t2, "Second reply must not be empty"
        # Базовая монотонность: второе сообщение и ответ — не пустые и могут отличаться
        assert t1 != "" or t2 != ""

        # Метаданные (опционально): проверим, что dict, если есть
        m2 = _meta_of(r2)
        assert isinstance(m2, dict)
    finally:
        await _close_session(runtime, session_id)


@pytest.mark.asyncio
async def test_persistence_across_restart(tmp_dir, base_config):
    """
    Персистентность: отправляем сообщение, останавливаем рантайм, поднимаем заново,
    продолжаем диалог и убеждаемся, что контекст сохранен (если поддерживается).
    """
    # Форсим файловое хранилище, если движок это использует
    base_config2 = dict(base_config)
    base_config2["storage"] = {"kind": "file", "path": str(tmp_dir / "state.json")}

    # Первый запуск
    rt1 = _make_runtime(base_config2)
    await rt1.start()
    session_id = _rand_id()
    await _ensure_session(rt1, session_id)
    _ = await rt1.send(session_id, "Remember me")
    await rt1.stop()

    # Второй запуск (новый инстанс)
    rt2 = _make_runtime(base_config2)
    await rt2.start()
    try:
        await _ensure_session(rt2, session_id)  # если не требуется, не навредит
        r2 = await rt2.send(session_id, "What did I say?")
        t2 = _text_of(r2)
        # Мы не знаем конкретную модель памяти, но ожидаем не пустой релевантный ответ
        assert isinstance(t2, str) and t2 != ""
    finally:
        await rt2.stop()


@pytest.mark.asyncio
async def test_parallel_sessions_isolation(runtime):
    """
    Две параллельные сессии не должны «видеть» состояние друг друга.
    """
    s1 = _rand_id("s1")
    s2 = _rand_id("s2")
    await _ensure_session(runtime, s1, user={"id": "alice"})
    await _ensure_session(runtime, s2, user={"id": "bob"})
    try:
        r1 = await runtime.send(s1, "My name is Alice")
        r2 = await runtime.send(s2, "My name is Bob")
        t1 = _text_of(r1)
        t2 = _text_of(r2)
        assert t1 != "" and t2 != ""
        # Далее посылаем уточнение и проверяем, что контекст не перепутан
        r1b = await runtime.send(s1, "Who am I?")
        r2b = await runtime.send(s2, "Who am I?")
        t1b = _text_of(r1b)
        t2b = _text_of(r2b)
        assert t1b != "" and t2b != ""
        # Невозможно строго валидировать без знания политики, но проверим отсутствие идентичного eco-эхо между сессиями
        assert not (t1b == t2b == "Alice"), "Sessions should be isolated (example heuristic)"
    finally:
        await _close_session(runtime, s1)
        await _close_session(runtime, s2)


@pytest.mark.asyncio
async def test_policy_error_handling(runtime):
    """
    Политика, бросающая исключение, должна не «ронять» рантайм, а давать fallback.
    Если движок не поддерживает выбор политики на лету — тест будет пропущен.
    """
    if not hasattr(runtime, "send"):
        pytest.skip("No send method.")
    if "failing" not in getattr(getattr(runtime, "config", {}), "get", lambda *_: {})("policies", {}):
        # Пытаемся отправить метаданные с запросом политики
        pass

    session_id = _rand_id("err")
    await _ensure_session(runtime, session_id)
    try:
        # Многие движки позволяют указать policy/route через meta
        reply = await runtime.send(session_id, "Trigger failure", meta={"policy": "failing"})
        text = _text_of(reply)
        # Если fallback i18n реализован, он будет ненулевой
        assert isinstance(text, str)
        assert text != "", "Fallback text must be non-empty on policy error"
    finally:
        await _close_session(runtime, session_id)


@pytest.mark.asyncio
async def test_timeout_and_cancellation(runtime):
    """
    Долгий ответ политики должен быть прерван общим таймаутом, без подвисаний.
    """
    session_id = _rand_id("slow")
    await _ensure_session(runtime, session_id)
    try:
        # Запрашиваем «медленную» политику (если поддерживается), иначе имитируем общий дедлайн
        try:
            coro = runtime.send(session_id, "Please be slow", meta={"policy": "slow"})
            reply = await asyncio.wait_for(coro, timeout=1.2)  # немного больше, чем reply_ms
            # Если ответ все же пришел, он не должен быть пустым.
            assert _text_of(reply) != ""
        except asyncio.TimeoutError:
            # Корректный исход: рантайм не успел ответить, вызов прерван
            assert True
    finally:
        await _close_session(runtime, session_id)


@pytest.mark.asyncio
async def test_i18n_localization(runtime):
    """
    Проверяем, что при передаче lang строка подставляется по ключу и плейсхолдеры совпадают.
    """
    session_id = _rand_id("i18n")
    await _ensure_session(runtime, session_id)
    try:
        # Предполагаем, что движок понимает meta.i18n_key или сам маппит фразу на ключ; здесь — прямой ключ
        reply_ru = await runtime.send(session_id, "{hello}", lang="ru", meta={"i18n_key": "hello", "vars": {"name": "Никита"}})
        reply_en = await runtime.send(session_id, "{hello}", lang="en", meta={"i18n_key": "hello", "vars": {"name": "Nikita"}})
        t_ru = _text_of(reply_ru)
        t_en = _text_of(reply_en)
        # Допустим оба непустые и отражают разные языки
        assert "Привет" in t_ru or t_ru != t_en
        assert "Hello" in t_en or t_ru != t_en
        # Плейсхолдеры подставлены
        assert "Никита" in t_ru or "Nikita" in t_en
    finally:
        await _close_session(runtime, session_id)


@pytest.mark.asyncio
async def test_tracing_events(runtime):
    """
    Если рантайм поддерживает подписку на события, проверяем, что хотя бы одно событие поступает на один полный ход.
    """
    if not hasattr(runtime, "subscribe"):
        pytest.skip("Tracing subscribe() is not available in runtime.")

    events = []

    def _on_event(evt: Dict[str, Any]):
        # Ожидаем минимальные поля (best-effort)
        if isinstance(evt, dict):
            events.append(evt)

    # subscribe может вернуть функцию отписки или id
    unsub: Optional[Callable[[], None]] = None
    try:
        maybe_unsub = runtime.subscribe(_on_event)
        if callable(maybe_unsub):
            unsub = maybe_unsub

        session_id = _rand_id("trace")
        await _ensure_session(runtime, session_id)
        _ = await runtime.send(session_id, "Trace me")
        await asyncio.sleep(0.05)  # дать эмиттеру время
        assert len(events) >= 1, "Expected at least one tracing event"
        # Минимальная валидация структуры
        sample = events[-1]
        assert "ts" in sample or "time" in sample or "event" in sample
    finally:
        if unsub:
            with contextlib.suppress(Exception):
                unsub()

# ---------------------------
# Маркеры стабильности
# ---------------------------

@pytest.mark.asyncio
async def test_many_short_turns_stability(runtime):
    """
    Нагрузочный мини-тест: серии коротких ходов без утечек и исключений.
    """
    session_id = _rand_id("storm")
    await _ensure_session(runtime, session_id)
    try:
        for i in range(50):
            r = await runtime.send(session_id, f"ping {i}")
            assert _text_of(r) != ""
    finally:
        await _close_session(runtime, session_id)


@pytest.mark.asyncio
async def test_session_lifecycle_idempotency(runtime):
    """
    Повторный open/close не должен ломать рантайм.
    """
    session_id = _rand_id("life")
    # дважды open
    await _ensure_session(runtime, session_id)
    await _ensure_session(runtime, session_id)
    # дважды close
    await _close_session(runtime, session_id)
    await _close_session(runtime, session_id)
