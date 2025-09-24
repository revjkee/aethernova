# automation-core/tests/unit/test_http_client.py
# -*- coding: utf-8 -*-
"""
Индустриальные unit-тесты для абстрактного HttpClient проекта `automation_core`.

Цели:
- Не выполнять реальные сетевые вызовы.
- Поддержать как sync (requests), так и async (httpx) реализации.
- Проверять ключевые аспекты: успех, ошибки, ретраи, таймауты.

Ожидаемый контракт клиента (минимум):
- Класс HttpClient(...), методы: get, post, delete, put, patch.
- Методы принимают path (или url), опционально params/json/data/headers.
- На 2xx возвращают объект с .status_code, .headers, .text и .json().
- На !2xx бросают HttpClientError (или подкласс), при таймауте — HttpTimeoutError (или подкласс).
- Реализация может быть sync или async. Тесты адаптируются.

Если в вашем проекте имена/пути отличаются, скорректируйте импорты ниже.
"""

from __future__ import annotations

import asyncio
import inspect
from types import SimpleNamespace
from typing import Any, Callable, Dict, Optional, Tuple

import pytest


# ------------------------------- Импорты клиента ------------------------------

def _import_client():
    """
    Пытаемся импортировать HttpClient и исключения из наиболее вероятных модулей.
    Если модуль не найден — помечаем весь набор тестов как SKIP.
    """
    candidates = [
        "automation_core.http.client",
        "automation_core.http_client",
        "automation_core.client.http",
    ]
    last_err = None
    for mod in candidates:
        try:
            m = __import__(mod, fromlist=["*"])
            HttpClient = getattr(m, "HttpClient")
            HttpClientError = getattr(m, "HttpClientError", Exception)
            HttpTimeoutError = getattr(m, "HttpTimeoutError", TimeoutError)
            return HttpClient, HttpClientError, HttpTimeoutError
        except Exception as e:
            last_err = e
            continue
    pytest.skip(f"HttpClient module not found in {candidates}: {last_err}")


HttpClient, HttpClientError, HttpTimeoutError = _import_client()


# ------------------------------- Утилиты тестов -------------------------------

class FakeResponse:
    """
    Минимальный ответ, совместимый с requests/httpx: .status_code, .headers, .text, .content, .json()
    """
    def __init__(self, status_code=200, headers=None, json_data=None, text_data=None, content=None):
        self.status_code = status_code
        self.headers = headers or {"content-type": "application/json"}
        self._json = json_data
        self._text = text_data if text_data is not None else (
            "" if json_data is None else __import__("json").dumps(json_data)
        )
        self.content = content if content is not None else self._text.encode("utf-8")

    def json(self):
        if self._json is not None:
            return self._json
        import json
        try:
            return json.loads(self._text)
        except Exception as e:
            raise ValueError("Invalid JSON") from e

    @property
    def text(self):
        return self._text


def _is_async_client(obj: Any) -> bool:
    # эвристика: async методы и/или наличие _client атрибутов httpx
    meth = getattr(obj, "get", None)
    return inspect.iscoroutinefunction(meth)


def _instantiate_client() -> Any:
    """
    Пытаемся создать HttpClient с наиболее типичными сигнатурами:
    - HttpClient(base_url=..., timeout=...)
    - HttpClient(base_url=...)
    - HttpClient()
    """
    base = "https://api.example.com"
    for kwargs in (
        dict(base_url=base, timeout=0.05),
        dict(base_url=base),
        dict(),
    ):
        try:
            return HttpClient(**kwargs)
        except TypeError:
            continue
    # если ни один вариант не подошел — попробуем без аргументов
    return HttpClient()


@pytest.fixture()
def client():
    return _instantiate_client()


def _patch_request_backend(client_obj: Any, monkeypatch: pytest.MonkeyPatch, side_effect: Optional[Callable[..., Any]] = None):
    """
    Унифицированная подмена низкоуровневого .request(...) у backend-а:
    - requests.Session.request (атрибут _session)
    - httpx.AsyncClient.request (атрибут _client)
    - или сам client.request (на крайний случай)
    Возвращает (is_async_backend, call_recorder), где call_recorder хранит количество вызовов.
    """
    is_async_backend = False
    target_obj = None
    for attr in ("_session", "_client", "session", "client"):
        if hasattr(client_obj, attr):
            target_obj = getattr(client_obj, attr)
            break
    if target_obj is None:
        # fallback: сам объект клиента
        target_obj = client_obj

    # определяем, корутина ли request
    orig_request = getattr(target_obj, "request", None)
    if orig_request is None:
        pytest.skip("Client backend has no .request to patch")

    is_async_backend = inspect.iscoroutinefunction(orig_request)

    calls = {"count": 0}

    if side_effect is None:
        # дефолтный успешный ответ
        async def async_ok(*a, **kw):
            calls["count"] += 1
            return FakeResponse(200, json_data={"ok": True})
        def sync_ok(*a, **kw):
            calls["count"] += 1
            return FakeResponse(200, json_data={"ok": True})
        side_effect = async_ok if is_async_backend else sync_ok

    if is_async_backend:
        async def proxy(*a, **kw):
            return await side_effect(*a, **kw)
    else:
        def proxy(*a, **kw):
            return side_effect(*a, **kw)

    monkeypatch.setattr(target_obj, "request", proxy)
    return is_async_backend, calls


async def _maybe_await(is_async: bool, coro_or_val):
    if is_async:
        return await coro_or_val
    return coro_or_val


# ---------------------------------- Тесты -------------------------------------

def test_get_json_success(client, monkeypatch):
    """
    Успешный GET с JSON-ответом: .json()['ok'] == True.
    """
    is_async_b, calls = _patch_request_backend(client, monkeypatch)
    # вызов
    if _is_async_client(client) or is_async_b:
        async def run():
            resp = await client.get("/status")
            assert hasattr(resp, "status_code") and resp.status_code == 200
            assert resp.json()["ok"] is True
            assert calls["count"] == 1
        asyncio.run(run())
    else:
        resp = client.get("/status")
        assert hasattr(resp, "status_code") and resp.status_code == 200
        assert resp.json()["ok"] is True
        assert calls["count"] == 1


def test_4xx_raises_client_error(client, monkeypatch):
    """
    4xx должен приводить к HttpClientError (или его подклассу).
    """
    def sync_4xx(*a, **kw):
        return FakeResponse(status_code=404, json_data={"error": "not found"})
    async def async_4xx(*a, **kw):
        return FakeResponse(status_code=404, json_data={"error": "not found"})

    is_async_b, _ = _patch_request_backend(client, monkeypatch, side_effect=async_4xx if _is_async_client(client) or is_async_b else sync_4xx)  # type: ignore[name-defined]

    if _is_async_client(client) or is_async_b:
        async def run():
            with pytest.raises(HttpClientError):
                await client.get("/missing")
        asyncio.run(run())
    else:
        with pytest.raises(HttpClientError):
            client.get("/missing")


def test_5xx_retries_then_success(client, monkeypatch):
    """
    5xx: первый и второй вызов -> 500, третий -> 200; клиент должен сделать 3 запроса,
    если реализована политика ретраев. Если ретраев нет — тест помечается xfail.
    """
    seq = [FakeResponse(502), FakeResponse(503), FakeResponse(200, json_data={"ok": True})]

    def sync_seq(*a, **kw):
        return seq.pop(0)

    async def async_seq(*a, **kw):
        return seq.pop(0)

    is_async_b, calls = _patch_request_backend(client, monkeypatch, side_effect=async_seq if _is_async_client(client) or is_async_b else sync_seq)  # type: ignore[name-defined]

    # эвристика: если у клиента нет признаков ретраев — xfail
    has_retry_attr = any(hasattr(client, attr) for attr in ("retries", "retry", "retry_config"))

    if _is_async_client(client) or is_async_b:
        async def run():
            if not has_retry_attr:
                pytest.xfail("Client has no retry configuration")
            resp = await client.get("/flaky")
            assert resp.status_code == 200
            assert calls["count"] >= 3  # допустим больше, если есть джиттер/проброс
        asyncio.run(run())
    else:
        if not has_retry_attr:
            pytest.xfail("Client has no retry configuration")
        resp = client.get("/flaky")
        assert resp.status_code == 200
        assert calls["count"] >= 3


def test_timeout_maps_to_domain_error(client, monkeypatch):
    """
    Таймаут нижнего уровня должен маппиться на HttpTimeoutError (или подкласс).
    """
    class _TimeoutExc(Exception):
        pass

    def sync_timeout(*a, **kw):
        raise _TimeoutExc("timeout")

    async def async_timeout(*a, **kw):
        raise _TimeoutExc("timeout")

    is_async_b, _ = _patch_request_backend(client, monkeypatch, side_effect=async_timeout if _is_async_client(client) or is_async_b else sync_timeout)  # type: ignore[name-defined]

    # Подменяем маппинг исключения на уровне клиента, если он его делает через catch;
    # иначе ожидаем, что клиент сам перехватывает нижний timeout и поднимает HttpTimeoutError.
    if _is_async_client(client) or is_async_b:
        async def run():
            with pytest.raises(HttpTimeoutError):
                await client.get("/sleep")
        asyncio.run(run())
    else:
        with pytest.raises(HttpTimeoutError):
            client.get("/sleep")


def test_post_sends_json_and_receives_text(client, monkeypatch):
    """
    POST с JSON-телом, сервер отвечает текстом (например, id).
    """
    payload_captured = {}

    def sync_post(*a, **kw):
        # типичный requests: data/json/headers приходят в kwargs
        payload_captured.update(kw)
        return FakeResponse(200, headers={"content-type": "text/plain"}, text_data="accepted")

    async def async_post(*a, **kw):
        payload_captured.update(kw)
        return FakeResponse(200, headers={"content-type": "text/plain"}, text_data="accepted")

    is_async_b, _ = _patch_request_backend(client, monkeypatch, side_effect=async_post if _is_async_client(client) or is_async_b else sync_post)  # type: ignore[name-defined]

    if _is_async_client(client) or is_async_b:
        async def run():
            resp = await client.post("/submit", json={"a": 1})
            assert resp.status_code == 200
            assert resp.text == "accepted"
            # проверяем, что json действительно передавался вниз
            assert "json" in payload_captured and payload_captured["json"] == {"a": 1}
        asyncio.run(run())
    else:
        resp = client.post("/submit", json={"a": 1})
        assert resp.status_code == 200
        assert resp.text == "accepted"
        assert "json" in payload_captured and payload_captured["json"] == {"a": 1}


def test_delete_non_2xx_raises(client, monkeypatch):
    """
    DELETE, получаем 409 — ожидаем HttpClientError.
    """
    def sync_conflict(*a, **kw):
        return FakeResponse(409, json_data={"error": "conflict"})

    async def async_conflict(*a, **kw):
        return FakeResponse(409, json_data={"error": "conflict"})

    is_async_b, _ = _patch_request_backend(client, monkeypatch, side_effect=async_conflict if _is_async_client(client) or is_async_b else sync_conflict)  # type: ignore[name-defined]

    if _is_async_client(client) or is_async_b:
        async def run():
            with pytest.raises(HttpClientError):
                await client.delete("/resource/1")
        asyncio.run(run())
    else:
        with pytest.raises(HttpClientError):
            client.delete("/resource/1")
