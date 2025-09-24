# -*- coding: utf-8 -*-
"""
Контрактные тесты API v1 для DataFabric (HTTP).
Зависимости: pytest, requests.

Конфигурация через переменные окружения:
- DF_API_BASE_URL      (по умолчанию: http://localhost:8080)
- DF_API_TIMEOUT_SEC   (по умолчанию: 5.0)
- DF_API_TOKEN         (опционально, Bearer)
- DF_API_FEATURES      (JSON-манифест возможностей, см. DEFAULT_FEATURES ниже)

Пример DF_API_FEATURES:
{
  "health": true,
  "version": true,
  "pagination": {"endpoint": "/api/v1/schemas", "limit_param": "limit", "page_param": "page"},
  "idempotency": {"endpoint": "/api/v1/echo", "method": "POST"},
  "cors": true,
  "ratelimit_headers": true
}
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, Optional

import pytest
import requests

# -------------------------------
# Константы/дефолты
# -------------------------------

DEFAULT_BASE_URL = "http://localhost:8080"
DEFAULT_TIMEOUT = 5.0

DEFAULT_FEATURES: Dict[str, Any] = {
    "health": True,
    "version": True,
    "pagination": None,       # {"endpoint": "/api/v1/schemas", "limit_param": "limit", "page_param": "page"}
    "idempotency": None,      # {"endpoint": "/api/v1/echo", "method": "POST"}
    "cors": False,
    "ratelimit_headers": False,
}

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z\.-]+)?$")


# -------------------------------
# Фикстуры
# -------------------------------

@pytest.fixture(scope="session")
def base_url() -> str:
    return os.getenv("DF_API_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


@pytest.fixture(scope="session")
def timeout_sec() -> float:
    try:
        return float(os.getenv("DF_API_TIMEOUT_SEC", str(DEFAULT_TIMEOUT)))
    except Exception:
        return DEFAULT_TIMEOUT


@pytest.fixture(scope="session")
def features() -> Dict[str, Any]:
    raw = os.getenv("DF_API_FEATURES")
    if not raw:
        return DEFAULT_FEATURES
    try:
        obj = json.loads(raw)
        merged = dict(DEFAULT_FEATURES)
        merged.update(obj or {})
        return merged
    except Exception:
        return DEFAULT_FEATURES


@pytest.fixture(scope="session")
def session() -> requests.Session:
    s = requests.Session()
    token = os.getenv("DF_API_TOKEN")
    headers = {
        "Accept": "application/json",
        "User-Agent": "datafabric-contract-tests/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    s.headers.update(headers)
    return s


# -------------------------------
# Хелперы
# -------------------------------

def _url(base_url: str, path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return base_url + path

def _is_json_content(resp: requests.Response) -> bool:
    ct = resp.headers.get("Content-Type", "")
    return "application/json" in ct or "application/problem+json" in ct

def _json_or_error(resp: requests.Response) -> Dict[str, Any]:
    try:
        return resp.json()
    except Exception:
        return {"_raw": resp.text[:1000], "_note": "non-json response"}

def _assert_json(resp: requests.Response) -> Dict[str, Any]:
    assert _is_json_content(resp), f"expected JSON Content-Type, got: {resp.headers.get('Content-Type')}"
    return resp.json()

def _roundtrip_latency(func, *args, **kwargs) -> (float, requests.Response):
    t0 = time.perf_counter()
    resp = func(*args, **kwargs)
    dt = time.perf_counter() - t0
    return dt, resp


# -------------------------------
# Базовые тесты: health / version
# -------------------------------

@pytest.mark.contract
def test_health_endpoint(session: requests.Session, base_url: str, timeout_sec: float, features: Dict[str, Any]) -> None:
    if not features.get("health"):
        pytest.skip("health not declared in DF_API_FEATURES")
    dt, resp = _roundtrip_latency(session.get, _url(base_url, "/api/v1/health"), timeout=timeout_sec)
    assert resp.status_code == 200, f"unexpected status: {resp.status_code}, body={resp.text}"
    body = _assert_json(resp)
    assert isinstance(body, dict)
    assert "ok" in body and isinstance(body["ok"], bool), f"missing/invalid 'ok' field: {body}"
    assert dt < timeout_sec, f"health latency too high: {dt:.3f}s"


@pytest.mark.contract
def test_version_endpoint(session: requests.Session, base_url: str, timeout_sec: float, features: Dict[str, Any]) -> None:
    if not features.get("version"):
        pytest.skip("version not declared in DF_API_FEATURES")
    dt, resp = _roundtrip_latency(session.get, _url(base_url, "/api/v1/version"), timeout=timeout_sec)
    assert resp.status_code == 200, f"unexpected status: {resp.status_code}, body={resp.text}"
    body = _assert_json(resp)
    assert "version" in body, f"no 'version' in response: {body}"
    ver = str(body["version"])
    assert SEMVER_RE.match(ver), f"version is not semver: {ver}"
    # Доп. поля (не обязательны, но если есть — проверим типы)
    for k in ("app", "build", "commit", "python", "platform"):
        if k in body:
            assert isinstance(body[k], (str, int)), f"field {k} has invalid type"
    assert dt < timeout_sec, f"version latency too high: {dt:.3f}s"


# -------------------------------
# Контент-тайпы, CORS, rate-limit
# -------------------------------

@pytest.mark.contract
def test_content_type_is_json(session: requests.Session, base_url: str, timeout_sec: float) -> None:
    resp = session.get(_url(base_url, "/api/v1/health"), timeout=timeout_sec)
    assert _is_json_content(resp), f"Content-Type must be JSON, got {resp.headers.get('Content-Type')}"

@pytest.mark.contract
def test_cors_headers_if_enabled(session: requests.Session, base_url: str, timeout_sec: float, features: Dict[str, Any]) -> None:
    if not features.get("cors"):
        pytest.skip("CORS not declared in DF_API_FEATURES")
    # Пробный preflight
    resp = session.options(_url(base_url, "/api/v1/health"), headers={
        "Origin": "http://example.test",
        "Access-Control-Request-Method": "GET",
    }, timeout=timeout_sec)
    assert resp.status_code in (200, 204)
    # Проверяем базовые заголовки
    assert "Access-Control-Allow-Origin" in resp.headers
    assert resp.headers["Access-Control-Allow-Origin"] in ("*", "http://example.test")

@pytest.mark.contract
def test_rate_limit_headers_if_enabled(session: requests.Session, base_url: str, timeout_sec: float, features: Dict[str, Any]) -> None:
    if not features.get("ratelimit_headers"):
        pytest.skip("rate limit headers not declared in DF_API_FEATURES")
    resp = session.get(_url(base_url, "/api/v1/health"), timeout=timeout_sec)
    # Стандартные имена варьируются; проверим распространённые
    candidates = ["X-RateLimit-Limit", "RateLimit-Limit"]
    assert any(h in resp.headers for h in candidates), f"no rate limit headers among: {candidates}"


# -------------------------------
# Ошибки и problem+json
# -------------------------------

@pytest.mark.contract
def test_404_problem_json(session: requests.Session, base_url: str, timeout_sec: float) -> None:
    resp = session.get(_url(base_url, "/api/v1/__nonexistent__"), timeout=timeout_sec)
    assert resp.status_code in (404, 400, 405)
    if _is_json_content(resp):
        body = _json_or_error(resp)
        # RFC 7807 поля (если поддерживаются)
        for k in ("type", "title", "status"):
            if k in body:
                assert body.get(k) is not None


# -------------------------------
# Пагинация (если объявлена)
# -------------------------------

@pytest.mark.contract
def test_pagination_contract(session: requests.Session, base_url: str, timeout_sec: float, features: Dict[str, Any]) -> None:
    pg = features.get("pagination")
    if not pg:
        pytest.skip("pagination not declared in DF_API_FEATURES")
    endpoint = pg["endpoint"]
    qp_limit = pg.get("limit_param", "limit")
    qp_page = pg.get("page_param", "page")

    # Страница 1 с малым лимитом
    resp1 = session.get(_url(base_url, endpoint), params={qp_limit: 2, qp_page: 1}, timeout=timeout_sec)
    assert resp1.status_code == 200, f"status={resp1.status_code}, body={resp1.text}"
    body1 = _assert_json(resp1)
    # Ожидаем объект с полями items и (возможно) next/prev/total
    assert isinstance(body1, dict), "pagination response must be an object"
    assert "items" in body1 and isinstance(body1["items"], list), "pagination must include 'items' list"
    # Если есть total — проверим тип
    if "total" in body1:
        assert isinstance(body1["total"], int)
    # Если есть next — это строка URL или None
    if "next" in body1:
        assert body1["next"] is None or isinstance(body1["next"], str)

    # Страница 2
    resp2 = session.get(_url(base_url, endpoint), params={qp_limit: 2, qp_page: 2}, timeout=timeout_sec)
    assert resp2.status_code == 200
    body2 = _assert_json(resp2)
    assert isinstance(body2.get("items"), list)
    # Допустим пересечение элементов между страницами отсутствует (мягкая проверка)
    if body1["items"] and body2["items"]:
        assert body1["items"] != body2["items"], "page 1 items should differ from page 2 items"


# -------------------------------
# Идемпотентность (если объявлена)
# -------------------------------

@pytest.mark.contract
def test_idempotency_key_contract(session: requests.Session, base_url: str, timeout_sec: float, features: Dict[str, Any]) -> None:
    idem = features.get("idempotency")
    if not idem:
        pytest.skip("idempotency not declared in DF_API_FEATURES")
    endpoint = idem["endpoint"]
    method = idem.get("method", "POST").upper()

    payload = {"now": int(time.time()), "value": "test"}
    headers = {"Idempotency-Key": f"df-tests-{payload['now']}"}

    # Первый вызов
    req1 = getattr(session, method.lower())
    resp1 = req1(_url(base_url, endpoint), json=payload, headers=headers, timeout=timeout_sec)
    assert resp1.status_code in (200, 201, 202), f"unexpected status: {resp1.status_code}"
    body1 = _json_or_error(resp1)

    # Повтор с тем же ключом (должен вернуть эквивалентный ответ)
    resp2 = req1(_url(base_url, endpoint), json=payload, headers=headers, timeout=timeout_sec)
    assert resp2.status_code in (200, 201, 202), f"unexpected status: {resp2.status_code}"
    body2 = _json_or_error(resp2)

    # Сравниваем стабильные части ответа
    assert type(body1) == type(body2)
    if isinstance(body1, dict):
        # Игнорируем поля-временные метки/идентификаторы, если встречаются
        def stable(d: Dict[str, Any]) -> Dict[str, Any]:
            return {k: v for k, v in d.items() if k not in ("ts", "timestamp", "request_id", "id")}
        assert stable(body1) == stable(body2), f"idempotent responses differ: {body1} vs {body2}"


# -------------------------------
# Безопасность заголовков (минимум)
# -------------------------------

@pytest.mark.contract
def test_security_headers_minimal(session: requests.Session, base_url: str, timeout_sec: float) -> None:
    resp = session.get(_url(base_url, "/api/v1/health"), timeout=timeout_sec)
    # Не падаем, если хедеров нет; если есть — проверим типичные значения
    h = resp.headers
    if "X-Content-Type-Options" in h:
        assert h["X-Content-Type-Options"].lower() == "nosniff"
    if "Referrer-Policy" in h:
        assert h["Referrer-Policy"] in ("no-referrer", "strict-origin-when-cross-origin")


# -------------------------------
# Регресс «медленного ответа»
# -------------------------------

@pytest.mark.contract
def test_response_time_under_timeout(session: requests.Session, base_url: str, timeout_sec: float) -> None:
    # Smoke: несколько быстрых GET подряд не должны превышать таймаут
    for _ in range(3):
        dt, resp = _roundtrip_latency(session.get, _url(base_url, "/api/v1/health"), timeout=timeout_sec)
        assert resp.status_code == 200
        assert dt < timeout_sec, f"single request exceeded timeout: {dt:.3f}s"
