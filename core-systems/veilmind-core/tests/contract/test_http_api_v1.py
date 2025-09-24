# -*- coding: utf-8 -*-
"""
Контрактные тесты HTTP API v1 для veilmind-core.

ENV:
  VEILMIND_API_BASE   — базовый URL, по умолчанию https://localhost:8443
  VEILMIND_TOKEN      — Bearer токен (опционально)
  VEILMIND_TIMEOUT    — таймаут запроса в секундах, по умолчанию 5.0
  VEILMIND_RETRIES    — число повторов при сетевых ошибках, по умолчанию 2
  VEILMIND_VERIFY_TLS — "1" (дефолт) или "0" чтобы отключить проверку TLS

Тесты:
  - /v1/synthetic/healthz, /v1/synthetic/readyz — 200, JSON, поле status
  - /v1/synthetic/echo GET/POST — JSON roundtrip и отражение метода
  - /v1/synthetic/decision — JSON с полями decision, headers трассировки/идемпотентности
  - /v1/synthetic/risk/score — JSON со score в [0,1]
  - /v1/synthetic/telemetry/events — 200/202, JSON
  - /v1/synthetic/chaos?kind=latency — 200, JSON (с малой задержкой)

Для нестабильных окружений: если базовая проверка не проходит, тесты помечаются xfail.
"""
from __future__ import annotations

import json
import os
import random
import string
import time
import uuid
from typing import Any, Dict, Optional, Tuple

import pytest

try:
    import requests
except Exception as e:  # pragma: no cover
    raise RuntimeError("Для контрактных тестов необходим пакет 'requests'") from e


# ------------------------------- Конфиг/фикстуры --------------------------------

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip() not in ("0", "false", "no", "False", "No")


@pytest.fixture(scope="session")
def api() -> Dict[str, Any]:
    return {
        "base": os.getenv("VEILMIND_API_BASE", "https://localhost:8443").rstrip("/"),
        "token": os.getenv("VEILMIND_TOKEN"),
        "timeout": float(os.getenv("VEILMIND_TIMEOUT", "5.0")),
        "retries": int(os.getenv("VEILMIND_RETRIES", "2")),
        "verify": _env_bool("VEILMIND_VERIFY_TLS", True),
    }


@pytest.fixture(scope="session")
def session(api: Dict[str, Any]) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Accept": "application/json",
        "User-Agent": "veilmind-contract-tests/1.0",
    })
    if api["token"]:
        s.headers["Authorization"] = f"Bearer {api['token']}"
    # requests.verify контролируется на каждом вызове
    return s


# ------------------------------ HTTP утилиты -----------------------------------

def _join(base: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return f"{base}{path if path.startswith('/') else '/' + path}"


def _backoff(attempt: int, base: float = 0.2, cap: float = 2.0) -> float:
    # полуслучайный экспон. бэкофф
    return min(cap, base * (2 ** attempt)) * (0.5 + random.random() / 2.0)


def _req(
    s: requests.Session,
    api: Dict[str, Any],
    method: str,
    path: str,
    *,
    json_body: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    trace_id: Optional[str] = None,
    idem: Optional[str] = None,
) -> Tuple[requests.Response, Any]:
    url = _join(api["base"], path)
    h: Dict[str, str] = {}
    if headers:
        h.update(headers)
    if trace_id:
        h["X-Trace-Id"] = trace_id
    if idem:
        h["Idempotency-Key"] = idem

    last_exc: Optional[Exception] = None
    for attempt in range(api["retries"] + 1):
        try:
            resp = s.request(
                method=method.upper(),
                url=url,
                json=json_body,
                headers=h or None,
                timeout=api["timeout"],
                verify=api["verify"],
            )
            body: Any
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if "application/json" in ctype or resp.text.strip().startswith(("{", "[")):
                try:
                    body = resp.json()
                except Exception:
                    body = {"raw": resp.text}
            else:
                body = {"raw": resp.text}
            return resp, body
        except (requests.ConnectionError, requests.Timeout) as e:
            last_exc = e
            if attempt >= api["retries"]:
                break
            time.sleep(_backoff(attempt))
    assert last_exc is not None
    raise last_exc


def _assert_json_object(body: Any, *, path: str) -> Dict[str, Any]:
    assert isinstance(body, dict), f"{path}: ожидался JSON-объект, получено: {type(body).__name__} -> {body!r}"
    return body


def _rand_trace() -> str:
    return uuid.uuid4().hex


def _rand_idem() -> str:
    return str(uuid.uuid4())


def _rand_subject() -> str:
    left = "".join(random.choice(string.ascii_lowercase) for _ in range(6))
    return f"{left}@example.com"


# ------------------------------ Предусловие окружения --------------------------

@pytest.fixture(scope="session", autouse=True)
def _xfail_if_unavailable(api: Dict[str, Any], session: requests.Session):
    """Если инстанс не отвечает на /healthz, помечаем весь модуль xfail."""
    try:
        resp, _ = _req(session, api, "GET", "/v1/synthetic/healthz")
        if resp.status_code >= 500:
            pytest.xfail(f"Сервис недоступен: /healthz -> {resp.status_code}")
    except Exception as e:  # pragma: no cover
        pytest.xfail(f"Не удалось подключиться к {api['base']}: {e}")


# ---------------------------------- Тесты -------------------------------------

@pytest.mark.contract
def test_health_and_ready(api: Dict[str, Any], session: requests.Session):
    for path in ("/v1/synthetic/healthz", "/v1/synthetic/readyz"):
        resp, body = _req(session, api, "GET", path, trace_id=_rand_trace())
        assert resp.status_code == 200, f"{path}: ожидаем 200, получено {resp.status_code}, body={body}"
        obj = _assert_json_object(body, path=path)
        assert "status" in obj and isinstance(obj["status"], str), f"{path}: отсутствует строковое поле 'status'"


@pytest.mark.contract
def test_echo_get_contract(api: Dict[str, Any], session: requests.Session):
    trace = _rand_trace()
    resp, body = _req(session, api, "GET", "/v1/synthetic/echo?delay_ms=5&status_code=200", trace_id=trace)
    assert resp.status_code == 200, f"/echo GET: ожидаем 200, получено {resp.status_code}"
    obj = _assert_json_object(body, path="/v1/synthetic/echo")
    # Разрешаем разные реализации, но минимальный контракт такой:
    # сервер должен вернуть то, что явно указывает на метод/эхо
    assert any(k in obj for k in ("method", "echo", "path")), "echo GET: в ответе нет ни method, ни echo, ни path"
    # трассировка «сквозь» заголовки
    assert resp.headers.get("X-Trace-Id"), "echo GET: сервер должен выставлять X-Trace-Id в ответе"


@pytest.mark.contract
def test_echo_post_roundtrip(api: Dict[str, Any], session: requests.Session):
    payload = {"hello": "world", "n": 42}
    trace = _rand_trace()
    resp, body = _req(session, api, "POST", "/v1/synthetic/echo", json_body=payload, trace_id=trace)
    assert resp.status_code in (200, 201), f"/echo POST: ожидаем 200/201, получено {resp.status_code}"
    obj = _assert_json_object(body, path="/v1/synthetic/echo")
    # Разные реализации могут оборачивать payload, но должны отразить его содержимое
    joined = json.dumps(obj, ensure_ascii=False)
    for k, v in payload.items():
        assert str(v) in joined, f"/echo POST: значение {k} не отражено в ответе"


@pytest.mark.contract
def test_decision_contract_minimal(api: Dict[str, Any], session: requests.Session):
    trace = _rand_trace()
    idem = _rand_idem()
    payload = {
        "subject": {"user": {"id": _rand_subject()}},
        "action": "read",
        "resource": {"id": "file:example", "labels": {"sensitivity": "low"}},
        "environment": {"ip": "203.0.113.42", "geo": "EEA"},
        "context": {"signals": {"gpc": True}},
        "idempotencyKey": idem,
    }
    resp, body = _req(session, api, "POST", "/v1/synthetic/decision", json_body=payload, trace_id=trace, idem=idem)
    assert resp.status_code in (200, 201), f"/decision: ожидаем 200/201, получено {resp.status_code}, body={body}"
    obj = _assert_json_object(body, path="/v1/synthetic/decision")
    # Минимальный контракт
    assert "decision" in obj and isinstance(obj["decision"], str), "/decision: отсутствует строковое поле 'decision'"
    assert obj["decision"] in {"allow", "deny", "prompt"}, "/decision: значение 'decision' вне допустимого множества"
    # Заголовки корреляции
    assert resp.headers.get("X-Trace-Id"), "/decision: сервер должен возвращать X-Trace-Id"
    assert resp.headers.get("Idempotency-Key") == idem, "/decision: сервер должен отражать Idempotency-Key"


@pytest.mark.contract
def test_decision_idempotency_replay(api: Dict[str, Any], session: requests.Session):
    trace = _rand_trace()
    idem = _rand_idem()
    payload = {
        "subject": {"user": {"id": _rand_subject()}},
        "action": "read",
        "resource": {"id": "file:1"},
        "idempotencyKey": idem,
    }
    # Первый вызов
    resp1, body1 = _req(session, api, "POST", "/v1/synthetic/decision", json_body=payload, trace_id=trace, idem=idem)
    assert resp1.status_code in (200, 201), f"1st /decision: {resp1.status_code} body={body1}"
    # Повтор
    resp2, body2 = _req(session, api, "POST", "/v1/synthetic/decision", json_body=payload, trace_id=trace, idem=idem)
    assert resp2.status_code in (200, 201), f"2nd /decision: {resp2.status_code} body={body2}"
    # Контракт: повтор с тем же Idempotency-Key возвращает идентичный результат
    assert body2 == body1, "Идемпотентность нарушена: повторный ответ тела отличается"
    assert resp2.headers.get("Idempotency-Key") == idem, "Ответ не отражает исходный Idempotency-Key"


@pytest.mark.contract
def test_risk_score_contract(api: Dict[str, Any], session: requests.Session):
    payload = {
        "subject": {"user": {"id": _rand_subject()}},
        "signals": {"posture": {"score": 0.7}, "idp": {"risk_score": 0.3}, "threat_intel": {"score": 0.1}},
    }
    resp, body = _req(session, api, "POST", "/v1/synthetic/risk/score", json_body=payload, trace_id=_rand_trace())
    assert resp.status_code in (200, 201), f"/risk/score: ожидаем 200/201, получено {resp.status_code}, body={body}"
    obj = _assert_json_object(body, path="/v1/synthetic/risk/score")
    # Минимальный контракт: score (float [0,1]) и/или разложение
    score = obj.get("score")
    assert isinstance(score, (int, float)), "/risk/score: поле 'score' отсутствует или не число"
    assert 0.0 <= float(score) <= 1.0, "/risk/score: 'score' должен быть в диапазоне [0,1]"


@pytest.mark.contract
def test_telemetry_batch_contract(api: Dict[str, Any], session: requests.Session):
    batch = {"events": [{"type": "audit", "fields": {"x": 1}}, {"type": "metric", "fields": {"name": "demo", "v": 1}}]}
    resp, body = _req(session, api, "POST", "/v1/synthetic/telemetry/events", json_body=batch, trace_id=_rand_trace())
    assert resp.status_code in (200, 202), f"/telemetry/events: ожидаем 200/202, получено {resp.status_code}, body={body}"
    obj = _assert_json_object(body, path="/v1/synthetic/telemetry/events")
    # Разные реализации могут возвращать count/accepted/ok — проверим что это объект без ошибки
    assert not obj.get("error"), f"/telemetry/events: unexpected error={obj.get('error')}"


@pytest.mark.contract
def test_chaos_latency_contract(api: Dict[str, Any], session: requests.Session):
    # Должен вернуть JSON и 200 при умеренной задержке
    resp, body = _req(session, api, "GET", "/v1/synthetic/chaos?kind=latency&ms=10", trace_id=_rand_trace())
    assert resp.status_code == 200, f"/chaos latency: ожидаем 200, получено {resp.status_code}, body={body}"
    _assert_json_object(body, path="/v1/synthetic/chaos")
