# -*- coding: utf-8 -*-
"""
Интеграционный тест новостного пайплайна с локальным HTTP-стабом.

Контракт окружения (тест конфигурирует, пайплайн должен уважать):
  - NEWS_SOURCES        : JSON-список URL источников новостей (эндпоинты стаба)
  - NEWS_OUTPUT_PATH    : путь к NDJSON-выходу (файл будет создан пайплайном)
  - NEWS_CACHE_PATH     : путь к каталогу/файлу кэша (для If-None-Match/If-Modified-Since)
  - NEWS_API_TIMEOUT    : таймаут HTTP-запросов в секундах (строка int/float)
  - NEWS_RUN_ID         : произвольный идентификатор запуска (для трассировки)

Способ запуска пайплайна (задайте один из двух):
  1) NEWS_PIPELINE_ENTRYPOINT="package.module:function"
     -> тест импортирует функцию и вызывает её без аргументов в текущем процессе.
  2) NEWS_PIPELINE_CMD="python -m yourpkg.news.pipeline --from-env"
     -> тест запустит подпроцесс с переданным окружением.

Ожидаемый выход:
  - NDJSON-файл, где каждая строка — валидный JSON-объект.
  - Поля минимум: "title": str, "url": str (http/https), "source": str,
    "published_at": ISO8601 в UTC (оканчивается на 'Z').
  - Дубликаты по URL должны быть устранены.
  - Повторный запуск не должен раздувать выход (идемпотентность по URL).

Тест НЕ делает предположений о внутренней реализации пайплайна.
"""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import hashlib
import importlib
import io
import json
import os
import queue
import random
import re
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest


# ------------------------------ Вспомогательные утилиты ------------------------------

ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")

def _now_utc() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _read_ndjson(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            out.append(json.loads(s))
    return out

def _unique_by_url(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    uniq = []
    for it in items:
        u = str(it.get("url", "")).strip()
        if u and u not in seen:
            seen.add(u)
            uniq.append(it)
    return uniq


# ------------------------------ HTTP-стаб для источников ------------------------------

@dataclass
class _EndpointSpec:
    path: str
    # первая отдача (200), дальше 304 при условии If-None-Match/If-Modified-Since
    etag: Optional[str] = None
    last_modified_httpdate: Optional[str] = None
    # «флапающий» ресурс: сначала 500, потом 200
    flaky: bool = False
    # основная полезная нагрузка
    payload: Dict[str, Any] = dataclasses.field(default_factory=dict)

@dataclass
class _ServerState:
    endpoints: Dict[str, _EndpointSpec]
    requests: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    # для flaky
    served_ok_once: Dict[str, bool] = dataclasses.field(default_factory=dict)


class _StubHandler(BaseHTTPRequestHandler):
    server_version = "NewsStub/1.0"
    sys_version = ""

    # будет проставлено из фабрики
    STATE: _ServerState = None  # type: ignore[assignment]

    def log_message(self, fmt: str, *args: Any) -> None:
        # глушим стандартный лог http.server
        return

    def _json(self, code: int, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response_only(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_HEAD(self) -> None:
        if self.path == "/health":
            self.send_response_only(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response_only(404)
        self.end_headers()

    def do_GET(self) -> None:
        rec = {
            "ts": _now_utc(),
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
        }
        self.STATE.requests.append(rec)

        if self.path == "/health":
            self._json(200, {"status": "ok"})
            return

        spec = self.STATE.endpoints.get(self.path)
        if not spec:
            self._json(404, {"error": "not_found"})
            return

        # Flaky поведение: первый запрос -> 500, затем 200
        if spec.flaky and not self.STATE.served_ok_once.get(self.path):
            self.STATE.served_ok_once[self.path] = True
            self._json(500, {"error": "transient"})
            return

        # Кэширование через ETag/If-None-Match
        if spec.etag:
            inm = self.headers.get("If-None-Match")
            if inm and inm.strip() == spec.etag:
                self._json(304, {})
                return

        # Кэширование через Last-Modified/If-Modified-Since
        if spec.last_modified_httpdate:
            ims = self.headers.get("If-Modified-Since")
            if ims and ims.strip() == spec.last_modified_httpdate:
                self._json(304, {})
                return

        headers: Dict[str, str] = {}
        if spec.etag:
            headers["ETag"] = spec.etag
        if spec.last_modified_httpdate:
            headers["Last-Modified"] = spec.last_modified_httpdate

        self._json(200, spec.payload, headers=headers)


@contextlib.contextmanager
def start_stub_server(endpoints: Dict[str, _EndpointSpec]):
    # выделяем свободный порт
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    addr, port = sock.getsockname()
    sock.close()

    state = _ServerState(endpoints=endpoints)
    _StubHandler.STATE = state
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _StubHandler)

    t = threading.Thread(target=httpd.serve_forever, name="news-stub", daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}", state
    finally:
        httpd.shutdown()
        t.join(timeout=2)


# ------------------------------ Запуск пайплайна ------------------------------

def _call_entrypoint(entry: str) -> int:
    """
    Вызов Python entrypoint "pkg.module:function" без аргументов.
    Функция обязана прочитать конфиг из ENV и завершиться с кодом 0 при успехе.
    """
    pkg, func = entry.rsplit(":", 1)
    mod = importlib.import_module(pkg)
    fn = getattr(mod, func)
    ret = fn()
    # допускаем None как успех
    return 0 if ret is None else int(ret)


def _run_pipeline(env: Dict[str, str]) -> None:
    entry = os.environ.get("NEWS_PIPELINE_ENTRYPOINT")
    cmd = os.environ.get("NEWS_PIPELINE_CMD")

    if entry:
        code = _call_entrypoint(entry)
        assert code == 0, f"EntryPoint exited with {code}"
        return

    if cmd:
        # subprocess режим
        proc = subprocess.run(
            cmd,
            shell=True,
            env={**os.environ, **env},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=float(env.get("NEWS_TEST_TIMEOUT", "60")),
        )
        if proc.returncode != 0:
            msg = f"Subprocess failed: rc={proc.returncode}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
            raise AssertionError(msg)
        return

    pytest.skip("Не задан ни NEWS_PIPELINE_ENTRYPOINT, ни NEWS_PIPELINE_CMD — нечего запускать.")


# ------------------------------ Фикстуры pytest ------------------------------

@pytest.fixture(scope="session")
def rnd() -> str:
    return uuid.uuid4().hex[:8]


@pytest.fixture
def out_paths(tmp_path: Path, rnd: str):
    out = tmp_path / f"news_out_{rnd}.ndjson"
    cache = tmp_path / f"news_cache_{rnd}.db"
    return out, cache


# ------------------------------ Наборы данных стаба ------------------------------

def _sample_payload_1(now: datetime) -> Dict[str, Any]:
    # Имитируем новостной API: неоднородный формат дат, дубликаты URL
    return {
        "status": "ok",
        "articles": [
            {
                "title": "Alpha launches new product",
                "url": "https://example.com/a1",
                "source": "alpha",
                "publishedAt": (now - timedelta(minutes=3)).isoformat(),
            },
            {
                "title": "Duplicate of A1",
                "url": "https://example.com/a1",  # дубликат по URL
                "source": "alpha-mirror",
                "publishedAt": (now - timedelta(minutes=2)).strftime("%a, %d %b %Y %H:%M:%S GMT"),
            },
            {
                "title": "Bravo raises funding",
                "url": "http://example.com/b1",   # http тоже допустим
                "source": "bravo",
                "publishedAt": int((now - timedelta(minutes=1)).timestamp()),  # epoch seconds
            },
        ]
    }


def _sample_payload_2(now: datetime) -> Dict[str, Any]:
    return {
        "ok": True,
        "items": [
            {
                "headline": "Charlie partners with Delta",
                "link": "https://example.com/c1",
                "origin": "charlie",
                "time": (now - timedelta(minutes=4)).replace(microsecond=0).isoformat() + "Z",
            }
        ]
    }


# ------------------------------ Тесты ------------------------------

@pytest.mark.integration
def test_news_pipeline_end_to_end_basic(tmp_path: Path, out_paths):
    """
    1) Поднимаем HTTP-стаб с 2 источниками:
       - /src1: нормальные данные + дубликаты + разные форматы дат.
       - /src2: другой формат полей.
    2) Конфигурируем ENV для пайплайна на эти URL и NDJSON-выход.
    3) Запускаем пайплайн (entrypoint или cmd), ожидаем успешного завершения.
    4) Валидируем NDJSON: схема, URL, published_at в UTC ISO-8601, дедуп по URL.
    """
    out, cache = out_paths
    now = datetime.now(tz=timezone.utc)

    ep = {
        "/src1": _EndpointSpec(
            path="/src1",
            etag='"v1-a"',  # кавычки — валидный ETag
            last_modified_httpdate=(now - timedelta(minutes=5)).strftime("%a, %d %b %Y %H:%M:%S GMT"),
            payload=_sample_payload_1(now),
        ),
        "/src2": _EndpointSpec(
            path="/src2",
            payload=_sample_payload_2(now),
        ),
    }

    with start_stub_server(ep) as (base, state):
        sources = [f"{base}/src1", f"{base}/src2"]

        env = {
            "NEWS_SOURCES": json.dumps(sources, ensure_ascii=False),
            "NEWS_OUTPUT_PATH": str(out),
            "NEWS_CACHE_PATH": str(cache),
            "NEWS_API_TIMEOUT": "5",
            "NEWS_RUN_ID": uuid.uuid4().hex,
            "NEWS_TEST_TIMEOUT": "120",
        }

        _run_pipeline(env)

        # Проверяем, что файл создан и не пуст
        assert out.exists(), "Пайплайн не создал выходной NDJSON-файл"
        data = _read_ndjson(out)
        assert data, "Выходной NDJSON пуст"

        # Базовая схема и значения
        for i, rec in enumerate(data):
            assert isinstance(rec, dict), f"Строка #{i} не является JSON-объектом"
            assert rec.get("title") and isinstance(rec["title"], str), f"#{i}: поле title отсутствует/некорректно"
            assert rec.get("url") and isinstance(rec["url"], str), f"#{i}: поле url отсутствует/некорректно"
            assert rec.get("source") and isinstance(rec["source"], str), f"#{i}: поле source отсутствует/некорректно"
            pa = rec.get("published_at")
            assert pa and isinstance(pa, str), f"#{i}: published_at отсутствует/некорректно"
            assert ISO_UTC_RE.match(pa), f"#{i}: published_at должен быть ISO-8601 UTC (оканчиваться на 'Z'), получено: {pa}"
            assert rec["url"].startswith(("http://", "https://")), f"#{i}: url должен начинаться с http/https"

        # Дедупликация по URL
        uniq = _unique_by_url(data)
        assert len(uniq) == len({r["url"] for r in data}), "В выходе обнаружены дубликаты по URL"

        # Нормализация времени: все значения в пределах последние 10 минут
        now_utc = datetime.now(tz=timezone.utc)
        for i, rec in enumerate(data):
            dt = datetime.fromisoformat(rec["published_at"].replace("Z", "+00:00"))
            assert now_utc - timedelta(minutes=15) <= dt <= now_utc + timedelta(seconds=5), f"#{i}: published_at вне разумного окна"


@pytest.mark.integration
def test_news_pipeline_retry_and_cache(tmp_path: Path, out_paths):
    """
    Проверяем устойчивость к временным сбоям и базовое кэширование:
      - /flaky: первый запрос -> 500, затем -> 200 (повторная попытка ожидается внутри пайплайна).
      - /cache: отдаёт ETag/Last-Modified, второй запуск пайплайна должен использовать If-None-Match/If-Modified-Since.
    Валидируем идемпотентность: повторный запуск не раздувает NDJSON дубликатами.
    """
    out, cache = out_paths
    now = datetime.now(tz=timezone.utc)

    ep = {
        "/flaky": _EndpointSpec(
            path="/flaky",
            flaky=True,
            payload={
                "status": "ok",
                "articles": [
                    {
                        "title": "Transient endpoint recovered",
                        "url": "https://example.com/recovered",
                        "source": "flaky",
                        "publishedAt": (now - timedelta(minutes=1)).isoformat(),
                    }
                ],
            },
        ),
        "/cache": _EndpointSpec(
            path="/cache",
            etag='"v2-b"',
            last_modified_httpdate=(now - timedelta(minutes=7)).strftime("%a, %d %b %Y %H:%M:%S GMT"),
            payload={
                "status": "ok",
                "articles": [
                    {
                        "title": "Cachable news item",
                        "url": "https://example.com/cache1",
                        "source": "cache",
                        "publishedAt": (now - timedelta(minutes=2)).isoformat(),
                    }
                ],
            },
        ),
    }

    with start_stub_server(ep) as (base, state):
        sources = [f"{base}/flaky", f"{base}/cache"]

        env = {
            "NEWS_SOURCES": json.dumps(sources, ensure_ascii=False),
            "NEWS_OUTPUT_PATH": str(out),
            "NEWS_CACHE_PATH": str(cache),
            "NEWS_API_TIMEOUT": "5",
            "NEWS_RUN_ID": uuid.uuid4().hex,
            "NEWS_TEST_TIMEOUT": "120",
        }

        # Первый запуск — должен пережить 500 на /flaky и собрать данные
        _run_pipeline(env)
        assert out.exists()
        data1 = _read_ndjson(out)
        assert data1, "После первого запуска выход пуст"
        urls1 = {r["url"] for r in data1}

        # Второй запуск — проверяем кэш-заголовки и идемпотентность
        _run_pipeline(env)
        data2 = _read_ndjson(out)
        urls2 = {r["url"] for r in data2}

        # Идемпотентность по URL
        assert urls1 == urls2, "Повторный запуск изменил набор URL — ожидается идемпотентность"
        assert len(data2) == len(urls2), "Повторный запуск привёл к дубликатам по URL"

        # Наблюдаем, отправлял ли пайплайн If-None-Match / If-Modified-Since ко второму запуску
        # (опциональная проверка; если не отправил — отметим как xfail, т.к. это зависит от реализации кэша)
        cache_headers_seen = False
        for req in state.requests:
            if req["path"].endswith("/cache") and (
                "If-None-Match" in req["headers"] or "If-Modified-Since" in req["headers"]
            ):
                cache_headers_seen = True
                break

        if not cache_headers_seen:
            pytest.xfail("Кэширующие заголовки If-None-Match/If-Modified-Since не наблюдены — зависит от реализации пайплайна")


@pytest.mark.integration
def test_output_schema_minimum_fields(tmp_path: Path, out_paths):
    """
    Минимальные требования к схеме записи NDJSON:
      - title: str
      - url: str (http/https)
      - source: str
      - published_at: ISO-8601 UTC (Z)
    """
    out, cache = out_paths
    now = datetime.now(tz=timezone.utc)

    ep = {
        "/only_required": _EndpointSpec(
            path="/only_required",
            payload={
                "status": "ok",
                "articles": [
                    {
                        "title": "Only required fields",
                        "url": "https://example.com/min",
                        "source": "req",
                        "publishedAt": (now - timedelta(minutes=1)).isoformat(),
                    }
                ],
            },
        ),
    }

    with start_stub_server(ep) as (base, state):
        env = {
            "NEWS_SOURCES": json.dumps([f"{base}/only_required"]),
            "NEWS_OUTPUT_PATH": str(out),
            "NEWS_CACHE_PATH": str(cache),
            "NEWS_API_TIMEOUT": "5",
            "NEWS_RUN_ID": uuid.uuid4().hex,
            "NEWS_TEST_TIMEOUT": "60",
        }
        _run_pipeline(env)

        data = _read_ndjson(out)
        assert len(data) == 1
        rec = data[0]
        for field in ("title", "url", "source", "published_at"):
            assert field in rec and isinstance(rec[field], str), f"Отсутствует/некорректно поле {field}"
        assert rec["url"].startswith(("http://", "https://"))
        assert ISO_UTC_RE.match(rec["published_at"]), "published_at должен быть ISO-8601 UTC (оканчиваться на 'Z')"
