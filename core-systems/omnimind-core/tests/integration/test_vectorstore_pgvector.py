# -*- coding: utf-8 -*-
import contextlib
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

try:
    import psycopg  # psycopg>=3
except Exception as e:  # помечаем отсутствие драйвера как скип, а не падение сбора
    psycopg = None

# Импортируем тестируемый адаптер
try:
    from omnimind.adapters.vectorstore.pgvector_adapter import (
        PgVectorAdapter,
        Document,
        QueryFilter,
        SchemaMismatchError,
    )
except Exception as e:
    PgVectorAdapter = None  # type: ignore


# -----------------------------
# Константы и маркеры
# -----------------------------

pytestmark = pytest.mark.integration

PG_IMAGE = os.getenv("PGVECTOR_TEST_IMAGE", "pgvector/pgvector:pg16")
DB_USER = "postgres"
DB_PASSWORD = "postgres"
DB_NAME = "postgres"
EMBED_DIMS = 4


# -----------------------------
# Утилиты окружения
# -----------------------------

def _have_docker() -> bool:
    return subprocess.call(["which", "docker"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_pg_ready(dsn: str, timeout_s: float = 30.0) -> None:
    if psycopg is None:
        pytest.skip("psycopg not available")
    deadline = time.time() + timeout_s
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
                cur.execute("SELECT 1")
                return
        except Exception as e:
            last_err = e
            time.sleep(0.5)
    raise TimeoutError(f"Postgres not ready: {last_err}")


# -----------------------------
# Фикстуры: БД (docker или DSN)
# -----------------------------

@pytest.fixture(scope="session")
def pg_dsn() -> str:
    """
    Возвращает DSN для тестов. Если задан PGVECTOR_TEST_DSN, используем его.
    Иначе запускаем контейнер с pgvector и маппим порт на localhost.
    """
    if PgVectorAdapter is None:
        pytest.skip("PgVectorAdapter module not importable")

    if psycopg is None:
        pytest.skip("psycopg not available")

    env_dsn = os.getenv("PGVECTOR_TEST_DSN")
    if env_dsn:
        _wait_pg_ready(env_dsn, 60.0)
        # гарантируем наличие расширения
        with psycopg.connect(env_dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
        return env_dsn

    if not _have_docker():
        pytest.skip("docker not available and PGVECTOR_TEST_DSN not provided")

    port = _free_port()
    name = f"pgvector-test-{uuid.uuid4().hex[:8]}"
    env = [
        "-e", f"POSTGRES_PASSWORD={DB_PASSWORD}",
        "-e", f"POSTGRES_USER={DB_USER}",
        "-e", f"POSTGRES_DB={DB_NAME}",
    ]
    run = [
        "docker", "run", "-d", "--rm",
        "-p", f"{port}:5432",
        "--name", name,
        *env,
        PG_IMAGE,
    ]
    proc = subprocess.run(run, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        pytest.skip(f"failed to start docker: {proc.stderr}")

    dsn = f"postgresql://{DB_USER}:{DB_PASSWORD}@127.0.0.1:{port}/{DB_NAME}"

    try:
        _wait_pg_ready(dsn, 60.0)
        # расширение pgvector должно быть доступно в образе
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
        yield dsn
    finally:
        subprocess.run(["docker", "logs", name, "--tail", "50"], stdout=sys.stderr, stderr=sys.stderr)
        subprocess.run(["docker", "stop", "-t", "2", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@pytest.fixture()
def adapter(pg_dsn: str):
    """
    Адаптер с отдельной таблицей на каждый тест для изоляции.
    """
    table = f"docs_{uuid.uuid4().hex[:6]}"
    a = PgVectorAdapter(
        pg_dsn,
        embedding_dims=EMBED_DIMS,
        schema="public",
        table=table,
        ivfflat_lists=50,
        default_probes=8,
        pool_max_size=5,
        tsconfig="simple",
        statement_timeout_ms=15_000,
    )
    a.init_schema()
    try:
        yield a
    finally:
        # чистка за собой
        with contextlib.suppress(Exception):
            import psycopg
            with psycopg.connect(pg_dsn, autocommit=True) as conn, conn.cursor() as cur:
                cur.execute(f'DROP TABLE IF EXISTS public."{table}" CASCADE')
        with contextlib.suppress(Exception):
            a.close()


# -----------------------------
# Хелперы данных
# -----------------------------

def _doc(doc_id: str, ns: str, text: str, vec: list[float], **meta):
    return Document(id=doc_id, namespace=ns, content=text, embedding=vec, metadata=meta or {})


# -----------------------------
# Тесты
# -----------------------------

def test_init_schema_idempotent(adapter: PgVectorAdapter):
    # повторный вызов не должен падать
    adapter.init_schema()
    adapter.init_schema()


def test_upsert_and_vector_search_basic(adapter: PgVectorAdapter):
    ns = "demo"
    docs = [
        _doc("a1", ns, "апельсин мандарин цитрус", [0.10, 0.20, 0.30, 0.40], lang="ru", cat="fruit"),
        _doc("b2", ns, "яблоко груша фрукт",       [0.20, 0.10, 0.40, 0.30], lang="ru", cat="fruit"),
        _doc("c3", ns, "банан тропический фрукт",  [0.90, 0.10, 0.20, 0.10], lang="ru", cat="fruit"),
    ]
    assert adapter.upsert(docs) == 3

    # Повторная вставка (обновление) не должна дублировать записи
    assert adapter.upsert([_doc("a1", ns, "цитрусовый плод", [0.11, 0.21, 0.31, 0.41], lang="ru", cat="fruit")]) == 1

    q = [0.2, 0.2, 0.3, 0.3]
    res = adapter.search(q, top_k=3, flt=QueryFilter(namespace=ns))
    assert len(res) == 3
    # Проверка упорядочивания по близости (первая запись должна иметь наибольший score)
    scores = [r.score for r in res]
    assert scores == sorted(scores, reverse=True)
    # Поля результата
    r0 = res[0]
    assert r0.id in {"a1", "b2", "c3"}
    assert r0.namespace == ns
    assert isinstance(r0.distance, float)


def test_vector_search_with_metadata_filter(adapter: PgVectorAdapter):
    ns = "nsmeta"
    docs = [
        _doc("x1", ns, "red apple", [0.1, 0.3, 0.2, 0.1], lang="en", color="red", store=1),
        _doc("x2", ns, "green apple", [0.1, 0.25, 0.25, 0.1], lang="en", color="green", store=2),
        _doc("x3", ns, "blue car", [0.9, 0.0, 0.1, 0.0], lang="en", color="blue", store=2),
    ]
    adapter.upsert(docs)
    q = [0.11, 0.28, 0.23, 0.11]
    # Фильтр по JSONB: lang=en и store=2
    flt = QueryFilter(namespace=ns, metadata_contains={"lang": "en", "store": 2})
    res = adapter.search(q, top_k=5, flt=flt)
    ids = [r.id for r in res]
    assert set(ids) <= {"x2"}  # только x2 подходит по фильтрам


def test_hybrid_search_reranks_with_text(adapter: PgVectorAdapter):
    ns = "hybrid"
    docs = [
        _doc("p1", ns, "car repair manual", [0.1, 0.2, 0.3, 0.4]),
        _doc("p2", ns, "apple pie recipe",  [0.1, 0.21, 0.31, 0.39]),
        _doc("p3", ns, "fresh green apple fruit", [0.11, 0.22, 0.32, 0.38]),
    ]
    adapter.upsert(docs)
    q = [0.1, 0.2, 0.3, 0.4]

    # alpha=1.0 -> чисто векторный, как baseline
    vres = adapter.search(q, top_k=3, flt=QueryFilter(namespace=ns))
    hres_vec = adapter.search_hybrid("apple", q, top_k=3, alpha=1.0, flt=QueryFilter(namespace=ns))
    assert [r.id for r in vres] == [r.id for r in hres_vec]

    # alpha=0.0 -> чисто текст: "apple" должен поднять p2/p3
    hres_text = adapter.search_hybrid("apple", q, top_k=3, alpha=0.0, flt=QueryFilter(namespace=ns))
    ids = [r.id for r in hres_text]
    assert ids[0] in {"p2", "p3"}


def test_mmr_diversification(adapter: PgVectorAdapter):
    ns = "mmr"
    docs = [
        _doc("m1", ns, "t1", [0.20, 0.20, 0.30, 0.30]),
        _doc("m2", ns, "t2", [0.21, 0.20, 0.29, 0.30]),
        _doc("m3", ns, "t3", [0.19, 0.20, 0.31, 0.30]),
        _doc("m4", ns, "t4", [0.9, 0.0, 0.0, 0.0]),
        _doc("m5", ns, "t5", [0.88, 0.02, 0.02, 0.02]),
    ]
    adapter.upsert(docs)
    q = [0.2, 0.2, 0.3, 0.3]
    res = adapter.search_mmr(q, top_k=3, lambda_mult=0.5, flt=QueryFilter(namespace=ns))
    ids = [r.id for r in res]
    assert len(ids) == len(set(ids)) == 3  # уникальные и ровно 3


def test_delete_by_ids_and_namespace(adapter: PgVectorAdapter):
    ns = "del"
    docs = [
        _doc("d1", ns, "a", [0.1, 0.2, 0.3, 0.4]),
        _doc("d2", ns, "b", [0.1, 0.2, 0.31, 0.39]),
        _doc("d3", ns, "c", [0.11, 0.22, 0.33, 0.44]),
    ]
    adapter.upsert(docs)

    # удаление по id
    n = adapter.delete(ids=["d1"], namespace=ns)
    assert n == 1

    # удаление остального по namespace
    n = adapter.delete(namespace=ns)
    assert n >= 2  # d2, d3


def test_probes_session_setting(adapter: PgVectorAdapter):
    ns = "probe"
    docs = [
        _doc("p1", ns, "x", [0.1, 0.2, 0.3, 0.4]),
        _doc("p2", ns, "y", [0.11, 0.21, 0.31, 0.41]),
    ]
    adapter.upsert(docs)
    q = [0.1, 0.2, 0.3, 0.4]
    # Явно задаем probes; проверяем, что запрос отрабатывает без ошибок
    res = adapter.search(q, top_k=2, flt=QueryFilter(namespace=ns), probes=5)
    assert len(res) == 2


def test_schema_mismatch_raises(adapter: PgVectorAdapter):
    ns = "mismatch"
    bad = Document(id="bad", namespace=ns, content="oops", embedding=[0.1, 0.2], metadata={})
    with pytest.raises(SchemaMismatchError):
        adapter.upsert([bad])


def test_concurrent_upserts(adapter: PgVectorAdapter):
    """
    Проверяем одновременные upsert’ы из нескольких батчей.
    """
    ns = "conc"
    batch1 = [_doc(f"c{i}", ns, "t", [0.1, 0.2, 0.3, 0.4]) for i in range(50)]
    batch2 = [_doc(f"c{i+1000}", ns, "t", [0.2, 0.1, 0.4, 0.3]) for i in range(50)]

    import threading
    err: list[Exception] = []

    def _w(docs):
        try:
            adapter.upsert(docs)
        except Exception as e:
            err.append(e)

    t1 = threading.Thread(target=_w, args=(batch1,))
    t2 = threading.Thread(target=_w, args=(batch2,))
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert not err

    q = [0.15, 0.15, 0.35, 0.35]
    res = adapter.search(q, top_k=5, flt=QueryFilter(namespace=ns))
    assert len(res) <= 5 and len(res) > 0
