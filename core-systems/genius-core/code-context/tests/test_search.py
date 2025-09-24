# genius-core/code-context/tests/test_search.py

import pytest
from code_context.search.semantic_search import SemanticSearchEngine
from code_context.search.hybrid_ranker import HybridRanker
from code_context.config.loader import load_config
from code_context.indexer import index_engine
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent / "fixtures"
MOCK_FILE = FIXTURE_DIR / "example_code.py"


@pytest.fixture(scope="module")
def config():
    return load_config("code_context/config/config.yaml")


@pytest.fixture(scope="module")
def embedded_index(config):
    return index_engine.build_index(MOCK_FILE, config=config)


@pytest.fixture
def semantic_search(embedded_index):
    return SemanticSearchEngine(indexes=[embedded_index])


@pytest.fixture
def hybrid_ranker(embedded_index):
    return HybridRanker(indexes=[embedded_index])


def test_semantic_top_result_exact_match(semantic_search):
    query = "calculate sum"
    results = semantic_search.search(query, top_k=1)
    assert len(results) == 1
    assert "sum" in results[0]['context'] or "calculate" in results[0]['context']


def test_semantic_top_k_results(semantic_search):
    query = "initialize class"
    results = semantic_search.search(query, top_k=3)
    assert len(results) == 3
    for r in results:
        assert isinstance(r, dict)
        assert "score" in r and isinstance(r["score"], float)


def test_hybrid_ranking_stability(hybrid_ranker):
    query = "get user data"
    r1 = hybrid_ranker.search(query, top_k=3)
    r2 = hybrid_ranker.search(query, top_k=3)
    assert [r['context'] for r in r1] == [r['context'] for r in r2]


def test_fallback_to_bm25_only(hybrid_ranker):
    query = "unrelated gibberish zzz"
    results = hybrid_ranker.search(query, top_k=2)
    assert len(results) == 2
    for res in results:
        assert "context" in res


def test_ranking_precision_on_similar_terms(hybrid_ranker):
    results = hybrid_ranker.search("load config", top_k=5)
    scores = [r['score'] for r in results]
    assert scores == sorted(scores, reverse=True)


def test_vector_embedding_hash_consistency(embedded_index):
    vec_hash1 = embedded_index.get("embedding_vector_hash")
    vec_hash2 = embedded_index.get("embedding_vector_hash")
    assert vec_hash1 == vec_hash2


def test_search_handles_multilingual_query(hybrid_ranker):
    query = "получить данные"  # русский
    results = hybrid_ranker.search(query, top_k=2)
    assert len(results) == 2
    for res in results:
        assert isinstance(res, dict)
        assert "context" in res


def test_semantic_search_handles_code_tokens(semantic_search):
    query = "def __init__"
    results = semantic_search.search(query, top_k=2)
    assert any("__init__" in r['context'] for r in results)
