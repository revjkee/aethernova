# genius-core/code-context/tests/test_indexer.py

import pytest
from code_context.indexer import index_engine
from code_context.config.loader import load_config
from code_context.indexer.dag_tracker import compute_dag_hash
from code_context.indexer.symbol_graph_builder import extract_symbol_graph
from pathlib import Path
import json
import hashlib

TEST_FIXTURE_DIR = Path(__file__).parent / "fixtures"
MOCK_SOURCE = TEST_FIXTURE_DIR / "mock_script.py"


@pytest.fixture
def minimal_config():
    return load_config(config_path="code_context/config/config.yaml")


def test_index_build_structure(minimal_config):
    index = index_engine.build_index(MOCK_SOURCE, config=minimal_config)

    assert "path" in index
    assert "language" in index
    assert "symbols" in index
    assert "code_hash" in index
    assert "dag_node_id" in index
    assert index["path"].endswith("mock_script.py")


def test_ast_consistency(minimal_config):
    index = index_engine.build_index(MOCK_SOURCE, config=minimal_config)
    code = MOCK_SOURCE.read_text()
    expected_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()[:32]
    assert index["ast_digest"][:32] == expected_hash[:32]


def test_symbol_graph_generation(minimal_config):
    index = index_engine.build_index(MOCK_SOURCE, config=minimal_config)
    graph = extract_symbol_graph(index["symbols"])
    assert isinstance(graph, dict)
    assert "edges" in graph
    for edge in graph["edges"]:
        assert "from" in edge and "to" in edge


def test_embedding_hash_presence(minimal_config):
    index = index_engine.build_index(MOCK_SOURCE, config=minimal_config)
    assert "embedding_vector_hash" in index
    assert len(index["embedding_vector_hash"]) > 10


def test_dag_node_is_valid_uuid(minimal_config):
    import uuid
    index = index_engine.build_index(MOCK_SOURCE, config=minimal_config)
    try:
        uuid.UUID(index["dag_node_id"])
    except ValueError:
        pytest.fail("dag_node_id is not valid UUID")


def test_dag_hash_stability(minimal_config):
    index1 = index_engine.build_index(MOCK_SOURCE, config=minimal_config)
    index2 = index_engine.build_index(MOCK_SOURCE, config=minimal_config)
    dag1 = {"nodes": [index1], "edges": []}
    dag2 = {"nodes": [index2], "edges": []}
    hash1 = compute_dag_hash(dag1)
    hash2 = compute_dag_hash(dag2)
    assert hash1 == hash2


def test_index_json_schema():
    with open("code_context/data/code_context_index.json", "r") as f:
        data = json.load(f)

    assert "index_version" in data
    assert isinstance(data["indexed_files"], list)
    assert isinstance(data["symbol_graph"], dict)
    assert "embedding_model" in data
    assert "validation" in data
    assert data["validation"]["validated"] is True
