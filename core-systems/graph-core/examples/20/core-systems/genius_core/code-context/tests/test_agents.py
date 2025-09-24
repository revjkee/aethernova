# genius-core/code-context/tests/test_agents.py

import pytest
from code_context.agents.context_expander import ContextExpander
from code_context.agents.dependency_tracer import DependencyTracer
from code_context.agents.code_summary_agent import CodeSummaryAgent
from code_context.agents.comment_mapper import CommentMapper

from code_context.indexer.index_engine import build_index
from code_context.config.loader import load_config
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent / "fixtures"
MOCK_FILE = FIXTURE_DIR / "sample_module.py"


@pytest.fixture(scope="module")
def config():
    return load_config("code_context/config/config.yaml")


@pytest.fixture(scope="module")
def index(config):
    return build_index(MOCK_FILE, config=config)


def test_context_expansion_returns_dependent_blocks(index):
    agent = ContextExpander(index)
    block_id = "func:calculate_metrics"
    context = agent.expand(block_id=block_id)
    assert isinstance(context, list)
    assert any("def" in c or "return" in c for c in context)


def test_dependency_tracer_extracts_graph(index):
    tracer = DependencyTracer(index)
    graph = tracer.trace()
    assert isinstance(graph, dict)
    assert all(isinstance(k, str) for k in graph.keys())
    assert all(isinstance(v, list) for v in graph.values())


def test_dependency_graph_has_expected_nodes(index):
    tracer = DependencyTracer(index)
    graph = tracer.trace()
    assert "func:calculate_metrics" in graph
    assert "class:ModelTrainer" in graph


def test_code_summary_generation(index):
    agent = CodeSummaryAgent(index)
    summary = agent.summarize("func:calculate_metrics")
    assert isinstance(summary, str)
    assert len(summary) > 10
    assert "calculates" in summary or "returns" in summary


def test_comment_mapping_accuracy(index):
    mapper = CommentMapper(index)
    links = mapper.map()
    assert isinstance(links, list)
    assert all("comment" in l and "target" in l for l in links)
    assert all(isinstance(l['target'], str) for l in links)
    assert any("calculate" in l["comment"].lower() for l in links)


def test_context_expander_handles_missing_block(index):
    agent = ContextExpander(index)
    result = agent.expand("nonexistent:block")
    assert result == []


def test_comment_mapper_handles_empty_file():
    empty_index = {"code_blocks": [], "comments": []}
    mapper = CommentMapper(empty_index)
    result = mapper.map()
    assert result == []


def test_summary_fallback_on_unknown_block(index):
    agent = CodeSummaryAgent(index)
    summary = agent.summarize("block:does_not_exist")
    assert isinstance(summary, str)
    assert summary == "No summary available."
