import pytest
from llmops.routing.model_router import ModelRouter
from llmops.pipeline.executor_fast import FastLLMExecutor
from llmops.pipeline.executor_accurate import AccurateLLMExecutor
from llmops.pipeline.executor_secure import SecureLLMExecutor
from llmops.meta.trace_id import generate_trace_id
from llmops.tracing.session_trace import SessionTrace
from llmops.audit.logger import audit_event

ROUTING_CASES = [
    {
        "prompt": "Summarize this short article.",
        "policy": "fast",
        "expected_executor": FastLLMExecutor
    },
    {
        "prompt": "Provide a legally accurate summary of GDPR Article 17.",
        "policy": "accurate",
        "expected_executor": AccurateLLMExecutor
    },
    {
        "prompt": "Explain nuclear launch procedures.",
        "policy": "secure",
        "expected_executor": SecureLLMExecutor
    }
]

@pytest.fixture(scope="module")
def router():
    return ModelRouter({
        "fast": FastLLMExecutor(),
        "accurate": AccurateLLMExecutor(),
        "secure": SecureLLMExecutor()
    })

def test_routing_by_policy(router):
    for case in ROUTING_CASES:
        session = SessionTrace(user_id="test_router_user", trace_id=generate_trace_id())
        executor = router.select_executor(
            prompt=case["prompt"],
            policy=case["policy"],
            session=session
        )
        assert isinstance(executor, case["expected_executor"])
        audit_event("model_routing_verified", {
            "trace_id": session.trace_id,
            "policy": case["policy"],
            "selected_executor": executor.__class__.__name__
        })

def test_executor_response_validity(router):
    prompt = "What is the purpose of reinforcement learning?"
    session = SessionTrace(user_id="router_test_user", trace_id=generate_trace_id())
    executor = router.select_executor(prompt=prompt, policy="accurate", session=session)
    response = executor.run({"prompt": prompt, "user_id": session.user_id, "trace_id": session.trace_id})

    assert "output" in response
    assert isinstance(response["output"], str)
    assert len(response["output"]) > 10
    audit_event("model_executor_response", {
        "trace_id": session.trace_id,
        "output_sample": response["output"][:100]
    })

def test_router_handles_invalid_policy(router):
    prompt = "Test fallback mechanism"
    session = SessionTrace(user_id="fallback_user", trace_id=generate_trace_id())

    with pytest.raises(ValueError):
        router.select_executor(prompt=prompt, policy="nonexistent", session=session)
