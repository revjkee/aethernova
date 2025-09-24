import pytest
from llmops.routing.model_router import ModelRouter
from llmops.pipeline.executor_fast import FastLLMExecutor
from llmops.pipeline.executor_accurate import AccurateLLMExecutor
from llmops.pipeline.executor_secure import SecureLLMExecutor
from llmops.tracing.session_trace import SessionTrace
from llmops.meta.trace_id import generate_trace_id

@pytest.fixture(scope="module")
def router_instance():
    return ModelRouter({
        "fast": FastLLMExecutor(),
        "accurate": AccurateLLMExecutor(),
        "secure": SecureLLMExecutor()
    })

def test_router_fast_selection(router_instance):
    session = SessionTrace(user_id="unit_fast", trace_id=generate_trace_id())
    executor = router_instance.select_executor(
        prompt="Summarize this article quickly.",
        policy="fast",
        session=session
    )
    assert isinstance(executor, FastLLMExecutor)

def test_router_accurate_selection(router_instance):
    session = SessionTrace(user_id="unit_accurate", trace_id=generate_trace_id())
    executor = router_instance.select_executor(
        prompt="Explain in detail the Second Law of Thermodynamics.",
        policy="accurate",
        session=session
    )
    assert isinstance(executor, AccurateLLMExecutor)

def test_router_secure_selection(router_instance):
    session = SessionTrace(user_id="unit_secure", trace_id=generate_trace_id())
    executor = router_instance.select_executor(
        prompt="Explain confidential data access procedures.",
        policy="secure",
        session=session
    )
    assert isinstance(executor, SecureLLMExecutor)

def test_router_invalid_policy(router_instance):
    session = SessionTrace(user_id="unit_invalid", trace_id=generate_trace_id())
    with pytest.raises(ValueError):
        router_instance.select_executor(
            prompt="Test unknown policy",
            policy="nonexistent",
            session=session
        )

def test_router_policy_type_validation(router_instance):
    session = SessionTrace(user_id="unit_typecheck", trace_id=generate_trace_id())
    with pytest.raises(TypeError):
        router_instance.select_executor(
            prompt="Policy should be a string",
            policy=123,  # invalid type
            session=session
        )

def test_router_idempotent_behavior(router_instance):
    session = SessionTrace(user_id="unit_idempotent", trace_id=generate_trace_id())
    prompt = "Explain Bayesian inference."
    executor1 = router_instance.select_executor(prompt=prompt, policy="accurate", session=session)
    executor2 = router_instance.select_executor(prompt=prompt, policy="accurate", session=session)
    assert executor1.__class__ == executor2.__class__
