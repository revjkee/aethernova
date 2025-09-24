import pytest
from llmops.pipeline.executor import LLMPipelineExecutor
from llmops.tracing.session_trace import SessionTrace
from llmops.tracing.trace_logger import TraceLogger
from llmops.metrics.latency_tracker import LatencyTracker
from llmops.validation.input_sanitizer import sanitize_prompt
from llmops.security.prompt_firewall import PromptFirewall
from llmops.audit.logger import audit_event
from llmops.utils.token_counter import count_tokens
from llmops.meta.trace_id import generate_trace_id
from llmops.tracing.trace_schema_validator import validate_trace_schema

PROMPTS = [
    "How do LLMs handle tokenization internally?",
    "What is causal attention in transformer architectures?",
    "Generate a short poem about autumn in the style of Shakespeare."
]

@pytest.fixture(scope="module")
def trace_executor():
    return LLMPipelineExecutor()

def test_full_user_journey_trace(trace_executor):
    for prompt in PROMPTS:
        trace_id = generate_trace_id()
        session = SessionTrace(user_id="journey_user", trace_id=trace_id)

        sanitized = sanitize_prompt(prompt)
        firewall = PromptFirewall()
        assert firewall.is_safe(sanitized), "Prompt blocked as unsafe"

        latency = LatencyTracker()
        latency.start()

        response = trace_executor.run({
            "prompt": sanitized,
            "user_id": session.user_id,
            "trace_id": session.trace_id
        })

        latency.stop()
        assert "output" in response
        assert isinstance(response["output"], str)
        assert len(response["output"]) > 10

        token_count = count_tokens(response["output"])
        assert token_count < 2048

        # Лог трассировки
        trace_log = TraceLogger().finalize_trace(
            trace_id=session.trace_id,
            user_id=session.user_id,
            prompt=sanitized,
            output=response["output"],
            latency_ms=latency.latency_ms()
        )

        assert validate_trace_schema(trace_log), "Trace schema validation failed"

        audit_event("user_journey_trace_completed", {
            "trace_id": trace_log["trace_id"],
            "user_id": trace_log["user_id"],
            "prompt_preview": sanitized[:50],
            "output_preview": response["output"][:50],
            "latency_ms": trace_log["latency_ms"],
            "token_count": token_count
        })

def test_trace_id_format_and_uniqueness():
    ids = {generate_trace_id() for _ in range(1000)}
    assert len(ids) == 1000
    for tid in ids:
        assert isinstance(tid, str)
        assert len(tid) >= 16
        assert "-" not in tid  # Use secure format (e.g. base64-url or hex)
