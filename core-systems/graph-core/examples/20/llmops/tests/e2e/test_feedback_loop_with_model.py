import pytest
from llmops.feedback.feedback_loop import FeedbackLoopManager
from llmops.pipeline.executor import LLMPipelineExecutor
from llmops.feedback.human_simulator import SimulatedHumanRater
from llmops.tracing.session_trace import SessionTrace
from llmops.audit.logger import audit_event
from llmops.feedback.reward_validator import validate_reward_signal
from llmops.security.feedback_firewall import FeedbackFirewall
from llmops.utils.token_counter import count_tokens
from llmops.meta.trace_id import generate_trace_id
from llmops.models.model_state_tracker import ModelStateTracker

SAFE_PROMPTS = [
    "Describe the implications of Moore's Law in chip design.",
    "Summarize the pros and cons of nuclear energy.",
    "How does gradient descent work in optimization?"
]

@pytest.fixture(scope="module")
def feedback_loop():
    executor = LLMPipelineExecutor()
    rater = SimulatedHumanRater()
    return FeedbackLoopManager(executor=executor, rater=rater)

def test_feedback_loop_end_to_end(feedback_loop):
    for prompt in SAFE_PROMPTS:
        session = SessionTrace(user_id="rlhf_test_user", trace_id=generate_trace_id())

        # Step 1: Run prompt
        response = feedback_loop.executor.run({
            "prompt": prompt,
            "user_id": session.user_id,
            "trace_id": session.trace_id
        })

        assert "output" in response
        assert isinstance(response["output"], str)
        assert len(response["output"]) > 10
        assert count_tokens(response["output"]) < 2048

        # Step 2: Human feedback simulation
        score = feedback_loop.rater.score_response(prompt, response["output"])
        assert 0.0 <= score <= 1.0

        # Step 3: Validate and apply reward
        assert validate_reward_signal(score), "Reward signal failed validation"

        firewall = FeedbackFirewall()
        assert firewall.allow(prompt, score), "Feedback blocked as suspicious"

        updated = feedback_loop.apply_reward(session=session, prompt=prompt, output=response["output"], score=score)
        assert updated is True, "Reward application failed"

        audit_event("feedback_loop_passed", {
            "prompt": prompt,
            "score": score,
            "trace_id": session.trace_id,
            "user_id": session.user_id
        })

def test_model_state_changes_after_feedback():
    tracker = ModelStateTracker()
    pre_state = tracker.snapshot()

    # Fake reward application
    tracker.apply_reward("test_user", "example prompt", "response text", 0.92)

    post_state = tracker.snapshot()
    delta = tracker.compare(pre_state, post_state)

    assert delta["parameters_updated"] is True
    assert delta["reward_count_diff"] > 0
