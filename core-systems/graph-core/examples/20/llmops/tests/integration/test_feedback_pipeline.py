import pytest
from llmops.feedback.feedback_pipeline import FeedbackPipeline
from llmops.pipeline.executor import LLMPipelineExecutor
from llmops.feedback.human_simulator import SimulatedHumanRater
from llmops.security.reward_sanitizer import RewardSanitizer
from llmops.audit.logger import audit_event
from llmops.models.reward_model_updater import RewardModelUpdater
from llmops.models.model_state_tracker import ModelStateTracker
from llmops.tracing.session_trace import SessionTrace
from llmops.meta.trace_id import generate_trace_id

@pytest.fixture(scope="module")
def feedback_pipeline():
    executor = LLMPipelineExecutor()
    rater = SimulatedHumanRater()
    updater = RewardModelUpdater()
    return FeedbackPipeline(executor=executor, rater=rater, updater=updater)

def test_feedback_pipeline_executes(feedback_pipeline):
    prompt = "Compare the economic systems of capitalism and socialism."
    session = SessionTrace(user_id="integration_user", trace_id=generate_trace_id())

    # Генерация ответа
    response = feedback_pipeline.executor.run({
        "prompt": prompt,
        "user_id": session.user_id,
        "trace_id": session.trace_id
    })

    assert "output" in response
    assert isinstance(response["output"], str)
    assert len(response["output"]) > 10

    # Эмуляция оценки пользователя
    score = feedback_pipeline.rater.score_response(prompt, response["output"])
    assert 0.0 <= score <= 1.0

    # Очистка и проверка сигнала
    sanitized_score = RewardSanitizer().sanitize(score)
    assert sanitized_score >= 0.0 and sanitized_score <= 1.0

    # Применение обновления
    success = feedback_pipeline.updater.update_with_feedback(
        prompt=prompt,
        output=response["output"],
        score=sanitized_score,
        trace_id=session.trace_id
    )

    assert success is True

    audit_event("feedback_pipeline_passed", {
        "trace_id": session.trace_id,
        "prompt": prompt,
        "score": sanitized_score,
        "output_sample": response["output"][:100]
    })

def test_reward_model_updates_state():
    tracker = ModelStateTracker()
    pre_state = tracker.snapshot()

    updater = RewardModelUpdater()
    updater.update_with_feedback(
        prompt="Example prompt",
        output="Example output",
        score=0.88,
        trace_id=generate_trace_id()
    )

    post_state = tracker.snapshot()
    delta = tracker.compare(pre_state, post_state)

    assert delta["reward_count_diff"] > 0
    assert delta["parameters_updated"] is True
