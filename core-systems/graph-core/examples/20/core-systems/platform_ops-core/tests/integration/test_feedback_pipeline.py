import pytest
from llmops.feedback_pipeline import FeedbackPipeline
from llmops.data_store import FeedbackStore

@pytest.fixture
def feedback_store():
    # Заглушка для хранилища отзывов
    class DummyFeedbackStore:
        def __init__(self):
            self.data = []

        def save_feedback(self, feedback):
            self.data.append(feedback)
            return True

        def get_all_feedback(self):
            return self.data

    return DummyFeedbackStore()

@pytest.fixture
def pipeline(feedback_store):
    return FeedbackPipeline(store=feedback_store)

def test_feedback_saving(pipeline, feedback_store):
    feedback = {"user_id": 1, "rating": 5, "comment": "Excellent!"}
    result = pipeline.submit_feedback(feedback)
    assert result is True
    assert feedback in feedback_store.get_all_feedback()

def test_feedback_validation(pipeline):
    invalid_feedback = {"user_id": 2, "rating": 6}  # Рейтинг вне диапазона
    with pytest.raises(ValueError):
        pipeline.submit_feedback(invalid_feedback)

def test_multiple_feedbacks(pipeline, feedback_store):
    feedbacks = [
        {"user_id": 3, "rating": 4, "comment": "Good"},
        {"user_id": 4, "rating": 2, "comment": "Needs improvement"},
    ]
    for fb in feedbacks:
        pipeline.submit_feedback(fb)

    stored = feedback_store.get_all_feedback()
    assert all(fb in stored for fb in feedbacks)

def test_feedback_pipeline_integration(pipeline):
    feedback = {"user_id": 5, "rating": 3, "comment": "Average"}
    result = pipeline.submit_feedback(feedback)
    assert result is True

