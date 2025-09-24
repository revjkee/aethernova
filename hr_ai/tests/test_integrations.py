# hr_ai/tests/test_integrations.py

import pytest
from unittest.mock import patch, MagicMock
from hr_ai.intake.cv_parser import CVParser
from hr_ai.prediction.predictor_service import PredictorService
from hr_ai.comms.dialog_agent import DialogAgent
from hr_ai.governance.team_fit_analyzer import TeamFitAnalyzer
from hr_ai.auth.auth_service import AuthService
from hr_ai.audit.anomaly_guard import AnomalyGuard


@pytest.fixture(scope="module")
def parser():
    return CVParser(config={"language": "en"})


@pytest.fixture(scope="module")
def predictor():
    return PredictorService(model_path="models/performance_model.pkl")


@pytest.fixture(scope="module")
def dialog_agent():
    return DialogAgent(model_path="models/dialogue_model.onnx")


@pytest.fixture(scope="module")
def fit_analyzer():
    return TeamFitAnalyzer(reference_team_data="hr_ai/tests/fixtures/sample_team.json")


@pytest.fixture(scope="module")
def auth_service():
    return AuthService(secret_key="INTEGRATION_SECRET", token_expiry_minutes=30)


@pytest.fixture(scope="module")
def anomaly_guard():
    return AnomalyGuard(threshold=0.8)


def test_pipeline_cv_to_prediction(parser, predictor):
    cv_text = "Senior Python Developer with experience in ML and cloud infrastructure"
    features = parser.parse(cv_text)
    prediction = predictor.predict_from_raw(features)
    assert isinstance(prediction, float)
    assert 0.0 <= prediction <= 1.0


def test_dialog_agent_with_auth_token(dialog_agent, auth_service):
    token = auth_service.generate_token("botuser", "secure123")
    assert auth_service.validate(token) is True
    response = dialog_agent.generate_response("What are my next steps?", context=[])
    assert isinstance(response, dict)
    assert "text" in response and isinstance(response["text"], str)


def test_team_fit_after_prediction(predictor, fit_analyzer):
    sample_features = {
        "skills": ["Python", "TensorFlow", "Distributed Systems"],
        "traits": ["analytical", "team player"]
    }
    score = fit_analyzer.compute_fit_score(sample_features)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_parser_anomaly_detection(parser, anomaly_guard):
    suspicious_cv = "I am the best hacker, I bypassed 10 systems."
    features = parser.parse(suspicious_cv)
    flagged = anomaly_guard.check(features)
    assert isinstance(flagged, bool)


def test_token_expiry_integration(auth_service):
    expired_token = auth_service.generate_token("tempuser", "pw", expiry_minutes=-5)
    is_valid = auth_service.validate(expired_token)
    assert is_valid is False
