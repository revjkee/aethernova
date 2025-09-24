# hr_ai/tests/test_predictor.py

import pytest
import numpy as np
from hr_ai.prediction.predictor_service import PredictorService
from hr_ai.prediction.feature_engineering import FeatureEngineer
from hr_ai.prediction.retraining_loop import retrain_model_if_needed

from unittest.mock import patch, MagicMock
from sklearn.ensemble import RandomForestRegressor
from sklearn.exceptions import NotFittedError


@pytest.fixture(scope="module")
def sample_input() -> dict:
    return {
        "skills": ["Python", "ML", "Data Analysis"],
        "experience_years": 5,
        "education_level": "Master",
        "certifications": ["AWS", "GCP"]
    }


@pytest.fixture(scope="module")
def predictor() -> PredictorService:
    return PredictorService(model_path="models/performance_model.pkl")


@pytest.fixture(scope="module")
def engineered_features(sample_input) -> np.ndarray:
    fe = FeatureEngineer()
    return fe.transform(sample_input)


def test_feature_engineering_output_shape(engineered_features):
    assert isinstance(engineered_features, np.ndarray), "Features must be NumPy array"
    assert engineered_features.ndim == 2, "Feature vector must be 2D"
    assert engineered_features.shape[0] == 1, "Only one instance expected"


def test_predictor_prediction_range(predictor, engineered_features):
    try:
        prediction = predictor.predict(engineered_features)
        assert isinstance(prediction, float), "Prediction must be a float"
        assert 0.0 <= prediction <= 1.0, "Prediction score must be within [0.0, 1.0]"
    except NotFittedError:
        pytest.skip("Model is not fitted — skipping prediction test")


def test_predictor_with_invalid_input(predictor):
    with pytest.raises(ValueError):
        predictor.predict(np.array([]))


def test_predictor_model_loading():
    service = PredictorService(model_path="models/performance_model.pkl")
    assert isinstance(service.model, RandomForestRegressor), "Expected RandomForestRegressor instance"


@patch("hr_ai.prediction.retraining_loop.retrain_model_if_needed")
def test_model_retraining_triggered(mock_retrain):
    mock_retrain.return_value = True
    result = retrain_model_if_needed(metric_drop=0.2, threshold=0.1)
    assert result is True, "Retraining should be triggered if metric drop exceeds threshold"
    mock_retrain.assert_called_once()


def test_predictor_integration_full_cycle(sample_input):
    fe = FeatureEngineer()
    model = PredictorService(model_path="models/performance_model.pkl")
    try:
        features = fe.transform(sample_input)
        score = model.predict(features)
        assert 0.0 <= score <= 1.0
    except NotFittedError:
        pytest.skip("Model not trained — skipping full-cycle test")
