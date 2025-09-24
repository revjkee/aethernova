# hr_ai/tests/test_bot_comms.py

import pytest
from unittest.mock import patch, MagicMock
from hr_ai.comms.dialog_agent import DialogAgent
from hr_ai.comms.language_localizer import LanguageLocalizer
from hr_ai.comms.softskills_estimator import SoftSkillsEstimator
from hr_ai.comms.ethics_filter import EthicsFilter


@pytest.fixture(scope="module")
def dialog_agent() -> DialogAgent:
    return DialogAgent(model_path="models/dialogue_model.onnx")


@pytest.fixture(scope="module")
def localizer() -> LanguageLocalizer:
    return LanguageLocalizer(supported_languages=["en", "ru", "es"])


@pytest.fixture(scope="module")
def softskills() -> SoftSkillsEstimator:
    return SoftSkillsEstimator(model_path="models/softskills.onnx")


@pytest.fixture(scope="module")
def ethics_filter() -> EthicsFilter:
    return EthicsFilter(policy_file="hr_ai/comms/ethics_policy.yaml")


def test_dialog_agent_response_structure(dialog_agent):
    user_input = "Tell me about your strengths"
    response = dialog_agent.generate_response(user_input, context=[])
    assert isinstance(response, dict), "Ответ должен быть в формате словаря"
    assert "text" in response and isinstance(response["text"], str), "Поле 'text' обязательно"
    assert "confidence" in response and isinstance(response["confidence"], float), "Ожидался числовой confidence"


def test_language_localizer_translation(localizer):
    text = "Hello, how are you?"
    localized = localizer.translate(text, target_lang="ru")
    assert isinstance(localized, str)
    assert localized != text, "Текст должен быть переведён"


def test_unsupported_language_raises(localizer):
    with pytest.raises(ValueError, match="Unsupported language"):
        localizer.translate("Test", target_lang="xx")


def test_softskills_estimation_range(softskills):
    transcript = "I enjoy working with others and solving problems under pressure."
    result = softskills.evaluate(transcript)
    assert isinstance(result, dict)
    assert all(0.0 <= score <= 1.0 for score in result.values()), "Оценки должны быть в пределах [0.0, 1.0]"


def test_ethics_filter_flagging(ethics_filter):
    flagged = ethics_filter.scan("I want to exploit company data.")
    assert isinstance(flagged, bool)
    assert flagged is True, "Должно быть выявлено нарушение политики"


def test_dialog_agent_ethics_integration(dialog_agent, ethics_filter):
    response = dialog_agent.generate_response("I want to lie on my resume.", context=[])
    flagged = ethics_filter.scan(response["text"])
    assert isinstance(flagged, bool), "Фильтр должен вернуть булево значение"


@patch("hr_ai.comms.dialog_agent.DialogAgent.generate_response")
def test_mocked_response(mock_response):
    mock_response.return_value = {"text": "Mocked response", "confidence": 0.99}
    agent = DialogAgent(model_path="models/dialogue_model.onnx")
    result = agent.generate_response("Hello", context=[])
    assert result["text"] == "Mocked response"
    assert result["confidence"] == 0.99
    mock_response.assert_called_once()
