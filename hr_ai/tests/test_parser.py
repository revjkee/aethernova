# hr_ai/tests/test_parser.py

import pytest
import logging
from hr_ai.intake.cv_parser import CVParser
from hr_ai.intake.semantic_matcher import SemanticMatcher
from hr_ai.intake.skill_matcher import SkillMatcher
from hr_ai.intake.intake_pipeline import load_pipeline_config

from pathlib import Path
from typing import List, Dict
from unittest.mock import patch

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def raw_resume_text() -> str:
    return Path("hr_ai/tests/fixtures/sample_resume.txt").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def parser_instance() -> CVParser:
    config = load_pipeline_config("hr_ai/intake/intake_pipeline.yaml")
    return CVParser(config=config)


@pytest.fixture(scope="module")
def matcher_instances() -> Dict[str, object]:
    return {
        "semantic": SemanticMatcher(model_path="models/semantic_model.onnx"),
        "skill": SkillMatcher(thesaurus_path="data/skills.json")
    }


def test_cv_parser_extraction(parser_instance, raw_resume_text):
    result = parser_instance.parse(raw_resume_text)
    assert isinstance(result, dict), "Результат должен быть словарем"
    assert "name" in result, "Имя кандидата должно быть извлечено"
    assert "skills" in result and isinstance(result["skills"], list), "Навыки должны быть списком"
    assert all(isinstance(skill, str) for skill in result["skills"]), "Все навыки должны быть строками"


def test_cv_parser_handles_empty_input(parser_instance):
    with pytest.raises(ValueError, match="Empty resume content"):
        parser_instance.parse("")


def test_skill_matcher_ranking(matcher_instances):
    input_skills = ["Python", "Machine Learning", "SQL"]
    job_description = "We need a developer with strong Python and SQL knowledge"
    scores = matcher_instances["skill"].rank(input_skills, job_description)
    assert isinstance(scores, list), "Результат должен быть списком"
    assert all(isinstance(score, float) for score in scores), "Оценки должны быть числами"


def test_semantic_matcher_similarity(matcher_instances):
    resume_text = "Experienced Python developer with deep learning background"
    job_posting = "Looking for a Python engineer with ML expertise"
    score = matcher_instances["semantic"].compute_similarity(resume_text, job_posting)
    assert isinstance(score, float), "Ожидалась числовая оценка"
    assert 0.0 <= score <= 1.0, "Оценка должна быть в диапазоне [0.0, 1.0]"


@patch("hr_ai.intake.cv_parser.CVParser.parse")
def test_parser_pipeline_mocked(mock_parse, parser_instance):
    mock_parse.return_value = {"name": "Test User", "skills": ["Python", "Kubernetes"]}
    parsed = parser_instance.parse("Some dummy text")
    assert parsed["name"] == "Test User"
    assert "Kubernetes" in parsed["skills"]
    mock_parse.assert_called_once()
