# hr_ai/tests/test_governance.py

import pytest
from unittest.mock import patch, MagicMock
from hr_ai.governance.ideal_candidate_generator import IdealCandidateGenerator
from hr_ai.governance.team_fit_analyzer import TeamFitAnalyzer
from hr_ai.governance.decision_explainer import DecisionExplainer
from hr_ai.governance.policy_rules import load_policy_rules

from pathlib import Path


@pytest.fixture(scope="module")
def policy_config() -> dict:
    return load_policy_rules("hr_ai/governance/policy_rules.yaml")


@pytest.fixture(scope="module")
def generator(policy_config) -> IdealCandidateGenerator:
    return IdealCandidateGenerator(policies=policy_config)


@pytest.fixture(scope="module")
def analyzer() -> TeamFitAnalyzer:
    return TeamFitAnalyzer(reference_team_data="hr_ai/tests/fixtures/sample_team.json")


@pytest.fixture(scope="module")
def explainer() -> DecisionExplainer:
    return DecisionExplainer(explanation_model="models/explainer_model.onnx")


def test_generate_ideal_candidate_structure(generator):
    result = generator.generate("software_engineer", seniority="senior")
    assert isinstance(result, dict), "Output must be a dictionary"
    assert "skills" in result, "Expected 'skills' key in output"
    assert "traits" in result, "Expected 'traits' key in output"
    assert isinstance(result["skills"], list)
    assert isinstance(result["traits"], list)


def test_team_fit_score_type(analyzer):
    profile = {
        "skills": ["Python", "Docker", "AI Ethics"],
        "traits": ["collaborative", "detail-oriented"]
    }
    score = analyzer.compute_fit_score(profile)
    assert isinstance(score, float), "Fit score must be float"
    assert 0.0 <= score <= 1.0, "Score must be between 0.0 and 1.0"


def test_policy_rules_integrity(policy_config):
    assert isinstance(policy_config, dict), "Policy rules must be a dictionary"
    required_sections = {"mandatory_traits", "excluded_behaviors", "skill_weights"}
    assert required_sections.issubset(policy_config.keys()), "Missing required policy sections"


def test_decision_explainer_output(explainer):
    input_features = {
        "education": "Master",
        "experience": 7,
        "certs": ["GCP", "Kubernetes"],
        "fit_score": 0.85
    }
    explanation = explainer.explain(input_features)
    assert isinstance(explanation, dict)
    assert "highlighted_features" in explanation
    assert "rationale" in explanation


@patch("hr_ai.governance.ideal_candidate_generator.IdealCandidateGenerator.generate")
def test_mocked_candidate_generation(mock_generate):
    mock_generate.return_value = {"skills": ["AI", "Python"], "traits": ["logical"]}
    gen = IdealCandidateGenerator(policies={})
    result = gen.generate("analyst")
    assert "skills" in result and "traits" in result
    mock_generate.assert_called_once()
