import pytest
from calibration.presets.profile_loader import load_profile
from calibration.rules.rule_loader import load_rules
from calibration.rules.rule_schema import RULE_SCHEMA
from calibration.rules.validator import validate_schema
from pathlib import Path
import yaml
import json

BASE_DIR = Path(__file__).parent.parent

@pytest.fixture
def valid_rule_path():
    return BASE_DIR / "rules" / "samples" / "valid_rules.yaml"

@pytest.fixture
def invalid_rule_path():
    return BASE_DIR / "rules" / "samples" / "invalid_rules.yaml"

@pytest.fixture
def rule_schema():
    return RULE_SCHEMA

@pytest.fixture
def valid_profile_path():
    return BASE_DIR / "presets" / "samples" / "valid_profile.yaml"

@pytest.fixture
def invalid_profile_path():
    return BASE_DIR / "presets" / "samples" / "invalid_profile.yaml"

def test_valid_rule_file_schema(valid_rule_path, rule_schema):
    rules = load_rules(valid_rule_path)
    for rule in rules:
        errors = validate_schema(rule, rule_schema)
        assert not errors, f"Unexpected validation error: {errors}"

def test_invalid_rule_file_schema(invalid_rule_path, rule_schema):
    rules = load_rules(invalid_rule_path)
    found_errors = False
    for rule in rules:
        errors = validate_schema(rule, rule_schema)
        if errors:
            found_errors = True
    assert found_errors, "Expected validation to fail but it passed"

def test_valid_profile_load(valid_profile_path):
    profile = load_profile(valid_profile_path)
    assert isinstance(profile, dict)
    assert "parameters" in profile
    assert isinstance(profile["parameters"], dict)

def test_invalid_profile_raises(invalid_profile_path):
    with pytest.raises(ValueError):
        load_profile(invalid_profile_path)

def test_rule_schema_self_consistency(rule_schema):
    # Проверка, что сама схема соответствует JSON Schema Draft-07
    from jsonschema.validators import Draft7Validator
    try:
        Draft7Validator.check_schema(rule_schema)
    except Exception as e:
        pytest.fail(f"Rule schema is not self-consistent: {e}")

def test_schema_missing_fields(rule_schema):
    broken_rule = {"if": "x > 0"}
    errors = validate_schema(broken_rule, rule_schema)
    assert errors, "Expected schema errors for missing fields"

def test_schema_with_extra_fields(rule_schema):
    noisy_rule = {"if": "x > 0", "then": "y = 1", "unknown_field": "ignored"}
    errors = validate_schema(noisy_rule, rule_schema)
    assert errors, "Unexpected pass for rule with undefined fields"

def test_rule_validation_fuzzed(rule_schema):
    invalid_inputs = [
        {"if": None, "then": None},
        {"if": "", "then": 123},
        {"if": "x >", "then": "y = 1"},
        {"then": "y = 1"},  # missing 'if'
    ]
    for rule in invalid_inputs:
        errors = validate_schema(rule, rule_schema)
        assert errors, f"Expected error for malformed rule: {rule}"
