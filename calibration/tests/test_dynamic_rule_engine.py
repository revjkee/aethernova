import pytest
from calibration.rules.dynamic_rule_engine import DynamicRuleEngine, RuleExecutionError

@pytest.fixture
def sample_context():
    return {
        "temperature": 22.5,
        "humidity": 55,
        "battery_level": 80,
        "calibration_required": False,
        "location": "indoors",
        "pressure": 1013
    }

def test_simple_condition_true(sample_context):
    rule = {"if": "temperature > 20", "then": "calibration_required = True"}
    engine = DynamicRuleEngine(context=sample_context.copy())
    updated = engine.apply_rule(rule)
    assert updated["calibration_required"] is True

def test_simple_condition_false(sample_context):
    rule = {"if": "temperature < 10", "then": "calibration_required = True"}
    engine = DynamicRuleEngine(context=sample_context.copy())
    updated = engine.apply_rule(rule)
    assert updated["calibration_required"] is False

def test_logical_and_condition(sample_context):
    rule = {
        "if": "temperature > 20 and humidity < 60",
        "then": "calibration_required = True"
    }
    engine = DynamicRuleEngine(context=sample_context.copy())
    updated = engine.apply_rule(rule)
    assert updated["calibration_required"] is True

def test_logical_or_condition(sample_context):
    rule = {
        "if": "battery_level < 30 or pressure < 1000",
        "then": "calibration_required = True"
    }
    engine = DynamicRuleEngine(context=sample_context.copy())
    updated = engine.apply_rule(rule)
    assert updated["calibration_required"] is False

def test_nested_if_else(sample_context):
    rules = [
        {
            "if": "temperature > 30",
            "then": "calibration_required = True",
            "else": "calibration_required = False"
        }
    ]
    engine = DynamicRuleEngine(context=sample_context.copy())
    updated = engine.apply_rule(rules[0])
    assert updated["calibration_required"] is False

def test_assignment_of_variable(sample_context):
    rule = {"then": "battery_level = battery_level - 10"}
    engine = DynamicRuleEngine(context=sample_context.copy())
    updated = engine.apply_rule(rule)
    assert updated["battery_level"] == 70

def test_missing_variable_raises(sample_context):
    rule = {"if": "non_existent > 0", "then": "calibration_required = True"}
    engine = DynamicRuleEngine(context=sample_context.copy())
    with pytest.raises(RuleExecutionError):
        engine.apply_rule(rule)

def test_invalid_expression_raises(sample_context):
    rule = {"if": "temperature >>", "then": "calibration_required = True"}
    engine = DynamicRuleEngine(context=sample_context.copy())
    with pytest.raises(RuleExecutionError):
        engine.apply_rule(rule)

def test_multiple_rules_execution(sample_context):
    rules = [
        {"if": "humidity > 50", "then": "calibration_required = True"},
        {"if": "calibration_required == True", "then": "battery_level = battery_level - 5"}
    ]
    engine = DynamicRuleEngine(context=sample_context.copy())
    for rule in rules:
        engine.apply_rule(rule)
    updated = engine.context
    assert updated["calibration_required"] is True
    assert updated["battery_level"] == 75

def test_rule_engine_preserves_external_context():
    original_context = {"x": 10, "y": 5}
    rule = {"if": "x > y", "then": "z = x * y"}
    engine = DynamicRuleEngine(context=original_context.copy())
    updated = engine.apply_rule(rule)
    assert updated["z"] == 50
    assert updated["x"] == 10 and updated["y"] == 5

