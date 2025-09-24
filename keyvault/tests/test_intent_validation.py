import pytest
from keyvault.core.intent_validator import validate_intent, IntentValidationError
from keyvault.config.rbac_rules import ALLOWED_ACTIONS
from unittest.mock import patch

VALID_INTENT = {
    "actor": "user:admin",
    "intent": "rotate_key",
    "target": "vault:key:master",
    "reason": "compliance_check"
}

INVALID_INTENT = {
    "actor": "user:guest",
    "intent": "delete_vault",
    "target": "vault:db:core",
    "reason": "no_reason"
}


def test_validate_valid_intent():
    assert validate_intent(VALID_INTENT) is True


def test_validate_invalid_intent_raises():
    with pytest.raises(IntentValidationError) as exc_info:
        validate_intent(INVALID_INTENT)
    assert "not permitted" in str(exc_info.value)


def test_missing_fields():
    incomplete = {"actor": "user:admin", "intent": "rotate_key"}
    with pytest.raises(IntentValidationError) as exc_info:
        validate_intent(incomplete)
    assert "missing fields" in str(exc_info.value)


def test_unknown_actor_format():
    malformed = VALID_INTENT.copy()
    malformed["actor"] = "admin"  # no prefix
    with pytest.raises(IntentValidationError) as exc_info:
        validate_intent(malformed)
    assert "actor format" in str(exc_info.value)


def test_intent_not_in_policy():
    unlisted = VALID_INTENT.copy()
    unlisted["intent"] = "nuclear_launch"
    with pytest.raises(IntentValidationError) as exc_info:
        validate_intent(unlisted)
    assert "denied by policy" in str(exc_info.value)


def test_target_scope_violation():
    out_of_scope = VALID_INTENT.copy()
    out_of_scope["target"] = "external:system"
    with pytest.raises(IntentValidationError) as exc_info:
        validate_intent(out_of_scope)
    assert "invalid target" in str(exc_info.value)


def test_rbac_rule_lookup_mock():
    with patch("keyvault.core.intent_validator._lookup_rbac_rule") as mock_lookup:
        mock_lookup.return_value = True
        result = validate_intent(VALID_INTENT)
        assert result is True
        mock_lookup.assert_called_once()


def test_rbac_rule_denied():
    with patch("keyvault.core.intent_validator._lookup_rbac_rule") as mock_lookup:
        mock_lookup.return_value = False
        with pytest.raises(IntentValidationError):
            validate_intent(VALID_INTENT)


@pytest.mark.parametrize("intent", ALLOWED_ACTIONS)
def test_allowed_action_list(intent):
    # Проверка всех разрешённых намерений из rbac_rules.yaml
    test_case = VALID_INTENT.copy()
    test_case["intent"] = intent
    assert validate_intent(test_case) is True


def test_reason_policy_required():
    test_case = VALID_INTENT.copy()
    test_case["reason"] = ""
    with pytest.raises(IntentValidationError) as exc_info:
        validate_intent(test_case)
    assert "reason required" in str(exc_info.value)
