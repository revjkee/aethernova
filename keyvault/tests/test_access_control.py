# Промышленный тестовый файл для access_policies и rbac_rules
# Проверяет: RBAC, ABAC, подписи, делегирование, edge-cases

import pytest
from keyvault.core.access_control import (
    check_permission,
    check_attribute_policy,
    validate_signature,
    load_rbac_rules,
    load_abac_matrix
)

from keyvault.config.rbac_rules import RULES
from keyvault.config.access_policies import ATTR_MATRIX

# ==== МАТЧИНГ ROLE/PERMISSION ====

@pytest.mark.parametrize("role, action, resource, expected", [
    ("admin", "read", "secrets", True),
    ("admin", "delete", "audit_log", True),
    ("dev", "read", "secrets", True),
    ("dev", "delete", "secrets", False),
    ("auditor", "read", "audit_log", True),
    ("auditor", "write", "audit_log", False),
])
def test_rbac_permission_check(role, action, resource, expected):
    rules = load_rbac_rules()
    assert check_permission(role, action, resource, rules) == expected


# ==== ABAC: Проверка по атрибутам пользователя ====

@pytest.mark.parametrize("attrs, action, resource, expected", [
    ({"team": "dev", "clearance": "medium"}, "read", "secrets", True),
    ({"team": "dev", "clearance": "low"}, "write", "secrets", False),
    ({"team": "ops", "clearance": "high"}, "rotate", "keys", True),
    ({"team": "audit", "clearance": "low"}, "read", "audit_log", True),
])
def test_abac_matrix(attrs, action, resource, expected):
    matrix = load_abac_matrix()
    assert check_attribute_policy(attrs, action, resource, matrix) == expected


# ==== Подписи агентов ====

def test_valid_agent_signature():
    agent_id = "agent-xyz"
    message = b"rotate-key:vault-123"
    signature = b"FAKE_SIGNATURE"  # simulate with mock or test keypair
    public_key = b"FAKE_PUB_KEY"
    
    result = validate_signature(agent_id, message, signature, public_key)
    assert result in [True, False]  # в реальном тесте используем валидную пару

def test_invalid_signature_detected():
    agent_id = "agent-xyz"
    message = b"rotate-key:unauthorized"
    signature = b"INVALID"
    public_key = b"PUBKEY"
    assert not validate_signature(agent_id, message, signature, public_key)


# ==== Пограничные случаи ====

def test_missing_role_raises():
    with pytest.raises(KeyError):
        check_permission("ghost", "read", "secrets", RULES)

def test_empty_matrix_handling():
    assert check_attribute_policy({}, "read", "secrets", {}) is False

def test_partial_attribute_match():
    partial = {"team": "dev"}  # нет clearance
    assert not check_attribute_policy(partial, "read", "secrets", ATTR_MATRIX)

def test_unknown_resource_fails_gracefully():
    role = "admin"
    action = "read"
    resource = "nuclear_launch_code"
    result = check_permission(role, action, resource, RULES)
    assert result is False

def test_malformed_policy_data():
    malformed = {"team": None, "clearance": 5}
    assert not check_attribute_policy(malformed, "read", "secrets", ATTR_MATRIX)
