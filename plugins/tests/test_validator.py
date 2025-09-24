import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from plugins.core.plugin_validator import PluginValidator, ValidationError
from plugins.utils.plugin_signature import sign_data, verify_signature

TEST_PLUGIN_META = {
    "name": "my_secure_plugin",
    "version": "1.0.0",
    "entry": "my_secure_plugin.py",
    "schema_version": "1.0"
}

@pytest.fixture
def validator():
    return PluginValidator(schema_path="plugins/schemas/plugin_schema.json")

def test_validate_valid_plugin_schema(validator, tmp_path):
    meta_path = tmp_path / "valid_meta.json"
    meta_path.write_text(json.dumps(TEST_PLUGIN_META))
    validator.validate_schema(meta_path)

def test_invalid_schema_missing_field(validator, tmp_path):
    invalid_meta = {k: v for k, v in TEST_PLUGIN_META.items() if k != "name"}
    path = tmp_path / "bad_meta.json"
    path.write_text(json.dumps(invalid_meta))
    with pytest.raises(ValidationError, match="Missing required property"):
        validator.validate_schema(path)

def test_validate_signature_valid(tmp_path):
    data = b"trusted_plugin_payload"
    priv_key = "secret_key_123"
    signature = sign_data(data, priv_key)
    assert verify_signature(data, signature, priv_key)

def test_validate_signature_forged(tmp_path):
    data = b"payload"
    attacker_key = "fake_key"
    legit_key = "true_key"
    signature = sign_data(data, attacker_key)
    assert not verify_signature(data, signature, legit_key)

def test_validate_full_plugin_pass(tmp_path, validator):
    meta_path = tmp_path / "plugin_meta.json"
    payload = b"secure_logic_bytes"
    key = "sign_key"
    meta_path.write_text(json.dumps(TEST_PLUGIN_META))
    sig = sign_data(payload, key)
    validator.validate(meta_path, payload, sig, key)

def test_validate_full_plugin_fail_on_bad_sig(tmp_path, validator):
    meta_path = tmp_path / "plugin_meta.json"
    payload = b"malicious"
    legit_key = "K1"
    forged_key = "K2"
    meta_path.write_text(json.dumps(TEST_PLUGIN_META))
    sig = sign_data(payload, forged_key)
    with pytest.raises(ValidationError, match="Signature verification failed"):
        validator.validate(meta_path, payload, sig, legit_key)

def test_validate_schema_version_check(validator, tmp_path):
    incompatible = dict(TEST_PLUGIN_META, schema_version="9.9")
    path = tmp_path / "invalid_schema_version.json"
    path.write_text(json.dumps(incompatible))
    with pytest.raises(ValidationError, match="Unsupported schema_version"):
        validator.validate_schema(path)

def test_sandboxed_validation_mocks(validator):
    # simulate runtime sandbox behavior
    with patch("plugins.core.plugin_validator.run_in_sandbox", return_value=True):
        assert validator.sandbox_check("plugins/analyzer/analyzer_plugin.py")

def test_sandboxed_validation_failure(validator):
    with patch("plugins.core.plugin_validator.run_in_sandbox", return_value=False):
        assert not validator.sandbox_check("plugins/scanner/scanner_plugin.py")

def test_plugin_validator_repr():
    v = PluginValidator("plugins/schemas/plugin_schema.json")
    assert "PluginValidator" in repr(v)
