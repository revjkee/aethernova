import pytest
from unittest.mock import MagicMock
from plugins.scanner.scanner_plugin import ScannerPlugin
from plugins.core.plugin_validator import validate_plugin_signature
from plugins.schemas.plugin_schema import validate_metadata_schema
from plugins.utils.plugin_signature import sign_plugin, verify_signature

from datetime import datetime
import json
import logging

logger = logging.getLogger("plugin_test")

@pytest.fixture
def mock_plugin():
    class TestScanner(ScannerPlugin):
        def scan(self, data):
            return {"status": "ok", "timestamp": datetime.utcnow().isoformat(), "detected": False}
    return TestScanner()

def test_basic_scan(mock_plugin):
    data = {"input": "some payload"}
    result = mock_plugin.scan(data)
    assert isinstance(result, dict), "Scan result should be a dictionary"
    assert "status" in result
    assert "timestamp" in result
    assert isinstance(result["detected"], bool)

def test_plugin_metadata_schema_compliance():
    metadata = {
        "id": "scanner-alpha",
        "name": "Alpha Scanner",
        "version": "1.0.0",
        "description": "Detects anomalies in data",
        "entrypoint": "plugins.scanner.scanner_plugin.ScannerPlugin",
        "type": "scanner",
        "author": {
            "name": "TeslaAI Team",
            "contact": "security@tesla.ai"
        },
        "security": {
            "signed": True,
            "sandbox": True
        }
    }
    validate_metadata_schema(metadata)  # raises exception if invalid

def test_signature_verification():
    payload = {
        "plugin_id": "scanner-alpha",
        "timestamp": datetime.utcnow().isoformat(),
        "payload_hash": "abc123def456"
    }
    private_key = "test_private_key"
    signed = sign_plugin(payload, private_key)
    assert "signature" in signed
    verified = verify_signature(signed, private_key)
    assert verified is True

def test_plugin_validation_logic():
    plugin = MagicMock()
    plugin.name = "Scanner"
    plugin.version = "1.0.0"
    plugin.entrypoint = "plugins.scanner.scanner_plugin.ScannerPlugin"
    plugin.security = {"signed": True, "sandbox": True}
    assert validate_plugin_signature(plugin) is True

def test_scan_output_structure(mock_plugin):
    result = mock_plugin.scan({"input": "test"})
    expected_keys = {"status", "timestamp", "detected"}
    assert expected_keys.issubset(result.keys()), "Scan output structure mismatch"

def test_no_false_positive(mock_plugin):
    result = mock_plugin.scan({"input": "safe content"})
    assert result["detected"] is False, "Expected no detection in safe content"

def test_sandbox_mode_respected(mock_plugin):
    assert hasattr(mock_plugin, "run_in_sandbox")
    assert mock_plugin.run_in_sandbox is True, "Plugin must be sandbox-safe"

