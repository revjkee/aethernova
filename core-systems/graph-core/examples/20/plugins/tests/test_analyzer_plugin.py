import pytest
from unittest.mock import MagicMock
from plugins.analyzer.analyzer_plugin import AnalyzerPlugin
from plugins.schemas.plugin_schema import validate_metadata_schema
from plugins.utils.plugin_signature import sign_plugin, verify_signature
from plugins.core.plugin_validator import validate_plugin_signature
import datetime
import logging

logger = logging.getLogger("plugin_test")

@pytest.fixture
def mock_plugin():
    class TestAnalyzer(AnalyzerPlugin):
        def analyze(self, payload):
            if "error" in payload.get("content", "").lower():
                return {"verdict": "suspicious", "confidence": 0.92}
            return {"verdict": "clean", "confidence": 0.99}
    return TestAnalyzer()

def test_analyze_clean_input(mock_plugin):
    result = mock_plugin.analyze({"content": "normal data stream"})
    assert result["verdict"] == "clean"
    assert result["confidence"] >= 0.90

def test_analyze_suspicious_input(mock_plugin):
    result = mock_plugin.analyze({"content": "contains ERROR signature"})
    assert result["verdict"] == "suspicious"
    assert result["confidence"] > 0.9

def test_analyze_structure_compliance(mock_plugin):
    result = mock_plugin.analyze({"content": "anything"})
    assert isinstance(result, dict)
    assert "verdict" in result
    assert "confidence" in result

def test_plugin_metadata_valid():
    metadata = {
        "id": "analyzer-x1",
        "name": "Generic Analyzer",
        "version": "2.3.1",
        "description": "Analyzes logs and content",
        "entrypoint": "plugins.analyzer.analyzer_plugin.AnalyzerPlugin",
        "type": "analyzer",
        "author": {
            "name": "TeslaAI Genesis Core",
            "contact": "dev@tesla.ai"
        },
        "security": {
            "signed": True,
            "sandbox": True
        }
    }
    validate_metadata_schema(metadata)  # Will raise if invalid

def test_signature_validation():
    payload = {
        "plugin_id": "analyzer-x1",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "payload_hash": "abcdef123456"
    }
    private_key = "mock_private_key"
    signed = sign_plugin(payload, private_key)
    assert verify_signature(signed, private_key) is True

def test_plugin_validation():
    plugin = MagicMock()
    plugin.name = "Generic Analyzer"
    plugin.version = "2.3.1"
    plugin.entrypoint = "plugins.analyzer.analyzer_plugin.AnalyzerPlugin"
    plugin.security = {"signed": True, "sandbox": True}
    assert validate_plugin_signature(plugin) is True

def test_confidence_bounds(mock_plugin):
    result = mock_plugin.analyze({"content": "normal"})
    assert 0.0 <= result["confidence"] <= 1.0, "Confidence must be in range 0-1"

def test_invalid_input_handling(mock_plugin):
    with pytest.raises(Exception):
        mock_plugin.analyze(None)  # Simulate bad payload
