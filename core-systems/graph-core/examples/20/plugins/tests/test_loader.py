import pytest
from unittest.mock import patch, MagicMock
from plugins.core.plugin_loader import PluginLoader
from plugins.core.plugin_registry import PluginRegistry
from plugins.core.plugin_validator import validate_plugin_signature
from plugins.core.plugin_exceptions import PluginLoadError, InvalidPluginSignature
import importlib.util
import os
import tempfile
import shutil
import textwrap

@pytest.fixture
def temp_plugin_file():
    temp_dir = tempfile.mkdtemp()
    plugin_code = textwrap.dedent("""
        from plugins.core.base_plugin import BasePlugin

        class CustomPlugin(BasePlugin):
            def run(self, **kwargs):
                return "executed"
    """)
    plugin_path = os.path.join(temp_dir, "sample_plugin.py")
    with open(plugin_path, "w") as f:
        f.write(plugin_code)
    yield plugin_path
    shutil.rmtree(temp_dir)

def test_load_valid_plugin(temp_plugin_file):
    loader = PluginLoader()
    plugin = loader.load_plugin(temp_plugin_file, sandbox=True)
    assert hasattr(plugin, 'run')
    assert plugin.run() == "executed"

def test_load_plugin_signature_validated(temp_plugin_file):
    loader = PluginLoader()
    with patch("plugins.core.plugin_validator.validate_plugin_signature") as validator:
        validator.return_value = True
        loader.load_plugin(temp_plugin_file, sandbox=True)
        validator.assert_called()

def test_invalid_signature_raises(temp_plugin_file):
    loader = PluginLoader()
    with patch("plugins.core.plugin_validator.validate_plugin_signature", side_effect=InvalidPluginSignature):
        with pytest.raises(InvalidPluginSignature):
            loader.load_plugin(temp_plugin_file)

def test_plugin_registry_registers_successful_load(temp_plugin_file):
    registry = PluginRegistry()
    loader = PluginLoader(registry=registry)
    plugin = loader.load_plugin(temp_plugin_file)
    assert registry.is_registered(plugin.__class__.__name__)

def test_loader_handles_missing_class_gracefully():
    with tempfile.TemporaryDirectory() as temp_dir:
        plugin_path = os.path.join(temp_dir, "bad_plugin.py")
        with open(plugin_path, "w") as f:
            f.write("print('no plugin class')")
        loader = PluginLoader()
        with pytest.raises(PluginLoadError):
            loader.load_plugin(plugin_path)

def test_loader_prevents_non_base_plugin_injection():
    with tempfile.TemporaryDirectory() as temp_dir:
        plugin_path = os.path.join(temp_dir, "fake_plugin.py")
        with open(plugin_path, "w") as f:
            f.write("class Fake: pass")
        loader = PluginLoader()
        with pytest.raises(PluginLoadError):
            loader.load_plugin(plugin_path)

def test_loader_handles_corrupted_plugin():
    with tempfile.TemporaryDirectory() as temp_dir:
        plugin_path = os.path.join(temp_dir, "corrupted_plugin.py")
        with open(plugin_path, "w") as f:
            f.write("def syntax_error(")
        loader = PluginLoader()
        with pytest.raises(SyntaxError):
            loader.load_plugin(plugin_path)

def test_loader_runs_in_sandboxed_env(temp_plugin_file):
    loader = PluginLoader(sandbox=True)
    plugin = loader.load_plugin(temp_plugin_file)
    assert plugin.run() == "executed"

def test_loader_rejects_duplicate_plugin_ids(temp_plugin_file):
    registry = PluginRegistry()
    loader = PluginLoader(registry=registry)
    plugin1 = loader.load_plugin(temp_plugin_file)
    with pytest.raises(PluginLoadError):
        loader.load_plugin(temp_plugin_file)  # same path and class name
