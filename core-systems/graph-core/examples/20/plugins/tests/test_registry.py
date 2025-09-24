import pytest
from plugins.core.plugin_registry import PluginRegistry
from plugins.core.base_plugin import BasePlugin
from plugins.core.plugin_exceptions import PluginRegistryError, PluginAlreadyRegistered

class DummyPluginV1(BasePlugin):
    def run(self, **kwargs):
        return "v1"

class DummyPluginV2(BasePlugin):
    def run(self, **kwargs):
        return "v2"

@pytest.fixture
def fresh_registry():
    return PluginRegistry()

def test_register_plugin_success(fresh_registry):
    fresh_registry.register("plugin_a", DummyPluginV1)
    assert fresh_registry.get("plugin_a") == DummyPluginV1

def test_register_duplicate_plugin_raises(fresh_registry):
    fresh_registry.register("plugin_a", DummyPluginV1)
    with pytest.raises(PluginAlreadyRegistered):
        fresh_registry.register("plugin_a", DummyPluginV1)

def test_get_unregistered_plugin_raises(fresh_registry):
    with pytest.raises(PluginRegistryError):
        fresh_registry.get("unknown")

def test_unregister_plugin(fresh_registry):
    fresh_registry.register("plugin_a", DummyPluginV1)
    fresh_registry.unregister("plugin_a")
    with pytest.raises(PluginRegistryError):
        fresh_registry.get("plugin_a")

def test_unregister_nonexistent_plugin_raises(fresh_registry):
    with pytest.raises(PluginRegistryError):
        fresh_registry.unregister("missing_plugin")

def test_list_plugins(fresh_registry):
    fresh_registry.register("plugin_x", DummyPluginV1)
    fresh_registry.register("plugin_y", DummyPluginV2)
    registered = fresh_registry.list_plugins()
    assert "plugin_x" in registered
    assert "plugin_y" in registered

def test_cache_integrity_after_registration(fresh_registry):
    fresh_registry.register("plugin_cached", DummyPluginV1)
    assert fresh_registry._cache["plugin_cached"] == DummyPluginV1

def test_cache_cleared_on_unregister(fresh_registry):
    fresh_registry.register("to_be_deleted", DummyPluginV1)
    fresh_registry.unregister("to_be_deleted")
    assert "to_be_deleted" not in fresh_registry._cache

def test_registry_supports_versioning(fresh_registry):
    fresh_registry.register("plugin_v1", DummyPluginV1, version="1.0.0")
    fresh_registry.register("plugin_v1", DummyPluginV2, version="2.0.0")
    assert fresh_registry.get("plugin_v1", version="2.0.0").run() == "v2"
    assert fresh_registry.get("plugin_v1", version="1.0.0").run() == "v1"

def test_registry_missing_version_error(fresh_registry):
    fresh_registry.register("plugin_x", DummyPluginV1, version="1.0.0")
    with pytest.raises(PluginRegistryError):
        fresh_registry.get("plugin_x", version="9.9.9")

def test_registry_multiple_versions_listed(fresh_registry):
    fresh_registry.register("versioned", DummyPluginV1, version="1.0.0")
    fresh_registry.register("versioned", DummyPluginV2, version="2.0.0")
    versions = fresh_registry.list_versions("versioned")
    assert "1.0.0" in versions
    assert "2.0.0" in versions

def test_registry_rejects_invalid_plugin_class(fresh_registry):
    class NotAPlugin:
        pass
    with pytest.raises(TypeError):
        fresh_registry.register("fake", NotAPlugin)

def test_registry_is_singleton_like_if_configured_global():
    reg1 = PluginRegistry()
    reg2 = PluginRegistry()
    reg1.register("same_instance_test", DummyPluginV1)
    assert reg2.get("same_instance_test") == DummyPluginV1

def test_plugin_registry_repr(fresh_registry):
    fresh_registry.register("repr_plugin", DummyPluginV1)
    assert "PluginRegistry" in repr(fresh_registry)
    assert "repr_plugin" in repr(fresh_registry)
