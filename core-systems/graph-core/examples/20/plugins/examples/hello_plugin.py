from plugins.core.base_plugin import BasePlugin
from plugins.core.plugin_context import PluginContext
from plugins.core.plugin_validator import validate_plugin_schema
from plugins.utils.plugin_signature import verify_signature
import logging
import datetime
import json

logger = logging.getLogger("hello_plugin")

class HelloPlugin(BasePlugin):
    """
    Example plugin demonstrating lifecycle hooks, secure initialization,
    signature verification, and isolated context access.
    """

    def __init__(self, context: PluginContext):
        self.context = context
        self.metadata = {
            "name": "hello_plugin",
            "version": "1.0.0",
            "author": "TeslaAI Genesis",
            "description": "Demonstration plugin for plugin engine",
            "entrypoint": "HelloPlugin",
            "secure": True,
            "tags": ["demo", "secure", "example"]
        }

    def validate(self):
        logger.info("[hello_plugin] Validating plugin schema...")
        validate_plugin_schema(self.metadata)

    def get_metadata(self) -> dict:
        return self.metadata

    def secure_initialize(self):
        """
        Optional hook to validate integrity and signature before start.
        """
        plugin_payload = json.dumps(self.metadata).encode("utf-8")
        signature = self.context.get_plugin_signature("hello_plugin")
        if not verify_signature(plugin_payload, signature, self.context.get_signing_key()):
            raise RuntimeError("Invalid plugin signature detected!")
        logger.info("[hello_plugin] Signature verified successfully.")

    def execute(self, **kwargs) -> dict:
        user = kwargs.get("user", "anonymous")
        now = datetime.datetime.utcnow().isoformat()

        logger.info(f"[hello_plugin] Hello executed for user: {user}")
        return {
            "status": "success",
            "timestamp": now,
            "message": f"Hello, {user}! This is TeslaAI plugin system at {now} UTC."
        }

    def shutdown(self):
        logger.info("[hello_plugin] Plugin shutdown cleanly.")
