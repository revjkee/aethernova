import json
import importlib
import traceback
from typing import Any, Dict, Optional
from jsonschema import validate as jsonschema_validate, ValidationError
from plugins.utils.plugin_signature import verify_signature
from plugins.utils.plugin_logger import plugin_logger as logger
from plugins.utils.validator import is_valid_plugin_class
from plugins.schemas.plugin_schema import SCHEMA_DEFINITION

TRUSTED_ISSUERS = {"TeslaAI Genesis Core", "Internal Plugin Authority"}

class PluginValidationError(Exception):
    pass


class PluginValidator:
    """
    Валидатор плагинов: проверяет подпись, соответствие JSON-схеме, безопасность, типы и доверенного автора.
    """

    def __init__(self, schema: Optional[Dict[str, Any]] = None):
        self.schema = schema or SCHEMA_DEFINITION

    def validate_metadata(self, metadata: Dict[str, Any]) -> None:
        try:
            jsonschema_validate(instance=metadata, schema=self.schema)
            logger.debug(f"[PluginValidator] JSON schema passed for {metadata.get('plugin_id')}")
        except ValidationError as e:
            raise PluginValidationError(f"Schema validation failed: {e.message}")

        if metadata.get("issuer") not in TRUSTED_ISSUERS:
            raise PluginValidationError(f"Untrusted plugin issuer: {metadata.get('issuer')}")

    def validate_signature(self, plugin_path: str, signature_path: str) -> None:
        if not verify_signature(plugin_path, signature_path):
            raise PluginValidationError(f"Plugin signature invalid or tampered: {plugin_path}")
        logger.debug(f"[PluginValidator] Signature OK for {plugin_path}")

    def validate_runtime(self, plugin_module: str, plugin_class: str) -> None:
        try:
            module = importlib.import_module(plugin_module)
            cls = getattr(module, plugin_class, None)
            if not is_valid_plugin_class(cls):
                raise PluginValidationError(f"Plugin class {plugin_class} does not conform to base interface")
            logger.debug(f"[PluginValidator] Runtime check OK for {plugin_module}.{plugin_class}")
        except Exception as e:
            logger.error(traceback.format_exc())
            raise PluginValidationError(f"Runtime validation failed: {str(e)}")

    def full_validation(self, metadata: Dict[str, Any], plugin_path: str, signature_path: str) -> None:
        self.validate_metadata(metadata)
        self.validate_signature(plugin_path, signature_path)
        self.validate_runtime(metadata["module"], metadata["class"])
        logger.info(f"[PluginValidator] Full validation passed for plugin {metadata['plugin_id']}")
