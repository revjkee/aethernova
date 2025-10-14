"""Integration Module - Connect with external systems"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any
from enum import Enum
import json
import uuid

class IntegrationType(Enum):
    IDENTITY_SERVICE = "identity"
    AUDIT_SERVICE = "audit"
    STORAGE_SERVICE = "storage"

@dataclass
class IntegrationConfig:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    integration_type: IntegrationType = IntegrationType.IDENTITY_SERVICE
    endpoint_url: str = ""
    api_key: str = ""

class IntegrationService:
    def __init__(self):
        self.configs: Dict[IntegrationType, IntegrationConfig] = {}
    
    def register_integration(self, integration_type: IntegrationType, endpoint_url: str, api_key: str) -> IntegrationConfig:
        config = IntegrationConfig(integration_type=integration_type, endpoint_url=endpoint_url, api_key=api_key)
        self.configs[integration_type] = config
        return config
