"""
AI Ethics Engine Configuration
Конфигурация для системы этических решений AI
"""

import yaml
from pathlib import Path
from typing import Dict, Any, List
from dataclasses import dataclass, field


@dataclass
class EthicsConfig:
    """Configuration for AI Ethics Engine"""
    
    system_name: str = "ai-ethics-engine"
    version: str = "1.0.0"
    category: str = "AI Ethics & Governance"
    priority: int = 7
    description: str = "Ethical AI frameworks, bias detection, fairness algorithms"
    
    core_systems_path: str = "/workspaces/aethernova/core-systems"
    
    # Ethics frameworks
    frameworks: List[str] = field(default_factory=lambda: [
        "Utilitarian",
        "Deontological",
        "Virtue Ethics",
        "Care Ethics"
    ])
    
    # Bias detection
    bias_detection_enabled: bool = True
    bias_threshold: float = 0.7
    protected_attributes: List[str] = field(default_factory=lambda: [
        "race", "gender", "age", "religion", 
        "nationality", "disability", "sexual_orientation"
    ])
    
    # Fairness metrics
    fairness_metrics: List[str] = field(default_factory=lambda: [
        "demographic_parity",
        "equal_opportunity",
        "equalized_odds",
        "disparate_impact"
    ])
    
    # Decision validation
    decision_validation_enabled: bool = True
    require_justification: bool = True
    risk_threshold: float = 0.75
    
    # Transparency
    explainability_required: bool = True
    audit_trail: bool = True
    human_oversight: bool = True
    
    # Monitoring
    emergency_mode: bool = True
    log_level: str = "INFO"
    metrics_enabled: bool = True
    audit_all_decisions: bool = True
    
    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "system_name": self.system_name,
            "version": self.version,
            "category": self.category,
            "priority": self.priority,
            "description": self.description,
            "core_systems_path": self.core_systems_path,
            "frameworks": self.frameworks,
            "bias_detection_enabled": self.bias_detection_enabled,
            "bias_threshold": self.bias_threshold,
            "protected_attributes": self.protected_attributes,
            "fairness_metrics": self.fairness_metrics,
            "decision_validation_enabled": self.decision_validation_enabled,
            "require_justification": self.require_justification,
            "risk_threshold": self.risk_threshold,
            "explainability_required": self.explainability_required,
            "audit_trail": self.audit_trail,
            "human_oversight": self.human_oversight,
            "emergency_mode": self.emergency_mode,
            "log_level": self.log_level,
            "metrics_enabled": self.metrics_enabled,
            "audit_all_decisions": self.audit_all_decisions
        }


def load_config(config_path: str = None) -> EthicsConfig:
    """Load configuration from YAML file"""
    if config_path is None:
        config_path = Path(__file__).parent / "config.yaml"
    
    try:
        with open(config_path, 'r') as f:
            yaml_config = yaml.safe_load(f)
        
        return EthicsConfig(
            system_name=yaml_config.get("system_name", "ai-ethics-engine"),
            version=yaml_config.get("version", "1.0.0"),
            category=yaml_config.get("category", "AI Ethics & Governance"),
            priority=yaml_config.get("priority", 7),
            description=yaml_config.get("description", ""),
            core_systems_path=yaml_config.get("core_systems_path", ""),
            frameworks=yaml_config.get("ethics", {}).get("frameworks", []),
            bias_detection_enabled=yaml_config.get("ethics", {}).get("bias_detection", {}).get("enabled", True),
            bias_threshold=yaml_config.get("ethics", {}).get("bias_detection", {}).get("threshold", 0.7),
            protected_attributes=yaml_config.get("ethics", {}).get("bias_detection", {}).get("protected_attributes", []),
            fairness_metrics=yaml_config.get("ethics", {}).get("fairness_metrics", []),
            decision_validation_enabled=yaml_config.get("ethics", {}).get("decision_validation", {}).get("enabled", True),
            require_justification=yaml_config.get("ethics", {}).get("decision_validation", {}).get("require_justification", True),
            risk_threshold=yaml_config.get("ethics", {}).get("decision_validation", {}).get("risk_threshold", 0.75),
            explainability_required=yaml_config.get("ethics", {}).get("transparency", {}).get("explainability_required", True),
            audit_trail=yaml_config.get("ethics", {}).get("transparency", {}).get("audit_trail", True),
            human_oversight=yaml_config.get("ethics", {}).get("transparency", {}).get("human_oversight", True),
            emergency_mode=yaml_config.get("monitoring", {}).get("emergency_mode", True),
            log_level=yaml_config.get("monitoring", {}).get("log_level", "INFO"),
            metrics_enabled=yaml_config.get("monitoring", {}).get("metrics_enabled", True),
            audit_all_decisions=yaml_config.get("monitoring", {}).get("audit_all_decisions", True)
        )
    except Exception as e:
        print(f"Warning: Could not load config from {config_path}: {e}")
        return EthicsConfig()


# Global config instance
config = load_config()
