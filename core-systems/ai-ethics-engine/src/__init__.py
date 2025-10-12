"""
AI Ethics Engine - Source Module
Exports for all AI ethics components
"""

from src.bias_detector import (
    BiasDetector,
    BiasType,
    BiasSeverity,
    BiasDetectionResult,
    quick_bias_check
)

from src.ethical_framework import (
    EthicalFramework,
    EthicalFrameworkType,
    EthicalEvaluation,
    UtilitarianFramework,
    DeontologicalFramework,
    VirtueEthicsFramework,
    CareEthicsFramework,
    MultiFrameworkEthicalAnalyzer
)

from src.fairness_metrics import (
    FairnessAnalyzer,
    FairnessMetrics,
    quick_fairness_check
)

from src.decision_validator import (
    EthicalDecisionValidator,
    DecisionValidationResult,
    RiskLevel
)

__all__ = [
    # Bias Detection
    "BiasDetector",
    "BiasType",
    "BiasSeverity",
    "BiasDetectionResult",
    "quick_bias_check",
    
    # Ethical Frameworks
    "EthicalFramework",
    "EthicalFrameworkType",
    "EthicalEvaluation",
    "UtilitarianFramework",
    "DeontologicalFramework",
    "VirtueEthicsFramework",
    "CareEthicsFramework",
    "MultiFrameworkEthicalAnalyzer",
    
    # Fairness Metrics
    "FairnessAnalyzer",
    "FairnessMetrics",
    "quick_fairness_check",
    
    # Decision Validation
    "EthicalDecisionValidator",
    "DecisionValidationResult",
    "RiskLevel",
]
