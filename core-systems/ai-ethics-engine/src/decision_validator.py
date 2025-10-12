"""
Decision Validator Module
Валидация и оценка этических решений AI
ВОССТАНОВЛЕНО для ai-ethics-engine
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
from loguru import logger

from src.ethical_framework import MultiFrameworkEthicalAnalyzer, EthicalFrameworkType
from src.bias_detector import BiasDetector, BiasSeverity
from src.fairness_metrics import FairnessAnalyzer


class RiskLevel(Enum):
    """Risk levels for decisions"""
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DecisionValidationResult:
    """Result of decision validation"""
    is_approved: bool
    risk_level: RiskLevel
    ethical_score: float
    bias_score: float
    fairness_score: float
    justification: str
    violations: List[str]
    recommendations: List[str]
    requires_human_review: bool


class EthicalDecisionValidator:
    """
    Validates AI decisions for ethical compliance
    
    Checks:
    - Ethical framework compliance
    - Bias detection
    - Fairness metrics
    - Risk assessment
    """
    
    def __init__(
        self,
        ethical_frameworks: Optional[List[EthicalFrameworkType]] = None,
        bias_threshold: float = 0.7,
        fairness_threshold: float = 0.8,
        risk_threshold: float = 0.75
    ):
        self.ethical_analyzer = MultiFrameworkEthicalAnalyzer(ethical_frameworks)
        self.bias_detector = BiasDetector()
        self.fairness_analyzer = FairnessAnalyzer(fairness_threshold)
        
        self.bias_threshold = bias_threshold
        self.fairness_threshold = fairness_threshold
        self.risk_threshold = risk_threshold
        
        logger.info(f"EthicalDecisionValidator initialized with thresholds: "
                   f"bias={bias_threshold}, fairness={fairness_threshold}, risk={risk_threshold}")
    
    def validate_decision(
        self,
        decision: Dict[str, Any],
        context: Dict[str, Any],
        agent_id: Optional[str] = None
    ) -> DecisionValidationResult:
        """
        Comprehensive ethical validation of a decision
        
        Args:
            decision: Decision to validate (action, consequences, etc.)
            context: Context of the decision
            agent_id: ID of agent making decision (optional)
            
        Returns:
            DecisionValidationResult with validation results
        """
        logger.info(f"Validating decision: {decision.get('action', 'Unknown')} "
                   f"(Agent: {agent_id or 'Unknown'})")
        
        violations = []
        recommendations = []
        
        # 1. Ethical Framework Analysis
        ethical_analysis = self.ethical_analyzer.analyze(decision, context)
        ethical_score = ethical_analysis["overall_score"]
        
        if not ethical_analysis["is_ethical"]:
            violations.extend(ethical_analysis["all_violations"])
        recommendations.extend(ethical_analysis["all_recommendations"])
        
        # 2. Bias Detection
        bias_score = 0.0
        decision_text = decision.get("description", "") or decision.get("action", "")
        if decision_text:
            bias_result = self.bias_detector.detect_text_bias(decision_text)
            bias_score = bias_result.score
            
            if bias_result.has_bias and bias_result.severity.value >= BiasSeverity.MEDIUM.value:
                violations.append(f"Bias detected: {bias_result.bias_type.value} "
                                f"(severity: {bias_result.severity.name})")
                recommendations.append(bias_result.recommendation)
        
        # 3. Fairness Assessment (if data provided)
        fairness_score = 1.0  # Default: assume fair if no data
        if "predictions" in decision and "sensitive_attribute" in context:
            predictions = decision["predictions"]
            sensitive_attr = context["sensitive_attribute"]
            ground_truth = context.get("ground_truth")
            
            if ground_truth is not None:
                fairness_metrics = self.fairness_analyzer.calculate_all_metrics(
                    predictions, ground_truth, sensitive_attr
                )
                fairness_score = fairness_metrics.overall_fairness
                
                if not fairness_metrics.is_fair:
                    violations.extend(fairness_metrics.violations)
                    recommendations.append("Apply bias mitigation techniques")
        
        # 4. Risk Assessment
        risk_level = self._assess_risk(ethical_score, bias_score, fairness_score, decision, context)
        
        # 5. Determine if human review required
        requires_human_review = (
            risk_level.value in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value] or
            ethical_score < 0.5 or
            bias_score > self.bias_threshold or
            fairness_score < self.fairness_threshold
        )
        
        # 6. Final approval decision
        is_approved = (
            ethical_score >= 0.6 and
            bias_score < self.bias_threshold and
            fairness_score >= self.fairness_threshold and
            risk_level.value not in [RiskLevel.CRITICAL.value]
        )
        
        # 7. Generate justification
        justification = self._generate_justification(
            is_approved, ethical_score, bias_score, fairness_score,
            risk_level, ethical_analysis
        )
        
        result = DecisionValidationResult(
            is_approved=is_approved,
            risk_level=risk_level,
            ethical_score=ethical_score,
            bias_score=bias_score,
            fairness_score=fairness_score,
            justification=justification,
            violations=violations,
            recommendations=recommendations,
            requires_human_review=requires_human_review
        )
        
        logger.info(f"Validation complete: {'APPROVED' if is_approved else 'REJECTED'} "
                   f"(Risk: {risk_level.value}, Ethical: {ethical_score:.2f})")
        
        return result
    
    def _assess_risk(
        self,
        ethical_score: float,
        bias_score: float,
        fairness_score: float,
        decision: Dict[str, Any],
        context: Dict[str, Any]
    ) -> RiskLevel:
        """Assess overall risk level of decision"""
        
        # Critical factors
        critical_harm = context.get("potential_harm", {}).get("severity") == "critical"
        irreversible = decision.get("irreversible", False)
        affects_many = len(decision.get("affected_parties", [])) > 100
        
        # Risk score calculation
        risk_factors = []
        
        # Ethical risk
        if ethical_score < 0.4:
            risk_factors.append(0.8)
        elif ethical_score < 0.6:
            risk_factors.append(0.5)
        else:
            risk_factors.append(0.2)
        
        # Bias risk
        if bias_score > 0.8:
            risk_factors.append(0.9)
        elif bias_score > 0.6:
            risk_factors.append(0.6)
        else:
            risk_factors.append(0.2)
        
        # Fairness risk
        if fairness_score < 0.6:
            risk_factors.append(0.8)
        elif fairness_score < 0.8:
            risk_factors.append(0.5)
        else:
            risk_factors.append(0.2)
        
        # Context risk
        if critical_harm:
            risk_factors.append(1.0)
        if irreversible:
            risk_factors.append(0.7)
        if affects_many:
            risk_factors.append(0.6)
        
        # Calculate average risk
        import numpy as np
        overall_risk = np.mean(risk_factors)
        
        # Determine risk level
        if overall_risk >= 0.9 or critical_harm:
            return RiskLevel.CRITICAL
        elif overall_risk >= 0.7:
            return RiskLevel.HIGH
        elif overall_risk >= 0.5:
            return RiskLevel.MEDIUM
        elif overall_risk >= 0.3:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def _generate_justification(
        self,
        is_approved: bool,
        ethical_score: float,
        bias_score: float,
        fairness_score: float,
        risk_level: RiskLevel,
        ethical_analysis: Dict[str, Any]
    ) -> str:
        """Generate human-readable justification"""
        
        parts = []
        
        if is_approved:
            parts.append("✅ DECISION APPROVED")
        else:
            parts.append("❌ DECISION REJECTED")
        
        parts.append(f"\nEthical Assessment:")
        parts.append(f"  - Ethical Score: {ethical_score:.2f}/1.0")
        parts.append(f"  - Bias Score: {bias_score:.2f}/1.0 (lower is better)")
        parts.append(f"  - Fairness Score: {fairness_score:.2f}/1.0")
        parts.append(f"  - Risk Level: {risk_level.value.upper()}")
        
        parts.append(f"\nFramework Analysis:")
        parts.append(f"  - Framework Agreement: {ethical_analysis['framework_agreement']}")
        parts.append(f"  - Consensus: {'Yes' if ethical_analysis['consensus'] else 'No'}")
        
        if is_approved:
            parts.append("\nDecision meets ethical standards and can proceed.")
        else:
            parts.append("\nDecision does not meet ethical standards. Review required.")
        
        return "\n".join(parts)
    
    def validate_batch(
        self,
        decisions: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[DecisionValidationResult]:
        """Validate multiple decisions"""
        results = []
        for i, decision in enumerate(decisions):
            logger.info(f"Validating decision {i+1}/{len(decisions)}")
            result = self.validate_decision(decision, context)
            results.append(result)
        return results
    
    def generate_validation_report(self, result: DecisionValidationResult) -> str:
        """Generate detailed validation report"""
        report = []
        report.append("=" * 70)
        report.append("ETHICAL DECISION VALIDATION REPORT")
        report.append("=" * 70)
        
        status = "✅ APPROVED" if result.is_approved else "❌ REJECTED"
        report.append(f"\nStatus: {status}")
        report.append(f"Risk Level: {result.risk_level.value.upper()}")
        report.append(f"Requires Human Review: {'Yes' if result.requires_human_review else 'No'}")
        
        report.append(f"\nScores:")
        report.append(f"  - Ethical Score:   {result.ethical_score:.3f}")
        report.append(f"  - Bias Score:      {result.bias_score:.3f} (lower is better)")
        report.append(f"  - Fairness Score:  {result.fairness_score:.3f}")
        
        if result.violations:
            report.append(f"\n⚠️  Violations ({len(result.violations)}):")
            for violation in result.violations:
                report.append(f"  - {violation}")
        else:
            report.append(f"\n✅ No violations detected")
        
        if result.recommendations:
            report.append(f"\n💡 Recommendations ({len(result.recommendations)}):")
            for rec in result.recommendations:
                report.append(f"  - {rec}")
        
        report.append(f"\nJustification:")
        for line in result.justification.split("\n"):
            report.append(f"  {line}")
        
        report.append("=" * 70)
        
        return "\n".join(report)
