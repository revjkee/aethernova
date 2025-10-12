"""
Ethical Frameworks Module
Реализация этических фреймворков для принятия решений
ВОССТАНОВЛЕНО для ai-ethics-engine
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod
import numpy as np
from loguru import logger


class EthicalFrameworkType(Enum):
    """Types of ethical frameworks"""
    UTILITARIAN = "utilitarian"              # Maximum good for maximum people
    DEONTOLOGICAL = "deontological"          # Rule-based ethics
    VIRTUE_ETHICS = "virtue_ethics"          # Character-based ethics
    CARE_ETHICS = "care_ethics"              # Relationship-focused ethics
    RIGHTS_BASED = "rights_based"            # Human rights focused
    JUSTICE_BASED = "justice_based"          # Fairness and equality


@dataclass
class EthicalEvaluation:
    """Result of ethical evaluation"""
    framework: EthicalFrameworkType
    score: float  # 0-1, higher is more ethical
    is_ethical: bool
    reasoning: str
    violations: List[str]
    recommendations: List[str]


class EthicalFramework(ABC):
    """Base class for ethical frameworks"""
    
    def __init__(self, framework_type: EthicalFrameworkType):
        self.framework_type = framework_type
        self.threshold = 0.6  # Minimum ethical score
    
    @abstractmethod
    def evaluate(self, decision: Dict[str, Any], context: Dict[str, Any]) -> EthicalEvaluation:
        """Evaluate a decision using this framework"""
        pass
    
    def _create_evaluation(
        self,
        score: float,
        reasoning: str,
        violations: List[str] = None,
        recommendations: List[str] = None
    ) -> EthicalEvaluation:
        """Helper to create evaluation result"""
        return EthicalEvaluation(
            framework=self.framework_type,
            score=score,
            is_ethical=score >= self.threshold,
            reasoning=reasoning,
            violations=violations or [],
            recommendations=recommendations or []
        )


class UtilitarianFramework(EthicalFramework):
    """
    Utilitarian Ethics: Maximum good for maximum people
    
    Evaluates actions based on their consequences and overall utility.
    """
    
    def __init__(self):
        super().__init__(EthicalFrameworkType.UTILITARIAN)
    
    def evaluate(self, decision: Dict[str, Any], context: Dict[str, Any]) -> EthicalEvaluation:
        action = decision.get("action", "")
        consequences = decision.get("consequences", {})
        affected_parties = decision.get("affected_parties", [])
        
        # Calculate utility score
        positive_outcomes = consequences.get("positive", [])
        negative_outcomes = consequences.get("negative", [])
        
        # Weight by number of affected people
        num_affected = len(affected_parties)
        positive_weight = len(positive_outcomes) * num_affected
        negative_weight = len(negative_outcomes) * num_affected
        
        total_impact = positive_weight + negative_weight
        if total_impact == 0:
            utility_score = 0.5  # Neutral
        else:
            utility_score = positive_weight / total_impact
        
        violations = []
        recommendations = []
        
        # Check for significant harm to minorities
        minority_harm = context.get("minority_harm", False)
        if minority_harm:
            utility_score *= 0.7  # Reduce score
            violations.append("Potential harm to minority groups")
            recommendations.append("Consider alternative actions that don't harm minorities")
        
        # Check for long-term consequences
        long_term_negative = consequences.get("long_term_negative", [])
        if long_term_negative:
            utility_score *= 0.8
            violations.append(f"Long-term negative consequences: {long_term_negative}")
        
        reasoning = (
            f"Utilitarian analysis: {len(positive_outcomes)} positive vs "
            f"{len(negative_outcomes)} negative outcomes affecting {num_affected} parties. "
            f"Utility score: {utility_score:.2f}"
        )
        
        return self._create_evaluation(utility_score, reasoning, violations, recommendations)


class DeontologicalFramework(EthicalFramework):
    """
    Deontological Ethics: Rule-based ethics
    
    Evaluates actions based on adherence to moral rules and duties.
    """
    
    def __init__(self):
        super().__init__(EthicalFrameworkType.DEONTOLOGICAL)
        
        # Universal moral rules (Kantian categorical imperatives)
        self.moral_rules = {
            "no_harm": {"weight": 1.0, "description": "Do not harm others"},
            "truth": {"weight": 0.9, "description": "Tell the truth"},
            "promise_keeping": {"weight": 0.8, "description": "Keep promises"},
            "respect_autonomy": {"weight": 0.9, "description": "Respect individual autonomy"},
            "justice": {"weight": 0.9, "description": "Treat people fairly"},
            "beneficence": {"weight": 0.7, "description": "Do good when possible"},
        }
    
    def evaluate(self, decision: Dict[str, Any], context: Dict[str, Any]) -> EthicalEvaluation:
        action = decision.get("action", "")
        rules_followed = decision.get("rules_followed", [])
        rules_violated = decision.get("rules_violated", [])
        
        # Check against moral rules
        compliance_scores = []
        violations = []
        recommendations = []
        
        for rule_name, rule_info in self.moral_rules.items():
            if rule_name in rules_violated:
                compliance_scores.append(0.0)
                violations.append(f"Violated rule: {rule_info['description']}")
            elif rule_name in rules_followed:
                compliance_scores.append(rule_info["weight"])
            else:
                # Rule not explicitly mentioned, assume partial compliance
                compliance_scores.append(0.5 * rule_info["weight"])
        
        # Calculate overall deontological score
        if compliance_scores:
            deontological_score = np.mean(compliance_scores)
        else:
            deontological_score = 0.5
        
        # Critical violation check
        critical_violations = ["no_harm", "respect_autonomy"]
        if any(rule in rules_violated for rule in critical_violations):
            deontological_score = min(deontological_score, 0.3)
            violations.append("Critical moral rule violated")
            recommendations.append("Revise action to comply with fundamental moral duties")
        
        # Universalizability test (Kant's Categorical Imperative)
        if decision.get("universalizable", False):
            deontological_score = min(deontological_score * 1.1, 1.0)
        else:
            violations.append("Action fails universalizability test")
            recommendations.append("Consider if this action could be a universal law")
        
        reasoning = (
            f"Deontological analysis: {len(rules_followed)} rules followed, "
            f"{len(rules_violated)} violated. Compliance score: {deontological_score:.2f}"
        )
        
        return self._create_evaluation(deontological_score, reasoning, violations, recommendations)


class VirtueEthicsFramework(EthicalFramework):
    """
    Virtue Ethics: Character-based ethics
    
    Evaluates actions based on virtuous character traits.
    """
    
    def __init__(self):
        super().__init__(EthicalFrameworkType.VIRTUE_ETHICS)
        
        # Aristotelian virtues
        self.virtues = {
            "honesty": 0.9,
            "courage": 0.8,
            "compassion": 0.9,
            "wisdom": 0.9,
            "temperance": 0.7,
            "justice": 0.9,
            "integrity": 0.9,
            "humility": 0.7
        }
    
    def evaluate(self, decision: Dict[str, Any], context: Dict[str, Any]) -> EthicalEvaluation:
        action = decision.get("action", "")
        virtues_demonstrated = decision.get("virtues_demonstrated", [])
        vices_demonstrated = decision.get("vices_demonstrated", [])
        
        # Calculate virtue score
        virtue_scores = []
        violations = []
        recommendations = []
        
        for virtue, weight in self.virtues.items():
            if virtue in virtues_demonstrated:
                virtue_scores.append(weight)
            elif virtue in vices_demonstrated:
                virtue_scores.append(0.0)
                violations.append(f"Demonstrates vice opposite to {virtue}")
        
        if virtue_scores:
            virtue_score = np.mean(virtue_scores)
        else:
            virtue_score = 0.5  # Neutral if no virtues specified
        
        # Check for character consistency
        character_consistent = context.get("character_consistent", True)
        if not character_consistent:
            virtue_score *= 0.8
            violations.append("Action inconsistent with virtuous character")
            recommendations.append("Align actions with virtuous character traits")
        
        # Check for practical wisdom (phronesis)
        wisdom_applied = decision.get("wisdom_applied", False)
        if wisdom_applied:
            virtue_score = min(virtue_score * 1.1, 1.0)
        else:
            recommendations.append("Apply practical wisdom to find the golden mean")
        
        reasoning = (
            f"Virtue ethics analysis: {len(virtues_demonstrated)} virtues demonstrated, "
            f"{len(vices_demonstrated)} vices shown. Virtue score: {virtue_score:.2f}"
        )
        
        return self._create_evaluation(virtue_score, reasoning, violations, recommendations)


class CareEthicsFramework(EthicalFramework):
    """
    Care Ethics: Relationship-focused ethics
    
    Evaluates actions based on care, empathy, and relationships.
    """
    
    def __init__(self):
        super().__init__(EthicalFrameworkType.CARE_ETHICS)
    
    def evaluate(self, decision: Dict[str, Any], context: Dict[str, Any]) -> EthicalEvaluation:
        action = decision.get("action", "")
        relationships_affected = decision.get("relationships_affected", [])
        care_demonstrated = decision.get("care_demonstrated", False)
        empathy_shown = decision.get("empathy_shown", False)
        
        # Calculate care score
        care_score = 0.5  # Base score
        violations = []
        recommendations = []
        
        # Check for care and empathy
        if care_demonstrated:
            care_score += 0.2
        else:
            recommendations.append("Demonstrate more care and compassion")
        
        if empathy_shown:
            care_score += 0.2
        else:
            recommendations.append("Show empathy for affected parties")
        
        # Check relationship impact
        positive_relationships = len([r for r in relationships_affected if r.get("impact") == "positive"])
        negative_relationships = len([r for r in relationships_affected if r.get("impact") == "negative"])
        
        if relationships_affected:
            relationship_score = positive_relationships / len(relationships_affected)
            care_score = (care_score + relationship_score) / 2
        
        if negative_relationships > 0:
            violations.append(f"{negative_relationships} relationships negatively impacted")
            recommendations.append("Minimize harm to existing relationships")
        
        # Check for vulnerability consideration
        vulnerable_parties = context.get("vulnerable_parties", [])
        if vulnerable_parties:
            protection_provided = decision.get("protects_vulnerable", False)
            if protection_provided:
                care_score = min(care_score * 1.2, 1.0)
            else:
                care_score *= 0.7
                violations.append("Insufficient protection for vulnerable parties")
                recommendations.append("Prioritize care for vulnerable individuals")
        
        care_score = min(max(care_score, 0.0), 1.0)
        
        reasoning = (
            f"Care ethics analysis: Care demonstrated={care_demonstrated}, "
            f"Empathy shown={empathy_shown}, {positive_relationships} positive "
            f"vs {negative_relationships} negative relationship impacts. Care score: {care_score:.2f}"
        )
        
        return self._create_evaluation(care_score, reasoning, violations, recommendations)


class MultiFrameworkEthicalAnalyzer:
    """
    Analyzes decisions using multiple ethical frameworks
    """
    
    def __init__(self, frameworks: Optional[List[EthicalFrameworkType]] = None):
        self.frameworks = {}
        
        # Initialize specified frameworks or all by default
        framework_types = frameworks or list(EthicalFrameworkType)
        
        for framework_type in framework_types:
            if framework_type == EthicalFrameworkType.UTILITARIAN:
                self.frameworks[framework_type] = UtilitarianFramework()
            elif framework_type == EthicalFrameworkType.DEONTOLOGICAL:
                self.frameworks[framework_type] = DeontologicalFramework()
            elif framework_type == EthicalFrameworkType.VIRTUE_ETHICS:
                self.frameworks[framework_type] = VirtueEthicsFramework()
            elif framework_type == EthicalFrameworkType.CARE_ETHICS:
                self.frameworks[framework_type] = CareEthicsFramework()
        
        logger.info(f"MultiFrameworkEthicalAnalyzer initialized with {len(self.frameworks)} frameworks")
    
    def analyze(self, decision: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze decision using all frameworks
        
        Returns:
            Dict with evaluations from each framework and overall ethical assessment
        """
        evaluations = {}
        all_scores = []
        all_violations = []
        all_recommendations = []
        
        for framework_type, framework in self.frameworks.items():
            evaluation = framework.evaluate(decision, context)
            evaluations[framework_type.value] = {
                "score": evaluation.score,
                "is_ethical": evaluation.is_ethical,
                "reasoning": evaluation.reasoning,
                "violations": evaluation.violations,
                "recommendations": evaluation.recommendations
            }
            
            all_scores.append(evaluation.score)
            all_violations.extend(evaluation.violations)
            all_recommendations.extend(evaluation.recommendations)
        
        # Calculate overall ethical score (average across frameworks)
        overall_score = np.mean(all_scores) if all_scores else 0.0
        is_ethical = overall_score >= 0.6
        
        # Find consensus and disagreements
        ethical_count = sum(1 for eval in evaluations.values() if eval["is_ethical"])
        consensus = ethical_count == len(evaluations) or ethical_count == 0
        
        return {
            "overall_score": overall_score,
            "is_ethical": is_ethical,
            "consensus": consensus,
            "evaluations": evaluations,
            "all_violations": list(set(all_violations)),  # Remove duplicates
            "all_recommendations": list(set(all_recommendations)),
            "framework_agreement": f"{ethical_count}/{len(evaluations)} frameworks agree"
        }
