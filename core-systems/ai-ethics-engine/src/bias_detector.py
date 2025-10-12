"""
Bias Detection Module
Обнаружение и измерение предвзятости в AI-системах
ВОССТАНОВЛЕНО для ai-ethics-engine
"""

import re
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from loguru import logger


class BiasType(Enum):
    """Types of bias"""
    GENDER = "gender"
    RACE = "race"
    AGE = "age"
    RELIGION = "religion"
    NATIONALITY = "nationality"
    DISABILITY = "disability"
    SEXUAL_ORIENTATION = "sexual_orientation"
    SOCIOECONOMIC = "socioeconomic"
    UNKNOWN = "unknown"


class BiasSeverity(Enum):
    """Severity levels of detected bias"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class BiasDetectionResult:
    """Result of bias detection"""
    has_bias: bool
    bias_type: BiasType
    severity: BiasSeverity
    score: float  # 0-1, higher is more biased
    evidence: List[str]
    affected_groups: List[str]
    recommendation: str


class BiasDetector:
    """
    Обнаруживает предвзятость в данных, моделях и решениях AI
    
    Supports:
    - Text bias detection (keywords, patterns)
    - Statistical bias detection (demographic parity, etc.)
    - Model prediction bias
    """
    
    def __init__(self, protected_attributes: Optional[List[str]] = None):
        self.protected_attributes = protected_attributes or [
            "race", "gender", "age", "religion", 
            "nationality", "disability", "sexual_orientation"
        ]
        
        # Bias patterns for text analysis
        self.bias_patterns = {
            BiasType.GENDER: {
                "keywords": [
                    "men are", "women are", "male", "female",
                    "he should", "she should", "boys", "girls",
                    "manly", "feminine", "masculine"
                ],
                "stereotypes": [
                    r"\b(women|girls)\s+(can't|cannot|shouldn't)\b",
                    r"\b(men|boys)\s+are\s+(better|superior)\b",
                    r"\bgirls?\s+are\s+(emotional|weak|fragile)\b",
                    r"\bboys?\s+are\s+(strong|logical|rational)\b"
                ]
            },
            BiasType.RACE: {
                "keywords": [
                    "race", "ethnicity", "racial", "ethnic",
                    "white", "black", "asian", "hispanic", "latino"
                ],
                "stereotypes": [
                    r"\b(race|ethnicity)\s+(determines|affects)\s+(intelligence|ability)\b",
                    r"\b(white|black|asian)\s+people\s+(are|tend\s+to\s+be)\b"
                ]
            },
            BiasType.AGE: {
                "keywords": [
                    "old", "young", "elderly", "senior", "millennial",
                    "boomer", "gen z", "generation"
                ],
                "stereotypes": [
                    r"\b(old|elderly)\s+people\s+(can't|cannot)\b",
                    r"\byoung\s+people\s+(don't|lack)\b",
                    r"\bmillennials?\s+are\s+(lazy|entitled)\b"
                ]
            },
            BiasType.RELIGION: {
                "keywords": [
                    "christian", "muslim", "jewish", "hindu", "buddhist",
                    "atheist", "religious", "religion"
                ],
                "stereotypes": [
                    r"\b(muslims?|christians?|jews?)\s+(are|tend\s+to\s+be)\s+(violent|peaceful|greedy)\b"
                ]
            }
        }
        
        logger.info(f"BiasDetector initialized with {len(self.protected_attributes)} protected attributes")
    
    def detect_text_bias(self, text: str) -> BiasDetectionResult:
        """
        Detect bias in text content
        
        Args:
            text: Text to analyze
            
        Returns:
            BiasDetectionResult with detected bias information
        """
        text_lower = text.lower()
        detected_biases = []
        evidence = []
        max_score = 0.0
        max_bias_type = BiasType.UNKNOWN
        
        # Check for bias patterns
        for bias_type, patterns in self.bias_patterns.items():
            bias_score = 0.0
            type_evidence = []
            
            # Check keywords
            for keyword in patterns["keywords"]:
                if keyword.lower() in text_lower:
                    bias_score += 0.1
                    type_evidence.append(f"Keyword: '{keyword}'")
            
            # Check stereotypes (regex patterns)
            for pattern in patterns["stereotypes"]:
                matches = re.findall(pattern, text_lower, re.IGNORECASE)
                if matches:
                    bias_score += 0.5
                    type_evidence.append(f"Stereotype pattern detected: {matches}")
            
            if bias_score > 0:
                detected_biases.append((bias_type, bias_score, type_evidence))
                if bias_score > max_score:
                    max_score = bias_score
                    max_bias_type = bias_type
                    evidence = type_evidence
        
        # Normalize score to 0-1
        max_score = min(max_score, 1.0)
        
        # Determine severity
        if max_score >= 0.8:
            severity = BiasSeverity.CRITICAL
        elif max_score >= 0.6:
            severity = BiasSeverity.HIGH
        elif max_score >= 0.4:
            severity = BiasSeverity.MEDIUM
        elif max_score >= 0.2:
            severity = BiasSeverity.LOW
        else:
            severity = BiasSeverity.NONE
        
        has_bias = max_score > 0.2
        
        return BiasDetectionResult(
            has_bias=has_bias,
            bias_type=max_bias_type,
            severity=severity,
            score=max_score,
            evidence=evidence,
            affected_groups=[max_bias_type.value] if has_bias else [],
            recommendation=self._get_recommendation(max_bias_type, severity)
        )
    
    def detect_statistical_bias(
        self,
        predictions: np.ndarray,
        sensitive_attribute: np.ndarray,
        ground_truth: Optional[np.ndarray] = None
    ) -> BiasDetectionResult:
        """
        Detect statistical bias in model predictions
        
        Args:
            predictions: Model predictions (binary: 0 or 1)
            sensitive_attribute: Protected attribute values (e.g., gender: 0=male, 1=female)
            ground_truth: True labels (optional, for fairness metrics)
            
        Returns:
            BiasDetectionResult with statistical bias analysis
        """
        # Convert to numpy arrays
        predictions = np.array(predictions)
        sensitive_attribute = np.array(sensitive_attribute)
        
        unique_groups = np.unique(sensitive_attribute)
        if len(unique_groups) < 2:
            return BiasDetectionResult(
                has_bias=False,
                bias_type=BiasType.UNKNOWN,
                severity=BiasSeverity.NONE,
                score=0.0,
                evidence=["Not enough groups to compare"],
                affected_groups=[],
                recommendation="Provide data with multiple groups for analysis"
            )
        
        # Calculate positive prediction rates for each group
        group_rates = {}
        for group in unique_groups:
            group_mask = sensitive_attribute == group
            positive_rate = np.mean(predictions[group_mask])
            group_rates[group] = positive_rate
        
        # Calculate disparate impact (ratio of rates)
        rates = list(group_rates.values())
        min_rate = min(rates)
        max_rate = max(rates)
        disparate_impact = min_rate / max_rate if max_rate > 0 else 1.0
        
        # Calculate demographic parity difference
        demographic_parity_diff = max_rate - min_rate
        
        # Bias score (inverse of disparate impact, normalized)
        # Perfect fairness: disparate_impact = 1.0, bias_score = 0.0
        # Strong bias: disparate_impact < 0.8, bias_score > 0.2
        bias_score = 1.0 - disparate_impact
        
        evidence = [
            f"Disparate Impact: {disparate_impact:.3f}",
            f"Demographic Parity Difference: {demographic_parity_diff:.3f}",
            f"Group positive rates: {group_rates}"
        ]
        
        # Determine severity (80% rule: disparate impact < 0.8 indicates bias)
        if disparate_impact < 0.5:
            severity = BiasSeverity.CRITICAL
        elif disparate_impact < 0.7:
            severity = BiasSeverity.HIGH
        elif disparate_impact < 0.8:
            severity = BiasSeverity.MEDIUM
        elif disparate_impact < 0.9:
            severity = BiasSeverity.LOW
        else:
            severity = BiasSeverity.NONE
        
        has_bias = disparate_impact < 0.8
        
        # Equal Opportunity if ground truth provided
        if ground_truth is not None:
            ground_truth = np.array(ground_truth)
            tpr_by_group = {}
            for group in unique_groups:
                group_mask = sensitive_attribute == group
                positives = ground_truth[group_mask] == 1
                if np.sum(positives) > 0:
                    tpr = np.mean(predictions[group_mask][positives])
                    tpr_by_group[group] = tpr
            
            if tpr_by_group:
                evidence.append(f"True Positive Rates by group: {tpr_by_group}")
        
        return BiasDetectionResult(
            has_bias=has_bias,
            bias_type=BiasType.UNKNOWN,
            severity=severity,
            score=bias_score,
            evidence=evidence,
            affected_groups=[str(g) for g in unique_groups],
            recommendation=self._get_statistical_recommendation(disparate_impact)
        )
    
    def _get_recommendation(self, bias_type: BiasType, severity: BiasSeverity) -> str:
        """Get recommendation based on bias type and severity"""
        if severity == BiasSeverity.NONE:
            return "No significant bias detected. Continue monitoring."
        
        base_recommendations = {
            BiasType.GENDER: "Review content for gender stereotypes. Use inclusive language.",
            BiasType.RACE: "Remove racial stereotypes and ensure equal representation.",
            BiasType.AGE: "Avoid age-based generalizations. Consider diverse age groups.",
            BiasType.RELIGION: "Ensure religious neutrality and respect all beliefs.",
            BiasType.NATIONALITY: "Avoid nationality-based assumptions.",
            BiasType.DISABILITY: "Use person-first language and avoid ableist terms.",
            BiasType.SEXUAL_ORIENTATION: "Ensure LGBTQ+ inclusivity.",
            BiasType.UNKNOWN: "Review content for potential bias patterns."
        }
        
        recommendation = base_recommendations.get(bias_type, "Review for bias.")
        
        if severity >= BiasSeverity.HIGH:
            recommendation += " URGENT: High bias detected. Immediate review required."
        
        return recommendation
    
    def _get_statistical_recommendation(self, disparate_impact: float) -> str:
        """Get recommendation for statistical bias"""
        if disparate_impact >= 0.9:
            return "Model shows good fairness. Continue monitoring."
        elif disparate_impact >= 0.8:
            return "Minor bias detected. Consider rebalancing training data or adjusting decision threshold."
        elif disparate_impact >= 0.7:
            return "Significant bias detected. Retrain model with balanced data or apply bias mitigation techniques."
        else:
            return "CRITICAL: Severe bias detected. Model should not be deployed. Complete redesign recommended."
    
    def analyze_fairness_metrics(
        self,
        predictions: np.ndarray,
        sensitive_attribute: np.ndarray,
        ground_truth: np.ndarray
    ) -> Dict[str, float]:
        """
        Calculate comprehensive fairness metrics
        
        Args:
            predictions: Model predictions (binary)
            sensitive_attribute: Protected attribute
            ground_truth: True labels
            
        Returns:
            Dictionary of fairness metrics
        """
        predictions = np.array(predictions)
        sensitive_attribute = np.array(sensitive_attribute)
        ground_truth = np.array(ground_truth)
        
        unique_groups = np.unique(sensitive_attribute)
        metrics = {}
        
        # Demographic Parity (Statistical Parity)
        group_positive_rates = []
        for group in unique_groups:
            group_mask = sensitive_attribute == group
            positive_rate = np.mean(predictions[group_mask])
            group_positive_rates.append(positive_rate)
        
        demographic_parity_diff = max(group_positive_rates) - min(group_positive_rates)
        metrics["demographic_parity_difference"] = demographic_parity_diff
        
        # Equal Opportunity (True Positive Rate parity)
        tpr_by_group = []
        for group in unique_groups:
            group_mask = sensitive_attribute == group
            positives = ground_truth[group_mask] == 1
            if np.sum(positives) > 0:
                tpr = np.mean(predictions[group_mask][positives])
                tpr_by_group.append(tpr)
        
        if tpr_by_group:
            equal_opportunity_diff = max(tpr_by_group) - min(tpr_by_group)
            metrics["equal_opportunity_difference"] = equal_opportunity_diff
        
        # Equalized Odds (TPR and FPR parity)
        fpr_by_group = []
        for group in unique_groups:
            group_mask = sensitive_attribute == group
            negatives = ground_truth[group_mask] == 0
            if np.sum(negatives) > 0:
                fpr = np.mean(predictions[group_mask][negatives])
                fpr_by_group.append(fpr)
        
        if fpr_by_group:
            equalized_odds_diff = max(tpr_by_group + fpr_by_group) - min(tpr_by_group + fpr_by_group)
            metrics["equalized_odds_difference"] = equalized_odds_diff
        
        # Disparate Impact
        if group_positive_rates:
            disparate_impact = min(group_positive_rates) / max(group_positive_rates) if max(group_positive_rates) > 0 else 1.0
            metrics["disparate_impact"] = disparate_impact
        
        return metrics


# Helper function for quick bias check
def quick_bias_check(text: str) -> Dict[str, Any]:
    """Quick text bias check"""
    detector = BiasDetector()
    result = detector.detect_text_bias(text)
    
    return {
        "has_bias": result.has_bias,
        "bias_type": result.bias_type.value,
        "severity": result.severity.name,
        "score": result.score,
        "evidence": result.evidence,
        "recommendation": result.recommendation
    }
