"""
Fairness Metrics Module
Расчет метрик справедливости для AI-систем
ВОССТАНОВЛЕНО для ai-ethics-engine
"""

import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from loguru import logger


@dataclass
class FairnessMetrics:
    """Comprehensive fairness metrics"""
    demographic_parity: float
    equal_opportunity: float
    equalized_odds: float
    disparate_impact: float
    calibration_score: float
    overall_fairness: float
    is_fair: bool
    violations: List[str]


class FairnessAnalyzer:
    """
    Calculates and analyzes fairness metrics for ML models
    
    Supports metrics:
    - Demographic Parity (Statistical Parity)
    - Equal Opportunity
    - Equalized Odds
    - Disparate Impact
    - Calibration
    """
    
    def __init__(self, fairness_threshold: float = 0.8):
        """
        Args:
            fairness_threshold: Minimum acceptable fairness score (0-1)
        """
        self.fairness_threshold = fairness_threshold
        logger.info(f"FairnessAnalyzer initialized with threshold={fairness_threshold}")
    
    def calculate_all_metrics(
        self,
        predictions: np.ndarray,
        ground_truth: np.ndarray,
        sensitive_attribute: np.ndarray,
        probabilities: Optional[np.ndarray] = None
    ) -> FairnessMetrics:
        """
        Calculate all fairness metrics
        
        Args:
            predictions: Binary predictions (0 or 1)
            ground_truth: True labels (0 or 1)
            sensitive_attribute: Protected attribute (e.g., 0=male, 1=female)
            probabilities: Prediction probabilities (optional, for calibration)
            
        Returns:
            FairnessMetrics object with all metrics
        """
        predictions = np.array(predictions)
        ground_truth = np.array(ground_truth)
        sensitive_attribute = np.array(sensitive_attribute)
        
        violations = []
        
        # 1. Demographic Parity
        demo_parity = self._demographic_parity(predictions, sensitive_attribute)
        if demo_parity < self.fairness_threshold:
            violations.append(f"Demographic parity violation: {demo_parity:.3f}")
        
        # 2. Equal Opportunity
        equal_opp = self._equal_opportunity(predictions, ground_truth, sensitive_attribute)
        if equal_opp < self.fairness_threshold:
            violations.append(f"Equal opportunity violation: {equal_opp:.3f}")
        
        # 3. Equalized Odds
        eq_odds = self._equalized_odds(predictions, ground_truth, sensitive_attribute)
        if eq_odds < self.fairness_threshold:
            violations.append(f"Equalized odds violation: {eq_odds:.3f}")
        
        # 4. Disparate Impact
        disp_impact = self._disparate_impact(predictions, sensitive_attribute)
        if disp_impact < self.fairness_threshold:
            violations.append(f"Disparate impact violation: {disp_impact:.3f} (80% rule)")
        
        # 5. Calibration (if probabilities provided)
        if probabilities is not None:
            calibration = self._calibration_score(probabilities, ground_truth, sensitive_attribute)
        else:
            calibration = 1.0  # Assume perfect calibration if not measured
        
        # Overall fairness score (average of all metrics)
        all_metrics = [demo_parity, equal_opp, eq_odds, disp_impact, calibration]
        overall_fairness = np.mean(all_metrics)
        
        is_fair = overall_fairness >= self.fairness_threshold and len(violations) == 0
        
        return FairnessMetrics(
            demographic_parity=demo_parity,
            equal_opportunity=equal_opp,
            equalized_odds=eq_odds,
            disparate_impact=disp_impact,
            calibration_score=calibration,
            overall_fairness=overall_fairness,
            is_fair=is_fair,
            violations=violations
        )
    
    def _demographic_parity(
        self,
        predictions: np.ndarray,
        sensitive_attribute: np.ndarray
    ) -> float:
        """
        Demographic Parity: P(Y_hat=1 | A=0) ≈ P(Y_hat=1 | A=1)
        
        Returns score from 0-1, where 1.0 = perfect parity
        """
        unique_groups = np.unique(sensitive_attribute)
        positive_rates = []
        
        for group in unique_groups:
            group_mask = sensitive_attribute == group
            positive_rate = np.mean(predictions[group_mask])
            positive_rates.append(positive_rate)
        
        if len(positive_rates) < 2:
            return 1.0
        
        # Ratio of min to max (closer to 1.0 is better)
        min_rate = min(positive_rates)
        max_rate = max(positive_rates)
        
        if max_rate == 0:
            return 1.0
        
        return min_rate / max_rate
    
    def _equal_opportunity(
        self,
        predictions: np.ndarray,
        ground_truth: np.ndarray,
        sensitive_attribute: np.ndarray
    ) -> float:
        """
        Equal Opportunity: TPR parity across groups
        TPR = P(Y_hat=1 | Y=1, A=a)
        
        Returns score from 0-1, where 1.0 = perfect equality
        """
        unique_groups = np.unique(sensitive_attribute)
        tpr_list = []
        
        for group in unique_groups:
            group_mask = sensitive_attribute == group
            positives = ground_truth[group_mask] == 1
            
            if np.sum(positives) == 0:
                continue
            
            tpr = np.mean(predictions[group_mask][positives])
            tpr_list.append(tpr)
        
        if len(tpr_list) < 2:
            return 1.0
        
        min_tpr = min(tpr_list)
        max_tpr = max(tpr_list)
        
        if max_tpr == 0:
            return 1.0
        
        return min_tpr / max_tpr
    
    def _equalized_odds(
        self,
        predictions: np.ndarray,
        ground_truth: np.ndarray,
        sensitive_attribute: np.ndarray
    ) -> float:
        """
        Equalized Odds: Both TPR and FPR parity across groups
        
        Returns score from 0-1, where 1.0 = perfect equality
        """
        unique_groups = np.unique(sensitive_attribute)
        tpr_list = []
        fpr_list = []
        
        for group in unique_groups:
            group_mask = sensitive_attribute == group
            
            # True Positive Rate
            positives = ground_truth[group_mask] == 1
            if np.sum(positives) > 0:
                tpr = np.mean(predictions[group_mask][positives])
                tpr_list.append(tpr)
            
            # False Positive Rate
            negatives = ground_truth[group_mask] == 0
            if np.sum(negatives) > 0:
                fpr = np.mean(predictions[group_mask][negatives])
                fpr_list.append(fpr)
        
        if len(tpr_list) < 2 or len(fpr_list) < 2:
            return 1.0
        
        # Calculate parity for both TPR and FPR
        tpr_parity = min(tpr_list) / max(tpr_list) if max(tpr_list) > 0 else 1.0
        fpr_parity = min(fpr_list) / max(fpr_list) if max(fpr_list) > 0 else 1.0
        
        # Average of both parities
        return (tpr_parity + fpr_parity) / 2
    
    def _disparate_impact(
        self,
        predictions: np.ndarray,
        sensitive_attribute: np.ndarray
    ) -> float:
        """
        Disparate Impact: Ratio of positive rates
        80% rule: ratio should be >= 0.8
        
        Returns ratio from 0-1
        """
        unique_groups = np.unique(sensitive_attribute)
        positive_rates = []
        
        for group in unique_groups:
            group_mask = sensitive_attribute == group
            positive_rate = np.mean(predictions[group_mask])
            positive_rates.append(positive_rate)
        
        if len(positive_rates) < 2:
            return 1.0
        
        min_rate = min(positive_rates)
        max_rate = max(positive_rates)
        
        if max_rate == 0:
            return 1.0
        
        return min_rate / max_rate
    
    def _calibration_score(
        self,
        probabilities: np.ndarray,
        ground_truth: np.ndarray,
        sensitive_attribute: np.ndarray
    ) -> float:
        """
        Calibration: P(Y=1 | Y_hat=p, A=a) ≈ p for all groups
        
        Measures if predicted probabilities match actual outcomes across groups
        
        Returns score from 0-1, where 1.0 = perfect calibration
        """
        unique_groups = np.unique(sensitive_attribute)
        calibration_errors = []
        
        # Bin probabilities
        bins = np.linspace(0, 1, 11)  # 10 bins
        
        for group in unique_groups:
            group_mask = sensitive_attribute == group
            group_probs = probabilities[group_mask]
            group_truth = ground_truth[group_mask]
            
            if len(group_probs) == 0:
                continue
            
            # Calculate calibration error for this group
            for i in range(len(bins) - 1):
                bin_mask = (group_probs >= bins[i]) & (group_probs < bins[i + 1])
                if np.sum(bin_mask) == 0:
                    continue
                
                avg_prob = np.mean(group_probs[bin_mask])
                actual_positive_rate = np.mean(group_truth[bin_mask])
                
                error = abs(avg_prob - actual_positive_rate)
                calibration_errors.append(error)
        
        if not calibration_errors:
            return 1.0
        
        # Average calibration error (lower is better)
        avg_error = np.mean(calibration_errors)
        
        # Convert to score (1.0 - error)
        calibration_score = 1.0 - min(avg_error, 1.0)
        
        return calibration_score
    
    def generate_fairness_report(self, metrics: FairnessMetrics) -> str:
        """Generate human-readable fairness report"""
        report = []
        report.append("=" * 60)
        report.append("FAIRNESS ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"\nOverall Fairness Score: {metrics.overall_fairness:.3f}")
        report.append(f"Status: {'✅ FAIR' if metrics.is_fair else '❌ UNFAIR'}")
        report.append(f"\nDetailed Metrics:")
        report.append(f"  - Demographic Parity:  {metrics.demographic_parity:.3f}")
        report.append(f"  - Equal Opportunity:   {metrics.equal_opportunity:.3f}")
        report.append(f"  - Equalized Odds:      {metrics.equalized_odds:.3f}")
        report.append(f"  - Disparate Impact:    {metrics.disparate_impact:.3f}")
        report.append(f"  - Calibration Score:   {metrics.calibration_score:.3f}")
        
        if metrics.violations:
            report.append(f"\n⚠️  Violations ({len(metrics.violations)}):")
            for violation in metrics.violations:
                report.append(f"  - {violation}")
        else:
            report.append(f"\n✅ No violations detected")
        
        report.append("\nInterpretation:")
        if metrics.overall_fairness >= 0.9:
            report.append("  Excellent fairness. Model shows minimal bias.")
        elif metrics.overall_fairness >= 0.8:
            report.append("  Good fairness. Minor improvements possible.")
        elif metrics.overall_fairness >= 0.7:
            report.append("  Moderate fairness. Consider bias mitigation.")
        else:
            report.append("  Poor fairness. Significant bias detected. Redesign recommended.")
        
        report.append("=" * 60)
        
        return "\n".join(report)


# Helper function for quick fairness check
def quick_fairness_check(
    predictions: List[int],
    ground_truth: List[int],
    sensitive_attribute: List[int]
) -> Dict[str, Any]:
    """Quick fairness check"""
    analyzer = FairnessAnalyzer()
    metrics = analyzer.calculate_all_metrics(
        np.array(predictions),
        np.array(ground_truth),
        np.array(sensitive_attribute)
    )
    
    return {
        "overall_fairness": metrics.overall_fairness,
        "is_fair": metrics.is_fair,
        "demographic_parity": metrics.demographic_parity,
        "equal_opportunity": metrics.equal_opportunity,
        "disparate_impact": metrics.disparate_impact,
        "violations": metrics.violations
    }
