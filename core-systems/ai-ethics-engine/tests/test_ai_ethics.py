"""
Comprehensive Tests for AI Ethics Engine
ВОССТАНОВЛЕНО - Test Suite для ai-ethics-engine
"""

import pytest
import asyncio
import numpy as np
from pathlib import Path

# Import the components we're testing
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.bias_detector import BiasDetector, BiasType, BiasSeverity
from src.ethical_framework import (
    UtilitarianFramework,
    DeontologicalFramework,
    VirtueEthicsFramework,
    CareEthicsFramework,
    MultiFrameworkEthicalAnalyzer,
    EthicalFrameworkType
)
from src.fairness_metrics import FairnessAnalyzer
from src.decision_validator import EthicalDecisionValidator, RiskLevel
from main import AIEthicsEngine


class TestBiasDetector:
    """Tests for Bias Detection"""
    
    def test_gender_bias_detection(self):
        """Test detection of gender bias"""
        detector = BiasDetector()
        
        biased_text = "Women can't be good engineers. Men are naturally better at math."
        result = detector.detect_text_bias(biased_text)
        
        assert result.has_bias is True
        assert result.bias_type == BiasType.GENDER
        assert result.severity.value >= BiasSeverity.MEDIUM.value
        assert result.score > 0.4
    
    def test_race_bias_detection(self):
        """Test detection of racial bias"""
        detector = BiasDetector()
        
        biased_text = "Race determines intelligence and ability."
        result = detector.detect_text_bias(biased_text)
        
        assert result.has_bias is True
        assert result.bias_type == BiasType.RACE
        assert result.score > 0.3
    
    def test_age_bias_detection(self):
        """Test detection of age bias"""
        detector = BiasDetector()
        
        biased_text = "Old people can't learn new technology. Young people don't have experience."
        result = detector.detect_text_bias(biased_text)
        
        assert result.has_bias is True
        assert result.bias_type == BiasType.AGE
    
    def test_no_bias(self):
        """Test that neutral text shows no bias"""
        detector = BiasDetector()
        
        neutral_text = "The software update improves performance and adds new features."
        result = detector.detect_text_bias(neutral_text)
        
        assert result.has_bias is False or result.severity == BiasSeverity.NONE
        assert result.score < 0.3
    
    def test_statistical_bias_detection(self):
        """Test statistical bias detection"""
        detector = BiasDetector()
        
        # Create biased predictions (group 0 gets 80% positive, group 1 gets 40%)
        predictions = np.array([1]*80 + [0]*20 + [1]*40 + [0]*60)
        sensitive_attr = np.array([0]*100 + [1]*100)
        
        result = detector.detect_statistical_bias(predictions, sensitive_attr)
        
        assert result.has_bias is True
        assert result.severity.value >= BiasSeverity.MEDIUM.value
        assert result.score > 0.3  # Disparate impact < 0.7
    
    def test_statistical_no_bias(self):
        """Test statistical detection with fair predictions"""
        detector = BiasDetector()
        
        # Fair predictions (both groups get 50% positive)
        predictions = np.array([1]*50 + [0]*50 + [1]*50 + [0]*50)
        sensitive_attr = np.array([0]*100 + [1]*100)
        
        result = detector.detect_statistical_bias(predictions, sensitive_attr)
        
        assert result.has_bias is False
        assert result.severity == BiasSeverity.NONE


class TestEthicalFrameworks:
    """Tests for Ethical Frameworks"""
    
    def test_utilitarian_framework(self):
        """Test Utilitarian ethics"""
        framework = UtilitarianFramework()
        
        decision = {
            "action": "Implement vaccination program",
            "consequences": {
                "positive": ["protect 95% of population", "reduce healthcare costs"],
                "negative": ["small risk for 1%"]
            },
            "affected_parties": list(range(1000))  # 1000 people
        }
        context = {"minority_harm": False}
        
        result = framework.evaluate(decision, context)
        
        assert result.is_ethical is True
        assert result.score > 0.6
    
    def test_deontological_framework(self):
        """Test Deontological ethics"""
        framework = DeontologicalFramework()
        
        decision = {
            "action": "Tell the truth to patient",
            "rules_followed": ["truth", "respect_autonomy"],
            "rules_violated": [],
            "universalizable": True
        }
        context = {}
        
        result = framework.evaluate(decision, context)
        
        assert result.is_ethical is True
        assert result.score > 0.7
    
    def test_virtue_ethics_framework(self):
        """Test Virtue Ethics"""
        framework = VirtueEthicsFramework()
        
        decision = {
            "action": "Help colleague with project",
            "virtues_demonstrated": ["compassion", "wisdom", "integrity"],
            "vices_demonstrated": [],
            "wisdom_applied": True
        }
        context = {"character_consistent": True}
        
        result = framework.evaluate(decision, context)
        
        assert result.is_ethical is True
        assert result.score > 0.7
    
    def test_care_ethics_framework(self):
        """Test Care Ethics"""
        framework = CareEthicsFramework()
        
        decision = {
            "action": "Provide support to vulnerable person",
            "care_demonstrated": True,
            "empathy_shown": True,
            "protects_vulnerable": True,
            "relationships_affected": [
                {"impact": "positive"},
                {"impact": "positive"}
            ]
        }
        context = {"vulnerable_parties": ["elderly patient"]}
        
        result = framework.evaluate(decision, context)
        
        assert result.is_ethical is True
        assert result.score > 0.6
    
    def test_multi_framework_analyzer(self):
        """Test multi-framework analysis"""
        analyzer = MultiFrameworkEthicalAnalyzer()
        
        decision = {
            "action": "Donate to charity",
            "consequences": {
                "positive": ["help people in need"],
                "negative": []
            },
            "affected_parties": list(range(100)),
            "rules_followed": ["beneficence"],
            "rules_violated": [],
            "virtues_demonstrated": ["compassion"],
            "care_demonstrated": True,
            "empathy_shown": True
        }
        context = {}
        
        analysis = analyzer.analyze(decision, context)
        
        assert analysis["is_ethical"] is True
        assert analysis["overall_score"] > 0.6
        assert len(analysis["evaluations"]) > 0


class TestFairnessMetrics:
    """Tests for Fairness Metrics"""
    
    def test_demographic_parity(self):
        """Test demographic parity calculation"""
        analyzer = FairnessAnalyzer()
        
        # Fair predictions (50% positive for both groups)
        predictions = np.array([1]*50 + [0]*50 + [1]*50 + [0]*50)
        ground_truth = np.array([1]*60 + [0]*40 + [1]*60 + [0]*40)
        sensitive_attr = np.array([0]*100 + [1]*100)
        
        metrics = analyzer.calculate_all_metrics(predictions, ground_truth, sensitive_attr)
        
        assert metrics.demographic_parity >= 0.9
        assert metrics.is_fair is True
    
    def test_equal_opportunity(self):
        """Test equal opportunity (TPR parity)"""
        analyzer = FairnessAnalyzer()
        
        # Create data with equal TPR
        predictions = np.array([1]*45 + [0]*15 + [0]*40 + [1]*45 + [0]*15 + [0]*40)
        ground_truth = np.array([1]*60 + [0]*40 + [1]*60 + [0]*40)
        sensitive_attr = np.array([0]*100 + [1]*100)
        
        metrics = analyzer.calculate_all_metrics(predictions, ground_truth, sensitive_attr)
        
        assert metrics.equal_opportunity >= 0.8
    
    def test_disparate_impact(self):
        """Test disparate impact (80% rule)"""
        analyzer = FairnessAnalyzer()
        
        # Biased predictions violating 80% rule
        predictions = np.array([1]*80 + [0]*20 + [1]*40 + [0]*60)
        ground_truth = np.array([1]*60 + [0]*40 + [1]*60 + [0]*40)
        sensitive_attr = np.array([0]*100 + [1]*100)
        
        metrics = analyzer.calculate_all_metrics(predictions, ground_truth, sensitive_attr)
        
        assert metrics.disparate_impact < 0.8
        assert metrics.is_fair is False
        assert len(metrics.violations) > 0
    
    def test_fairness_report_generation(self):
        """Test fairness report generation"""
        analyzer = FairnessAnalyzer()
        
        predictions = np.array([1]*50 + [0]*50 + [1]*50 + [0]*50)
        ground_truth = np.array([1]*60 + [0]*40 + [1]*60 + [0]*40)
        sensitive_attr = np.array([0]*100 + [1]*100)
        
        metrics = analyzer.calculate_all_metrics(predictions, ground_truth, sensitive_attr)
        report = analyzer.generate_fairness_report(metrics)
        
        assert "FAIRNESS ANALYSIS REPORT" in report
        assert "Overall Fairness Score" in report


class TestDecisionValidator:
    """Tests for Decision Validation"""
    
    def test_ethical_decision_approval(self):
        """Test approval of ethical decision"""
        validator = EthicalDecisionValidator()
        
        decision = {
            "action": "Provide healthcare to all citizens",
            "description": "Universal healthcare program for equal access",
            "consequences": {
                "positive": ["improved health outcomes", "reduced inequality"],
                "negative": []
            },
            "affected_parties": list(range(10000)),
            "rules_followed": ["beneficence", "justice"],
            "virtues_demonstrated": ["compassion", "wisdom"],
            "care_demonstrated": True,
            "empathy_shown": True
        }
        context = {"potential_harm": {"severity": "low"}}
        
        result = validator.validate_decision(decision, context)
        
        assert result.is_approved is True
        assert result.ethical_score > 0.6
        assert result.risk_level.value in [RiskLevel.MINIMAL.value, RiskLevel.LOW.value]
    
    def test_unethical_decision_rejection(self):
        """Test rejection of unethical decision"""
        validator = EthicalDecisionValidator()
        
        decision = {
            "action": "Discriminate based on race",
            "description": "This decision involves racial discrimination and bias",
            "consequences": {
                "positive": [],
                "negative": ["harm to minorities", "perpetuate inequality"]
            },
            "affected_parties": list(range(100)),
            "rules_violated": ["no_harm", "justice", "respect_autonomy"],
            "vices_demonstrated": ["injustice"]
        }
        context = {
            "potential_harm": {"severity": "critical"},
            "minority_harm": True
        }
        
        result = validator.validate_decision(decision, context)
        
        assert result.is_approved is False
        assert result.risk_level.value in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]
        assert len(result.violations) > 0
    
    def test_high_risk_decision_requires_review(self):
        """Test that high-risk decisions require human review"""
        validator = EthicalDecisionValidator()
        
        decision = {
            "action": "Deploy autonomous weapons system",
            "description": "AI system for military applications",
            "consequences": {
                "positive": ["defense capability"],
                "negative": ["potential for misuse", "loss of life"]
            },
            "affected_parties": list(range(10000)),
            "irreversible": True
        }
        context = {"potential_harm": {"severity": "critical"}}
        
        result = validator.validate_decision(decision, context)
        
        assert result.requires_human_review is True
        assert result.risk_level.value in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]
    
    def test_validation_report_generation(self):
        """Test validation report generation"""
        validator = EthicalDecisionValidator()
        
        decision = {
            "action": "Test decision",
            "description": "Sample decision for testing",
            "consequences": {"positive": ["benefit"], "negative": []},
            "affected_parties": [1, 2, 3]
        }
        context = {}
        
        result = validator.validate_decision(decision, context)
        report = validator.generate_validation_report(result)
        
        assert "ETHICAL DECISION VALIDATION REPORT" in report
        assert "Status:" in report


@pytest.mark.asyncio
class TestAIEthicsEngine:
    """Tests for main AI Ethics Engine"""
    
    async def test_engine_initialization(self):
        """Test engine initialization"""
        engine = AIEthicsEngine()
        assert engine is not None
        assert engine.emergency_mode is True
        assert engine.is_running is False
        
        # Initialize
        success = await engine.emergency_initialize()
        assert success is True
        assert engine.bias_detector is not None
        assert engine.ethical_analyzer is not None
        assert engine.fairness_analyzer is not None
        assert engine.decision_validator is not None
    
    async def test_detect_bias_api(self):
        """Test bias detection API"""
        engine = AIEthicsEngine()
        await engine.emergency_initialize()
        
        biased_text = "Women are not good at technical roles."
        result = await engine.detect_bias(biased_text)
        
        assert result["has_bias"] is True
        assert result["bias_type"] == BiasType.GENDER.value
        assert result["score"] > 0.3
    
    async def test_analyze_ethics_api(self):
        """Test ethics analysis API"""
        engine = AIEthicsEngine()
        await engine.emergency_initialize()
        
        decision = {
            "action": "Help others",
            "consequences": {"positive": ["benefit"], "negative": []},
            "affected_parties": [1, 2, 3],
            "rules_followed": ["beneficence"],
            "virtues_demonstrated": ["compassion"]
        }
        context = {}
        
        analysis = await engine.analyze_ethics(decision, context)
        
        assert "overall_score" in analysis
        assert "is_ethical" in analysis
        assert analysis["overall_score"] > 0
    
    async def test_calculate_fairness_api(self):
        """Test fairness calculation API"""
        engine = AIEthicsEngine()
        await engine.emergency_initialize()
        
        predictions = [1]*50 + [0]*50 + [1]*50 + [0]*50
        ground_truth = [1]*60 + [0]*40 + [1]*60 + [0]*40
        sensitive_attr = [0]*100 + [1]*100
        
        result = await engine.calculate_fairness(predictions, ground_truth, sensitive_attr)
        
        assert "overall_fairness" in result
        assert "is_fair" in result
        assert result["overall_fairness"] >= 0
    
    async def test_validate_decision_api(self):
        """Test decision validation API"""
        engine = AIEthicsEngine()
        await engine.emergency_initialize()
        
        decision = {
            "action": "Provide healthcare",
            "description": "Healthcare for all",
            "consequences": {"positive": ["health"], "negative": []},
            "affected_parties": [1, 2, 3],
            "rules_followed": ["beneficence"]
        }
        context = {}
        
        result = await engine.validate_decision(decision, context, "agent_1")
        
        assert "is_approved" in result
        assert "risk_level" in result
        assert "ethical_score" in result
        assert engine.metrics["decisions_validated"] == 1
    
    async def test_health_check(self):
        """Test emergency health check"""
        engine = AIEthicsEngine()
        await engine.emergency_initialize()
        
        health = await engine.emergency_health_check()
        
        assert health["status"] == "emergency_operational"
        assert health["emergency_mode"] is True
        assert health["checks"]["bias_detector_initialized"] is True
        assert health["checks"]["ethical_analyzer_initialized"] is True
    
    async def test_get_status(self):
        """Test get status"""
        engine = AIEthicsEngine()
        await engine.emergency_initialize()
        
        # Validate a decision to update metrics
        decision = {"action": "test", "consequences": {"positive": [], "negative": []}}
        await engine.validate_decision(decision, {})
        
        status = engine.get_status()
        
        assert status["system_name"] == "ai-ethics-engine"
        assert status["category"] == "AI Ethics & Governance"
        assert status["emergency_mode"] is True
        assert status["metrics"]["decisions_validated"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
