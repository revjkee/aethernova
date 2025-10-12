"""
AI Ethics Engine - Main System
Ethical AI frameworks, bias detection, fairness algorithms, and ethical decision-making
ВОССТАНОВЛЕНО для ai-ethics-engine
Критическая система категории: AI Ethics & Governance
"""

import asyncio
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from loguru import logger

from config import config
from src.bias_detector import BiasDetector, BiasType, BiasSeverity
from src.ethical_framework import MultiFrameworkEthicalAnalyzer, EthicalFrameworkType
from src.fairness_metrics import FairnessAnalyzer
from src.decision_validator import EthicalDecisionValidator, RiskLevel


class AIEthicsEngine:
    """
    КРИТИЧЕСКАЯ СИСТЕМА: AI Ethics & Governance
    
    Категория: AI Ethics
    Критические функции: Ethical frameworks, Bias detection, Fairness metrics, Decision validation
    """
    
    def __init__(self):
        self.config = config
        self.is_running = False
        self.emergency_mode = True
        self.components: Dict[str, Any] = {}
        self.metrics: Dict[str, Any] = {}
        
        # Core components
        self.bias_detector: Optional[BiasDetector] = None
        self.ethical_analyzer: Optional[MultiFrameworkEthicalAnalyzer] = None
        self.fairness_analyzer: Optional[FairnessAnalyzer] = None
        self.decision_validator: Optional[EthicalDecisionValidator] = None
        
        # Decision history
        self.decision_history: List[Dict[str, Any]] = []
        self.violation_log: List[Dict[str, Any]] = []
        
        # Логирование
        logger.add(
            f"logs/ai-ethics-engine.emergency.log",
            format="{time:YYYY-MM-DD HH:mm:ss} | EMERGENCY | {level} | {message}",
            level="INFO",
            rotation="1 day",
            retention="30 days"
        )
        
        logger.critical(f"🚨 ВОССТАНОВЛЕНИЕ AI-ETHICS-ENGINE АКТИВИРОВАНО")
    
    async def _initialize_critical_components(self) -> None:
        """Инициализирует критические компоненты AI Ethics"""
        try:
            # Bias Detector
            self.bias_detector = BiasDetector(
                protected_attributes=self.config.protected_attributes
            )
            
            # Ethical Framework Analyzer
            frameworks = [EthicalFrameworkType(f.lower().replace(" ", "_")) 
                         for f in self.config.frameworks]
            self.ethical_analyzer = MultiFrameworkEthicalAnalyzer(frameworks)
            
            # Fairness Analyzer
            self.fairness_analyzer = FairnessAnalyzer(
                fairness_threshold=self.config.fairness_threshold if hasattr(self.config, 'fairness_threshold') else 0.8
            )
            
            # Decision Validator
            self.decision_validator = EthicalDecisionValidator(
                ethical_frameworks=frameworks,
                bias_threshold=self.config.bias_threshold,
                risk_threshold=self.config.risk_threshold
            )
            
            # Регистрация компонентов
            self.components["bias_detector"] = self.bias_detector
            self.components["ethical_analyzer"] = self.ethical_analyzer
            self.components["fairness_analyzer"] = self.fairness_analyzer
            self.components["decision_validator"] = self.decision_validator
            
            logger.critical("⚖️ AI Ethics компоненты инициализированы")
            
        except Exception as e:
            logger.error(f"❌ Ошибка инициализации компонентов: {e}")
            raise
    
    async def emergency_initialize(self) -> bool:
        """ЭКСТРЕННАЯ инициализация системы"""
        try:
            logger.critical(f"🚨 ЭКСТРЕННАЯ ИНИЦИАЛИЗАЦИЯ {self.config.system_name} начата")
            
            # Инициализация компонентов
            await self._initialize_critical_components()
            
            # Настройка мониторинга
            await self._emergency_monitoring_setup()
            
            logger.critical(f"✅ ЭКСТРЕННАЯ ИНИЦИАЛИЗАЦИЯ {self.config.system_name} ЗАВЕРШЕНА")
            return True
            
        except Exception as e:
            logger.critical(f"💀 КРИТИЧЕСКАЯ ОШИБКА ЭКСТРЕННОЙ ИНИЦИАЛИЗАЦИИ: {e}")
            return False
    
    async def emergency_start(self) -> None:
        """ЭКСТРЕННЫЙ запуск системы"""
        if not await self.emergency_initialize():
            raise RuntimeError("💀 ЭКСТРЕННАЯ ИНИЦИАЛИЗАЦИЯ ПРОВАЛЕНА")
        
        self.is_running = True
        self.emergency_mode = True
        
        logger.critical(f"🚨 {self.config.system_name} ЗАПУЩЕНА В ЭКСТРЕННОМ РЕЖИМЕ")
        
        try:
            while self.is_running:
                await self._emergency_processing_loop()
                await asyncio.sleep(1.0)
                
        except KeyboardInterrupt:
            logger.critical("⚠️ ПОЛУЧЕН СИГНАЛ ЭКСТРЕННОЙ ОСТАНОВКИ")
        finally:
            await self.emergency_stop()
    
    async def emergency_stop(self) -> None:
        """ЭКСТРЕННАЯ остановка системы"""
        logger.critical("🛑 ЭКСТРЕННАЯ ОСТАНОВКА СИСТЕМЫ...")
        self.is_running = False
        
        # Сохранение данных
        await self._save_decision_history()
        await self._save_violation_log()
        
        logger.critical(f"🔒 {self.config.system_name} ЭКСТРЕННО ОСТАНОВЛЕНА")
    
    async def _emergency_monitoring_setup(self) -> None:
        """Настройка экстренного мониторинга"""
        self.metrics = {
            "start_time": datetime.now().isoformat(),
            "emergency_mode": True,
            "decisions_validated": 0,
            "decisions_approved": 0,
            "decisions_rejected": 0,
            "bias_detections": 0,
            "ethical_violations": 0,
            "fairness_violations": 0,
            "high_risk_decisions": 0,
            "human_reviews_required": 0,
            "error_count": 0,
            "last_health_check": datetime.now().isoformat(),
            "uptime_seconds": 0
        }
        
        logger.critical("📊 Экстренный мониторинг активирован")
    
    async def _emergency_processing_loop(self) -> None:
        """Основной цикл экстренной обработки"""
        # Обновление метрик
        self.metrics["last_health_check"] = datetime.now().isoformat()
        start_time = datetime.fromisoformat(self.metrics["start_time"])
        self.metrics["uptime_seconds"] = (datetime.now() - start_time).total_seconds()
    
    # Public API
    
    async def detect_bias(self, text: str) -> Dict[str, Any]:
        """Обнаружение предвзятости в тексте"""
        if not self.bias_detector:
            raise RuntimeError("Bias detector not initialized")
        
        result = self.bias_detector.detect_text_bias(text)
        
        if result.has_bias:
            self.metrics["bias_detections"] += 1
            
            # Log violation if severe
            if result.severity.value >= BiasSeverity.HIGH.value:
                await self._log_violation("bias", {
                    "text": text[:200],
                    "bias_type": result.bias_type.value,
                    "severity": result.severity.name,
                    "score": result.score
                })
        
        logger.info(f"Bias detection: {result.has_bias} (type: {result.bias_type.value}, score: {result.score:.2f})")
        
        return {
            "has_bias": result.has_bias,
            "bias_type": result.bias_type.value,
            "severity": result.severity.name,
            "score": result.score,
            "evidence": result.evidence,
            "recommendation": result.recommendation
        }
    
    async def analyze_ethics(self, decision: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Анализ этичности решения по всем фреймворкам"""
        if not self.ethical_analyzer:
            raise RuntimeError("Ethical analyzer not initialized")
        
        analysis = self.ethical_analyzer.analyze(decision, context)
        
        if not analysis["is_ethical"]:
            self.metrics["ethical_violations"] += 1
        
        logger.info(f"Ethical analysis: {analysis['overall_score']:.2f} "
                   f"(Agreement: {analysis['framework_agreement']})")
        
        return analysis
    
    async def calculate_fairness(
        self,
        predictions: List[int],
        ground_truth: List[int],
        sensitive_attribute: List[int]
    ) -> Dict[str, Any]:
        """Расчет метрик справедливости"""
        if not self.fairness_analyzer:
            raise RuntimeError("Fairness analyzer not initialized")
        
        import numpy as np
        metrics = self.fairness_analyzer.calculate_all_metrics(
            np.array(predictions),
            np.array(ground_truth),
            np.array(sensitive_attribute)
        )
        
        if not metrics.is_fair:
            self.metrics["fairness_violations"] += 1
        
        logger.info(f"Fairness analysis: {metrics.overall_fairness:.2f} (Fair: {metrics.is_fair})")
        
        return {
            "overall_fairness": metrics.overall_fairness,
            "is_fair": metrics.is_fair,
            "demographic_parity": metrics.demographic_parity,
            "equal_opportunity": metrics.equal_opportunity,
            "equalized_odds": metrics.equalized_odds,
            "disparate_impact": metrics.disparate_impact,
            "violations": metrics.violations
        }
    
    async def validate_decision(
        self,
        decision: Dict[str, Any],
        context: Dict[str, Any],
        agent_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Полная валидация этического решения"""
        if not self.decision_validator:
            raise RuntimeError("Decision validator not initialized")
        
        result = self.decision_validator.validate_decision(decision, context, agent_id)
        
        # Update metrics
        self.metrics["decisions_validated"] += 1
        if result.is_approved:
            self.metrics["decisions_approved"] += 1
        else:
            self.metrics["decisions_rejected"] += 1
        
        if result.risk_level.value in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]:
            self.metrics["high_risk_decisions"] += 1
        
        if result.requires_human_review:
            self.metrics["human_reviews_required"] += 1
        
        # Log decision
        decision_record = {
            "timestamp": datetime.now().isoformat(),
            "agent_id": agent_id,
            "decision": decision,
            "context": context,
            "result": {
                "approved": result.is_approved,
                "risk_level": result.risk_level.value,
                "ethical_score": result.ethical_score,
                "bias_score": result.bias_score,
                "fairness_score": result.fairness_score
            }
        }
        self.decision_history.append(decision_record)
        
        # Log violations
        if result.violations:
            await self._log_violation("decision", {
                "agent_id": agent_id,
                "decision": decision.get("action"),
                "violations": result.violations,
                "risk_level": result.risk_level.value
            })
        
        logger.info(f"Decision validated: {'APPROVED' if result.is_approved else 'REJECTED'} "
                   f"(Risk: {result.risk_level.value})")
        
        return {
            "is_approved": result.is_approved,
            "risk_level": result.risk_level.value,
            "ethical_score": result.ethical_score,
            "bias_score": result.bias_score,
            "fairness_score": result.fairness_score,
            "justification": result.justification,
            "violations": result.violations,
            "recommendations": result.recommendations,
            "requires_human_review": result.requires_human_review
        }
    
    async def _log_violation(self, violation_type: str, details: Dict[str, Any]) -> None:
        """Логирование этического нарушения"""
        violation = {
            "timestamp": datetime.now().isoformat(),
            "type": violation_type,
            "details": details
        }
        self.violation_log.append(violation)
        
        logger.warning(f"⚠️ Ethical violation logged: {violation_type}")
    
    async def _save_decision_history(self) -> None:
        """Сохранение истории решений"""
        try:
            Path("data").mkdir(exist_ok=True)
            
            with open("data/decision_history.json", "w") as f:
                json.dump(self.decision_history, f, indent=2, default=str)
            
            logger.info(f"Saved {len(self.decision_history)} decisions to history")
            
        except Exception as e:
            logger.error(f"Failed to save decision history: {e}")
    
    async def _save_violation_log(self) -> None:
        """Сохранение лога нарушений"""
        try:
            Path("data").mkdir(exist_ok=True)
            
            with open("data/violation_log.json", "w") as f:
                json.dump(self.violation_log, f, indent=2, default=str)
            
            logger.info(f"Saved {len(self.violation_log)} violations to log")
            
        except Exception as e:
            logger.error(f"Failed to save violation log: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Получение статуса системы"""
        status = {
            "system_name": self.config.system_name,
            "version": self.config.version,
            "category": self.config.category,
            "emergency_mode": self.emergency_mode,
            "is_running": self.is_running,
            "components": list(self.components.keys()),
            "metrics": self.metrics,
            "uptime": self.metrics.get("uptime_seconds", 0),
            "decision_history_size": len(self.decision_history),
            "violation_log_size": len(self.violation_log)
        }
        
        return status
    
    async def emergency_health_check(self) -> Dict[str, Any]:
        """ЭКСТРЕННАЯ проверка работоспособности"""
        checks = {
            "system_running": self.is_running,
            "emergency_mode_active": self.emergency_mode,
            "components_initialized": len(self.components) > 0,
            "bias_detector_initialized": self.bias_detector is not None,
            "ethical_analyzer_initialized": self.ethical_analyzer is not None,
            "fairness_analyzer_initialized": self.fairness_analyzer is not None,
            "decision_validator_initialized": self.decision_validator is not None,
        }
        
        # Определяем общий статус
        if all(checks.values()):
            status = "emergency_operational" if self.emergency_mode else "healthy"
        else:
            status = "critical_failure"
        
        return {
            "status": status,
            "emergency_mode": self.emergency_mode,
            "timestamp": datetime.now().isoformat(),
            "checks": checks,
            "metrics": self.metrics,
            "uptime_seconds": self.metrics.get("uptime_seconds", 0)
        }


# API для экстренного создания экземпляра
async def create_emergency_ethics_instance() -> AIEthicsEngine:
    """Создает экземпляр системы в экстренном режиме"""
    instance = AIEthicsEngine()
    await instance.emergency_initialize()
    return instance


# Экстренный запуск
async def emergency_main():
    """Экстренный запуск системы"""
    logger.critical("🚨 АКТИВАЦИЯ ЭКСТРЕННОГО РЕЖИМА AI-ETHICS-ENGINE")
    engine = AIEthicsEngine()
    await engine.emergency_start()


# Для прямого запуска
async def main():
    await emergency_main()


if __name__ == "__main__":
    asyncio.run(main())
