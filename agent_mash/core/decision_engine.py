# agent_mash/core/decision_engine.py

from typing import Dict, Any, List, Optional, Union, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import asyncio
import numpy as np
import json
from datetime import datetime, timedelta
import logging
from collections import deque
import hashlib

logger = logging.getLogger(__name__)

class DecisionStrategy(Enum):
    RULE_BASED = "rule_based"
    ML_BASED = "ml_based" 
    HYBRID = "hybrid"
    CONSENSUS = "consensus"
    WEIGHTED_VOTING = "weighted_voting"

class ConfidenceLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

class DecisionUrgency(Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class DecisionContext:
    """Контекст для принятия решения"""
    agent_id: str
    task_type: str
    input_data: Dict[str, Any]
    constraints: Dict[str, Any] = field(default_factory=dict)
    deadline: Optional[datetime] = None
    urgency: DecisionUrgency = DecisionUrgency.NORMAL
    historical_context: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class DecisionRule:
    """Правило для принятия решений"""
    name: str
    condition: Callable[[Dict[str, Any]], bool]
    action: Callable[[Dict[str, Any]], Any]
    priority: int = 100
    confidence_boost: float = 0.0
    enabled: bool = True

@dataclass
class DecisionOption:
    """Вариант решения"""
    name: str
    value: Any
    confidence: float
    estimated_outcome: Dict[str, float]
    cost: float = 0.0
    risk_level: float = 0.0
    execution_time: float = 0.0

@dataclass  
class DecisionResult:
    """Результат принятия решения"""
    chosen_option: DecisionOption
    alternatives: List[DecisionOption]
    confidence: float
    confidence_level: ConfidenceLevel
    reasoning: List[str]
    decision_time: float
    strategy_used: DecisionStrategy
    metadata: Dict[str, Any] = field(default_factory=dict)

class DecisionMaker(ABC):
    """Абстрактный класс для принятия решений"""
    
    @abstractmethod
    async def make_decision(self, context: DecisionContext) -> DecisionResult:
        pass
    
    @abstractmethod
    def get_confidence_threshold(self) -> float:
        pass

class RuleBasedDecisionMaker(DecisionMaker):
    """Принятие решений на основе правил"""
    
    def __init__(self, confidence_threshold: float = 0.7):
        self.rules: List[DecisionRule] = []
        self.confidence_threshold = confidence_threshold
        
    def add_rule(self, rule: DecisionRule):
        """Добавление правила"""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority, reverse=True)
        
    async def make_decision(self, context: DecisionContext) -> DecisionResult:
        """Принятие решения на основе правил"""
        start_time = datetime.utcnow()
        options = []
        reasoning = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
                
            try:
                if rule.condition(context.input_data):
                    result = rule.action(context.input_data)
                    confidence = min(0.8 + rule.confidence_boost, 1.0)
                    
                    option = DecisionOption(
                        name=f"rule_{rule.name}",
                        value=result,
                        confidence=confidence,
                        estimated_outcome={"success_probability": confidence},
                        cost=0.0,
                        risk_level=1.0 - confidence
                    )
                    options.append(option)
                    reasoning.append(f"Rule '{rule.name}' matched with confidence {confidence}")
                    
                    if confidence >= self.confidence_threshold:
                        break
                        
            except Exception as e:
                logger.error(f"Error in rule '{rule.name}': {e}")
                reasoning.append(f"Rule '{rule.name}' failed: {e}")
                
        if not options:
            # Создаем дефолтный вариант
            default_option = DecisionOption(
                name="default",
                value=None,
                confidence=0.1,
                estimated_outcome={"success_probability": 0.1},
                risk_level=0.9
            )
            options.append(default_option)
            reasoning.append("No rules matched - using default option")
            
        chosen = max(options, key=lambda o: o.confidence)
        confidence_level = self._calculate_confidence_level(chosen.confidence)
        
        decision_time = (datetime.utcnow() - start_time).total_seconds()
        
        return DecisionResult(
            chosen_option=chosen,
            alternatives=options[1:] if len(options) > 1 else [],
            confidence=chosen.confidence,
            confidence_level=confidence_level,
            reasoning=reasoning,
            decision_time=decision_time,
            strategy_used=DecisionStrategy.RULE_BASED
        )
        
    def get_confidence_threshold(self) -> float:
        return self.confidence_threshold
        
    def _calculate_confidence_level(self, confidence: float) -> ConfidenceLevel:
        """Расчет уровня уверенности"""
        if confidence >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif confidence >= 0.7:
            return ConfidenceLevel.HIGH
        elif confidence >= 0.5:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW

class MLBasedDecisionMaker(DecisionMaker):
    """Принятие решений на основе машинного обучения"""
    
    def __init__(self, model_path: Optional[str] = None, confidence_threshold: float = 0.8):
        self.model = None  # Здесь будет ML модель
        self.confidence_threshold = confidence_threshold
        self.feature_extractors: List[Callable] = []
        self.prediction_history = deque(maxlen=1000)
        
    def add_feature_extractor(self, extractor: Callable[[Dict[str, Any]], np.ndarray]):
        """Добавление экстрактора признаков"""
        self.feature_extractors.append(extractor)
        
    async def make_decision(self, context: DecisionContext) -> DecisionResult:
        """Принятие решения на основе ML модели"""
        start_time = datetime.utcnow()
        reasoning = []
        
        try:
            # Извлечение признаков
            features = await self._extract_features(context.input_data)
            reasoning.append(f"Extracted {len(features)} features")
            
            # Предсказание (заглушка - здесь будет реальная ML модель)
            predictions = await self._predict(features, context)
            
            # Создание вариантов решения из предсказаний
            options = []
            for i, (pred, conf) in enumerate(predictions):
                option = DecisionOption(
                    name=f"ml_option_{i}",
                    value=pred,
                    confidence=conf,
                    estimated_outcome={"success_probability": conf},
                    risk_level=1.0 - conf
                )
                options.append(option)
                
            if not options:
                raise ValueError("No predictions generated")
                
            # Выбор лучшего варианта
            chosen = max(options, key=lambda o: o.confidence)
            confidence_level = self._calculate_confidence_level(chosen.confidence)
            
            # Сохранение в истории
            self.prediction_history.append({
                "timestamp": datetime.utcnow(),
                "context": context.task_type,
                "prediction": chosen.value,
                "confidence": chosen.confidence
            })
            
            decision_time = (datetime.utcnow() - start_time).total_seconds()
            reasoning.append(f"Selected option with confidence {chosen.confidence}")
            
            return DecisionResult(
                chosen_option=chosen,
                alternatives=options[1:] if len(options) > 1 else [],
                confidence=chosen.confidence,
                confidence_level=confidence_level,
                reasoning=reasoning,
                decision_time=decision_time,
                strategy_used=DecisionStrategy.ML_BASED
            )
            
        except Exception as e:
            logger.error(f"ML decision making failed: {e}")
            # Возврат к простому решению
            fallback_option = DecisionOption(
                name="fallback",
                value="default_action",
                confidence=0.3,
                estimated_outcome={"success_probability": 0.3},
                risk_level=0.7
            )
            
            decision_time = (datetime.utcnow() - start_time).total_seconds()
            
            return DecisionResult(
                chosen_option=fallback_option,
                alternatives=[],
                confidence=0.3,
                confidence_level=ConfidenceLevel.LOW,
                reasoning=[f"ML prediction failed: {e}", "Using fallback option"],
                decision_time=decision_time,
                strategy_used=DecisionStrategy.ML_BASED
            )
            
    async def _extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Извлечение признаков из данных"""
        if not self.feature_extractors:
            # Простое извлечение признаков по умолчанию
            numeric_values = []
            for key, value in data.items():
                if isinstance(value, (int, float)):
                    numeric_values.append(value)
                elif isinstance(value, str):
                    numeric_values.append(len(value))
            return np.array(numeric_values) if numeric_values else np.array([0.0])
        
        # Применение пользовательских экстракторов
        all_features = []
        for extractor in self.feature_extractors:
            try:
                features = extractor(data)
                all_features.extend(features)
            except Exception as e:
                logger.warning(f"Feature extractor failed: {e}")
                
        return np.array(all_features) if all_features else np.array([0.0])
        
    async def _predict(self, features: np.ndarray, 
                      context: DecisionContext) -> List[Tuple[Any, float]]:
        """Предсказание (заглушка для ML модели)"""
        # Здесь должна быть реальная ML модель
        # Сейчас генерируем случайные предсказания для демонстрации
        
        predictions = []
        num_options = min(3, max(1, len(features)))
        
        for i in range(num_options):
            # Простая эвристика на основе признаков
            confidence = min(0.9, 0.5 + np.mean(features) * 0.1)
            confidence = max(0.1, confidence + np.random.normal(0, 0.1))
            
            if context.task_type == "classification":
                prediction = f"class_{i}"
            elif context.task_type == "regression":
                prediction = float(np.mean(features) + np.random.normal(0, 0.5))
            else:
                prediction = f"action_{i}"
                
            predictions.append((prediction, confidence))
            
        return sorted(predictions, key=lambda x: x[1], reverse=True)
        
    def get_confidence_threshold(self) -> float:
        return self.confidence_threshold
        
    def _calculate_confidence_level(self, confidence: float) -> ConfidenceLevel:
        """Расчет уровня уверенности"""
        if confidence >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif confidence >= 0.75:
            return ConfidenceLevel.HIGH  
        elif confidence >= 0.5:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW

class ConsensusDecisionMaker(DecisionMaker):
    """Принятие решений на основе консенсуса нескольких методов"""
    
    def __init__(self, decision_makers: List[DecisionMaker], 
                 confidence_threshold: float = 0.75):
        self.decision_makers = decision_makers
        self.confidence_threshold = confidence_threshold
        self.weights = [1.0] * len(decision_makers)  # Равные веса по умолчанию
        
    def set_weights(self, weights: List[float]):
        """Установка весов для различных методов принятия решений"""
        if len(weights) != len(self.decision_makers):
            raise ValueError("Number of weights must match number of decision makers")
        self.weights = weights
        
    async def make_decision(self, context: DecisionContext) -> DecisionResult:
        """Принятие решения на основе консенсуса"""
        start_time = datetime.utcnow()
        
        # Получение решений от всех методов
        individual_results = []
        tasks = []
        
        for maker in self.decision_makers:
            task = asyncio.create_task(maker.make_decision(context))
            tasks.append(task)
            
        try:
            individual_results = await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logger.error(f"Error in consensus decision making: {e}")
            
        # Фильтрация успешных результатов
        valid_results = []
        reasoning = []
        
        for i, result in enumerate(individual_results):
            if isinstance(result, DecisionResult):
                valid_results.append((result, self.weights[i]))
                reasoning.append(
                    f"Decision maker {i}: {result.chosen_option.name} "
                    f"(confidence: {result.confidence:.3f})"
                )
            else:
                reasoning.append(f"Decision maker {i} failed: {result}")
                
        if not valid_results:
            # Все методы отказали - возвращаем дефолтное решение
            fallback_option = DecisionOption(
                name="consensus_fallback",
                value="no_consensus",
                confidence=0.1,
                estimated_outcome={"success_probability": 0.1},
                risk_level=0.9
            )
            
            decision_time = (datetime.utcnow() - start_time).total_seconds()
            
            return DecisionResult(
                chosen_option=fallback_option,
                alternatives=[],
                confidence=0.1,
                confidence_level=ConfidenceLevel.LOW,
                reasoning=reasoning + ["All decision makers failed - using fallback"],
                decision_time=decision_time,
                strategy_used=DecisionStrategy.CONSENSUS
            )
            
        # Расчет консенсуса
        consensus_result = self._calculate_consensus(valid_results)
        consensus_result.reasoning.extend(reasoning)
        
        decision_time = (datetime.utcnow() - start_time).total_seconds()
        consensus_result.decision_time = decision_time
        consensus_result.strategy_used = DecisionStrategy.CONSENSUS
        
        return consensus_result
        
    def _calculate_consensus(self, results: List[Tuple[DecisionResult, float]]) -> DecisionResult:
        """Расчет консенсусного решения"""
        # Собираем все варианты с их весами
        weighted_options = {}
        all_alternatives = []
        
        total_weight = sum(weight for _, weight in results)
        
        for result, weight in results:
            option = result.chosen_option
            key = str(option.value)  # Простой способ группировки похожих вариантов
            
            if key not in weighted_options:
                weighted_options[key] = {
                    "option": option,
                    "total_confidence": 0.0,
                    "total_weight": 0.0,
                    "count": 0
                }
                
            # Взвешенное накопление уверенности
            weighted_confidence = option.confidence * weight
            weighted_options[key]["total_confidence"] += weighted_confidence
            weighted_options[key]["total_weight"] += weight
            weighted_options[key]["count"] += 1
            
            all_alternatives.extend(result.alternatives)
            
        # Выбор лучшего варианта
        best_option = None
        best_score = 0.0
        
        final_options = []
        
        for data in weighted_options.values():
            # Нормализованная уверенность
            normalized_confidence = data["total_confidence"] / data["total_weight"]
            
            # Бонус за консенсус (больше методов согласны)
            consensus_bonus = data["count"] / len(results) * 0.1
            
            final_confidence = min(1.0, normalized_confidence + consensus_bonus)
            
            option = DecisionOption(
                name=f"consensus_{data['option'].name}",
                value=data["option"].value,
                confidence=final_confidence,
                estimated_outcome=data["option"].estimated_outcome,
                cost=data["option"].cost,
                risk_level=data["option"].risk_level
            )
            
            final_options.append(option)
            
            if final_confidence > best_score:
                best_score = final_confidence
                best_option = option
                
        confidence_level = self._calculate_confidence_level(best_option.confidence)
        
        return DecisionResult(
            chosen_option=best_option,
            alternatives=final_options[1:] if len(final_options) > 1 else [],
            confidence=best_option.confidence,
            confidence_level=confidence_level,
            reasoning=[],  # Будет заполнено в вызывающем методе
            decision_time=0.0,  # Будет установлено в вызывающем методе
            strategy_used=DecisionStrategy.CONSENSUS,
            metadata={
                "consensus_options": len(weighted_options),
                "participating_makers": len(results),
                "total_alternatives": len(all_alternatives)
            }
        )
        
    def get_confidence_threshold(self) -> float:
        return self.confidence_threshold
        
    def _calculate_confidence_level(self, confidence: float) -> ConfidenceLevel:
        """Расчет уровня уверенности"""
        if confidence >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif confidence >= 0.75:
            return ConfidenceLevel.HIGH
        elif confidence >= 0.5:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW

class AdvancedDecisionEngine:
    """
    Продвинутая система принятия решений с поддержкой:
    - Множественных стратегий принятия решений
    - Адаптивного выбора стратегии
    - Обучения на основе результатов
    - Мониторинга качества решений
    """
    
    def __init__(self):
        self.decision_makers: Dict[str, DecisionMaker] = {}
        self.decision_history = deque(maxlen=10000)
        self.performance_metrics: Dict[str, Dict[str, float]] = {}
        self.adaptive_strategy = True
        
    def register_decision_maker(self, name: str, maker: DecisionMaker):
        """Регистрация метода принятия решений"""
        self.decision_makers[name] = maker
        self.performance_metrics[name] = {
            "total_decisions": 0,
            "successful_decisions": 0,
            "avg_confidence": 0.0,
            "avg_decision_time": 0.0
        }
        
    async def make_decision(self, context: DecisionContext, 
                          strategy: Optional[str] = None) -> DecisionResult:
        """Принятие решения с выбором оптимальной стратегии"""
        
        if strategy and strategy in self.decision_makers:
            # Использование указанной стратегии
            maker = self.decision_makers[strategy]
        elif self.adaptive_strategy:
            # Адаптивный выбор стратегии
            maker = await self._select_optimal_strategy(context)
        else:
            # Использование первой доступной стратегии
            if not self.decision_makers:
                raise ValueError("No decision makers registered")
            maker = next(iter(self.decision_makers.values()))
            
        # Принятие решения
        result = await maker.make_decision(context)
        
        # Сохранение в истории
        decision_record = {
            "timestamp": datetime.utcnow(),
            "context": context,
            "result": result,
            "strategy": strategy or maker.__class__.__name__
        }
        self.decision_history.append(decision_record)
        
        # Обновление метрик
        await self._update_performance_metrics(strategy or maker.__class__.__name__, result)
        
        return result
        
    async def _select_optimal_strategy(self, context: DecisionContext) -> DecisionMaker:
        """Адаптивный выбор оптимальной стратегии"""
        
        # Простая эвристика выбора стратегии
        if context.urgency == DecisionUrgency.CRITICAL:
            # Для критических задач - быстрые правила
            for name, maker in self.decision_makers.items():
                if isinstance(maker, RuleBasedDecisionMaker):
                    return maker
                    
        elif context.urgency == DecisionUrgency.LOW and len(self.decision_makers) > 1:
            # Для некритических задач - консенсус
            for name, maker in self.decision_makers.items():
                if isinstance(maker, ConsensusDecisionMaker):
                    return maker
                    
        # По умолчанию - ML если доступно
        for name, maker in self.decision_makers.items():
            if isinstance(maker, MLBasedDecisionMaker):
                return maker
                
        # Иначе - первый доступный
        return next(iter(self.decision_makers.values()))
        
    async def _update_performance_metrics(self, strategy: str, result: DecisionResult):
        """Обновление метрик производительности"""
        if strategy not in self.performance_metrics:
            return
            
        metrics = self.performance_metrics[strategy]
        old_total = metrics["total_decisions"]
        
        metrics["total_decisions"] += 1
        
        # Обновление средней уверенности
        old_confidence = metrics["avg_confidence"]
        metrics["avg_confidence"] = (
            (old_confidence * old_total + result.confidence) / metrics["total_decisions"]
        )
        
        # Обновление среднего времени принятия решения
        old_time = metrics["avg_decision_time"]
        metrics["avg_decision_time"] = (
            (old_time * old_total + result.decision_time) / metrics["total_decisions"]
        )
        
    async def evaluate_decision_outcome(self, decision_id: str, 
                                      actual_outcome: Dict[str, Any],
                                      success: bool):
        """Оценка результата принятого решения для обучения"""
        # Поиск решения в истории
        for record in reversed(self.decision_history):
            # Простой поиск по метаданным (в реальности нужен более надежный ID)
            if record["result"].metadata.get("id") == decision_id:
                strategy = record["strategy"]
                
                if strategy in self.performance_metrics:
                    if success:
                        self.performance_metrics[strategy]["successful_decisions"] += 1
                        
                # Здесь можно добавить обучение ML моделей на основе результатов
                break
                
    async def get_performance_report(self) -> Dict[str, Any]:
        """Получение отчета о производительности"""
        report = {
            "strategies": {},
            "total_decisions": len(self.decision_history),
            "recent_performance": {}
        }
        
        # Метрики по стратегиям
        for name, metrics in self.performance_metrics.items():
            success_rate = 0.0
            if metrics["total_decisions"] > 0:
                success_rate = metrics["successful_decisions"] / metrics["total_decisions"]
                
            report["strategies"][name] = {
                **metrics,
                "success_rate": success_rate
            }
            
        # Анализ последних решений
        recent_decisions = list(self.decision_history)[-100:] if self.decision_history else []
        
        if recent_decisions:
            recent_confidence = [r["result"].confidence for r in recent_decisions]
            recent_time = [r["result"].decision_time for r in recent_decisions]
            
            report["recent_performance"] = {
                "avg_confidence": sum(recent_confidence) / len(recent_confidence),
                "avg_decision_time": sum(recent_time) / len(recent_time),
                "confidence_trend": self._calculate_trend(recent_confidence),
                "time_trend": self._calculate_trend(recent_time)
            }
            
        return report
        
    def _calculate_trend(self, values: List[float]) -> str:
        """Расчет тренда значений"""
        if len(values) < 2:
            return "stable"
            
        mid_point = len(values) // 2
        first_half_avg = sum(values[:mid_point]) / mid_point
        second_half_avg = sum(values[mid_point:]) / (len(values) - mid_point)
        
        change_percent = ((second_half_avg - first_half_avg) / first_half_avg) * 100
        
        if change_percent > 5:
            return "improving"
        elif change_percent < -5:
            return "declining"
        else:
            return "stable"

# Утилитарные функции

def create_simple_rule(name: str, condition_func: Callable, 
                      action_func: Callable, priority: int = 100) -> DecisionRule:
    """Создание простого правила принятия решения"""
    return DecisionRule(
        name=name,
        condition=condition_func,
        action=action_func,
        priority=priority
    )

def create_threshold_rule(name: str, field: str, threshold: float, 
                         action_value: Any, operator: str = ">=") -> DecisionRule:
    """Создание правила на основе порога"""
    
    def condition(data: Dict[str, Any]) -> bool:
        if field not in data:
            return False
        value = data[field]
        if not isinstance(value, (int, float)):
            return False
            
        if operator == ">=":
            return value >= threshold
        elif operator == "<=":
            return value <= threshold
        elif operator == ">":
            return value > threshold
        elif operator == "<":
            return value < threshold
        elif operator == "==":
            return abs(value - threshold) < 1e-9
        return False
        
    def action(data: Dict[str, Any]) -> Any:
        return action_value
        
    return DecisionRule(
        name=name,
        condition=condition,
        action=action,
        priority=100
    )