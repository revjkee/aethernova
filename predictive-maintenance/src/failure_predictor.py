"""
Failure Prediction Module
Предсказание сбоев систем на основе исторических данных и ML
"""

import logging
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import asyncio

logger = logging.getLogger("predictive-maintenance.failure")


class FailureType(str, Enum):
    """Типы предсказываемых сбоев"""
    CRASH = "crash"  # Полный сбой системы
    DEGRADATION = "degradation"  # Деградация производительности
    RESOURCE_EXHAUSTION = "resource_exhaustion"  # Исчерпание ресурсов
    NETWORK_FAILURE = "network_failure"  # Сетевой сбой
    DATABASE_FAILURE = "database_failure"  # Сбой БД
    MEMORY_LEAK = "memory_leak"  # Утечка памяти
    DISK_FAILURE = "disk_failure"  # Сбой диска
    TIMEOUT = "timeout"  # Таймауты
    UNKNOWN = "unknown"  # Неизвестный тип


class FailureSeverity(str, Enum):
    """Уровни серьезности сбоя"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class FailurePrediction:
    """Результат предсказания сбоя"""
    will_fail: bool
    failure_type: FailureType
    severity: FailureSeverity
    probability: float  # 0.0 - 1.0
    time_to_failure: Optional[timedelta]  # Примерное время до сбоя
    system_name: str
    affected_components: List[str]
    contributing_factors: Dict[str, float]  # Факторы и их веса
    recommended_actions: List[str]
    timestamp: datetime
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразование в словарь"""
        return {
            "will_fail": self.will_fail,
            "failure_type": self.failure_type.value,
            "severity": self.severity.value,
            "probability": self.probability,
            "time_to_failure_seconds": (
                self.time_to_failure.total_seconds() 
                if self.time_to_failure else None
            ),
            "system_name": self.system_name,
            "affected_components": self.affected_components,
            "contributing_factors": self.contributing_factors,
            "recommended_actions": self.recommended_actions,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context
        }


class FailurePredictor:
    """
    Предиктор сбоев систем с использованием ML и эвристик
    
    Подходы:
    - Time series forecasting (ARIMA, LSTM)
    - Survival analysis
    - Random Forest для классификации типов сбоев
    - Rule-based expert system
    """
    
    def __init__(
        self,
        prediction_horizon: timedelta = timedelta(hours=24),
        probability_threshold: float = 0.7,
        use_ml: bool = True
    ):
        self.prediction_horizon = prediction_horizon
        self.probability_threshold = probability_threshold
        self.use_ml = use_ml
        
        # История предсказаний для обучения
        self.prediction_history: List[Dict[str, Any]] = []
        
        # ML модели (заглушки)
        self.time_series_model = None
        self.classification_model = None
        self.survival_model = None
        
        # Правила для эвристического предсказания
        self.failure_rules = self._initialize_failure_rules()
        
        logger.info(
            f"FailurePredictor initialized: "
            f"horizon={prediction_horizon}, threshold={probability_threshold}"
        )
    
    def _initialize_failure_rules(self) -> Dict[str, Dict[str, Any]]:
        """Инициализация правил для предсказания сбоев"""
        return {
            "high_cpu_sustained": {
                "condition": lambda metrics: metrics.get("cpu_usage", 0) > 90,
                "duration_threshold": timedelta(minutes=30),
                "failure_type": FailureType.CRASH,
                "probability_base": 0.8
            },
            "memory_leak_pattern": {
                "condition": lambda metrics: (
                    metrics.get("memory_growth_rate", 0) > 5  # MB/min
                ),
                "duration_threshold": timedelta(hours=2),
                "failure_type": FailureType.MEMORY_LEAK,
                "probability_base": 0.9
            },
            "disk_space_critical": {
                "condition": lambda metrics: metrics.get("disk_usage", 0) > 95,
                "duration_threshold": timedelta(minutes=5),
                "failure_type": FailureType.DISK_FAILURE,
                "probability_base": 0.95
            },
            "error_rate_spike": {
                "condition": lambda metrics: metrics.get("error_rate", 0) > 0.1,
                "duration_threshold": timedelta(minutes=10),
                "failure_type": FailureType.DEGRADATION,
                "probability_base": 0.75
            },
            "connection_pool_exhaustion": {
                "condition": lambda metrics: (
                    metrics.get("active_connections", 0) > 
                    metrics.get("max_connections", 100) * 0.95
                ),
                "duration_threshold": timedelta(minutes=5),
                "failure_type": FailureType.RESOURCE_EXHAUSTION,
                "probability_base": 0.85
            }
        }
    
    async def predict(
        self,
        system_name: str,
        current_metrics: Dict[str, float],
        historical_metrics: Optional[List[Dict[str, Any]]] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> FailurePrediction:
        """
        Предсказание сбоя для системы
        
        Args:
            system_name: Название системы
            current_metrics: Текущие метрики
            historical_metrics: Исторические метрики
            context: Дополнительный контекст
            
        Returns:
            FailurePrediction с результатами предсказания
        """
        if context is None:
            context = {}
        
        timestamp = datetime.now()
        
        # Эвристическое предсказание на основе правил
        rule_predictions = await self._predict_by_rules(
            system_name,
            current_metrics,
            historical_metrics or []
        )
        
        # ML предсказание (если доступно)
        ml_predictions = []
        if self.use_ml and self.classification_model:
            ml_predictions = await self._predict_by_ml(
                system_name,
                current_metrics,
                historical_metrics or []
            )
        
        # Комбинирование предсказаний
        combined = self._combine_predictions(rule_predictions, ml_predictions)
        
        if not combined["will_fail"]:
            return FailurePrediction(
                will_fail=False,
                failure_type=FailureType.UNKNOWN,
                severity=FailureSeverity.LOW,
                probability=0.0,
                time_to_failure=None,
                system_name=system_name,
                affected_components=[],
                contributing_factors={},
                recommended_actions=[],
                timestamp=timestamp,
                context=context
            )
        
        # Предсказание времени до сбоя
        time_to_failure = await self._estimate_time_to_failure(
            combined["failure_type"],
            current_metrics,
            historical_metrics or []
        )
        
        # Определение затронутых компонентов
        affected_components = self._identify_affected_components(
            combined["failure_type"],
            current_metrics
        )
        
        # Рекомендуемые действия
        recommended_actions = self._generate_recommendations(
            combined["failure_type"],
            combined["contributing_factors"]
        )
        
        # Определение серьезности
        severity = self._calculate_severity(
            combined["probability"],
            time_to_failure,
            affected_components
        )
        
        logger.warning(
            f"Failure predicted for {system_name}: "
            f"type={combined['failure_type']}, "
            f"probability={combined['probability']:.2f}, "
            f"time_to_failure={time_to_failure}"
        )
        
        prediction = FailurePrediction(
            will_fail=True,
            failure_type=combined["failure_type"],
            severity=severity,
            probability=combined["probability"],
            time_to_failure=time_to_failure,
            system_name=system_name,
            affected_components=affected_components,
            contributing_factors=combined["contributing_factors"],
            recommended_actions=recommended_actions,
            timestamp=timestamp,
            context=context
        )
        
        # Сохранение в историю для обучения
        self.prediction_history.append({
            "prediction": prediction.to_dict(),
            "metrics": current_metrics,
            "timestamp": timestamp
        })
        
        return prediction
    
    async def predict_batch(
        self,
        systems: Dict[str, Dict[str, float]],
        context: Optional[Dict[str, Any]] = None
    ) -> List[FailurePrediction]:
        """Предсказание сбоев для нескольких систем"""
        tasks = [
            self.predict(name, metrics, context=context)
            for name, metrics in systems.items()
        ]
        return await asyncio.gather(*tasks)
    
    async def _predict_by_rules(
        self,
        system_name: str,
        current_metrics: Dict[str, float],
        historical_metrics: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Предсказание на основе правил"""
        predictions = []
        
        for rule_name, rule in self.failure_rules.items():
            if rule["condition"](current_metrics):
                # Проверка длительности условия
                duration_met = True  # Упрощено
                
                if duration_met:
                    predictions.append({
                        "failure_type": rule["failure_type"],
                        "probability": rule["probability_base"],
                        "source": "rule",
                        "rule_name": rule_name
                    })
        
        return predictions
    
    async def _predict_by_ml(
        self,
        system_name: str,
        current_metrics: Dict[str, float],
        historical_metrics: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Предсказание на основе ML моделей"""
        predictions = []
        
        # Заглушка для ML предсказания
        # В production здесь будет:
        # - Feature engineering
        # - Model inference
        # - Ensemble predictions
        
        if self.classification_model:
            # Имитация ML предсказания
            probability = np.random.random()
            if probability > 0.7:
                predictions.append({
                    "failure_type": FailureType.DEGRADATION,
                    "probability": probability,
                    "source": "ml",
                    "model": "classification"
                })
        
        return predictions
    
    def _combine_predictions(
        self,
        rule_predictions: List[Dict[str, Any]],
        ml_predictions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Комбинирование предсказаний из разных источников"""
        all_predictions = rule_predictions + ml_predictions
        
        if not all_predictions:
            return {
                "will_fail": False,
                "failure_type": FailureType.UNKNOWN,
                "probability": 0.0,
                "contributing_factors": {}
            }
        
        # Выбор предсказания с максимальной вероятностью
        best_prediction = max(all_predictions, key=lambda x: x["probability"])
        
        # Сбор факторов
        factors = {}
        for pred in all_predictions:
            source = pred.get("source", "unknown")
            factors[f"{source}_{pred.get('rule_name', 'model')}"] = pred["probability"]
        
        return {
            "will_fail": best_prediction["probability"] >= self.probability_threshold,
            "failure_type": best_prediction["failure_type"],
            "probability": best_prediction["probability"],
            "contributing_factors": factors
        }
    
    async def _estimate_time_to_failure(
        self,
        failure_type: FailureType,
        current_metrics: Dict[str, float],
        historical_metrics: List[Dict[str, Any]]
    ) -> Optional[timedelta]:
        """Оценка времени до сбоя"""
        # Эвристические оценки на основе типа сбоя
        time_estimates = {
            FailureType.DISK_FAILURE: timedelta(hours=2),
            FailureType.MEMORY_LEAK: timedelta(hours=6),
            FailureType.RESOURCE_EXHAUSTION: timedelta(hours=1),
            FailureType.CRASH: timedelta(hours=4),
            FailureType.DEGRADATION: timedelta(hours=12),
            FailureType.NETWORK_FAILURE: timedelta(hours=8),
        }
        
        return time_estimates.get(failure_type, timedelta(hours=24))
    
    def _identify_affected_components(
        self,
        failure_type: FailureType,
        current_metrics: Dict[str, float]
    ) -> List[str]:
        """Идентификация затронутых компонентов"""
        components = []
        
        if failure_type == FailureType.DISK_FAILURE:
            components = ["storage", "database", "cache"]
        elif failure_type == FailureType.MEMORY_LEAK:
            components = ["application", "runtime", "gc"]
        elif failure_type == FailureType.NETWORK_FAILURE:
            components = ["network", "load_balancer", "api_gateway"]
        elif failure_type == FailureType.RESOURCE_EXHAUSTION:
            if current_metrics.get("cpu_usage", 0) > 90:
                components.append("cpu")
            if current_metrics.get("memory_usage", 0) > 90:
                components.append("memory")
            if current_metrics.get("active_connections", 0) > 1000:
                components.append("connection_pool")
        else:
            components = ["system"]
        
        return components
    
    def _generate_recommendations(
        self,
        failure_type: FailureType,
        contributing_factors: Dict[str, float]
    ) -> List[str]:
        """Генерация рекомендаций по предотвращению сбоя"""
        recommendations = {
            FailureType.DISK_FAILURE: [
                "Увеличить дисковое пространство",
                "Очистить старые логи и временные файлы",
                "Настроить ротацию логов",
                "Проверить рост данных"
            ],
            FailureType.MEMORY_LEAK: [
                "Перезапустить приложение",
                "Проверить код на утечки памяти",
                "Увеличить heap size",
                "Настроить профилирование памяти"
            ],
            FailureType.RESOURCE_EXHAUSTION: [
                "Масштабировать ресурсы",
                "Оптимизировать запросы",
                "Включить кэширование",
                "Настроить rate limiting"
            ],
            FailureType.CRASH: [
                "Проверить логи на ошибки",
                "Обновить зависимости",
                "Настроить автоматический рестарт",
                "Включить health checks"
            ],
            FailureType.DEGRADATION: [
                "Оптимизировать производительность",
                "Проверить медленные запросы",
                "Масштабировать horizontally",
                "Включить мониторинг APM"
            ]
        }
        
        return recommendations.get(failure_type, [
            "Проверить системные логи",
            "Увеличить мониторинг",
            "Подготовить план восстановления"
        ])
    
    def _calculate_severity(
        self,
        probability: float,
        time_to_failure: Optional[timedelta],
        affected_components: List[str]
    ) -> FailureSeverity:
        """Расчет уровня серьезности"""
        # Базовая оценка по вероятности
        if probability >= 0.95:
            base_severity = 4  # Critical
        elif probability >= 0.8:
            base_severity = 3  # High
        elif probability >= 0.6:
            base_severity = 2  # Medium
        else:
            base_severity = 1  # Low
        
        # Корректировка по времени до сбоя
        if time_to_failure:
            if time_to_failure < timedelta(hours=1):
                base_severity = min(4, base_severity + 1)
            elif time_to_failure < timedelta(hours=4):
                base_severity = min(4, base_severity)
            elif time_to_failure > timedelta(hours=24):
                base_severity = max(1, base_severity - 1)
        
        # Корректировка по количеству затронутых компонентов
        if len(affected_components) > 3:
            base_severity = min(4, base_severity + 1)
        
        severity_map = {
            1: FailureSeverity.LOW,
            2: FailureSeverity.MEDIUM,
            3: FailureSeverity.HIGH,
            4: FailureSeverity.CRITICAL
        }
        
        return severity_map[base_severity]
    
    async def train_models(
        self,
        training_data: List[Dict[str, Any]]
    ) -> None:
        """
        Обучение ML моделей на исторических данных
        
        В production здесь будет:
        - Feature engineering
        - Time series model training (ARIMA/LSTM)
        - Classification model training (Random Forest)
        - Survival analysis model training
        - Cross-validation
        - Hyperparameter tuning
        """
        logger.info(f"Training models on {len(training_data)} samples...")
        
        # Заглушка для обучения
        self.classification_model = {"trained": True}
        self.time_series_model = {"trained": True}
        self.survival_model = {"trained": True}
        
        logger.info("Models trained successfully")
    
    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики предсказаний"""
        if not self.prediction_history:
            return {"total_predictions": 0}
        
        total = len(self.prediction_history)
        failures_predicted = sum(
            1 for p in self.prediction_history 
            if p["prediction"]["will_fail"]
        )
        
        failure_types = {}
        for p in self.prediction_history:
            if p["prediction"]["will_fail"]:
                ftype = p["prediction"]["failure_type"]
                failure_types[ftype] = failure_types.get(ftype, 0) + 1
        
        return {
            "total_predictions": total,
            "failures_predicted": failures_predicted,
            "failure_rate": failures_predicted / total if total > 0 else 0,
            "failure_types_distribution": failure_types,
            "avg_probability": np.mean([
                p["prediction"]["probability"] 
                for p in self.prediction_history
                if p["prediction"]["will_fail"]
            ]) if failures_predicted > 0 else 0.0
        }
