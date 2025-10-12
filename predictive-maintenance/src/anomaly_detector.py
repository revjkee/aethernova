"""
Anomaly Detection Module
Детекция аномалий в метриках систем в реальном времени
"""

import logging
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import deque
import asyncio

logger = logging.getLogger("predictive-maintenance.anomaly")


class AnomalyType(str, Enum):
    """Типы аномалий"""
    SPIKE = "spike"  # Резкий скачок метрики
    DROP = "drop"  # Резкое падение метрики
    TREND = "trend"  # Аномальный тренд
    PATTERN = "pattern"  # Нарушение нормального паттерна
    SEASONAL = "seasonal"  # Сезонная аномалия
    MULTI_METRIC = "multi_metric"  # Аномалия по нескольким метрикам
    UNKNOWN = "unknown"  # Неизвестный тип


class AnomalySeverity(str, Enum):
    """Уровни серьезности аномалий"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AnomalyResult:
    """Результат детекции аномалии"""
    detected: bool
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    confidence: float  # 0.0 - 1.0
    metric_name: str
    metric_value: float
    expected_value: float
    deviation: float
    timestamp: datetime
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразование в словарь"""
        return {
            "detected": self.detected,
            "anomaly_type": self.anomaly_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "expected_value": self.expected_value,
            "deviation": self.deviation,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context
        }


class AnomalyDetector:
    """
    Детектор аномалий с использованием статистических методов и ML
    
    Методы детекции:
    - Z-score (статистическое отклонение)
    - IQR (межквартильный размах)
    - Moving average deviation
    - Pattern matching
    - Multi-metric correlation
    """
    
    def __init__(
        self,
        window_size: int = 100,
        z_threshold: float = 3.0,
        iqr_multiplier: float = 1.5,
        use_ml: bool = True
    ):
        self.window_size = window_size
        self.z_threshold = z_threshold
        self.iqr_multiplier = iqr_multiplier
        self.use_ml = use_ml
        
        # История метрик для каждого типа
        self.metric_history: Dict[str, deque] = {}
        
        # Статистики для каждой метрики
        self.metric_stats: Dict[str, Dict[str, float]] = {}
        
        # ML модель (заглушка, в production - sklearn/tensorflow)
        self.ml_model = None
        
        logger.info(
            f"AnomalyDetector initialized: "
            f"window={window_size}, z_threshold={z_threshold}"
        )
    
    async def detect(
        self,
        metric_name: str,
        value: float,
        timestamp: Optional[datetime] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> AnomalyResult:
        """
        Детекция аномалии для одной метрики
        
        Args:
            metric_name: Название метрики
            value: Значение метрики
            timestamp: Временная метка
            context: Дополнительный контекст
            
        Returns:
            AnomalyResult с результатами детекции
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        if context is None:
            context = {}
        
        # Инициализация истории для новой метрики
        if metric_name not in self.metric_history:
            self.metric_history[metric_name] = deque(maxlen=self.window_size)
            self.metric_stats[metric_name] = {}
        
        # Добавление нового значения
        self.metric_history[metric_name].append((timestamp, value))
        
        # Недостаточно данных для анализа
        if len(self.metric_history[metric_name]) < 10:
            return AnomalyResult(
                detected=False,
                anomaly_type=AnomalyType.UNKNOWN,
                severity=AnomalySeverity.LOW,
                confidence=0.0,
                metric_name=metric_name,
                metric_value=value,
                expected_value=value,
                deviation=0.0,
                timestamp=timestamp,
                context=context
            )
        
        # Методы детекции
        z_score_result = await self._detect_z_score(metric_name, value)
        iqr_result = await self._detect_iqr(metric_name, value)
        trend_result = await self._detect_trend(metric_name, value)
        
        # Комбинирование результатов
        detected = (
            z_score_result["detected"] or 
            iqr_result["detected"] or 
            trend_result["detected"]
        )
        
        if detected:
            # Определение типа аномалии
            if z_score_result["detected"]:
                if value > z_score_result["expected"]:
                    anomaly_type = AnomalyType.SPIKE
                else:
                    anomaly_type = AnomalyType.DROP
            elif trend_result["detected"]:
                anomaly_type = AnomalyType.TREND
            else:
                anomaly_type = AnomalyType.PATTERN
            
            # Расчет уверенности и серьезности
            confidence = max(
                z_score_result["confidence"],
                iqr_result["confidence"],
                trend_result["confidence"]
            )
            
            deviation = abs(value - z_score_result["expected"])
            severity = self._calculate_severity(confidence, deviation)
            
            logger.warning(
                f"Anomaly detected in {metric_name}: "
                f"value={value:.2f}, expected={z_score_result['expected']:.2f}, "
                f"type={anomaly_type}, severity={severity}"
            )
            
            return AnomalyResult(
                detected=True,
                anomaly_type=anomaly_type,
                severity=severity,
                confidence=confidence,
                metric_name=metric_name,
                metric_value=value,
                expected_value=z_score_result["expected"],
                deviation=deviation,
                timestamp=timestamp,
                context={**context, "detection_methods": {
                    "z_score": z_score_result["detected"],
                    "iqr": iqr_result["detected"],
                    "trend": trend_result["detected"]
                }}
            )
        
        return AnomalyResult(
            detected=False,
            anomaly_type=AnomalyType.UNKNOWN,
            severity=AnomalySeverity.LOW,
            confidence=0.0,
            metric_name=metric_name,
            metric_value=value,
            expected_value=z_score_result["expected"],
            deviation=0.0,
            timestamp=timestamp,
            context=context
        )
    
    async def detect_batch(
        self,
        metrics: Dict[str, float],
        timestamp: Optional[datetime] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> List[AnomalyResult]:
        """Детекция аномалий для пакета метрик"""
        tasks = [
            self.detect(name, value, timestamp, context)
            for name, value in metrics.items()
        ]
        return await asyncio.gather(*tasks)
    
    async def _detect_z_score(
        self,
        metric_name: str,
        value: float
    ) -> Dict[str, Any]:
        """Детекция аномалий методом Z-score"""
        history = [v for _, v in self.metric_history[metric_name]]
        
        mean = np.mean(history)
        std = np.std(history)
        
        if std == 0:
            return {"detected": False, "confidence": 0.0, "expected": mean}
        
        z_score = abs((value - mean) / std)
        detected = z_score > self.z_threshold
        confidence = min(z_score / self.z_threshold, 1.0) if detected else 0.0
        
        return {
            "detected": detected,
            "confidence": confidence,
            "expected": mean,
            "z_score": z_score
        }
    
    async def _detect_iqr(
        self,
        metric_name: str,
        value: float
    ) -> Dict[str, Any]:
        """Детекция аномалий методом IQR (межквартильный размах)"""
        history = [v for _, v in self.metric_history[metric_name]]
        
        q1 = np.percentile(history, 25)
        q3 = np.percentile(history, 75)
        iqr = q3 - q1
        
        lower_bound = q1 - self.iqr_multiplier * iqr
        upper_bound = q3 + self.iqr_multiplier * iqr
        
        detected = value < lower_bound or value > upper_bound
        
        if detected:
            if value < lower_bound:
                confidence = min(abs(value - lower_bound) / iqr, 1.0)
            else:
                confidence = min(abs(value - upper_bound) / iqr, 1.0)
        else:
            confidence = 0.0
        
        expected = np.median(history)
        
        return {
            "detected": detected,
            "confidence": confidence,
            "expected": expected,
            "lower_bound": lower_bound,
            "upper_bound": upper_bound
        }
    
    async def _detect_trend(
        self,
        metric_name: str,
        value: float
    ) -> Dict[str, Any]:
        """Детекция аномальных трендов"""
        history = [v for _, v in self.metric_history[metric_name]]
        
        if len(history) < 20:
            return {"detected": False, "confidence": 0.0, "expected": value}
        
        # Простая линейная регрессия
        x = np.arange(len(history))
        y = np.array(history)
        
        # Коэффициенты линейной регрессии
        coeffs = np.polyfit(x, y, 1)
        trend = coeffs[0]  # Наклон
        
        # Предсказанное значение
        predicted = coeffs[0] * len(history) + coeffs[1]
        
        # Проверка резкого изменения тренда
        recent_trend = np.polyfit(x[-10:], y[-10:], 1)[0]
        trend_change = abs(recent_trend - trend)
        
        # Аномалия если резкое изменение тренда
        detected = trend_change > np.std(history) * 0.5
        confidence = min(trend_change / np.std(history), 1.0) if detected else 0.0
        
        return {
            "detected": detected,
            "confidence": confidence,
            "expected": predicted,
            "trend": trend,
            "recent_trend": recent_trend
        }
    
    def _calculate_severity(
        self,
        confidence: float,
        deviation: float
    ) -> AnomalySeverity:
        """Расчет уровня серьезности аномалии"""
        # Комбинированная оценка на основе уверенности и отклонения
        score = confidence * 0.7 + min(deviation / 100, 1.0) * 0.3
        
        if score >= 0.9:
            return AnomalySeverity.CRITICAL
        elif score >= 0.7:
            return AnomalySeverity.HIGH
        elif score >= 0.5:
            return AnomalySeverity.MEDIUM
        else:
            return AnomalySeverity.LOW
    
    async def train_ml_model(
        self,
        training_data: Dict[str, List[Tuple[datetime, float]]]
    ) -> None:
        """
        Обучение ML модели на исторических данных
        
        В production здесь будет:
        - Feature engineering
        - Training sklearn/tensorflow model
        - Cross-validation
        - Model evaluation
        """
        logger.info(f"Training ML model on {len(training_data)} metrics...")
        # Заглушка для ML модели
        self.ml_model = {"trained": True, "metrics": len(training_data)}
        logger.info("ML model trained successfully")
    
    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики по всем метрикам"""
        stats = {}
        for metric_name, history in self.metric_history.items():
            values = [v for _, v in history]
            if values:
                stats[metric_name] = {
                    "count": len(values),
                    "mean": float(np.mean(values)),
                    "std": float(np.std(values)),
                    "min": float(np.min(values)),
                    "max": float(np.max(values)),
                    "median": float(np.median(values)),
                    "q25": float(np.percentile(values, 25)),
                    "q75": float(np.percentile(values, 75))
                }
        return stats
