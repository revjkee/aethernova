"""
Health Monitoring Module
Мониторинг здоровья систем и интеграция с аномалиями и предсказаниями
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from .anomaly_detector import AnomalyDetector, AnomalyResult
from .failure_predictor import FailurePredictor, FailurePrediction
from .metrics_collector import MetricsCollector, Metric

logger = logging.getLogger("predictive-maintenance.health")


class HealthStatus(str, Enum):
    """Статусы здоровья системы"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    AT_RISK = "at_risk"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class HealthReport:
    """Отчет о здоровье системы"""
    system_name: str
    status: HealthStatus
    score: float  # 0.0 - 100.0
    timestamp: datetime
    
    # Детальная информация
    metrics: Dict[str, float]
    anomalies: List[AnomalyResult]
    predictions: List[FailurePrediction]
    
    # Анализ
    issues: List[str]
    warnings: List[str]
    recommendations: List[str]
    
    # Тренды
    status_history: List[str] = field(default_factory=list)
    score_trend: str = "stable"  # improving, degrading, stable
    
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразование в словарь"""
        return {
            "system_name": self.system_name,
            "status": self.status.value,
            "score": self.score,
            "timestamp": self.timestamp.isoformat(),
            "metrics": self.metrics,
            "anomalies": [a.to_dict() for a in self.anomalies],
            "predictions": [p.to_dict() for p in self.predictions],
            "issues": self.issues,
            "warnings": self.warnings,
            "recommendations": self.recommendations,
            "status_history": self.status_history,
            "score_trend": self.score_trend,
            "context": self.context
        }


class HealthMonitor:
    """
    Комплексный мониторинг здоровья систем
    
    Интегрирует:
    - Сбор метрик (MetricsCollector)
    - Детекцию аномалий (AnomalyDetector)
    - Предсказание сбоев (FailurePredictor)
    """
    
    def __init__(
        self,
        metrics_collector: MetricsCollector,
        anomaly_detector: AnomalyDetector,
        failure_predictor: FailurePredictor,
        check_interval: float = 60.0,
        history_size: int = 100
    ):
        self.metrics_collector = metrics_collector
        self.anomaly_detector = anomaly_detector
        self.failure_predictor = failure_predictor
        self.check_interval = check_interval
        self.history_size = history_size
        
        # История проверок
        self.health_history: Dict[str, List[HealthReport]] = {}
        
        # Пороги для определения статуса
        self.status_thresholds = {
            HealthStatus.HEALTHY: 80.0,
            HealthStatus.DEGRADED: 60.0,
            HealthStatus.AT_RISK: 40.0,
            HealthStatus.UNHEALTHY: 20.0,
            HealthStatus.CRITICAL: 0.0
        }
        
        # Коллбэки для уведомлений
        self.status_change_callbacks: List[Callable] = []
        
        # Статус мониторинга
        self.is_monitoring = False
        self._monitoring_task: Optional[asyncio.Task] = None
        
        logger.info(
            f"HealthMonitor initialized: "
            f"check_interval={check_interval}s"
        )
    
    async def start_monitoring(
        self,
        systems: Optional[List[str]] = None
    ) -> None:
        """
        Запуск непрерывного мониторинга
        
        Args:
            systems: Список систем для мониторинга (None = все)
        """
        if self.is_monitoring:
            logger.warning("Monitoring already running")
            return
        
        self.is_monitoring = True
        self._monitoring_task = asyncio.create_task(
            self._monitoring_loop(systems)
        )
        
        logger.info(f"Health monitoring started for systems: {systems or 'all'}")
    
    async def stop_monitoring(self) -> None:
        """Остановка мониторинга"""
        if not self.is_monitoring:
            return
        
        self.is_monitoring = False
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Health monitoring stopped")
    
    async def _monitoring_loop(
        self,
        systems: Optional[List[str]]
    ) -> None:
        """Основной цикл мониторинга"""
        while self.is_monitoring:
            try:
                if systems:
                    for system in systems:
                        await self.check_health(system)
                else:
                    # Мониторинг всех известных систем
                    await self.check_all_systems()
                
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                await asyncio.sleep(5)
    
    async def check_health(
        self,
        system_name: str,
        context: Optional[Dict[str, Any]] = None
    ) -> HealthReport:
        """
        Комплексная проверка здоровья системы
        
        Args:
            system_name: Название системы
            context: Дополнительный контекст
            
        Returns:
            HealthReport с результатами проверки
        """
        if context is None:
            context = {}
        
        timestamp = datetime.now()
        
        # 1. Сбор текущих метрик
        latest_metrics = self.metrics_collector.get_latest_metrics()
        current_metrics = {
            name: metric.value
            for name, metric in latest_metrics.items()
        }
        
        # 2. Детекция аномалий
        anomalies = []
        for metric_name, value in current_metrics.items():
            history = self.metrics_collector.get_metric_values(
                metric_name,
                limit=self.anomaly_detector.window_size
            )
            
            if len(history) >= self.anomaly_detector.min_samples:
                anomaly = await self.anomaly_detector.detect(
                    metric_name,
                    value,
                    history[:-1],  # История без текущего значения
                    context={"system": system_name}
                )
                
                if anomaly.is_anomaly:
                    anomalies.append(anomaly)
        
        # 3. Предсказание сбоев
        predictions = []
        try:
            historical_metrics = [
                {
                    "timestamp": m.timestamp,
                    "metrics": {m.name: m.value}
                }
                for name in current_metrics.keys()
                for m in self.metrics_collector.get_metrics(name, limit=100)
            ]
            
            prediction = await self.failure_predictor.predict(
                system_name,
                current_metrics,
                historical_metrics,
                context=context
            )
            
            if prediction.will_fail:
                predictions.append(prediction)
        except Exception as e:
            logger.error(f"Error predicting failures: {e}", exc_info=True)
        
        # 4. Расчет health score
        health_score = self._calculate_health_score(
            current_metrics,
            anomalies,
            predictions
        )
        
        # 5. Определение статуса
        status = self._determine_status(health_score, anomalies, predictions)
        
        # 6. Анализ проблем и рекомендаций
        issues = self._identify_issues(
            current_metrics,
            anomalies,
            predictions
        )
        
        warnings = self._generate_warnings(
            anomalies,
            predictions
        )
        
        recommendations = self._generate_recommendations(
            status,
            anomalies,
            predictions
        )
        
        # 7. Анализ трендов
        score_trend, status_history = self._analyze_trends(
            system_name,
            health_score,
            status
        )
        
        # Создание отчета
        report = HealthReport(
            system_name=system_name,
            status=status,
            score=health_score,
            timestamp=timestamp,
            metrics=current_metrics,
            anomalies=anomalies,
            predictions=predictions,
            issues=issues,
            warnings=warnings,
            recommendations=recommendations,
            status_history=status_history,
            score_trend=score_trend,
            context=context
        )
        
        # Сохранение в историю
        if system_name not in self.health_history:
            self.health_history[system_name] = []
        
        self.health_history[system_name].append(report)
        
        # Ограничение размера истории
        if len(self.health_history[system_name]) > self.history_size:
            self.health_history[system_name] = (
                self.health_history[system_name][-self.history_size:]
            )
        
        # Уведомления о изменении статуса
        await self._notify_status_change(system_name, report)
        
        logger.info(
            f"Health check for {system_name}: "
            f"status={status.value}, score={health_score:.1f}"
        )
        
        return report
    
    async def check_all_systems(self) -> Dict[str, HealthReport]:
        """Проверка всех систем"""
        # Получение списка уникальных систем из метрик
        systems = set()
        for metric_name in self.metrics_collector.metrics_storage.keys():
            # Извлечение имени системы из метрики
            parts = metric_name.split(".")
            if len(parts) > 1:
                systems.add(parts[0])
        
        if not systems:
            systems = {"default"}
        
        reports = {}
        for system_name in systems:
            try:
                reports[system_name] = await self.check_health(system_name)
            except Exception as e:
                logger.error(
                    f"Error checking health of {system_name}: {e}",
                    exc_info=True
                )
        
        return reports
    
    def _calculate_health_score(
        self,
        metrics: Dict[str, float],
        anomalies: List[AnomalyResult],
        predictions: List[FailurePrediction]
    ) -> float:
        """
        Расчет общего показателя здоровья (0-100)
        
        Учитывается:
        - Критичные метрики
        - Количество и серьезность аномалий
        - Вероятность и серьезность предсказаний сбоев
        """
        base_score = 100.0
        
        # Штрафы за критичные метрики
        metric_penalties = {
            "cpu_usage": lambda v: max(0, (v - 80) * 0.5) if v > 80 else 0,
            "memory_usage": lambda v: max(0, (v - 85) * 0.6) if v > 85 else 0,
            "disk_usage": lambda v: max(0, (v - 90) * 0.8) if v > 90 else 0,
            "error_rate": lambda v: v * 100  # 1% ошибок = -100 баллов
        }
        
        for metric_name, value in metrics.items():
            for key, penalty_fn in metric_penalties.items():
                if key in metric_name.lower():
                    penalty = penalty_fn(value)
                    base_score -= penalty
        
        # Штрафы за аномалии
        anomaly_penalty = 0
        for anomaly in anomalies:
            if anomaly.severity.value == "critical":
                anomaly_penalty += 15
            elif anomaly.severity.value == "high":
                anomaly_penalty += 10
            elif anomaly.severity.value == "medium":
                anomaly_penalty += 5
            else:
                anomaly_penalty += 2
        
        base_score -= anomaly_penalty
        
        # Штрафы за предсказания сбоев
        prediction_penalty = 0
        for prediction in predictions:
            severity_multiplier = {
                "critical": 20,
                "high": 15,
                "medium": 10,
                "low": 5
            }.get(prediction.severity.value, 5)
            
            prediction_penalty += (
                prediction.probability * severity_multiplier
            )
        
        base_score -= prediction_penalty
        
        # Ограничение в диапазоне 0-100
        return max(0.0, min(100.0, base_score))
    
    def _determine_status(
        self,
        health_score: float,
        anomalies: List[AnomalyResult],
        predictions: List[FailurePrediction]
    ) -> HealthStatus:
        """Определение статуса на основе score и других факторов"""
        # Базовый статус по score
        if health_score >= self.status_thresholds[HealthStatus.HEALTHY]:
            base_status = HealthStatus.HEALTHY
        elif health_score >= self.status_thresholds[HealthStatus.DEGRADED]:
            base_status = HealthStatus.DEGRADED
        elif health_score >= self.status_thresholds[HealthStatus.AT_RISK]:
            base_status = HealthStatus.AT_RISK
        elif health_score >= self.status_thresholds[HealthStatus.UNHEALTHY]:
            base_status = HealthStatus.UNHEALTHY
        else:
            base_status = HealthStatus.CRITICAL
        
        # Повышение критичности при наличии критичных предсказаний
        for prediction in predictions:
            if prediction.severity.value == "critical":
                if base_status == HealthStatus.HEALTHY:
                    base_status = HealthStatus.AT_RISK
                elif base_status == HealthStatus.DEGRADED:
                    base_status = HealthStatus.UNHEALTHY
        
        return base_status
    
    def _identify_issues(
        self,
        metrics: Dict[str, float],
        anomalies: List[AnomalyResult],
        predictions: List[FailurePrediction]
    ) -> List[str]:
        """Идентификация конкретных проблем"""
        issues = []
        
        # Проблемы из метрик
        for name, value in metrics.items():
            if "cpu" in name.lower() and value > 90:
                issues.append(f"Критическое использование CPU: {value:.1f}%")
            elif "memory" in name.lower() and value > 90:
                issues.append(f"Критическое использование памяти: {value:.1f}%")
            elif "disk" in name.lower() and value > 95:
                issues.append(f"Критическое заполнение диска: {value:.1f}%")
            elif "error" in name.lower() and value > 0.05:
                issues.append(f"Высокий уровень ошибок: {value*100:.1f}%")
        
        # Проблемы из аномалий
        critical_anomalies = [
            a for a in anomalies
            if a.severity.value in ["critical", "high"]
        ]
        
        for anomaly in critical_anomalies[:3]:  # Топ-3
            issues.append(
                f"Аномалия в {anomaly.metric_name}: "
                f"{anomaly.anomaly_type.value}"
            )
        
        # Проблемы из предсказаний
        for prediction in predictions[:2]:  # Топ-2
            if prediction.probability > 0.7:
                issues.append(
                    f"Высокая вероятность сбоя: "
                    f"{prediction.failure_type.value} "
                    f"({prediction.probability*100:.0f}%)"
                )
        
        return issues
    
    def _generate_warnings(
        self,
        anomalies: List[AnomalyResult],
        predictions: List[FailurePrediction]
    ) -> List[str]:
        """Генерация предупреждений"""
        warnings = []
        
        # Предупреждения об аномалиях средней серьезности
        medium_anomalies = [
            a for a in anomalies
            if a.severity.value == "medium"
        ]
        
        if len(medium_anomalies) > 3:
            warnings.append(
                f"Обнаружено {len(medium_anomalies)} аномалий средней серьезности"
            )
        
        # Предупреждения о предсказаниях
        for prediction in predictions:
            if prediction.time_to_failure:
                hours = prediction.time_to_failure.total_seconds() / 3600
                if hours < 4:
                    warnings.append(
                        f"Возможный сбой через {hours:.1f} часов: "
                        f"{prediction.failure_type.value}"
                    )
        
        return warnings
    
    def _generate_recommendations(
        self,
        status: HealthStatus,
        anomalies: List[AnomalyResult],
        predictions: List[FailurePrediction]
    ) -> List[str]:
        """Генерация рекомендаций по улучшению"""
        recommendations = []
        
        if status in [HealthStatus.CRITICAL, HealthStatus.UNHEALTHY]:
            recommendations.append("Немедленно проверить состояние системы")
            recommendations.append("Подготовить план восстановления")
        
        if status == HealthStatus.AT_RISK:
            recommendations.append("Усилить мониторинг системы")
            recommendations.append("Подготовить превентивные меры")
        
        # Рекомендации из предсказаний
        for prediction in predictions[:2]:
            recommendations.extend(prediction.recommended_actions[:2])
        
        # Дедупликация
        return list(dict.fromkeys(recommendations))
    
    def _analyze_trends(
        self,
        system_name: str,
        current_score: float,
        current_status: HealthStatus
    ) -> tuple[str, List[str]]:
        """Анализ трендов изменения здоровья"""
        history = self.health_history.get(system_name, [])
        
        if len(history) < 2:
            return "stable", [current_status.value]
        
        # Последние 5 статусов
        status_history = [
            report.status.value
            for report in history[-5:]
        ] + [current_status.value]
        
        # Анализ тренда score
        recent_scores = [report.score for report in history[-5:]]
        avg_recent = sum(recent_scores) / len(recent_scores)
        
        if current_score > avg_recent + 5:
            trend = "improving"
        elif current_score < avg_recent - 5:
            trend = "degrading"
        else:
            trend = "stable"
        
        return trend, status_history[-5:]
    
    async def _notify_status_change(
        self,
        system_name: str,
        report: HealthReport
    ) -> None:
        """Уведомление о изменении статуса"""
        history = self.health_history.get(system_name, [])
        
        if len(history) < 2:
            return
        
        previous_status = history[-2].status
        current_status = report.status
        
        if previous_status != current_status:
            logger.warning(
                f"Status change for {system_name}: "
                f"{previous_status.value} -> {current_status.value}"
            )
            
            # Вызов коллбэков
            for callback in self.status_change_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(system_name, previous_status, current_status, report)
                    else:
                        callback(system_name, previous_status, current_status, report)
                except Exception as e:
                    logger.error(f"Error in status change callback: {e}")
    
    def register_status_change_callback(
        self,
        callback: Callable
    ) -> None:
        """Регистрация коллбэка для изменений статуса"""
        self.status_change_callbacks.append(callback)
        logger.info("Registered status change callback")
    
    def get_system_health(
        self,
        system_name: str
    ) -> Optional[HealthReport]:
        """Получение последнего отчета о здоровье системы"""
        history = self.health_history.get(system_name, [])
        return history[-1] if history else None
    
    def get_health_history(
        self,
        system_name: str,
        limit: Optional[int] = None
    ) -> List[HealthReport]:
        """Получение истории здоровья системы"""
        history = self.health_history.get(system_name, [])
        if limit:
            return history[-limit:]
        return history
    
    def get_all_systems_status(self) -> Dict[str, HealthStatus]:
        """Получение текущего статуса всех систем"""
        return {
            name: history[-1].status
            for name, history in self.health_history.items()
            if history
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики мониторинга"""
        total_checks = sum(
            len(history) for history in self.health_history.values()
        )
        
        status_distribution = {}
        for history in self.health_history.values():
            if history:
                status = history[-1].status.value
                status_distribution[status] = status_distribution.get(status, 0) + 1
        
        return {
            "is_monitoring": self.is_monitoring,
            "monitored_systems": len(self.health_history),
            "total_checks": total_checks,
            "status_distribution": status_distribution,
            "check_interval": self.check_interval
        }
