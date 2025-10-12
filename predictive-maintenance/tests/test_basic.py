"""
Basic tests for Predictive Maintenance modules
"""

import pytest
import asyncio
from datetime import datetime, timedelta
import numpy as np

from src.anomaly_detector import AnomalyDetector, AnomalyType, AnomalySeverity
from src.failure_predictor import FailurePredictor, FailureType
from src.metrics_collector import MetricsCollector, Metric, MetricType
from src.health_monitor import HealthMonitor, HealthStatus
from src.alerts import AlertManager, AlertSeverity, AlertChannel
from src.scheduler import MaintenanceScheduler, MaintenanceType, MaintenancePriority


# ============================================================================
# Anomaly Detector Tests
# ============================================================================

@pytest.mark.asyncio
async def test_anomaly_detector_z_score():
    """Test Z-score anomaly detection"""
    detector = AnomalyDetector(window_size=100, z_score_threshold=3.0)
    
    # Normal values
    history = [45.0 + np.random.normal(0, 2) for _ in range(100)]
    
    # Test normal value
    result = await detector.detect("cpu_usage", 46.0, history)
    assert not result.is_anomaly
    
    # Test anomaly
    result = await detector.detect("cpu_usage", 95.0, history)
    assert result.is_anomaly
    assert result.confidence > 0.8


@pytest.mark.asyncio
async def test_anomaly_detector_iqr():
    """Test IQR anomaly detection"""
    detector = AnomalyDetector()
    
    history = list(range(40, 60))  # 40-59
    
    # Normal value
    result = await detector.detect("memory_usage", 50.0, history)
    assert not result.is_anomaly
    
    # Outlier
    result = await detector.detect("memory_usage", 100.0, history)
    assert result.is_anomaly


@pytest.mark.asyncio
async def test_anomaly_detector_batch():
    """Test batch anomaly detection"""
    detector = AnomalyDetector()
    
    metrics = {
        "cpu": [45.0] * 100,
        "memory": [60.0] * 100
    }
    
    current_values = {
        "cpu": 90.0,  # Anomaly
        "memory": 62.0  # Normal
    }
    
    results = await detector.detect_batch(metrics, current_values)
    
    assert "cpu" in results
    assert results["cpu"].is_anomaly
    assert not results["memory"].is_anomaly


# ============================================================================
# Failure Predictor Tests
# ============================================================================

@pytest.mark.asyncio
async def test_failure_predictor_basic():
    """Test basic failure prediction"""
    predictor = FailurePredictor(probability_threshold=0.7)
    
    # High CPU - should predict potential failure
    current_metrics = {
        "cpu_usage": 95.0,
        "memory_usage": 88.0,
        "error_rate": 0.1
    }
    
    prediction = await predictor.predict(
        system_name="test-server",
        current_metrics=current_metrics
    )
    
    assert isinstance(prediction.failure_type, FailureType)
    assert 0.0 <= prediction.probability <= 1.0
    assert len(prediction.recommended_actions) > 0


@pytest.mark.asyncio
async def test_failure_predictor_disk_failure():
    """Test disk failure prediction"""
    predictor = FailurePredictor()
    
    metrics = {
        "disk_usage": 97.0  # Critical
    }
    
    prediction = await predictor.predict("storage", metrics)
    
    if prediction.will_fail:
        assert prediction.failure_type == FailureType.DISK_FAILURE
        assert prediction.time_to_failure is not None


@pytest.mark.asyncio
async def test_failure_predictor_stats():
    """Test prediction statistics"""
    predictor = FailurePredictor()
    
    # Make some predictions
    for i in range(5):
        await predictor.predict(f"system-{i}", {"cpu_usage": 50.0 + i * 10})
    
    stats = predictor.get_stats()
    assert stats["total_predictions"] == 5


# ============================================================================
# Metrics Collector Tests
# ============================================================================

@pytest.mark.asyncio
async def test_metrics_collector_system_metrics():
    """Test system metrics collection"""
    collector = MetricsCollector(collection_interval=1.0)
    
    metrics = await collector.collect_system_metrics()
    
    assert len(metrics) > 0
    assert any("cpu" in m.name.lower() for m in metrics)
    assert any("memory" in m.name.lower() for m in metrics)
    assert any("disk" in m.name.lower() for m in metrics)


@pytest.mark.asyncio
async def test_metrics_collector_custom():
    """Test custom metric registration"""
    collector = MetricsCollector()
    
    async def custom_collector():
        return [
            Metric(
                name="custom.metric",
                value=42.0,
                unit="count",
                metric_type=MetricType.CUSTOM,
                timestamp=datetime.now()
            )
        ]
    
    collector.register_collector("test", custom_collector)
    
    results = await collector.collect_all()
    assert "custom_test" in results


@pytest.mark.asyncio
async def test_metrics_collector_history():
    """Test metric history"""
    collector = MetricsCollector()
    
    # Add some metrics
    for i in range(10):
        metric = Metric(
            name="test.metric",
            value=float(i),
            unit="count",
            metric_type=MetricType.CUSTOM,
            timestamp=datetime.now()
        )
        collector.metrics_storage[metric.name].append(metric)
    
    history = collector.get_metrics("test.metric", limit=5)
    assert len(history) == 5


# ============================================================================
# Health Monitor Tests
# ============================================================================

@pytest.mark.asyncio
async def test_health_monitor_check():
    """Test health check"""
    collector = MetricsCollector()
    detector = AnomalyDetector()
    predictor = FailurePredictor()
    
    monitor = HealthMonitor(
        metrics_collector=collector,
        anomaly_detector=detector,
        failure_predictor=predictor
    )
    
    # Collect some metrics first
    await collector.collect_system_metrics()
    
    report = await monitor.check_health("test-system")
    
    assert isinstance(report.status, HealthStatus)
    assert 0.0 <= report.score <= 100.0
    assert isinstance(report.timestamp, datetime)


@pytest.mark.asyncio
async def test_health_monitor_score_calculation():
    """Test health score calculation"""
    collector = MetricsCollector()
    detector = AnomalyDetector()
    predictor = FailurePredictor()
    
    monitor = HealthMonitor(collector, detector, predictor)
    
    # Add test metrics
    metric = Metric(
        name="test.cpu.usage",
        value=50.0,  # Normal
        unit="percent",
        metric_type=MetricType.SYSTEM,
        timestamp=datetime.now()
    )
    collector.metrics_storage[metric.name].append(metric)
    
    report = await monitor.check_health("test")
    
    # Normal metrics should have high score
    assert report.score >= 70.0


# ============================================================================
# Alert Manager Tests
# ============================================================================

@pytest.mark.asyncio
async def test_alert_manager_create():
    """Test alert creation"""
    manager = AlertManager()
    
    alert = await manager.create_alert(
        title="Test Alert",
        description="Test description",
        severity=AlertSeverity.WARNING,
        source="test"
    )
    
    assert alert is not None
    assert alert.id.startswith("ALERT-")
    assert alert.severity == AlertSeverity.WARNING


@pytest.mark.asyncio
async def test_alert_manager_acknowledge():
    """Test alert acknowledgment"""
    manager = AlertManager()
    
    alert = await manager.create_alert(
        title="Test",
        description="Test",
        severity=AlertSeverity.ERROR,
        source="test"
    )
    
    success = await manager.acknowledge_alert(alert.id, "admin")
    
    assert success
    assert alert.acknowledged_by == "admin"
    assert alert.acknowledged_at is not None


@pytest.mark.asyncio
async def test_alert_manager_escalation():
    """Test alert escalation"""
    manager = AlertManager(max_escalation_level=3)
    
    alert = await manager.create_alert(
        title="Critical Issue",
        description="System down",
        severity=AlertSeverity.CRITICAL,
        source="test"
    )
    
    success = await manager.escalate_alert(alert.id, "No response")
    
    assert success
    assert alert.escalation_level == 1


@pytest.mark.asyncio
async def test_alert_manager_duplicate_suppression():
    """Test duplicate alert suppression"""
    manager = AlertManager()
    
    # Create first alert
    alert1 = await manager.create_alert(
        title="Duplicate Test",
        description="Test",
        severity=AlertSeverity.INFO,
        source="test"
    )
    
    # Try to create duplicate
    alert2 = await manager.create_alert(
        title="Duplicate Test",
        description="Test",
        severity=AlertSeverity.INFO,
        source="test"
    )
    
    assert alert1 is not None
    assert alert2 is None  # Suppressed


# ============================================================================
# Maintenance Scheduler Tests
# ============================================================================

@pytest.mark.asyncio
async def test_scheduler_schedule_task():
    """Test task scheduling"""
    scheduler = MaintenanceScheduler()
    
    task = await scheduler.schedule_task(
        title="Database Maintenance",
        description="Optimize indexes",
        maintenance_type=MaintenanceType.ROUTINE,
        system_name="database",
        actions=["VACUUM", "REINDEX"]
    )
    
    assert task.id.startswith("MAINT-")
    assert task.system_name == "database"
    assert len(task.actions) == 2


@pytest.mark.asyncio
async def test_scheduler_auto_priority():
    """Test automatic priority determination"""
    scheduler = MaintenanceScheduler()
    
    task = await scheduler.schedule_task(
        title="Emergency Fix",
        description="Critical issue",
        maintenance_type=MaintenanceType.EMERGENCY,
        system_name="api",
        actions=["Restart service"]
    )
    
    assert task.priority == MaintenancePriority.CRITICAL


@pytest.mark.asyncio
async def test_scheduler_cancel_task():
    """Test task cancellation"""
    scheduler = MaintenanceScheduler()
    
    task = await scheduler.schedule_task(
        title="Test Task",
        description="Test",
        maintenance_type=MaintenanceType.ROUTINE,
        system_name="test",
        actions=["Test action"]
    )
    
    success = await scheduler.cancel_task(task.id, "Test cancelled")
    
    assert success
    from src.scheduler import MaintenanceStatus
    assert task.status == MaintenanceStatus.CANCELLED


@pytest.mark.asyncio
async def test_scheduler_stats():
    """Test scheduler statistics"""
    scheduler = MaintenanceScheduler()
    
    # Create some tasks
    for i in range(3):
        await scheduler.schedule_task(
            title=f"Task {i}",
            description="Test",
            maintenance_type=MaintenanceType.ROUTINE,
            system_name="test",
            actions=["Action"]
        )
    
    stats = scheduler.get_stats()
    assert stats["total_tasks"] == 3


# ============================================================================
# Integration Tests
# ============================================================================

@pytest.mark.asyncio
async def test_integration_full_flow():
    """Test full integration flow"""
    # Setup
    collector = MetricsCollector()
    detector = AnomalyDetector()
    predictor = FailurePredictor()
    monitor = HealthMonitor(collector, detector, predictor)
    alert_manager = AlertManager()
    scheduler = MaintenanceScheduler()
    
    # Collect metrics
    await collector.collect_system_metrics()
    
    # Check health
    report = await monitor.check_health("integration-test")
    
    # Create alert if needed
    if report.status in [HealthStatus.UNHEALTHY, HealthStatus.CRITICAL]:
        alert = await alert_manager.create_alert(
            title="Health Check Failed",
            description=f"System unhealthy: {report.status}",
            severity=AlertSeverity.ERROR,
            source="integration-test"
        )
        assert alert is not None
    
    # Schedule maintenance
    task = await scheduler.schedule_task(
        title="Preventive Maintenance",
        description="Based on health check",
        maintenance_type=MaintenanceType.PREVENTIVE,
        system_name="integration-test",
        actions=["Check logs", "Optimize"]
    )
    
    assert task is not None
    assert report is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
