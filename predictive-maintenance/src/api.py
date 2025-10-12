"""
REST API and WebSocket Module
Comprehensive API for Predictive Maintenance System
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Path
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

from .anomaly_detector import AnomalyDetector, AnomalySeverity, AnomalyType
from .failure_predictor import FailurePredictor, FailureType, FailureSeverity
from .metrics_collector import MetricsCollector, Metric, MetricType
from .health_monitor import HealthMonitor, HealthStatus
from .alerts import AlertManager, Alert, AlertSeverity, AlertChannel
from .scheduler import MaintenanceScheduler, MaintenanceType, MaintenancePriority

logger = logging.getLogger("predictive-maintenance.api")


# ============================================================================
# Pydantic Models
# ============================================================================

class MetricInput(BaseModel):
    """Входная модель для метрики"""
    name: str
    value: float
    unit: str = "count"
    labels: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = None


class PredictionRequest(BaseModel):
    """Запрос на предсказание"""
    system_name: str
    metrics: Dict[str, float]
    context: Optional[Dict[str, Any]] = None


class AlertCreateRequest(BaseModel):
    """Запрос на создание алерта"""
    title: str
    description: str
    severity: AlertSeverity
    source: str
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class MaintenanceTaskRequest(BaseModel):
    """Запрос на создание задачи обслуживания"""
    title: str
    description: str
    maintenance_type: MaintenanceType
    system_name: str
    actions: List[str]
    priority: Optional[MaintenancePriority] = None
    scheduled_time: Optional[datetime] = None
    estimated_duration_minutes: int = 60


class HealthCheckResponse(BaseModel):
    """Ответ health check"""
    status: str
    timestamp: datetime
    version: str = "1.0.0"
    components: Dict[str, str]


# ============================================================================
# WebSocket Connection Manager
# ============================================================================

class ConnectionManager:
    """Менеджер WebSocket подключений"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        """Подключение клиента"""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """Отключение клиента"""
        self.active_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Отправка сообщения одному клиенту"""
        await websocket.send_json(message)
    
    async def broadcast(self, message: dict):
        """Broadcast сообщения всем клиентам"""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to client: {e}")


# ============================================================================
# FastAPI Application
# ============================================================================

class PredictiveMaintenanceAPI:
    """
    Comprehensive REST API for Predictive Maintenance
    
    Endpoints:
    - Metrics management
    - Anomaly detection
    - Failure prediction
    - Health monitoring
    - Alerts management
    - Maintenance scheduling
    - Real-time updates via WebSocket
    """
    
    def __init__(
        self,
        metrics_collector: MetricsCollector,
        anomaly_detector: AnomalyDetector,
        failure_predictor: FailurePredictor,
        health_monitor: HealthMonitor,
        alert_manager: AlertManager,
        maintenance_scheduler: MaintenanceScheduler
    ):
        self.metrics_collector = metrics_collector
        self.anomaly_detector = anomaly_detector
        self.failure_predictor = failure_predictor
        self.health_monitor = health_monitor
        self.alert_manager = alert_manager
        self.maintenance_scheduler = maintenance_scheduler
        
        # WebSocket manager
        self.ws_manager = ConnectionManager()
        
        # Создание FastAPI app
        self.app = self._create_app()
        
        logger.info("PredictiveMaintenanceAPI initialized")
    
    def _create_app(self) -> FastAPI:
        """Создание FastAPI приложения"""
        
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            """Lifecycle manager"""
            # Startup
            await self._startup()
            yield
            # Shutdown
            await self._shutdown()
        
        app = FastAPI(
            title="Predictive Maintenance API",
            description="Comprehensive API for system health monitoring and predictive maintenance",
            version="1.0.0",
            lifespan=lifespan
        )
        
        # Регистрация роутов
        self._register_routes(app)
        
        return app
    
    async def _startup(self):
        """Startup действия"""
        logger.info("Starting Predictive Maintenance API...")
        
        # Запуск всех сервисов
        await self.metrics_collector.start_collection()
        await self.health_monitor.start_monitoring()
        await self.alert_manager.start()
        await self.maintenance_scheduler.start()
        
        # Регистрация коллбэков для WebSocket broadcast
        self.alert_manager.register_callback(
            "alert_created",
            lambda alert: self._broadcast_alert(alert)
        )
        
        self.health_monitor.register_status_change_callback(
            lambda system, old, new, report: self._broadcast_health_change(system, old, new, report)
        )
        
        logger.info("API started successfully")
    
    async def _shutdown(self):
        """Shutdown действия"""
        logger.info("Shutting down Predictive Maintenance API...")
        
        await self.metrics_collector.stop_collection()
        await self.health_monitor.stop_monitoring()
        await self.alert_manager.stop()
        await self.maintenance_scheduler.stop()
        
        logger.info("API shut down successfully")
    
    def _register_routes(self, app: FastAPI):
        """Регистрация всех роутов"""
        
        # ====================================================================
        # Health & Status
        # ====================================================================
        
        @app.get("/", response_model=HealthCheckResponse)
        async def root():
            """Root endpoint with system status"""
            return HealthCheckResponse(
                status="healthy",
                timestamp=datetime.now(),
                components={
                    "metrics_collector": "running" if self.metrics_collector.is_collecting else "stopped",
                    "health_monitor": "running" if self.health_monitor.is_monitoring else "stopped",
                    "alert_manager": "running" if self.alert_manager.is_escalating else "stopped",
                    "scheduler": "running" if self.maintenance_scheduler.is_running else "stopped"
                }
            )
        
        @app.get("/health")
        async def health_check():
            """Detailed health check"""
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "metrics": self.metrics_collector.get_stats(),
                "anomalies": self.anomaly_detector.get_stats(),
                "predictions": self.failure_predictor.get_stats(),
                "health_monitor": self.health_monitor.get_stats(),
                "alerts": self.alert_manager.get_stats(),
                "scheduler": self.maintenance_scheduler.get_stats()
            }
        
        # ====================================================================
        # Metrics
        # ====================================================================
        
        @app.post("/api/v1/metrics")
        async def submit_metric(metric: MetricInput):
            """Submit a custom metric"""
            m = Metric(
                name=metric.name,
                value=metric.value,
                unit=metric.unit,
                metric_type=MetricType.CUSTOM,
                timestamp=datetime.now(),
                labels=metric.labels or {},
                metadata=metric.metadata or {}
            )
            
            self.metrics_collector.metrics_storage[m.name].append(m)
            
            return {"status": "success", "metric_id": m.name}
        
        @app.get("/api/v1/metrics/{metric_name}")
        async def get_metric(
            metric_name: str = Path(..., description="Metric name"),
            limit: Optional[int] = Query(100, description="Max results")
        ):
            """Get metric history"""
            metrics = self.metrics_collector.get_metrics(metric_name, limit=limit)
            
            if not metrics:
                raise HTTPException(status_code=404, detail="Metric not found")
            
            return {
                "metric_name": metric_name,
                "count": len(metrics),
                "data": [m.to_dict() for m in metrics]
            }
        
        @app.get("/api/v1/metrics")
        async def list_metrics():
            """List all available metrics"""
            latest = self.metrics_collector.get_latest_metrics()
            
            return {
                "count": len(latest),
                "metrics": {
                    name: metric.to_dict()
                    for name, metric in latest.items()
                }
            }
        
        # ====================================================================
        # Anomaly Detection
        # ====================================================================
        
        @app.post("/api/v1/anomalies/detect")
        async def detect_anomaly(
            metric_name: str = Query(..., description="Metric name"),
            value: float = Query(..., description="Current value")
        ):
            """Detect anomaly in a metric"""
            history = self.metrics_collector.get_metric_values(metric_name)
            
            if len(history) < self.anomaly_detector.min_samples:
                raise HTTPException(
                    status_code=400,
                    detail=f"Not enough historical data (need {self.anomaly_detector.min_samples})"
                )
            
            result = await self.anomaly_detector.detect(
                metric_name,
                value,
                history
            )
            
            return result.to_dict()
        
        @app.get("/api/v1/anomalies")
        async def get_anomalies(
            severity: Optional[AnomalySeverity] = Query(None, description="Filter by severity"),
            limit: Optional[int] = Query(50, description="Max results")
        ):
            """Get detected anomalies"""
            # В реальной системе здесь будет хранилище аномалий
            return {
                "count": 0,
                "anomalies": [],
                "message": "Anomaly history not yet implemented"
            }
        
        # ====================================================================
        # Failure Prediction
        # ====================================================================
        
        @app.post("/api/v1/predictions/predict")
        async def predict_failure(request: PredictionRequest):
            """Predict potential system failure"""
            prediction = await self.failure_predictor.predict(
                request.system_name,
                request.metrics,
                context=request.context
            )
            
            return prediction.to_dict()
        
        @app.get("/api/v1/predictions")
        async def get_predictions():
            """Get prediction statistics"""
            return self.failure_predictor.get_stats()
        
        # ====================================================================
        # Health Monitoring
        # ====================================================================
        
        @app.post("/api/v1/health/check/{system_name}")
        async def check_system_health(
            system_name: str = Path(..., description="System name")
        ):
            """Run health check for a system"""
            report = await self.health_monitor.check_health(system_name)
            return report.to_dict()
        
        @app.get("/api/v1/health/{system_name}")
        async def get_system_health(
            system_name: str = Path(..., description="System name")
        ):
            """Get latest health report for a system"""
            report = self.health_monitor.get_system_health(system_name)
            
            if not report:
                raise HTTPException(
                    status_code=404,
                    detail=f"No health data for system: {system_name}"
                )
            
            return report.to_dict()
        
        @app.get("/api/v1/health/{system_name}/history")
        async def get_health_history(
            system_name: str = Path(..., description="System name"),
            limit: Optional[int] = Query(10, description="Max results")
        ):
            """Get health history for a system"""
            history = self.health_monitor.get_health_history(system_name, limit=limit)
            
            return {
                "system_name": system_name,
                "count": len(history),
                "history": [report.to_dict() for report in history]
            }
        
        @app.get("/api/v1/health")
        async def get_all_health():
            """Get health status of all systems"""
            status = self.health_monitor.get_all_systems_status()
            
            return {
                "count": len(status),
                "systems": {
                    name: stat.value
                    for name, stat in status.items()
                }
            }
        
        # ====================================================================
        # Alerts
        # ====================================================================
        
        @app.post("/api/v1/alerts")
        async def create_alert(request: AlertCreateRequest):
            """Create a new alert"""
            alert = await self.alert_manager.create_alert(
                title=request.title,
                description=request.description,
                severity=request.severity,
                source=request.source,
                tags=request.tags,
                metadata=request.metadata
            )
            
            if not alert:
                raise HTTPException(
                    status_code=409,
                    detail="Duplicate alert suppressed"
                )
            
            return alert.to_dict()
        
        @app.get("/api/v1/alerts")
        async def list_alerts(
            status: Optional[str] = Query(None, description="Filter by status"),
            severity: Optional[AlertSeverity] = Query(None, description="Filter by severity"),
            limit: Optional[int] = Query(50, description="Max results")
        ):
            """List alerts with filters"""
            from .alerts import AlertStatus
            
            status_filter = AlertStatus(status) if status else None
            alerts = self.alert_manager.get_alerts(
                status=status_filter,
                severity=severity,
                limit=limit
            )
            
            return {
                "count": len(alerts),
                "alerts": [alert.to_dict() for alert in alerts]
            }
        
        @app.get("/api/v1/alerts/{alert_id}")
        async def get_alert(alert_id: str = Path(..., description="Alert ID")):
            """Get alert details"""
            alert = self.alert_manager.alerts.get(alert_id)
            
            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")
            
            return alert.to_dict()
        
        @app.post("/api/v1/alerts/{alert_id}/acknowledge")
        async def acknowledge_alert(
            alert_id: str = Path(..., description="Alert ID"),
            user: str = Query(..., description="User name")
        ):
            """Acknowledge an alert"""
            success = await self.alert_manager.acknowledge_alert(alert_id, user)
            
            if not success:
                raise HTTPException(status_code=404, detail="Alert not found")
            
            return {"status": "success", "alert_id": alert_id}
        
        @app.post("/api/v1/alerts/{alert_id}/resolve")
        async def resolve_alert(
            alert_id: str = Path(..., description="Alert ID"),
            resolution_note: str = Query(..., description="Resolution note"),
            user: Optional[str] = Query(None, description="User name")
        ):
            """Resolve an alert"""
            success = await self.alert_manager.resolve_alert(
                alert_id,
                resolution_note,
                user
            )
            
            if not success:
                raise HTTPException(status_code=404, detail="Alert not found")
            
            return {"status": "success", "alert_id": alert_id}
        
        # ====================================================================
        # Maintenance Scheduling
        # ====================================================================
        
        @app.post("/api/v1/maintenance")
        async def schedule_maintenance(request: MaintenanceTaskRequest):
            """Schedule a maintenance task"""
            task = await self.maintenance_scheduler.schedule_task(
                title=request.title,
                description=request.description,
                maintenance_type=request.maintenance_type,
                system_name=request.system_name,
                actions=request.actions,
                priority=request.priority,
                scheduled_time=request.scheduled_time,
                estimated_duration=timedelta(minutes=request.estimated_duration_minutes)
            )
            
            return task.to_dict()
        
        @app.get("/api/v1/maintenance")
        async def list_maintenance_tasks(
            status: Optional[str] = Query(None, description="Filter by status"),
            system_name: Optional[str] = Query(None, description="Filter by system"),
            limit: Optional[int] = Query(50, description="Max results")
        ):
            """List maintenance tasks"""
            from .scheduler import MaintenanceStatus
            
            status_filter = MaintenanceStatus(status) if status else None
            tasks = self.maintenance_scheduler.get_tasks(
                status=status_filter,
                system_name=system_name,
                limit=limit
            )
            
            return {
                "count": len(tasks),
                "tasks": [task.to_dict() for task in tasks]
            }
        
        @app.get("/api/v1/maintenance/{task_id}")
        async def get_maintenance_task(task_id: str = Path(..., description="Task ID")):
            """Get maintenance task details"""
            task = self.maintenance_scheduler.tasks.get(task_id)
            
            if not task:
                raise HTTPException(status_code=404, detail="Task not found")
            
            return task.to_dict()
        
        @app.post("/api/v1/maintenance/{task_id}/cancel")
        async def cancel_maintenance_task(
            task_id: str = Path(..., description="Task ID"),
            reason: str = Query(..., description="Cancellation reason")
        ):
            """Cancel a maintenance task"""
            success = await self.maintenance_scheduler.cancel_task(task_id, reason)
            
            if not success:
                raise HTTPException(status_code=404, detail="Task not found or cannot be cancelled")
            
            return {"status": "success", "task_id": task_id}
        
        # ====================================================================
        # WebSocket
        # ====================================================================
        
        @app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time updates"""
            await self.ws_manager.connect(websocket)
            
            try:
                while True:
                    # Ожидание сообщений от клиента
                    data = await websocket.receive_json()
                    
                    # Обработка команд
                    command = data.get("command")
                    
                    if command == "ping":
                        await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
                    
                    elif command == "subscribe":
                        # Подписка на обновления
                        await websocket.send_json({
                            "type": "subscribed",
                            "message": "Successfully subscribed to real-time updates"
                        })
            
            except WebSocketDisconnect:
                self.ws_manager.disconnect(websocket)
    
    async def _broadcast_alert(self, alert):
        """Broadcast нового алерта через WebSocket"""
        await self.ws_manager.broadcast({
            "type": "alert",
            "data": alert.to_dict()
        })
    
    async def _broadcast_health_change(self, system, old_status, new_status, report):
        """Broadcast изменения health status"""
        await self.ws_manager.broadcast({
            "type": "health_change",
            "data": {
                "system": system,
                "old_status": old_status.value,
                "new_status": new_status.value,
                "report": report.to_dict()
            }
        })
    
    def run(self, host: str = "0.0.0.0", port: int = 8000):
        """Запуск API сервера"""
        logger.info(f"Starting API server on {host}:{port}")
        uvicorn.run(self.app, host=host, port=port)


# ============================================================================
# Factory Function
# ============================================================================

async def create_api(
    collection_interval: float = 60.0,
    prediction_horizon_hours: int = 24,
    enable_auto_scheduling: bool = True
) -> PredictiveMaintenanceAPI:
    """
    Factory function для создания полного API
    
    Args:
        collection_interval: Интервал сбора метрик (секунды)
        prediction_horizon_hours: Горизонт предсказаний (часы)
        enable_auto_scheduling: Включить автоматическое планирование
    
    Returns:
        Настроенный instance PredictiveMaintenanceAPI
    """
    # Создание всех компонентов
    metrics_collector = MetricsCollector(
        collection_interval=collection_interval
    )
    
    anomaly_detector = AnomalyDetector()
    
    failure_predictor = FailurePredictor(
        prediction_horizon=timedelta(hours=prediction_horizon_hours)
    )
    
    health_monitor = HealthMonitor(
        metrics_collector=metrics_collector,
        anomaly_detector=anomaly_detector,
        failure_predictor=failure_predictor
    )
    
    alert_manager = AlertManager()
    
    maintenance_scheduler = MaintenanceScheduler(
        enable_auto_scheduling=enable_auto_scheduling
    )
    
    # Создание API
    api = PredictiveMaintenanceAPI(
        metrics_collector=metrics_collector,
        anomaly_detector=anomaly_detector,
        failure_predictor=failure_predictor,
        health_monitor=health_monitor,
        alert_manager=alert_manager,
        maintenance_scheduler=maintenance_scheduler
    )
    
    return api
