"""
Real-Time Monitoring System - Live Audit and Compliance Monitoring
==================================================================

Real-time monitoring system providing:
- WebSocket streaming of audit events
- Live dashboards
- Instant alerting for suspicious activities
- Compliance violation detection
- Performance monitoring
- Real-time analytics

Author: AetherNova Development Team
License: MIT
"""

import asyncio
import json
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MonitoringMetric(str, Enum):
    """Monitoring metrics"""
    FAILED_LOGINS = "failed_logins"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_ACCESS_VOLUME = "data_access_volume"
    COMPLIANCE_VIOLATIONS = "compliance_violations"
    SYSTEM_ERRORS = "system_errors"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class Alert(BaseModel):
    """Real-time alert"""
    
    alert_id: str
    severity: AlertSeverity
    metric: MonitoringMetric
    
    title: str
    description: str
    threshold_exceeded: float
    current_value: float
    
    triggered_at: datetime = Field(default_factory=datetime.utcnow)
    acknowledged: bool = False
    resolved: bool = False
    
    affected_resources: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)


class MonitoringRule(BaseModel):
    """Monitoring rule configuration"""
    
    rule_id: str
    name: str
    description: str
    
    metric: MonitoringMetric
    threshold: float
    time_window_seconds: int = 300  # 5 minutes default
    
    severity: AlertSeverity
    enabled: bool = True
    
    actions: List[str] = Field(default_factory=list)


class DashboardWidget(BaseModel):
    """Dashboard widget configuration"""
    
    widget_id: str
    widget_type: str  # chart, gauge, counter, list
    title: str
    
    metric: MonitoringMetric
    refresh_interval: int = 5  # seconds
    
    config: Dict[str, Any] = Field(default_factory=dict)


class RealTimeMonitor:
    """
    Real-time monitoring system
    
    Features:
    - WebSocket event streaming
    - Threshold-based alerting
    - Live dashboards
    - Metric aggregation
    - Anomaly detection
    """
    
    def __init__(self):
        self.active_connections: Set[Any] = set()
        self.alerts: List[Alert] = []
        self.rules: Dict[str, MonitoringRule] = {}
        self.metrics: Dict[MonitoringMetric, List[float]] = {}
        self.event_buffer: List[Dict[str, Any]] = []
        
        # Initialize default rules
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default monitoring rules"""
        self.rules["failed_logins"] = MonitoringRule(
            rule_id="failed_logins",
            name="Failed Login Attempts",
            description="Alert on excessive failed login attempts",
            metric=MonitoringMetric.FAILED_LOGINS,
            threshold=5.0,
            time_window_seconds=300,
            severity=AlertSeverity.HIGH,
            actions=["notify_security_team", "trigger_account_lockout"]
        )
        
        self.rules["unauthorized_access"] = MonitoringRule(
            rule_id="unauthorized_access",
            name="Unauthorized Access Attempts",
            description="Alert on unauthorized access attempts",
            metric=MonitoringMetric.UNAUTHORIZED_ACCESS,
            threshold=3.0,
            time_window_seconds=600,
            severity=AlertSeverity.CRITICAL,
            actions=["notify_security_team", "trigger_incident"]
        )
        
        self.rules["compliance_violations"] = MonitoringRule(
            rule_id="compliance_violations",
            name="Compliance Violations",
            description="Alert on compliance violations",
            metric=MonitoringMetric.COMPLIANCE_VIOLATIONS,
            threshold=1.0,
            time_window_seconds=60,
            severity=AlertSeverity.HIGH,
            actions=["notify_compliance_team", "create_compliance_ticket"]
        )
    
    async def connect_websocket(self, connection: Any):
        """Connect WebSocket client"""
        self.active_connections.add(connection)
    
    async def disconnect_websocket(self, connection: Any):
        """Disconnect WebSocket client"""
        self.active_connections.discard(connection)
    
    async def broadcast_event(self, event: Dict[str, Any]):
        """Broadcast event to all connected clients"""
        message = json.dumps(event, default=str)
        
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.add(connection)
        
        # Clean up disconnected clients
        self.active_connections -= disconnected
    
    def record_metric(self, metric: MonitoringMetric, value: float):
        """Record metric value"""
        if metric not in self.metrics:
            self.metrics[metric] = []
        
        self.metrics[metric].append(value)
        
        # Keep only recent values (last hour)
        max_values = 3600  # 1 hour at 1 value/second
        if len(self.metrics[metric]) > max_values:
            self.metrics[metric] = self.metrics[metric][-max_values:]
        
        # Check thresholds
        self._check_thresholds(metric)
    
    def _check_thresholds(self, metric: MonitoringMetric):
        """Check if metric exceeds thresholds"""
        for rule in self.rules.values():
            if not rule.enabled or rule.metric != metric:
                continue
            
            # Get recent values within time window
            if metric in self.metrics:
                recent_values = self.metrics[metric][-rule.time_window_seconds:]
                if recent_values:
                    current_value = sum(recent_values)
                    
                    if current_value > rule.threshold:
                        self._trigger_alert(rule, current_value)
    
    def _trigger_alert(self, rule: MonitoringRule, current_value: float):
        """Trigger alert for rule violation"""
        alert = Alert(
            alert_id=f"ALT-{len(self.alerts)}",
            severity=rule.severity,
            metric=rule.metric,
            title=rule.name,
            description=rule.description,
            threshold_exceeded=rule.threshold,
            current_value=current_value,
            recommended_actions=rule.actions
        )
        
        self.alerts.append(alert)
        
        # Broadcast alert
        asyncio.create_task(self.broadcast_event({
            "type": "alert",
            "alert": alert.dict()
        }))
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get current dashboard data"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "active_connections": len(self.active_connections),
            "metrics": {
                metric.value: {
                    "current": self.metrics[metric][-1] if metric in self.metrics and self.metrics[metric] else 0,
                    "average_5m": sum(self.metrics[metric][-300:]) / len(self.metrics[metric][-300:]) if metric in self.metrics and self.metrics[metric][-300:] else 0,
                    "peak_1h": max(self.metrics[metric]) if metric in self.metrics and self.metrics[metric] else 0
                }
                for metric in MonitoringMetric
            },
            "active_alerts": [
                a.dict() for a in self.alerts
                if not a.resolved
            ][-10:],
            "alert_counts": {
                "critical": len([a for a in self.alerts if a.severity == AlertSeverity.CRITICAL and not a.resolved]),
                "high": len([a for a in self.alerts if a.severity == AlertSeverity.HIGH and not a.resolved]),
                "medium": len([a for a in self.alerts if a.severity == AlertSeverity.MEDIUM and not a.resolved]),
                "low": len([a for a in self.alerts if a.severity == AlertSeverity.LOW and not a.resolved])
            }
        }
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge alert"""
        alert = next((a for a in self.alerts if a.alert_id == alert_id), None)
        if alert:
            alert.acknowledged = True
            return True
        return False
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve alert"""
        alert = next((a for a in self.alerts if a.alert_id == alert_id), None)
        if alert:
            alert.resolved = True
            return True
        return False


def create_monitor() -> RealTimeMonitor:
    """Create new real-time monitor"""
    return RealTimeMonitor()
