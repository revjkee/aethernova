"""
Transparency Audit Module - REST API + WebSocket
================================================

Complete API providing:
- Audit trail operations
- Compliance checking
- Forensic analysis
- Real-time monitoring
- Report generation

Author: AetherNova Development Team
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from audit_trail import (
    AuditTrailSystem, AuditLevel, AuditCategory,
    create_audit_system
)
from compliance_engine import (
    ComplianceEngine, ComplianceFramework, Severity,
    create_compliance_engine
)
from forensic_analyzer import (
    ForensicAnalyzer, IncidentSeverity, IncidentCategory, EvidenceType,
    create_forensic_analyzer
)
from real_time_monitor import RealTimeMonitor, MonitoringMetric, create_monitor
from report_generator import ReportGenerator, ReportFormat, ReportType, create_report_generator

# Initialize systems
audit_system = create_audit_system()
compliance_engine = create_compliance_engine()
forensic_analyzer = create_forensic_analyzer()
monitor = create_monitor()
report_generator = create_report_generator()

# Create FastAPI app
app = FastAPI(
    title="Transparency Audit Module API",
    description="Comprehensive audit, compliance, and forensic analysis system",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response Models
class AuditEventRequest(BaseModel):
    level: str
    category: str
    action: str
    resource: str
    description: str
    user_id: Optional[str] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None
    success: bool = True
    risk_score: float = 0.0


class ComplianceCheckRequest(BaseModel):
    framework: str
    control_id: str
    evidence: Optional[Dict[str, Any]] = None


class IncidentRequest(BaseModel):
    severity: str
    category: str
    title: str
    description: str
    affected_systems: Optional[List[str]] = None


class EvidenceRequest(BaseModel):
    evidence_type: str
    source_system: str
    source_location: str
    data: Dict[str, Any]
    collected_by: str


# === AUDIT TRAIL ENDPOINTS ===

@app.post("/api/v1/audit/events", tags=["Audit Trail"])
async def log_audit_event(request: AuditEventRequest):
    """Log audit event"""
    try:
        event = audit_system.log_event(
            level=AuditLevel(request.level),
            category=AuditCategory(request.category),
            action=request.action,
            resource=request.resource,
            description=request.description,
            user_id=request.user_id,
            username=request.username,
            ip_address=request.ip_address,
            success=request.success,
            risk_score=request.risk_score
        )
        return {"status": "success", "event_id": event.event_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/audit/events/search", tags=["Audit Trail"])
async def search_audit_events(
    user_id: Optional[str] = None,
    category: Optional[str] = None,
    level: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 100
):
    """Search audit events"""
    try:
        start = datetime.fromisoformat(start_time) if start_time else None
        end = datetime.fromisoformat(end_time) if end_time else None
        cat = AuditCategory(category) if category else None
        lv = AuditLevel(level) if level else None
        
        events = audit_system.search_events(
            user_id=user_id,
            category=cat,
            level=lv,
            start_time=start,
            end_time=end,
            limit=limit
        )
        
        return {
            "total": len(events),
            "events": [e.dict() for e in events]
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/audit/verify/{event_id}", tags=["Audit Trail"])
async def verify_event(event_id: str):
    """Verify event integrity"""
    is_valid, errors = audit_system.verify_event(event_id)
    return {"event_id": event_id, "valid": is_valid, "errors": errors}


@app.get("/api/v1/audit/statistics", tags=["Audit Trail"])
async def get_audit_statistics(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None
):
    """Get audit statistics"""
    start = datetime.fromisoformat(start_time) if start_time else None
    end = datetime.fromisoformat(end_time) if end_time else None
    stats = audit_system.get_audit_statistics(start, end)
    return stats


# === COMPLIANCE ENDPOINTS ===

@app.post("/api/v1/compliance/check", tags=["Compliance"])
async def check_compliance_control(request: ComplianceCheckRequest):
    """Check compliance control"""
    try:
        framework = ComplianceFramework(request.framework)
        status, findings = compliance_engine.check_control(
            framework,
            request.control_id,
            request.evidence
        )
        return {
            "framework": request.framework,
            "control_id": request.control_id,
            "status": status.value,
            "findings": findings
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/compliance/assess/{framework}", tags=["Compliance"])
async def assess_compliance_framework(framework: str):
    """Assess entire compliance framework"""
    try:
        fw = ComplianceFramework(framework)
        report = compliance_engine.assess_framework(fw)
        return report.dict()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/compliance/dashboard", tags=["Compliance"])
async def get_compliance_dashboard():
    """Get compliance dashboard"""
    return compliance_engine.get_compliance_dashboard()


@app.post("/api/v1/compliance/issue", tags=["Compliance"])
async def report_compliance_issue(
    framework: str,
    control_id: str,
    severity: str,
    title: str,
    description: str,
    impact: str,
    remediation_steps: List[str]
):
    """Report compliance issue"""
    try:
        issue = compliance_engine.report_issue(
            ComplianceFramework(framework),
            control_id,
            Severity(severity),
            title,
            description,
            impact,
            remediation_steps
        )
        return issue.dict()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# === FORENSIC ENDPOINTS ===

@app.post("/api/v1/forensic/evidence", tags=["Forensic"])
async def collect_evidence(request: EvidenceRequest):
    """Collect forensic evidence"""
    try:
        evidence = forensic_analyzer.collect_evidence(
            EvidenceType(request.evidence_type),
            request.source_system,
            request.source_location,
            request.data,
            request.collected_by
        )
        return {"evidence_id": evidence.evidence_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/forensic/incident", tags=["Forensic"])
async def create_incident(request: IncidentRequest):
    """Create forensic incident"""
    try:
        incident = forensic_analyzer.create_incident(
            IncidentSeverity(request.severity),
            IncidentCategory(request.category),
            request.title,
            request.description,
            request.affected_systems
        )
        return {"incident_id": incident.incident_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/forensic/timeline/{incident_id}", tags=["Forensic"])
async def reconstruct_timeline(incident_id: str):
    """Reconstruct forensic timeline"""
    try:
        timeline = forensic_analyzer.reconstruct_timeline(incident_id)
        return {
            "incident_id": incident_id,
            "events": [e.dict() for e in timeline]
        }
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/v1/forensic/analyze/{incident_id}", tags=["Forensic"])
async def analyze_incident(incident_id: str):
    """Perform root cause analysis"""
    try:
        analysis = forensic_analyzer.perform_root_cause_analysis(incident_id)
        return analysis
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/v1/forensic/report/{incident_id}", tags=["Forensic"])
async def get_forensic_report(incident_id: str, include_evidence: bool = True):
    """Generate forensic report"""
    try:
        report = forensic_analyzer.generate_forensic_report(incident_id, include_evidence)
        return report
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


# === MONITORING ENDPOINTS ===

@app.get("/api/v1/monitor/dashboard", tags=["Monitoring"])
async def get_monitor_dashboard():
    """Get monitoring dashboard"""
    return monitor.get_dashboard_data()


@app.post("/api/v1/monitor/metric", tags=["Monitoring"])
async def record_metric(metric: str, value: float):
    """Record monitoring metric"""
    try:
        monitor.record_metric(MonitoringMetric(metric), value)
        return {"status": "recorded"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/monitor/alert/{alert_id}/acknowledge", tags=["Monitoring"])
async def acknowledge_alert(alert_id: str):
    """Acknowledge alert"""
    if monitor.acknowledge_alert(alert_id):
        return {"status": "acknowledged"}
    raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/api/v1/monitor/alert/{alert_id}/resolve", tags=["Monitoring"])
async def resolve_alert(alert_id: str):
    """Resolve alert"""
    if monitor.resolve_alert(alert_id):
        return {"status": "resolved"}
    raise HTTPException(status_code=404, detail="Alert not found")


# === REPORTING ENDPOINTS ===

@app.post("/api/v1/reports/compliance", tags=["Reports"])
async def generate_compliance_report(
    framework: str,
    assessment_data: Dict[str, Any],
    period_start: str,
    period_end: str,
    generated_by: str,
    format: str = "pdf"
):
    """Generate compliance report"""
    try:
        report = report_generator.generate_compliance_report(
            framework,
            assessment_data,
            datetime.fromisoformat(period_start),
            datetime.fromisoformat(period_end),
            generated_by,
            ReportFormat(format)
        )
        return report.dict()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/reports/audit", tags=["Reports"])
async def generate_audit_report(
    events: List[Dict[str, Any]],
    period_start: str,
    period_end: str,
    generated_by: str,
    format: str = "json"
):
    """Generate audit trail report"""
    try:
        report = report_generator.generate_audit_trail_report(
            events,
            datetime.fromisoformat(period_start),
            datetime.fromisoformat(period_end),
            generated_by,
            ReportFormat(format)
        )
        return report.dict()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/reports/{report_id}", tags=["Reports"])
async def get_report(report_id: str):
    """Get generated report"""
    report = report_generator.reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report.dict()


# === WEBSOCKET ENDPOINT ===

@app.websocket("/ws/monitor")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time monitoring"""
    await websocket.accept()
    await monitor.connect_websocket(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            # Handle incoming messages if needed
            await websocket.send_text(f"Echo: {data}")
    except WebSocketDisconnect:
        await monitor.disconnect_websocket(websocket)


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "systems": {
            "audit": audit_system.storage.get_events_count(),
            "compliance": len(compliance_engine.reports),
            "forensic": len(forensic_analyzer.incidents),
            "monitoring": len(monitor.active_connections),
            "reporting": len(report_generator.reports)
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
