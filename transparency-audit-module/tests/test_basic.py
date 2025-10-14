"""Comprehensive tests for Transparency Audit Module"""
import pytest
from datetime import datetime, timedelta
import sys
sys.path.insert(0, '/workspaces/aethernova/transparency-audit-module')
from audit_trail import *
from compliance_engine import *
from forensic_analyzer import *
from real_time_monitor import *
from report_generator import *

def test_audit_event_creation():
    event = AuditEvent(
        level=AuditLevel.INFO,
        category=AuditCategory.AUTHENTICATION,
        action="login",
        resource="auth_system",
        description="User login successful"
    )
    assert event.event_id is not None

def test_audit_chain():
    system = create_audit_system()
    event1 = system.log_event(
        AuditLevel.INFO,
        AuditCategory.AUTHENTICATION,
        "login",
        "system",
        "User logged in"
    )
    event2 = system.log_event(
        AuditLevel.INFO,
        AuditCategory.DATA_ACCESS,
        "read",
        "database",
        "Data accessed"
    )
    assert event2.previous_hash == event1.hash

def test_compliance_engine():
    engine = create_compliance_engine()
    assert len(engine.controls) > 0

def test_forensic_analyzer():
    analyzer = create_forensic_analyzer()
    evidence = analyzer.collect_evidence(
        EvidenceType.LOG_FILE,
        "system1",
        "/var/log/app.log",
        {"content": "log data"},
        "analyst1"
    )
    assert evidence.evidence_id is not None

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
