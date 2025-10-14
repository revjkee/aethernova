"""
Report Generator - Compliance and Audit Report Generation
=========================================================

Comprehensive reporting system providing:
- Compliance reports (PDF/HTML/JSON)
- Audit trail reports
- Forensic investigation reports
- Executive summaries
- Customizable templates
- Automated scheduling

Author: AetherNova Development Team
License: MIT
"""

import json
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ReportFormat(str, Enum):
    """Report output formats"""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    MARKDOWN = "markdown"


class ReportType(str, Enum):
    """Types of reports"""
    COMPLIANCE = "compliance"
    AUDIT_TRAIL = "audit_trail"
    FORENSIC = "forensic"
    EXECUTIVE_SUMMARY = "executive_summary"
    INCIDENT = "incident"
    USER_ACTIVITY = "user_activity"
    SYSTEM_HEALTH = "system_health"


class Report(BaseModel):
    """Generated report"""
    
    report_id: str
    report_type: ReportType
    format: ReportFormat
    
    title: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generated_by: str
    
    period_start: datetime
    period_end: datetime
    
    content: Dict[str, Any] = Field(default_factory=dict)
    raw_data: Optional[str] = None
    
    file_path: Optional[str] = None
    file_size: Optional[int] = None


class ReportTemplate(BaseModel):
    """Report template configuration"""
    
    template_id: str
    name: str
    description: str
    
    report_type: ReportType
    default_format: ReportFormat
    
    sections: List[str] = Field(default_factory=list)
    styling: Dict[str, Any] = Field(default_factory=dict)


class ReportGenerator:
    """
    Report generation system
    
    Features:
    - Multiple output formats
    - Customizable templates
    - Automated generation
    - Compliance-ready reports
    """
    
    def __init__(self):
        self.reports: Dict[str, Report] = {}
        self.templates: Dict[str, ReportTemplate] = {}
        
        # Initialize default templates
        self._initialize_templates()
    
    def _initialize_templates(self):
        """Initialize default report templates"""
        self.templates["compliance_gdpr"] = ReportTemplate(
            template_id="compliance_gdpr",
            name="GDPR Compliance Report",
            description="Comprehensive GDPR compliance assessment",
            report_type=ReportType.COMPLIANCE,
            default_format=ReportFormat.PDF,
            sections=[
                "executive_summary",
                "compliance_status",
                "data_subject_rights",
                "data_protection_measures",
                "breach_notifications",
                "recommendations"
            ]
        )
        
        self.templates["audit_trail_full"] = ReportTemplate(
            template_id="audit_trail_full",
            name="Complete Audit Trail",
            description="Full audit trail with all events",
            report_type=ReportType.AUDIT_TRAIL,
            default_format=ReportFormat.JSON,
            sections=[
                "summary",
                "events_by_user",
                "events_by_category",
                "security_events",
                "compliance_events",
                "statistics"
            ]
        )
        
        self.templates["forensic_investigation"] = ReportTemplate(
            template_id="forensic_investigation",
            name="Forensic Investigation Report",
            description="Detailed forensic analysis report",
            report_type=ReportType.FORENSIC,
            default_format=ReportFormat.PDF,
            sections=[
                "executive_summary",
                "incident_details",
                "timeline",
                "evidence",
                "analysis",
                "root_cause",
                "recommendations",
                "appendix"
            ]
        )
    
    def generate_compliance_report(
        self,
        framework: str,
        assessment_data: Dict[str, Any],
        period_start: datetime,
        period_end: datetime,
        generated_by: str,
        format: ReportFormat = ReportFormat.PDF
    ) -> Report:
        """
        Generate compliance report
        
        Args:
            framework: Compliance framework (GDPR, SOC2, etc.)
            assessment_data: Assessment results
            period_start: Report period start
            period_end: Report period end
            generated_by: Person generating report
            format: Output format
            
        Returns:
            Generated report
        """
        report_id = f"COMP-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        content = {
            "framework": framework,
            "executive_summary": {
                "overall_status": assessment_data.get("overall_status", "unknown"),
                "compliance_score": assessment_data.get("compliance_score", 0.0),
                "period": f"{period_start.date()} to {period_end.date()}",
                "key_findings": assessment_data.get("key_findings", [])
            },
            "compliance_status": {
                "total_controls": assessment_data.get("total_controls", 0),
                "compliant": assessment_data.get("compliant_controls", 0),
                "non_compliant": assessment_data.get("non_compliant_controls", 0),
                "partially_compliant": assessment_data.get("partially_compliant_controls", 0)
            },
            "issues": {
                "critical": assessment_data.get("critical_issues", 0),
                "high": assessment_data.get("high_issues", 0),
                "medium": assessment_data.get("medium_issues", 0),
                "low": assessment_data.get("low_issues", 0)
            },
            "controls_summary": assessment_data.get("controls_summary", []),
            "recommendations": assessment_data.get("recommendations", [])
        }
        
        report = Report(
            report_id=report_id,
            report_type=ReportType.COMPLIANCE,
            format=format,
            title=f"{framework} Compliance Report",
            generated_by=generated_by,
            period_start=period_start,
            period_end=period_end,
            content=content
        )
        
        # Generate formatted output
        if format == ReportFormat.JSON:
            report.raw_data = json.dumps(content, indent=2, default=str)
        elif format == ReportFormat.HTML:
            report.raw_data = self._generate_html_report(content, "Compliance Report")
        elif format == ReportFormat.MARKDOWN:
            report.raw_data = self._generate_markdown_report(content, "Compliance Report")
        
        self.reports[report_id] = report
        return report
    
    def generate_audit_trail_report(
        self,
        events: List[Dict[str, Any]],
        period_start: datetime,
        period_end: datetime,
        generated_by: str,
        format: ReportFormat = ReportFormat.JSON
    ) -> Report:
        """
        Generate audit trail report
        
        Args:
            events: Audit events
            period_start: Report period start
            period_end: Report period end
            generated_by: Person generating report
            format: Output format
            
        Returns:
            Generated report
        """
        report_id = f"AUDIT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        # Analyze events
        by_user = {}
        by_category = {}
        by_level = {}
        
        for event in events:
            user = event.get("user_id", "unknown")
            if user not in by_user:
                by_user[user] = 0
            by_user[user] += 1
            
            category = event.get("category", "unknown")
            if category not in by_category:
                by_category[category] = 0
            by_category[category] += 1
            
            level = event.get("level", "info")
            if level not in by_level:
                by_level[level] = 0
            by_level[level] += 1
        
        content = {
            "summary": {
                "total_events": len(events),
                "period": f"{period_start.date()} to {period_end.date()}",
                "unique_users": len(by_user),
                "event_categories": len(by_category)
            },
            "events_by_user": by_user,
            "events_by_category": by_category,
            "events_by_level": by_level,
            "security_events": [
                e for e in events
                if e.get("level") in ["security", "critical", "error"]
            ][:100],
            "recent_events": events[-100:] if len(events) > 100 else events
        }
        
        report = Report(
            report_id=report_id,
            report_type=ReportType.AUDIT_TRAIL,
            format=format,
            title="Audit Trail Report",
            generated_by=generated_by,
            period_start=period_start,
            period_end=period_end,
            content=content
        )
        
        if format == ReportFormat.JSON:
            report.raw_data = json.dumps(content, indent=2, default=str)
        elif format == ReportFormat.HTML:
            report.raw_data = self._generate_html_report(content, "Audit Trail Report")
        
        self.reports[report_id] = report
        return report
    
    def generate_forensic_report(
        self,
        incident_data: Dict[str, Any],
        analysis_data: Dict[str, Any],
        evidence: List[Dict[str, Any]],
        generated_by: str,
        format: ReportFormat = ReportFormat.PDF
    ) -> Report:
        """
        Generate forensic investigation report
        
        Args:
            incident_data: Incident details
            analysis_data: Analysis results
            evidence: Evidence collected
            generated_by: Person generating report
            format: Output format
            
        Returns:
            Generated report
        """
        report_id = f"FORENSIC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        content = {
            "executive_summary": {
                "incident_id": incident_data.get("id"),
                "severity": incident_data.get("severity"),
                "category": incident_data.get("category"),
                "status": incident_data.get("status"),
                "impact": incident_data.get("impact", {})
            },
            "incident_details": incident_data,
            "timeline": analysis_data.get("timeline", []),
            "attack_path": analysis_data.get("attack_path", []),
            "patterns_detected": analysis_data.get("patterns", []),
            "root_cause": analysis_data.get("probable_root_cause"),
            "evidence": [
                {
                    "id": e.get("id"),
                    "type": e.get("type"),
                    "collected_at": e.get("collected_at"),
                    "hash": e.get("hash_sha256")
                }
                for e in evidence
            ],
            "recommendations": analysis_data.get("recommendations", [])
        }
        
        report = Report(
            report_id=report_id,
            report_type=ReportType.FORENSIC,
            format=format,
            title=f"Forensic Report: {incident_data.get('title', 'Incident')}",
            generated_by=generated_by,
            period_start=datetime.fromisoformat(incident_data.get("occurred_at")) if incident_data.get("occurred_at") else datetime.utcnow(),
            period_end=datetime.utcnow(),
            content=content
        )
        
        if format == ReportFormat.JSON:
            report.raw_data = json.dumps(content, indent=2, default=str)
        elif format == ReportFormat.HTML:
            report.raw_data = self._generate_html_report(content, "Forensic Investigation Report")
        elif format == ReportFormat.MARKDOWN:
            report.raw_data = self._generate_markdown_report(content, "Forensic Investigation Report")
        
        self.reports[report_id] = report
        return report
    
    def generate_executive_summary(
        self,
        summary_data: Dict[str, Any],
        period_start: datetime,
        period_end: datetime,
        generated_by: str,
        format: ReportFormat = ReportFormat.PDF
    ) -> Report:
        """
        Generate executive summary report
        
        Args:
            summary_data: Summary statistics
            period_start: Report period start
            period_end: Report period end
            generated_by: Person generating report
            format: Output format
            
        Returns:
            Generated report
        """
        report_id = f"EXEC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        content = {
            "period": f"{period_start.date()} to {period_end.date()}",
            "highlights": summary_data.get("highlights", []),
            "key_metrics": summary_data.get("metrics", {}),
            "security_posture": summary_data.get("security", {}),
            "compliance_status": summary_data.get("compliance", {}),
            "incidents": summary_data.get("incidents", {}),
            "trends": summary_data.get("trends", {}),
            "action_items": summary_data.get("action_items", [])
        }
        
        report = Report(
            report_id=report_id,
            report_type=ReportType.EXECUTIVE_SUMMARY,
            format=format,
            title="Executive Summary",
            generated_by=generated_by,
            period_start=period_start,
            period_end=period_end,
            content=content
        )
        
        if format == ReportFormat.JSON:
            report.raw_data = json.dumps(content, indent=2, default=str)
        elif format == ReportFormat.HTML:
            report.raw_data = self._generate_html_report(content, "Executive Summary")
        
        self.reports[report_id] = report
        return report
    
    def _generate_html_report(self, content: Dict[str, Any], title: str) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; border-bottom: 2px solid #0066cc; }}
        h2 {{ color: #666; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #0066cc; color: white; }}
        .summary {{ background-color: #f0f8ff; padding: 20px; margin: 20px 0; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <div class="summary">
        <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>
    <pre>{json.dumps(content, indent=2, default=str)}</pre>
</body>
</html>
"""
        return html
    
    def _generate_markdown_report(self, content: Dict[str, Any], title: str) -> str:
        """Generate Markdown report"""
        md = f"""# {title}

**Generated**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

---

"""
        md += f"\n```json\n{json.dumps(content, indent=2, default=str)}\n```\n"
        return md


def create_report_generator() -> ReportGenerator:
    """Create new report generator"""
    return ReportGenerator()
