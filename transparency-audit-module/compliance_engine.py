"""
Compliance Engine - Automated Compliance Checking and Reporting
===============================================================

Comprehensive compliance engine supporting:
- GDPR (General Data Protection Regulation)
- SOC 2 (System and Organization Controls)
- ISO 27001 (Information Security Management)
- HIPAA (Health Insurance Portability and Accountability Act)
- PCI DSS (Payment Card Industry Data Security Standard)
- Automated compliance checking
- Real-time compliance monitoring
- Compliance reporting and dashboards

Author: AetherNova Development Team
License: MIT
"""

import json
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks"""
    GDPR = "gdpr"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    CCPA = "ccpa"
    NIST = "nist"


class ComplianceStatus(str, Enum):
    """Compliance check status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    PENDING_REVIEW = "pending_review"


class Severity(str, Enum):
    """Issue severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceControl(BaseModel):
    """Individual compliance control"""
    
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    category: str
    requirements: List[str]
    
    # Implementation
    implemented: bool = False
    evidence_required: List[str] = Field(default_factory=list)
    automated_check: bool = False
    
    # Status
    status: ComplianceStatus = ComplianceStatus.PENDING_REVIEW
    last_checked: Optional[datetime] = None
    next_review: Optional[datetime] = None
    
    # Results
    findings: List[str] = Field(default_factory=list)
    remediation_steps: List[str] = Field(default_factory=list)


class ComplianceIssue(BaseModel):
    """Compliance violation or issue"""
    
    issue_id: str
    framework: ComplianceFramework
    control_id: str
    severity: Severity
    
    title: str
    description: str
    impact: str
    
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    
    remediation_steps: List[str]
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    
    status: str = "open"  # open, in_progress, resolved, accepted_risk
    
    evidence: Dict[str, Any] = Field(default_factory=dict)
    notes: List[str] = Field(default_factory=list)


class ComplianceReport(BaseModel):
    """Compliance assessment report"""
    
    report_id: str
    framework: ComplianceFramework
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    
    period_start: datetime
    period_end: datetime
    
    # Overall status
    overall_status: ComplianceStatus
    compliance_score: float = Field(ge=0.0, le=100.0)
    
    # Controls
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    partially_compliant_controls: int
    
    # Issues
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    
    # Details
    controls_summary: List[Dict[str, Any]] = Field(default_factory=list)
    issues: List[ComplianceIssue] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    
    # Metadata
    assessor: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None


class GDPRCompliance:
    """GDPR-specific compliance checks"""
    
    @staticmethod
    def get_controls() -> List[ComplianceControl]:
        """Get GDPR compliance controls"""
        return [
            ComplianceControl(
                control_id="GDPR-1",
                framework=ComplianceFramework.GDPR,
                title="Lawful Basis for Processing",
                description="Ensure lawful basis for processing personal data",
                category="Legal Basis",
                requirements=[
                    "Document lawful basis for each processing activity",
                    "Obtain consent where required",
                    "Maintain records of processing activities"
                ],
                evidence_required=["Privacy policy", "Consent records", "Processing register"],
                automated_check=True
            ),
            ComplianceControl(
                control_id="GDPR-2",
                framework=ComplianceFramework.GDPR,
                title="Data Subject Rights",
                description="Implement mechanisms for data subject rights",
                category="Individual Rights",
                requirements=[
                    "Right to access",
                    "Right to rectification",
                    "Right to erasure",
                    "Right to data portability",
                    "Right to object"
                ],
                evidence_required=["DSR process documentation", "Response logs"],
                automated_check=True
            ),
            ComplianceControl(
                control_id="GDPR-3",
                framework=ComplianceFramework.GDPR,
                title="Data Protection by Design and Default",
                description="Implement privacy by design principles",
                category="Technical Measures",
                requirements=[
                    "Privacy impact assessments",
                    "Data minimization",
                    "Pseudonymization where appropriate",
                    "Access controls"
                ],
                evidence_required=["DPIA documents", "System architecture"],
                automated_check=True
            ),
            ComplianceControl(
                control_id="GDPR-4",
                framework=ComplianceFramework.GDPR,
                title="Data Breach Notification",
                description="72-hour breach notification process",
                category="Incident Response",
                requirements=[
                    "Breach detection mechanisms",
                    "Notification procedures",
                    "Breach register"
                ],
                evidence_required=["Incident response plan", "Breach log"],
                automated_check=True
            ),
            ComplianceControl(
                control_id="GDPR-5",
                framework=ComplianceFramework.GDPR,
                title="Data Retention",
                description="Implement data retention policies",
                category="Data Lifecycle",
                requirements=[
                    "Define retention periods",
                    "Automated deletion processes",
                    "Retention policy documentation"
                ],
                evidence_required=["Retention policy", "Deletion logs"],
                automated_check=True
            )
        ]
    
    @staticmethod
    def check_data_retention(
        retention_days: int,
        last_access: datetime
    ) -> Tuple[bool, Optional[str]]:
        """Check if data retention is compliant"""
        days_since_access = (datetime.utcnow() - last_access).days
        
        if days_since_access > retention_days:
            return False, f"Data retained {days_since_access} days, exceeds limit of {retention_days}"
        
        return True, None
    
    @staticmethod
    def check_consent(
        consent_given: bool,
        consent_date: Optional[datetime],
        purpose: str
    ) -> Tuple[bool, Optional[str]]:
        """Check if consent is valid"""
        if not consent_given:
            return False, f"No consent for purpose: {purpose}"
        
        if not consent_date:
            return False, "Consent date not recorded"
        
        # Consent should be refreshed every 2 years
        if (datetime.utcnow() - consent_date).days > 730:
            return False, "Consent expired (>2 years old)"
        
        return True, None


class SOC2Compliance:
    """SOC 2-specific compliance checks"""
    
    @staticmethod
    def get_controls() -> List[ComplianceControl]:
        """Get SOC 2 compliance controls"""
        return [
            ComplianceControl(
                control_id="SOC2-CC6.1",
                framework=ComplianceFramework.SOC2,
                title="Logical and Physical Access Controls",
                description="Implement access controls to protect system resources",
                category="Security",
                requirements=[
                    "Multi-factor authentication",
                    "Role-based access control",
                    "Access reviews",
                    "Termination procedures"
                ],
                evidence_required=["Access logs", "Review reports"],
                automated_check=True
            ),
            ComplianceControl(
                control_id="SOC2-CC7.2",
                framework=ComplianceFramework.SOC2,
                title="System Monitoring",
                description="Monitor system components and operations",
                category="Monitoring",
                requirements=[
                    "Continuous monitoring",
                    "Anomaly detection",
                    "Alert mechanisms",
                    "Log retention"
                ],
                evidence_required=["Monitoring dashboards", "Alert logs"],
                automated_check=True
            ),
            ComplianceControl(
                control_id="SOC2-CC8.1",
                framework=ComplianceFramework.SOC2,
                title="Change Management",
                description="Manage changes to system infrastructure",
                category="Change Management",
                requirements=[
                    "Change approval process",
                    "Testing procedures",
                    "Rollback capabilities",
                    "Change documentation"
                ],
                evidence_required=["Change tickets", "Test results"],
                automated_check=False
            ),
            ComplianceControl(
                control_id="SOC2-A1.2",
                framework=ComplianceFramework.SOC2,
                title="Data Backup and Recovery",
                description="Implement backup and recovery procedures",
                category="Availability",
                requirements=[
                    "Regular backups",
                    "Backup testing",
                    "Recovery time objectives",
                    "Offsite storage"
                ],
                evidence_required=["Backup logs", "Recovery tests"],
                automated_check=True
            )
        ]
    
    @staticmethod
    def check_mfa_enabled(user_has_mfa: bool) -> Tuple[bool, Optional[str]]:
        """Check if MFA is enabled"""
        if not user_has_mfa:
            return False, "Multi-factor authentication not enabled"
        return True, None
    
    @staticmethod
    def check_backup_frequency(
        last_backup: datetime,
        required_frequency_hours: int = 24
    ) -> Tuple[bool, Optional[str]]:
        """Check if backups are current"""
        hours_since_backup = (datetime.utcnow() - last_backup).total_seconds() / 3600
        
        if hours_since_backup > required_frequency_hours:
            return False, f"Last backup {hours_since_backup:.1f}h ago, exceeds {required_frequency_hours}h"
        
        return True, None


class ISO27001Compliance:
    """ISO 27001-specific compliance checks"""
    
    @staticmethod
    def get_controls() -> List[ComplianceControl]:
        """Get ISO 27001 compliance controls"""
        return [
            ComplianceControl(
                control_id="ISO-A.9.2.1",
                framework=ComplianceFramework.ISO27001,
                title="User Registration and De-registration",
                description="Formal user registration/de-registration process",
                category="Access Control",
                requirements=[
                    "Documented procedures",
                    "Timely de-provisioning",
                    "Access reviews"
                ],
                evidence_required=["User management procedures", "Access logs"],
                automated_check=True
            ),
            ComplianceControl(
                control_id="ISO-A.12.3.1",
                framework=ComplianceFramework.ISO27001,
                title="Information Backup",
                description="Regular backup of information and software",
                category="Operations Security",
                requirements=[
                    "Backup policy",
                    "Regular backup testing",
                    "Secure backup storage"
                ],
                evidence_required=["Backup policy", "Test records"],
                automated_check=True
            ),
            ComplianceControl(
                control_id="ISO-A.12.4.1",
                framework=ComplianceFramework.ISO27001,
                title="Event Logging",
                description="Record user activities and security events",
                category="Logging and Monitoring",
                requirements=[
                    "Comprehensive logging",
                    "Log protection",
                    "Log retention",
                    "Regular log review"
                ],
                evidence_required=["Log configuration", "Review records"],
                automated_check=True
            ),
            ComplianceControl(
                control_id="ISO-A.18.1.1",
                framework=ComplianceFramework.ISO27001,
                title="Compliance with Legal Requirements",
                description="Identify and comply with legal requirements",
                category="Compliance",
                requirements=[
                    "Legal register",
                    "Regular reviews",
                    "Compliance assessments"
                ],
                evidence_required=["Legal register", "Assessment reports"],
                automated_check=False
            )
        ]


class HIPAACompliance:
    """HIPAA-specific compliance checks"""
    
    @staticmethod
    def get_controls() -> List[ComplianceControl]:
        """Get HIPAA compliance controls"""
        return [
            ComplianceControl(
                control_id="HIPAA-164.308(a)(1)(ii)(A)",
                framework=ComplianceFramework.HIPAA,
                title="Risk Analysis",
                description="Conduct accurate and thorough assessment of risks",
                category="Administrative Safeguards",
                requirements=[
                    "Annual risk assessments",
                    "Documented methodology",
                    "Risk mitigation plans"
                ],
                evidence_required=["Risk assessment reports"],
                automated_check=False
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(a)(1)",
                framework=ComplianceFramework.HIPAA,
                title="Access Control",
                description="Implement technical policies for access control",
                category="Technical Safeguards",
                requirements=[
                    "Unique user identification",
                    "Emergency access procedure",
                    "Automatic logoff",
                    "Encryption and decryption"
                ],
                evidence_required=["Access control policy", "Audit logs"],
                automated_check=True
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(b)",
                framework=ComplianceFramework.HIPAA,
                title="Audit Controls",
                description="Implement hardware, software, and procedural mechanisms",
                category="Technical Safeguards",
                requirements=[
                    "Record and examine activity in systems with ePHI",
                    "Regular audit log review"
                ],
                evidence_required=["Audit logs", "Review reports"],
                automated_check=True
            )
        ]
    
    @staticmethod
    def check_phi_encryption(data_encrypted: bool) -> Tuple[bool, Optional[str]]:
        """Check if PHI is encrypted"""
        if not data_encrypted:
            return False, "Protected Health Information must be encrypted"
        return True, None


class PCIDSSCompliance:
    """PCI DSS-specific compliance checks"""
    
    @staticmethod
    def get_controls() -> List[ComplianceControl]:
        """Get PCI DSS compliance controls"""
        return [
            ComplianceControl(
                control_id="PCI-3.4",
                framework=ComplianceFramework.PCI_DSS,
                title="Card Data Encryption",
                description="Render PAN unreadable wherever stored",
                category="Protect Stored Data",
                requirements=[
                    "Strong cryptography",
                    "Key management",
                    "Truncation or tokenization"
                ],
                evidence_required=["Encryption documentation", "Key management procedures"],
                automated_check=True
            ),
            ComplianceControl(
                control_id="PCI-10.2",
                framework=ComplianceFramework.PCI_DSS,
                title="Audit Logging",
                description="Implement automated audit trails",
                category="Monitor and Test Networks",
                requirements=[
                    "User access logs",
                    "Administrative actions",
                    "Access to audit trails",
                    "Invalid access attempts"
                ],
                evidence_required=["Log samples", "Retention policy"],
                automated_check=True
            ),
            ComplianceControl(
                control_id="PCI-11.2",
                framework=ComplianceFramework.PCI_DSS,
                title="Vulnerability Scans",
                description="Run internal and external vulnerability scans",
                category="Security Testing",
                requirements=[
                    "Quarterly scans",
                    "After significant changes",
                    "Remediation of high-risk vulnerabilities"
                ],
                evidence_required=["Scan reports", "Remediation records"],
                automated_check=True
            )
        ]


class ComplianceEngine:
    """
    Complete compliance engine for automated checking and reporting
    
    Features:
    - Multi-framework support (GDPR, SOC2, ISO27001, HIPAA, PCI DSS)
    - Automated compliance checking
    - Real-time monitoring
    - Issue tracking and remediation
    - Compliance reporting
    """
    
    def __init__(self):
        self.controls: Dict[ComplianceFramework, List[ComplianceControl]] = {}
        self.issues: List[ComplianceIssue] = []
        self.reports: List[ComplianceReport] = []
        
        # Initialize controls for all frameworks
        self._initialize_controls()
    
    def _initialize_controls(self):
        """Initialize compliance controls for all frameworks"""
        self.controls[ComplianceFramework.GDPR] = GDPRCompliance.get_controls()
        self.controls[ComplianceFramework.SOC2] = SOC2Compliance.get_controls()
        self.controls[ComplianceFramework.ISO27001] = ISO27001Compliance.get_controls()
        self.controls[ComplianceFramework.HIPAA] = HIPAACompliance.get_controls()
        self.controls[ComplianceFramework.PCI_DSS] = PCIDSSCompliance.get_controls()
    
    def check_control(
        self,
        framework: ComplianceFramework,
        control_id: str,
        evidence: Optional[Dict[str, Any]] = None
    ) -> Tuple[ComplianceStatus, List[str]]:
        """
        Check specific compliance control
        
        Args:
            framework: Compliance framework
            control_id: Control identifier
            evidence: Evidence for assessment
            
        Returns:
            Tuple of (status, findings)
        """
        controls = self.controls.get(framework, [])
        control = next((c for c in controls if c.control_id == control_id), None)
        
        if not control:
            return ComplianceStatus.NOT_APPLICABLE, [f"Control {control_id} not found"]
        
        findings = []
        
        # Framework-specific checks
        if framework == ComplianceFramework.GDPR:
            findings.extend(self._check_gdpr_control(control, evidence))
        elif framework == ComplianceFramework.SOC2:
            findings.extend(self._check_soc2_control(control, evidence))
        elif framework == ComplianceFramework.HIPAA:
            findings.extend(self._check_hipaa_control(control, evidence))
        elif framework == ComplianceFramework.PCI_DSS:
            findings.extend(self._check_pci_control(control, evidence))
        
        # Determine status
        if not findings:
            status = ComplianceStatus.COMPLIANT
        elif len(findings) == len(control.requirements):
            status = ComplianceStatus.NON_COMPLIANT
        else:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        
        # Update control
        control.status = status
        control.last_checked = datetime.utcnow()
        control.findings = findings
        
        return status, findings
    
    def _check_gdpr_control(
        self,
        control: ComplianceControl,
        evidence: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Check GDPR-specific control"""
        findings = []
        
        if control.control_id == "GDPR-2" and evidence:
            # Check DSR response times
            if evidence.get("avg_response_days", 0) > 30:
                findings.append("DSR response time exceeds 30 days")
        
        if control.control_id == "GDPR-5" and evidence:
            # Check retention policy
            if not evidence.get("retention_policy_documented"):
                findings.append("Data retention policy not documented")
        
        return findings
    
    def _check_soc2_control(
        self,
        control: ComplianceControl,
        evidence: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Check SOC 2-specific control"""
        findings = []
        
        if control.control_id == "SOC2-CC6.1" and evidence:
            # Check MFA
            if not evidence.get("mfa_enabled"):
                findings.append("Multi-factor authentication not enabled for all users")
        
        if control.control_id == "SOC2-A1.2" and evidence:
            # Check backup frequency
            last_backup = evidence.get("last_backup")
            if last_backup:
                compliant, message = SOC2Compliance.check_backup_frequency(last_backup)
                if not compliant:
                    findings.append(message)
        
        return findings
    
    def _check_hipaa_control(
        self,
        control: ComplianceControl,
        evidence: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Check HIPAA-specific control"""
        findings = []
        
        if control.control_id == "HIPAA-164.312(a)(1)" and evidence:
            # Check encryption
            if not evidence.get("phi_encrypted"):
                findings.append("PHI not encrypted at rest")
        
        return findings
    
    def _check_pci_control(
        self,
        control: ComplianceControl,
        evidence: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Check PCI DSS-specific control"""
        findings = []
        
        if control.control_id == "PCI-3.4" and evidence:
            # Check card data encryption
            if not evidence.get("card_data_encrypted"):
                findings.append("Card data not properly encrypted")
        
        return findings
    
    def assess_framework(
        self,
        framework: ComplianceFramework,
        evidence: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> ComplianceReport:
        """
        Assess compliance for entire framework
        
        Args:
            framework: Framework to assess
            evidence: Evidence mapped by control ID
            
        Returns:
            Compliance report
        """
        controls = self.controls.get(framework, [])
        
        # Check all controls
        results = []
        for control in controls:
            control_evidence = evidence.get(control.control_id) if evidence else None
            status, findings = self.check_control(framework, control.control_id, control_evidence)
            
            results.append({
                "control_id": control.control_id,
                "title": control.title,
                "status": status.value,
                "findings": findings
            })
        
        # Calculate statistics
        total = len(controls)
        compliant = sum(1 for c in controls if c.status == ComplianceStatus.COMPLIANT)
        non_compliant = sum(1 for c in controls if c.status == ComplianceStatus.NON_COMPLIANT)
        partial = sum(1 for c in controls if c.status == ComplianceStatus.PARTIALLY_COMPLIANT)
        
        compliance_score = (compliant / total * 100) if total > 0 else 0.0
        
        # Determine overall status
        if compliance_score >= 95:
            overall_status = ComplianceStatus.COMPLIANT
        elif compliance_score >= 70:
            overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            overall_status = ComplianceStatus.NON_COMPLIANT
        
        # Count issues by severity
        critical = sum(1 for i in self.issues if i.framework == framework and i.severity == Severity.CRITICAL)
        high = sum(1 for i in self.issues if i.framework == framework and i.severity == Severity.HIGH)
        medium = sum(1 for i in self.issues if i.framework == framework and i.severity == Severity.MEDIUM)
        low = sum(1 for i in self.issues if i.framework == framework and i.severity == Severity.LOW)
        
        # Create report
        report = ComplianceReport(
            report_id=f"{framework.value}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            framework=framework,
            period_start=datetime.utcnow() - timedelta(days=30),
            period_end=datetime.utcnow(),
            overall_status=overall_status,
            compliance_score=compliance_score,
            total_controls=total,
            compliant_controls=compliant,
            non_compliant_controls=non_compliant,
            partially_compliant_controls=partial,
            critical_issues=critical,
            high_issues=high,
            medium_issues=medium,
            low_issues=low,
            controls_summary=results,
            issues=[i for i in self.issues if i.framework == framework and i.status == "open"]
        )
        
        self.reports.append(report)
        return report
    
    def report_issue(
        self,
        framework: ComplianceFramework,
        control_id: str,
        severity: Severity,
        title: str,
        description: str,
        impact: str,
        remediation_steps: List[str]
    ) -> ComplianceIssue:
        """
        Report compliance issue
        
        Args:
            framework: Affected framework
            control_id: Related control
            severity: Issue severity
            title: Issue title
            description: Detailed description
            impact: Business impact
            remediation_steps: Steps to resolve
            
        Returns:
            Created issue
        """
        issue = ComplianceIssue(
            issue_id=f"{framework.value}_{control_id}_{len(self.issues)+1}",
            framework=framework,
            control_id=control_id,
            severity=severity,
            title=title,
            description=description,
            impact=impact,
            remediation_steps=remediation_steps
        )
        
        self.issues.append(issue)
        return issue
    
    def get_compliance_dashboard(self) -> Dict[str, Any]:
        """
        Get compliance dashboard overview
        
        Returns:
            Dashboard data
        """
        dashboard = {
            "frameworks": {},
            "overall_status": "unknown",
            "total_issues": len([i for i in self.issues if i.status == "open"]),
            "critical_issues": len([i for i in self.issues if i.severity == Severity.CRITICAL and i.status == "open"]),
            "recent_reports": []
        }
        
        # Framework summaries
        for framework in ComplianceFramework:
            controls = self.controls.get(framework, [])
            if not controls:
                continue
            
            total = len(controls)
            compliant = sum(1 for c in controls if c.status == ComplianceStatus.COMPLIANT)
            
            dashboard["frameworks"][framework.value] = {
                "total_controls": total,
                "compliant": compliant,
                "compliance_rate": (compliant / total * 100) if total > 0 else 0
            }
        
        # Recent reports
        recent = sorted(self.reports, key=lambda r: r.generated_at, reverse=True)[:5]
        dashboard["recent_reports"] = [
            {
                "framework": r.framework.value,
                "date": r.generated_at.isoformat(),
                "score": r.compliance_score,
                "status": r.overall_status.value
            }
            for r in recent
        ]
        
        return dashboard


# Convenience functions
def create_compliance_engine() -> ComplianceEngine:
    """Create new compliance engine"""
    return ComplianceEngine()


def quick_gdpr_check(engine: ComplianceEngine) -> ComplianceReport:
    """Run quick GDPR compliance check"""
    return engine.assess_framework(ComplianceFramework.GDPR)


def quick_soc2_check(engine: ComplianceEngine) -> ComplianceReport:
    """Run quick SOC 2 compliance check"""
    return engine.assess_framework(ComplianceFramework.SOC2)
