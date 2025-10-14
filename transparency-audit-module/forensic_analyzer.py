"""
Forensic Analyzer - Digital Forensics and Incident Investigation
================================================================

Comprehensive forensic analysis system providing:
- Timeline reconstruction
- Pattern detection
- Anomaly identification  
- Chain of custody tracking
- Evidence collection and preservation
- Root cause analysis
- Attack path reconstruction

Author: AetherNova Development Team
License: MIT
"""

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field


class EvidenceType(str, Enum):
    """Types of digital evidence"""
    LOG_FILE = "log_file"
    SYSTEM_STATE = "system_state"
    NETWORK_CAPTURE = "network_capture"
    MEMORY_DUMP = "memory_dump"
    DISK_IMAGE = "disk_image"
    DATABASE_RECORD = "database_record"
    API_RESPONSE = "api_response"
    USER_ACTION = "user_action"
    CONFIGURATION = "configuration"


class IncidentSeverity(str, Enum):
    """Incident severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentCategory(str, Enum):
    """Incident categories"""
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_BREACH = "data_breach"
    MALWARE = "malware"
    DOS_DDOS = "dos_ddos"
    INSIDER_THREAT = "insider_threat"
    POLICY_VIOLATION = "policy_violation"
    SYSTEM_FAILURE = "system_failure"
    DATA_CORRUPTION = "data_corruption"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class Evidence(BaseModel):
    """Digital evidence with chain of custody"""
    
    evidence_id: str
    evidence_type: EvidenceType
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Source information
    source_system: str
    source_location: str
    
    # Content
    data: Dict[str, Any] = Field(default_factory=dict)
    raw_data: Optional[str] = None
    
    # Integrity
    hash_md5: str
    hash_sha256: str
    
    # Chain of custody
    collected_by: str
    custody_chain: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Analysis
    analyzed: bool = False
    analysis_results: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    
    # Legal hold
    legal_hold: bool = False
    retention_date: Optional[datetime] = None
    
    def compute_hashes(self, data: bytes):
        """Compute integrity hashes"""
        self.hash_md5 = hashlib.md5(data).hexdigest()
        self.hash_sha256 = hashlib.sha256(data).hexdigest()
    
    def transfer_custody(self, from_person: str, to_person: str, reason: str):
        """Transfer evidence custody"""
        self.custody_chain.append({
            "timestamp": datetime.utcnow().isoformat(),
            "from": from_person,
            "to": to_person,
            "reason": reason
        })


class TimelineEvent(BaseModel):
    """Event in forensic timeline"""
    
    timestamp: datetime
    event_type: str
    source: str
    description: str
    
    # Related entities
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    resource: Optional[str] = None
    
    # Evidence
    evidence_ids: List[str] = Field(default_factory=list)
    
    # Analysis
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    significance: float = Field(default=0.5, ge=0.0, le=1.0)
    tags: List[str] = Field(default_factory=list)


class AttackPattern(BaseModel):
    """Detected attack pattern"""
    
    pattern_id: str
    pattern_name: str
    mitre_technique: Optional[str] = None  # MITRE ATT&CK technique ID
    
    description: str
    indicators: List[str]
    
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    confidence: float = Field(ge=0.0, le=1.0)
    
    events: List[TimelineEvent] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)


class Incident(BaseModel):
    """Security incident"""
    
    incident_id: str
    severity: IncidentSeverity
    category: IncidentCategory
    
    title: str
    description: str
    
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    occurred_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    
    # Impact
    affected_systems: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    affected_data: List[str] = Field(default_factory=list)
    
    # Analysis
    root_cause: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_patterns: List[AttackPattern] = Field(default_factory=list)
    
    # Evidence
    evidence_collected: List[str] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    
    # Response
    containment_actions: List[str] = Field(default_factory=list)
    remediation_steps: List[str] = Field(default_factory=list)
    
    # Assignment
    assigned_to: Optional[str] = None
    status: str = "open"  # open, investigating, contained, resolved, closed


class ForensicAnalyzer:
    """
    Complete forensic analysis system
    
    Features:
    - Timeline reconstruction
    - Pattern detection
    - Anomaly identification
    - Evidence management
    - Chain of custody
    - Incident investigation
    """
    
    def __init__(self):
        self.evidence: Dict[str, Evidence] = {}
        self.incidents: Dict[str, Incident] = {}
        self.timeline: List[TimelineEvent] = []
        self.patterns: Dict[str, AttackPattern] = {}
    
    def collect_evidence(
        self,
        evidence_type: EvidenceType,
        source_system: str,
        source_location: str,
        data: Dict[str, Any],
        collected_by: str,
        raw_data: Optional[str] = None
    ) -> Evidence:
        """
        Collect and preserve digital evidence
        
        Args:
            evidence_type: Type of evidence
            source_system: Source system name
            source_location: Source location/path
            data: Evidence data
            collected_by: Person collecting
            raw_data: Raw data if applicable
            
        Returns:
            Evidence object
        """
        evidence_id = f"EV-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{len(self.evidence)}"
        
        # Create evidence
        evidence = Evidence(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            source_system=source_system,
            source_location=source_location,
            data=data,
            raw_data=raw_data,
            collected_by=collected_by,
            hash_md5="",
            hash_sha256=""
        )
        
        # Compute hashes
        data_bytes = json.dumps(data, sort_keys=True).encode()
        evidence.compute_hashes(data_bytes)
        
        # Store
        self.evidence[evidence_id] = evidence
        
        return evidence
    
    def create_incident(
        self,
        severity: IncidentSeverity,
        category: IncidentCategory,
        title: str,
        description: str,
        affected_systems: Optional[List[str]] = None,
        occurred_at: Optional[datetime] = None
    ) -> Incident:
        """
        Create new incident investigation
        
        Args:
            severity: Incident severity
            category: Incident category
            title: Incident title
            description: Detailed description
            affected_systems: List of affected systems
            occurred_at: When incident occurred
            
        Returns:
            Created incident
        """
        incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        incident = Incident(
            incident_id=incident_id,
            severity=severity,
            category=category,
            title=title,
            description=description,
            affected_systems=affected_systems or [],
            occurred_at=occurred_at or datetime.utcnow()
        )
        
        self.incidents[incident_id] = incident
        
        return incident
    
    def add_timeline_event(
        self,
        timestamp: datetime,
        event_type: str,
        source: str,
        description: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        resource: Optional[str] = None,
        evidence_ids: Optional[List[str]] = None,
        significance: float = 0.5
    ) -> TimelineEvent:
        """
        Add event to forensic timeline
        
        Args:
            timestamp: When event occurred
            event_type: Type of event
            source: Event source
            description: Event description
            user_id: User involved
            ip_address: IP address
            resource: Affected resource
            evidence_ids: Related evidence
            significance: Event significance (0-1)
            
        Returns:
            Timeline event
        """
        event = TimelineEvent(
            timestamp=timestamp,
            event_type=event_type,
            source=source,
            description=description,
            user_id=user_id,
            ip_address=ip_address,
            resource=resource,
            evidence_ids=evidence_ids or [],
            significance=significance
        )
        
        self.timeline.append(event)
        
        # Sort timeline by timestamp
        self.timeline.sort(key=lambda e: e.timestamp)
        
        return event
    
    def reconstruct_timeline(
        self,
        incident_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[TimelineEvent]:
        """
        Reconstruct timeline for incident investigation
        
        Args:
            incident_id: Incident to investigate
            start_time: Timeline start
            end_time: Timeline end
            
        Returns:
            Reconstructed timeline
        """
        incident = self.incidents.get(incident_id)
        if not incident:
            return []
        
        # Default time range
        if not start_time and incident.occurred_at:
            start_time = incident.occurred_at - timedelta(hours=24)
        if not end_time:
            end_time = datetime.utcnow()
        
        # Filter timeline
        events = [
            e for e in self.timeline
            if start_time <= e.timestamp <= end_time
        ]
        
        # Filter by affected systems/users if available
        if incident.affected_systems or incident.affected_users:
            filtered = []
            for event in events:
                # Check system match
                if incident.affected_systems and event.resource:
                    if any(sys in event.resource for sys in incident.affected_systems):
                        filtered.append(event)
                        continue
                
                # Check user match
                if incident.affected_users and event.user_id:
                    if event.user_id in incident.affected_users:
                        filtered.append(event)
                        continue
            
            events = filtered if filtered else events
        
        # Update incident timeline
        incident.timeline = events
        
        return events
    
    def detect_patterns(
        self,
        events: List[TimelineEvent],
        min_confidence: float = 0.7
    ) -> List[AttackPattern]:
        """
        Detect attack patterns in timeline
        
        Args:
            events: Events to analyze
            min_confidence: Minimum confidence threshold
            
        Returns:
            Detected patterns
        """
        detected_patterns = []
        
        # Pattern 1: Brute force detection
        pattern = self._detect_brute_force(events)
        if pattern and pattern.confidence >= min_confidence:
            detected_patterns.append(pattern)
            self.patterns[pattern.pattern_id] = pattern
        
        # Pattern 2: Privilege escalation
        pattern = self._detect_privilege_escalation(events)
        if pattern and pattern.confidence >= min_confidence:
            detected_patterns.append(pattern)
            self.patterns[pattern.pattern_id] = pattern
        
        # Pattern 3: Data exfiltration
        pattern = self._detect_data_exfiltration(events)
        if pattern and pattern.confidence >= min_confidence:
            detected_patterns.append(pattern)
            self.patterns[pattern.pattern_id] = pattern
        
        # Pattern 4: Lateral movement
        pattern = self._detect_lateral_movement(events)
        if pattern and pattern.confidence >= min_confidence:
            detected_patterns.append(pattern)
            self.patterns[pattern.pattern_id] = pattern
        
        return detected_patterns
    
    def _detect_brute_force(self, events: List[TimelineEvent]) -> Optional[AttackPattern]:
        """Detect brute force attack pattern"""
        # Look for multiple failed login attempts
        failed_logins = defaultdict(list)
        
        for event in events:
            if "login" in event.event_type.lower() and "fail" in event.description.lower():
                key = (event.user_id, event.ip_address)
                failed_logins[key].append(event)
        
        # Check for suspicious patterns
        for (user, ip), attempts in failed_logins.items():
            if len(attempts) >= 5:  # 5+ failed attempts
                time_window = (attempts[-1].timestamp - attempts[0].timestamp).total_seconds()
                
                if time_window < 300:  # Within 5 minutes
                    pattern = AttackPattern(
                        pattern_id=f"PAT-BF-{len(self.patterns)}",
                        pattern_name="Brute Force Attack",
                        mitre_technique="T1110",
                        description=f"Multiple failed login attempts detected for user {user} from IP {ip}",
                        indicators=[
                            f"{len(attempts)} failed attempts in {time_window:.0f} seconds",
                            f"Target user: {user}",
                            f"Source IP: {ip}"
                        ],
                        confidence=min(0.9, 0.6 + (len(attempts) * 0.05)),
                        events=attempts
                    )
                    return pattern
        
        return None
    
    def _detect_privilege_escalation(self, events: List[TimelineEvent]) -> Optional[AttackPattern]:
        """Detect privilege escalation pattern"""
        escalation_events = []
        
        for event in events:
            if any(keyword in event.description.lower() for keyword in [
                "privilege", "escalat", "sudo", "admin", "root", "elevated"
            ]):
                escalation_events.append(event)
        
        if len(escalation_events) >= 2:
            pattern = AttackPattern(
                pattern_id=f"PAT-PE-{len(self.patterns)}",
                pattern_name="Privilege Escalation",
                mitre_technique="T1068",
                description="Potential privilege escalation detected",
                indicators=[
                    f"{len(escalation_events)} privilege-related events",
                    "Unusual administrative access patterns"
                ],
                confidence=0.75,
                events=escalation_events
            )
            return pattern
        
        return None
    
    def _detect_data_exfiltration(self, events: List[TimelineEvent]) -> Optional[AttackPattern]:
        """Detect data exfiltration pattern"""
        exfil_events = []
        data_volume = 0
        
        for event in events:
            if any(keyword in event.description.lower() for keyword in [
                "download", "export", "transfer", "copy", "exfiltrat"
            ]):
                exfil_events.append(event)
                # Estimate data volume if available
                if "size" in event.description.lower():
                    data_volume += 1
        
        if len(exfil_events) >= 3:
            pattern = AttackPattern(
                pattern_id=f"PAT-EX-{len(self.patterns)}",
                pattern_name="Data Exfiltration",
                mitre_technique="T1048",
                description="Potential data exfiltration detected",
                indicators=[
                    f"{len(exfil_events)} data transfer events",
                    "Unusual data access patterns"
                ],
                confidence=0.70,
                events=exfil_events
            )
            return pattern
        
        return None
    
    def _detect_lateral_movement(self, events: List[TimelineEvent]) -> Optional[AttackPattern]:
        """Detect lateral movement pattern"""
        # Track system-to-system access
        system_access = defaultdict(set)
        
        for event in events:
            if event.user_id and event.resource:
                system_access[event.user_id].add(event.resource)
        
        # Check for users accessing multiple systems
        for user, systems in system_access.items():
            if len(systems) >= 3:
                pattern = AttackPattern(
                    pattern_id=f"PAT-LM-{len(self.patterns)}",
                    pattern_name="Lateral Movement",
                    mitre_technique="T1021",
                    description=f"User {user} accessed multiple systems",
                    indicators=[
                        f"Access to {len(systems)} different systems",
                        f"User: {user}",
                        f"Systems: {', '.join(list(systems)[:5])}"
                    ],
                    confidence=0.65,
                    events=[e for e in events if e.user_id == user]
                )
                return pattern
        
        return None
    
    def perform_root_cause_analysis(
        self,
        incident_id: str
    ) -> Dict[str, Any]:
        """
        Perform root cause analysis for incident
        
        Args:
            incident_id: Incident to analyze
            
        Returns:
            Analysis results
        """
        incident = self.incidents.get(incident_id)
        if not incident:
            return {"error": "Incident not found"}
        
        # Reconstruct timeline if not done
        if not incident.timeline:
            self.reconstruct_timeline(incident_id)
        
        # Detect patterns
        patterns = self.detect_patterns(incident.timeline)
        incident.attack_patterns = patterns
        
        # Analyze timeline for root cause
        analysis = {
            "incident_id": incident_id,
            "timeline_events": len(incident.timeline),
            "patterns_detected": len(patterns),
            "initial_event": None,
            "attack_path": [],
            "probable_root_cause": None,
            "contributing_factors": [],
            "recommendations": []
        }
        
        if incident.timeline:
            # First significant event
            analysis["initial_event"] = {
                "timestamp": incident.timeline[0].timestamp.isoformat(),
                "type": incident.timeline[0].event_type,
                "description": incident.timeline[0].description
            }
            
            # Build attack path
            for event in incident.timeline:
                if event.significance >= 0.7:
                    analysis["attack_path"].append({
                        "timestamp": event.timestamp.isoformat(),
                        "event": event.description
                    })
        
        # Analyze patterns for root cause
        if patterns:
            # Earliest pattern is likely the root cause
            earliest = min(patterns, key=lambda p: p.detected_at)
            analysis["probable_root_cause"] = {
                "pattern": earliest.pattern_name,
                "mitre_technique": earliest.mitre_technique,
                "description": earliest.description,
                "confidence": earliest.confidence
            }
            
            # Other patterns are contributing factors
            for pattern in patterns:
                if pattern.pattern_id != earliest.pattern_id:
                    analysis["contributing_factors"].append({
                        "pattern": pattern.pattern_name,
                        "description": pattern.description
                    })
        
        # Generate recommendations
        if incident.category == IncidentCategory.UNAUTHORIZED_ACCESS:
            analysis["recommendations"].extend([
                "Review and strengthen authentication mechanisms",
                "Implement multi-factor authentication",
                "Review access logs for similar patterns"
            ])
        elif incident.category == IncidentCategory.DATA_BREACH:
            analysis["recommendations"].extend([
                "Implement data loss prevention controls",
                "Review data classification and access controls",
                "Conduct security awareness training"
            ])
        
        # Update incident
        if analysis["probable_root_cause"]:
            incident.root_cause = analysis["probable_root_cause"]["description"]
        
        return analysis
    
    def generate_forensic_report(
        self,
        incident_id: str,
        include_evidence: bool = True
    ) -> Dict[str, Any]:
        """
        Generate comprehensive forensic report
        
        Args:
            incident_id: Incident to report on
            include_evidence: Include evidence details
            
        Returns:
            Forensic report
        """
        incident = self.incidents.get(incident_id)
        if not incident:
            return {"error": "Incident not found"}
        
        # Perform analysis if not done
        rca = self.perform_root_cause_analysis(incident_id)
        
        report = {
            "report_id": f"FR-{incident_id}",
            "generated_at": datetime.utcnow().isoformat(),
            "incident": {
                "id": incident.incident_id,
                "severity": incident.severity.value,
                "category": incident.category.value,
                "title": incident.title,
                "description": incident.description,
                "detected_at": incident.detected_at.isoformat(),
                "occurred_at": incident.occurred_at.isoformat() if incident.occurred_at else None,
                "status": incident.status
            },
            "impact": {
                "affected_systems": incident.affected_systems,
                "affected_users": incident.affected_users,
                "affected_data": incident.affected_data
            },
            "analysis": rca,
            "timeline": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "type": e.event_type,
                    "description": e.description,
                    "significance": e.significance
                }
                for e in incident.timeline
            ],
            "patterns": [
                {
                    "name": p.pattern_name,
                    "mitre": p.mitre_technique,
                    "confidence": p.confidence,
                    "description": p.description
                }
                for p in incident.attack_patterns
            ],
            "response": {
                "containment": incident.containment_actions,
                "remediation": incident.remediation_steps
            }
        }
        
        if include_evidence:
            report["evidence"] = [
                {
                    "id": eid,
                    "type": self.evidence[eid].evidence_type.value,
                    "collected_at": self.evidence[eid].collected_at.isoformat(),
                    "hash_sha256": self.evidence[eid].hash_sha256
                }
                for eid in incident.evidence_collected
                if eid in self.evidence
            ]
        
        return report


# Convenience functions
def create_forensic_analyzer() -> ForensicAnalyzer:
    """Create new forensic analyzer"""
    return ForensicAnalyzer()
