"""Safety and Compliance Module"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum
import uuid

class HazardLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentType(Enum):
    SPILL = "spill"
    EXPOSURE = "exposure"
    EQUIPMENT_FAILURE = "equipment_failure"
    PROTOCOL_VIOLATION = "protocol_violation"
    EMERGENCY = "emergency"

@dataclass
class SafetyTraining:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    training_name: str = ""
    completion_date: datetime = field(default_factory=datetime.utcnow)
    expiry_date: Optional[datetime] = None
    certificate_url: Optional[str] = None
    score: float = 0.0
    
@dataclass
class Incident:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_type: IncidentType = IncidentType.SPILL
    reported_by: str = ""
    location: str = ""
    description: str = ""
    hazard_level: HazardLevel = HazardLevel.LOW
    timestamp: datetime = field(default_factory=datetime.utcnow)
    response_actions: List[str] = field(default_factory=list)
    resolved: bool = False
    resolution_time: Optional[datetime] = None

@dataclass
class ChemicalSafety:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    chemical_name: str = ""
    cas_number: str = ""
    hazard_level: HazardLevel = HazardLevel.LOW
    ghs_pictograms: List[str] = field(default_factory=list)
    h_statements: List[str] = field(default_factory=list)
    p_statements: List[str] = field(default_factory=list)
    sds_url: str = ""
    storage_requirements: Dict = field(default_factory=dict)
    incompatible_chemicals: List[str] = field(default_factory=list)
    ppe_required: List[str] = field(default_factory=list)

class SafetyComplianceSystem:
    def __init__(self):
        self.trainings: Dict[str, SafetyTraining] = {}
        self.incidents: Dict[str, Incident] = {}
        self.chemical_safety: Dict[str, ChemicalSafety] = {}
        
    def record_training(self, user_id: str, training_name: str, 
                       score: float, expiry_date: Optional[datetime] = None) -> SafetyTraining:
        training = SafetyTraining(
            user_id=user_id,
            training_name=training_name,
            score=score,
            expiry_date=expiry_date
        )
        self.trainings[training.id] = training
        return training
    
    def check_training_status(self, user_id: str, training_name: str) -> Dict:
        user_trainings = [t for t in self.trainings.values() 
                         if t.user_id == user_id and t.training_name == training_name]
        if not user_trainings:
            return {"valid": False, "reason": "No training found"}
        
        latest = max(user_trainings, key=lambda x: x.completion_date)
        if latest.expiry_date and latest.expiry_date < datetime.utcnow():
            return {"valid": False, "reason": "Training expired", "expiry": latest.expiry_date}
        
        return {"valid": True, "training": latest}
    
    def report_incident(self, incident_type: IncidentType, reported_by: str,
                       location: str, description: str, 
                       hazard_level: HazardLevel) -> Incident:
        incident = Incident(
            incident_type=incident_type,
            reported_by=reported_by,
            location=location,
            description=description,
            hazard_level=hazard_level
        )
        self.incidents[incident.id] = incident
        
        # Auto-notify if critical
        if hazard_level == HazardLevel.CRITICAL:
            self._trigger_emergency_response(incident)
        
        return incident
    
    def resolve_incident(self, incident_id: str, actions: List[str]) -> bool:
        if incident_id not in self.incidents:
            return False
        
        incident = self.incidents[incident_id]
        incident.response_actions = actions
        incident.resolved = True
        incident.resolution_time = datetime.utcnow()
        return True
    
    def add_chemical_safety(self, chemical_name: str, cas_number: str,
                           hazard_level: HazardLevel, **kwargs) -> ChemicalSafety:
        chem = ChemicalSafety(
            chemical_name=chemical_name,
            cas_number=cas_number,
            hazard_level=hazard_level,
            ghs_pictograms=kwargs.get('ghs_pictograms', []),
            h_statements=kwargs.get('h_statements', []),
            p_statements=kwargs.get('p_statements', []),
            sds_url=kwargs.get('sds_url', ''),
            storage_requirements=kwargs.get('storage_requirements', {}),
            incompatible_chemicals=kwargs.get('incompatible_chemicals', []),
            ppe_required=kwargs.get('ppe_required', [])
        )
        self.chemical_safety[chem.id] = chem
        return chem
    
    def check_chemical_compatibility(self, chemical_ids: List[str]) -> Dict:
        incompatibilities = []
        for i, cid1 in enumerate(chemical_ids):
            if cid1 not in self.chemical_safety:
                continue
            chem1 = self.chemical_safety[cid1]
            for cid2 in chemical_ids[i+1:]:
                if cid2 not in self.chemical_safety:
                    continue
                chem2 = self.chemical_safety[cid2]
                if chem2.chemical_name in chem1.incompatible_chemicals or                    chem1.chemical_name in chem2.incompatible_chemicals:
                    incompatibilities.append({
                        "chemical1": chem1.chemical_name,
                        "chemical2": chem2.chemical_name,
                        "warning": "Incompatible chemicals"
                    })
        
        return {
            "compatible": len(incompatibilities) == 0,
            "incompatibilities": incompatibilities
        }
    
    def get_required_ppe(self, chemical_ids: List[str]) -> List[str]:
        all_ppe = set()
        for cid in chemical_ids:
            if cid in self.chemical_safety:
                all_ppe.update(self.chemical_safety[cid].ppe_required)
        return list(all_ppe)
    
    def get_open_incidents(self) -> List[Incident]:
        return [i for i in self.incidents.values() if not i.resolved]
    
    def get_incidents_by_hazard(self, hazard_level: HazardLevel) -> List[Incident]:
        return [i for i in self.incidents.values() 
                if i.hazard_level == hazard_level]
    
    def _trigger_emergency_response(self, incident: Incident):
        # Integration point for emergency alerts
        pass
