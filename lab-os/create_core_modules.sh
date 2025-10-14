#!/bin/bash

# Lab Manager Module
cat > /workspaces/aethernova/lab-os/lab_manager.py << 'EOFPYTHON'
"""
Lab Management System - управление лабораториями, оборудованием, ресурсами
"""
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import uuid

class LabStatus(str, Enum):
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    CLOSED = "closed"
    
class ResourceType(str, Enum):
    EQUIPMENT = "equipment"
    ROOM = "room"
    MATERIAL = "material"
    SOFTWARE = "software"

@dataclass
class Lab:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    location: str = ""
    status: LabStatus = LabStatus.ACTIVE
    capacity: int = 10
    equipment: List[str] = field(default_factory=list)
    manager: str = ""
    safety_level: int = 1
    access_control: Dict[str, List[str]] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Equipment:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    type: str = ""
    lab_id: str = ""
    status: str = "available"
    calibration_date: Optional[datetime] = None
    next_maintenance: Optional[datetime] = None
    specifications: Dict[str, Any] = field(default_factory=dict)
    usage_hours: float = 0.0
    booking_schedule: List[Dict] = field(default_factory=list)

@dataclass
class Booking:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    resource_id: str = ""
    resource_type: ResourceType = ResourceType.EQUIPMENT
    user_id: str = ""
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(hours=1))
    purpose: str = ""
    status: str = "pending"
    priority: int = 5

class LabManager:
    def __init__(self):
        self.labs: Dict[str, Lab] = {}
        self.equipment: Dict[str, Equipment] = {}
        self.bookings: Dict[str, Booking] = {}
        
    def create_lab(self, name: str, location: str, capacity: int, manager: str, **kwargs) -> Lab:
        lab = Lab(
            name=name,
            location=location,
            capacity=capacity,
            manager=manager,
            **kwargs
        )
        self.labs[lab.id] = lab
        return lab
    
    def get_lab(self, lab_id: str) -> Optional[Lab]:
        return self.labs.get(lab_id)
    
    def list_labs(self, status: Optional[LabStatus] = None) -> List[Lab]:
        if status:
            return [lab for lab in self.labs.values() if lab.status == status]
        return list(self.labs.values())
    
    def update_lab_status(self, lab_id: str, status: LabStatus) -> bool:
        if lab_id in self.labs:
            self.labs[lab_id].status = status
            return True
        return False
    
    def add_equipment(self, lab_id: str, name: str, equipment_type: str, **kwargs) -> Equipment:
        equipment = Equipment(
            name=name,
            type=equipment_type,
            lab_id=lab_id,
            **kwargs
        )
        self.equipment[equipment.id] = equipment
        if lab_id in self.labs:
            self.labs[lab_id].equipment.append(equipment.id)
        return equipment
    
    def get_equipment(self, equipment_id: str) -> Optional[Equipment]:
        return self.equipment.get(equipment_id)
    
    def list_equipment(self, lab_id: Optional[str] = None, status: Optional[str] = None) -> List[Equipment]:
        equipment_list = list(self.equipment.values())
        if lab_id:
            equipment_list = [eq for eq in equipment_list if eq.lab_id == lab_id]
        if status:
            equipment_list = [eq for eq in equipment_list if eq.status == status]
        return equipment_list
    
    def create_booking(self, resource_id: str, resource_type: ResourceType, user_id: str, 
                      start_time: datetime, end_time: datetime, purpose: str, priority: int = 5) -> Optional[Booking]:
        if not self._check_availability(resource_id, start_time, end_time):
            return None
        
        booking = Booking(
            resource_id=resource_id,
            resource_type=resource_type,
            user_id=user_id,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
            priority=priority,
            status="confirmed"
        )
        self.bookings[booking.id] = booking
        return booking
    
    def _check_availability(self, resource_id: str, start_time: datetime, end_time: datetime) -> bool:
        overlapping = [
            booking for booking in self.bookings.values()
            if booking.resource_id == resource_id
            and booking.status == "confirmed"
            and not (end_time <= booking.start_time or start_time >= booking.end_time)
        ]
        return len(overlapping) == 0
    
    def cancel_booking(self, booking_id: str) -> bool:
        if booking_id in self.bookings:
            self.bookings[booking_id].status = "cancelled"
            return True
        return False
    
    def get_bookings(self, user_id: Optional[str] = None, resource_id: Optional[str] = None) -> List[Booking]:
        bookings = list(self.bookings.values())
        if user_id:
            bookings = [b for b in bookings if b.user_id == user_id]
        if resource_id:
            bookings = [b for b in bookings if b.resource_id == resource_id]
        return bookings
    
    def check_access(self, user_id: str, lab_id: str, permission: str = "read") -> bool:
        if lab_id not in self.labs:
            return False
        lab = self.labs[lab_id]
        if lab.manager == user_id:
            return True
        return permission in lab.access_control.get(user_id, [])
    
    def grant_access(self, lab_id: str, user_id: str, permissions: List[str]) -> bool:
        if lab_id in self.labs:
            self.labs[lab_id].access_control[user_id] = permissions
            return True
        return False
    
    def get_lab_utilization(self, lab_id: str, period_days: int = 30) -> Dict[str, Any]:
        start_date = datetime.utcnow() - timedelta(days=period_days)
        bookings = [
            b for b in self.bookings.values()
            if b.resource_id in self.labs.get(lab_id, Lab()).equipment
            and b.start_time >= start_date
            and b.status == "confirmed"
        ]
        
        total_hours = sum(
            (b.end_time - b.start_time).total_seconds() / 3600
            for b in bookings
        )
        
        return {
            "lab_id": lab_id,
            "period_days": period_days,
            "total_bookings": len(bookings),
            "total_hours": total_hours,
            "avg_booking_hours": total_hours / len(bookings) if bookings else 0,
            "utilization_rate": (total_hours / (period_days * 24)) * 100 if period_days > 0 else 0
        }
EOFPYTHON

echo "lab_manager.py created"

# Experiment Tracker
cat > /workspaces/aethernova/lab-os/experiment_tracker.py << 'EOFPYTHON2'
"""
Experiment Tracker - отслеживание экспериментов, протоколов, результатов
"""
from typing import List, Dict, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
import uuid
import hashlib

class ExperimentStatus(str, Enum):
    DRAFT = "draft"
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class Protocol:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    version: str = "1.0"
    description: str = ""
    steps: List[Dict[str, Any]] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    safety_notes: List[str] = field(default_factory=list)
    created_by: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    hash: str = field(default="")
    
    def __post_init__(self):
        if not self.hash:
            self.hash = self._calculate_hash()
    
    def _calculate_hash(self) -> str:
        content = f"{self.name}{self.version}{str(self.steps)}{str(self.parameters)}"
        return hashlib.sha256(content.encode()).hexdigest()

@dataclass
class Experiment:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    protocol_id: str = ""
    status: ExperimentStatus = ExperimentStatus.DRAFT
    researcher: str = ""
    lab_id: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    objectives: List[str] = field(default_factory=list)
    materials: List[Dict[str, Any]] = field(default_factory=list)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    conclusions: str = ""
    tags: List[str] = field(default_factory=list)
    collaborators: List[str] = field(default_factory=list)
    parent_experiment_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)

class ExperimentTracker:
    def __init__(self):
        self.protocols: Dict[str, Protocol] = {}
        self.experiments: Dict[str, Experiment] = {}
        
    def create_protocol(self, name: str, description: str, steps: List[Dict], 
                       created_by: str, **kwargs) -> Protocol:
        protocol = Protocol(
            name=name,
            description=description,
            steps=steps,
            created_by=created_by,
            **kwargs
        )
        self.protocols[protocol.id] = protocol
        return protocol
    
    def get_protocol(self, protocol_id: str) -> Optional[Protocol]:
        return self.protocols.get(protocol_id)
    
    def update_protocol(self, protocol_id: str, **updates) -> Optional[Protocol]:
        if protocol_id not in self.protocols:
            return None
        old_protocol = self.protocols[protocol_id]
        new_version = f"{float(old_protocol.version) + 0.1:.1f}"
        new_protocol = Protocol(
            name=updates.get('name', old_protocol.name),
            version=new_version,
            description=updates.get('description', old_protocol.description),
            steps=updates.get('steps', old_protocol.steps),
            parameters=updates.get('parameters', old_protocol.parameters),
            safety_notes=updates.get('safety_notes', old_protocol.safety_notes),
            created_by=old_protocol.created_by
        )
        self.protocols[new_protocol.id] = new_protocol
        return new_protocol
    
    def create_experiment(self, title: str, protocol_id: str, researcher: str, 
                         lab_id: str, **kwargs) -> Experiment:
        experiment = Experiment(
            title=title,
            protocol_id=protocol_id,
            researcher=researcher,
            lab_id=lab_id,
            **kwargs
        )
        self.experiments[experiment.id] = experiment
        return experiment
    
    def get_experiment(self, experiment_id: str) -> Optional[Experiment]:
        return self.experiments.get(experiment_id)
    
    def update_experiment_status(self, experiment_id: str, status: ExperimentStatus) -> bool:
        if experiment_id not in self.experiments:
            return False
        self.experiments[experiment_id].status = status
        if status == ExperimentStatus.RUNNING and not self.experiments[experiment_id].start_time:
            self.experiments[experiment_id].start_time = datetime.utcnow()
        elif status in [ExperimentStatus.COMPLETED, ExperimentStatus.FAILED]:
            self.experiments[experiment_id].end_time = datetime.utcnow()
        return True
    
    def add_observation(self, experiment_id: str, observation: str, data: Optional[Dict] = None) -> bool:
        if experiment_id not in self.experiments:
            return False
        obs = {
            "timestamp": datetime.utcnow().isoformat(),
            "observation": observation,
            "data": data or {}
        }
        self.experiments[experiment_id].observations.append(obs)
        return True
    
    def add_result(self, experiment_id: str, key: str, value: Any) -> bool:
        if experiment_id not in self.experiments:
            return False
        self.experiments[experiment_id].results[key] = value
        return True
    
    def set_conclusions(self, experiment_id: str, conclusions: str) -> bool:
        if experiment_id not in self.experiments:
            return False
        self.experiments[experiment_id].conclusions = conclusions
        return True
    
    def search_experiments(self, query: Optional[str] = None, status: Optional[ExperimentStatus] = None,
                          researcher: Optional[str] = None, tags: Optional[List[str]] = None) -> List[Experiment]:
        experiments = list(self.experiments.values())
        
        if query:
            experiments = [e for e in experiments if query.lower() in e.title.lower()]
        if status:
            experiments = [e for e in experiments if e.status == status]
        if researcher:
            experiments = [e for e in experiments if e.researcher == researcher]
        if tags:
            experiments = [e for e in experiments if any(tag in e.tags for tag in tags)]
        
        return experiments
    
    def clone_experiment(self, experiment_id: str, new_title: str, researcher: str) -> Optional[Experiment]:
        if experiment_id not in self.experiments:
            return None
        source = self.experiments[experiment_id]
        new_experiment = Experiment(
            title=new_title,
            protocol_id=source.protocol_id,
            researcher=researcher,
            lab_id=source.lab_id,
            objectives=source.objectives.copy(),
            materials=source.materials.copy(),
            tags=source.tags.copy(),
            parent_experiment_id=experiment_id,
            status=ExperimentStatus.DRAFT
        )
        self.experiments[new_experiment.id] = new_experiment
        return new_experiment
    
    def get_experiment_lineage(self, experiment_id: str) -> List[Experiment]:
        lineage = []
        current_id = experiment_id
        while current_id:
            if current_id not in self.experiments:
                break
            experiment = self.experiments[current_id]
            lineage.append(experiment)
            current_id = experiment.parent_experiment_id
        return lineage
    
    def verify_reproducibility(self, experiment_id: str) -> Dict[str, Any]:
        if experiment_id not in self.experiments:
            return {"reproducible": False, "errors": ["Experiment not found"]}
        
        experiment = self.experiments[experiment_id]
        errors = []
        
        if not experiment.protocol_id or experiment.protocol_id not in self.protocols:
            errors.append("Protocol not found or not specified")
        if not experiment.materials:
            errors.append("No materials documented")
        if experiment.status != ExperimentStatus.COMPLETED:
            errors.append("Experiment not completed")
        if not experiment.results:
            errors.append("No results recorded")
        
        return {
            "experiment_id": experiment_id,
            "reproducible": len(errors) == 0,
            "errors": errors,
            "protocol_hash": self.protocols[experiment.protocol_id].hash if experiment.protocol_id in self.protocols else None,
            "completeness_score": 100 - (len(errors) * 25)
        }
EOFPYTHON2

echo "experiment_tracker.py created"

