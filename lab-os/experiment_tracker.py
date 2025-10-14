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
