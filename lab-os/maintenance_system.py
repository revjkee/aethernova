"""Equipment Maintenance Module"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from enum import Enum
import uuid

class MaintenanceType(Enum):
    PREVENTIVE = "preventive"
    CORRECTIVE = "corrective"
    CALIBRATION = "calibration"
    INSPECTION = "inspection"

class MaintenanceStatus(Enum):
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    OVERDUE = "overdue"

@dataclass
class MaintenanceRecord:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    equipment_id: str = ""
    maintenance_type: MaintenanceType = MaintenanceType.PREVENTIVE
    scheduled_date: datetime = field(default_factory=datetime.utcnow)
    completed_date: Optional[datetime] = None
    technician_id: str = ""
    status: MaintenanceStatus = MaintenanceStatus.SCHEDULED
    notes: str = ""
    cost: float = 0.0
    parts_replaced: List[str] = field(default_factory=list)
    next_maintenance_date: Optional[datetime] = None

@dataclass
class CalibrationRecord:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    equipment_id: str = ""
    calibration_date: datetime = field(default_factory=datetime.utcnow)
    calibrated_by: str = ""
    standard_used: str = ""
    measurements: Dict = field(default_factory=dict)
    passed: bool = False
    certificate_url: Optional[str] = None
    next_calibration_date: Optional[datetime] = None

@dataclass
class EquipmentDowntime:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    equipment_id: str = ""
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    reason: str = ""
    impact: str = ""
    
class MaintenanceManagementSystem:
    def __init__(self):
        self.maintenance_records: Dict[str, MaintenanceRecord] = {}
        self.calibration_records: Dict[str, CalibrationRecord] = {}
        self.downtime_records: Dict[str, EquipmentDowntime] = {}
        
    def schedule_maintenance(self, equipment_id: str, maintenance_type: MaintenanceType,
                            scheduled_date: datetime, technician_id: str) -> MaintenanceRecord:
        record = MaintenanceRecord(
            equipment_id=equipment_id,
            maintenance_type=maintenance_type,
            scheduled_date=scheduled_date,
            technician_id=technician_id
        )
        self.maintenance_records[record.id] = record
        return record
    
    def complete_maintenance(self, record_id: str, notes: str, 
                            parts_replaced: List[str], cost: float) -> bool:
        if record_id not in self.maintenance_records:
            return False
        
        record = self.maintenance_records[record_id]
        record.completed_date = datetime.utcnow()
        record.status = MaintenanceStatus.COMPLETED
        record.notes = notes
        record.parts_replaced = parts_replaced
        record.cost = cost
        
        # Schedule next maintenance
        if record.maintenance_type == MaintenanceType.PREVENTIVE:
            record.next_maintenance_date = record.completed_date + timedelta(days=90)
        
        return True
    
    def record_calibration(self, equipment_id: str, calibrated_by: str,
                          standard_used: str, measurements: Dict,
                          passed: bool) -> CalibrationRecord:
        cal = CalibrationRecord(
            equipment_id=equipment_id,
            calibrated_by=calibrated_by,
            standard_used=standard_used,
            measurements=measurements,
            passed=passed,
            next_calibration_date=datetime.utcnow() + timedelta(days=365)
        )
        self.calibration_records[cal.id] = cal
        return cal
    
    def record_downtime(self, equipment_id: str, reason: str, impact: str) -> EquipmentDowntime:
        downtime = EquipmentDowntime(
            equipment_id=equipment_id,
            reason=reason,
            impact=impact
        )
        self.downtime_records[downtime.id] = downtime
        return downtime
    
    def end_downtime(self, downtime_id: str) -> bool:
        if downtime_id not in self.downtime_records:
            return False
        self.downtime_records[downtime_id].end_time = datetime.utcnow()
        return True
    
    def get_overdue_maintenance(self) -> List[MaintenanceRecord]:
        now = datetime.utcnow()
        return [r for r in self.maintenance_records.values()
                if r.status == MaintenanceStatus.SCHEDULED and r.scheduled_date < now]
    
    def get_upcoming_maintenance(self, days: int = 30) -> List[MaintenanceRecord]:
        cutoff = datetime.utcnow() + timedelta(days=days)
        return [r for r in self.maintenance_records.values()
                if r.status == MaintenanceStatus.SCHEDULED and r.scheduled_date <= cutoff]
    
    def get_calibration_due(self, days: int = 30) -> List[CalibrationRecord]:
        cutoff = datetime.utcnow() + timedelta(days=days)
        return [c for c in self.calibration_records.values()
                if c.next_calibration_date and c.next_calibration_date <= cutoff]
    
    def get_equipment_history(self, equipment_id: str) -> Dict:
        maintenance = [r for r in self.maintenance_records.values()
                      if r.equipment_id == equipment_id]
        calibrations = [c for c in self.calibration_records.values()
                       if c.equipment_id == equipment_id]
        downtime = [d for d in self.downtime_records.values()
                   if d.equipment_id == equipment_id]
        
        total_cost = sum(r.cost for r in maintenance)
        total_downtime = sum(
            (d.end_time - d.start_time).total_seconds() / 3600
            for d in downtime if d.end_time
        )
        
        return {
            "maintenance_records": maintenance,
            "calibration_records": calibrations,
            "downtime_records": downtime,
            "total_maintenance_cost": total_cost,
            "total_downtime_hours": total_downtime
        }
