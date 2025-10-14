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
