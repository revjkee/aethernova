"""Notification System Module"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Callable
from enum import Enum
import uuid

class NotificationType(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    SUCCESS = "success"
    URGENT = "urgent"

class NotificationChannel(Enum):
    EMAIL = "email"
    SMS = "sms"
    IN_APP = "in_app"
    WEBHOOK = "webhook"

@dataclass
class Notification:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    notification_type: NotificationType = NotificationType.INFO
    title: str = ""
    message: str = ""
    data: Dict = field(default_factory=dict)
    channels: List[NotificationChannel] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    read: bool = False
    read_at: Optional[datetime] = None

@dataclass
class NotificationPreference:
    user_id: str = ""
    channels: List[NotificationChannel] = field(default_factory=list)
    notify_experiment_status: bool = True
    notify_booking_reminders: bool = True
    notify_low_inventory: bool = True
    notify_safety_incidents: bool = True
    notify_maintenance_due: bool = True
    quiet_hours_start: Optional[int] = None
    quiet_hours_end: Optional[int] = None

class NotificationSystem:
    def __init__(self):
        self.notifications: Dict[str, Notification] = {}
        self.preferences: Dict[str, NotificationPreference] = {}
        self.handlers: Dict[NotificationChannel, Callable] = {}
    
    def register_handler(self, channel: NotificationChannel, handler: Callable):
        self.handlers[channel] = handler
    
    def set_user_preferences(self, user_id: str, **preferences) -> NotificationPreference:
        pref = NotificationPreference(user_id=user_id, **preferences)
        self.preferences[user_id] = pref
        return pref
    
    def send_notification(self, user_id: str, notification_type: NotificationType,
                         title: str, message: str, data: Dict = None,
                         channels: List[NotificationChannel] = None) -> Notification:
        # Check user preferences
        if user_id in self.preferences:
            pref = self.preferences[user_id]
            if channels is None:
                channels = pref.channels
            
            # Check quiet hours
            if pref.quiet_hours_start and pref.quiet_hours_end:
                current_hour = datetime.utcnow().hour
                if pref.quiet_hours_start <= current_hour < pref.quiet_hours_end:
                    if notification_type != NotificationType.URGENT:
                        channels = [NotificationChannel.IN_APP]
        
        if channels is None:
            channels = [NotificationChannel.IN_APP]
        
        notification = Notification(
            user_id=user_id,
            notification_type=notification_type,
            title=title,
            message=message,
            data=data or {},
            channels=channels
        )
        
        self.notifications[notification.id] = notification
        
        # Send through channels
        for channel in channels:
            if channel in self.handlers:
                try:
                    self.handlers[channel](notification)
                except Exception as e:
                    print(f"Error sending notification via {channel}: {e}")
        
        return notification
    
    def mark_as_read(self, notification_id: str) -> bool:
        if notification_id not in self.notifications:
            return False
        
        self.notifications[notification_id].read = True
        self.notifications[notification_id].read_at = datetime.utcnow()
        return True
    
    def get_user_notifications(self, user_id: str, 
                               unread_only: bool = False) -> List[Notification]:
        notifications = [n for n in self.notifications.values() 
                        if n.user_id == user_id]
        
        if unread_only:
            notifications = [n for n in notifications if not n.read]
        
        return sorted(notifications, key=lambda x: x.created_at, reverse=True)
    
    def notify_experiment_status_change(self, user_id: str, experiment_id: str, 
                                       old_status: str, new_status: str):
        if user_id in self.preferences:
            if not self.preferences[user_id].notify_experiment_status:
                return
        
        self.send_notification(
            user_id=user_id,
            notification_type=NotificationType.INFO,
            title="Experiment Status Updated",
            message=f"Experiment {experiment_id} changed from {old_status} to {new_status}",
            data={"experiment_id": experiment_id, "status": new_status}
        )
    
    def notify_booking_reminder(self, user_id: str, booking_id: str, 
                               resource_name: str, start_time: datetime):
        self.send_notification(
            user_id=user_id,
            notification_type=NotificationType.WARNING,
            title="Booking Reminder",
            message=f"Your booking for {resource_name} starts in 1 hour",
            data={"booking_id": booking_id, "start_time": start_time.isoformat()}
        )
    
    def notify_low_inventory(self, user_id: str, item_name: str, quantity: float):
        self.send_notification(
            user_id=user_id,
            notification_type=NotificationType.WARNING,
            title="Low Inventory Alert",
            message=f"{item_name} is running low (current: {quantity})",
            data={"item_name": item_name, "quantity": quantity}
        )
    
    def notify_safety_incident(self, user_id: str, incident_id: str, 
                              incident_type: str, location: str):
        self.send_notification(
            user_id=user_id,
            notification_type=NotificationType.URGENT,
            title="Safety Incident Reported",
            message=f"{incident_type} reported at {location}",
            data={"incident_id": incident_id, "location": location},
            channels=[NotificationChannel.EMAIL, NotificationChannel.SMS, NotificationChannel.IN_APP]
        )
    
    def notify_maintenance_due(self, user_id: str, equipment_name: str, due_date: datetime):
        self.send_notification(
            user_id=user_id,
            notification_type=NotificationType.INFO,
            title="Maintenance Due",
            message=f"Maintenance for {equipment_name} is due on {due_date.strftime('%Y-%m-%d')}",
            data={"equipment": equipment_name, "due_date": due_date.isoformat()}
        )
