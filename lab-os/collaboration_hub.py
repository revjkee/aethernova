"""
Collaboration Hub - командная работа и обмен экспериментами
"""
from typing import List, Dict, Set, Optional
from datetime import datetime
from dataclasses import dataclass, field
import uuid

@dataclass
class Team:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    members: Set[str] = field(default_factory=set)
    shared_experiments: List[str] = field(default_factory=list)
    permissions: Dict[str, List[str]] = field(default_factory=dict)
    
@dataclass  
class Notification:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    type: str = ""
    message: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    read: bool = False

class CollaborationHub:
    def __init__(self):
        self.teams: Dict[str, Team] = {}
        self.notifications: Dict[str, List[Notification]] = {}
        
    def create_team(self, name: str, creator: str) -> Team:
        team = Team(name=name, members={creator})
        self.teams[team.id] = team
        return team
    
    def add_member(self, team_id: str, user_id: str) -> bool:
        if team_id in self.teams:
            self.teams[team_id].members.add(user_id)
            self._notify(user_id, "team_invite", f"Added to team {self.teams[team_id].name}")
            return True
        return False
    
    def share_experiment(self, team_id: str, experiment_id: str) -> bool:
        if team_id in self.teams:
            self.teams[team_id].shared_experiments.append(experiment_id)
            for member in self.teams[team_id].members:
                self._notify(member, "experiment_shared", f"New experiment shared: {experiment_id}")
            return True
        return False
    
    def _notify(self, user_id: str, notif_type: str, message: str):
        if user_id not in self.notifications:
            self.notifications[user_id] = []
        notif = Notification(user_id=user_id, type=notif_type, message=message)
        self.notifications[user_id].append(notif)
    
    def get_notifications(self, user_id: str, unread_only: bool = False) -> List[Notification]:
        notifs = self.notifications.get(user_id, [])
        if unread_only:
            notifs = [n for n in notifs if not n.read]
        return notifs
    
    def mark_read(self, user_id: str, notification_id: str) -> bool:
        if user_id in self.notifications:
            for notif in self.notifications[user_id]:
                if notif.id == notification_id:
                    notif.read = True
                    return True
        return False
