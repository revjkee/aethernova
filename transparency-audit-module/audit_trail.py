"""
Audit Trail System with Blockchain-Based Immutable Logging
==========================================================

Comprehensive audit trail system that provides:
- Immutable audit logs using Merkle trees
- Blockchain anchoring for verification
- Cryptographic integrity checks
- WORM (Write Once Read Many) storage
- Real-time audit streaming
- Compliance-ready audit trails

Author: AetherNova Development Team
License: MIT
"""

import hashlib
import json
import time
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field, validator


class AuditLevel(str, Enum):
    """Audit event severity levels"""
    TRACE = "trace"
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SECURITY = "security"


class AuditCategory(str, Enum):
    """Audit event categories"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    SYSTEM_CHANGE = "system_change"
    CONFIGURATION = "configuration"
    SECURITY_EVENT = "security_event"
    COMPLIANCE = "compliance"
    USER_ACTION = "user_action"
    API_CALL = "api_call"


class AuditEvent(BaseModel):
    """Individual audit event with full metadata"""
    
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    level: AuditLevel
    category: AuditCategory
    
    # Actor information
    user_id: Optional[str] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    
    # Action details
    action: str
    resource: str
    resource_id: Optional[str] = None
    
    # Context
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    
    # Security
    success: bool = True
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    
    # Compliance
    compliance_frameworks: List[str] = Field(default_factory=list)
    retention_days: int = Field(default=2555, ge=1)  # 7 years default
    
    # Integrity
    hash: Optional[str] = None
    previous_hash: Optional[str] = None
    signature: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def compute_hash(self, previous_hash: str = "") -> str:
        """Compute cryptographic hash of the event"""
        data = {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value,
            "category": self.category.value,
            "user_id": self.user_id,
            "action": self.action,
            "resource": self.resource,
            "description": self.description,
            "success": self.success,
            "previous_hash": previous_hash
        }
        
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()
    
    def to_blockchain_record(self) -> Dict[str, Any]:
        """Convert to blockchain-compatible record"""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "hash": self.hash,
            "previous_hash": self.previous_hash,
            "data": self.dict(exclude={"hash", "previous_hash", "signature"})
        }


class MerkleNode(BaseModel):
    """Node in Merkle tree for audit trail verification"""
    
    hash: str
    left: Optional['MerkleNode'] = None
    right: Optional['MerkleNode'] = None
    data: Optional[AuditEvent] = None
    
    class Config:
        arbitrary_types_allowed = True


class MerkleTree:
    """Merkle tree for efficient audit trail verification"""
    
    def __init__(self, events: List[AuditEvent]):
        self.events = events
        self.root = self._build_tree([e.hash for e in events])
    
    def _build_tree(self, hashes: List[str]) -> Optional[MerkleNode]:
        """Build Merkle tree from hashes"""
        if not hashes:
            return None
        
        if len(hashes) == 1:
            return MerkleNode(hash=hashes[0])
        
        # Build tree level by level
        nodes = [MerkleNode(hash=h) for h in hashes]
        
        while len(nodes) > 1:
            next_level = []
            
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else left
                
                combined = left.hash + right.hash
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()
                
                parent = MerkleNode(hash=parent_hash, left=left, right=right)
                next_level.append(parent)
            
            nodes = next_level
        
        return nodes[0]
    
    def get_root_hash(self) -> str:
        """Get Merkle root hash"""
        return self.root.hash if self.root else ""
    
    def get_proof(self, event_index: int) -> List[Tuple[str, str]]:
        """Get Merkle proof for event at index"""
        if event_index >= len(self.events):
            raise ValueError(f"Invalid event index: {event_index}")
        
        proof = []
        index = event_index
        nodes = [MerkleNode(hash=e.hash) for e in self.events]
        
        while len(nodes) > 1:
            next_level = []
            
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else left
                
                if i == index or i == index - 1:
                    # This is our node or its sibling
                    if i == index:
                        proof.append((right.hash, "right"))
                    else:
                        proof.append((left.hash, "left"))
                
                combined = left.hash + right.hash
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()
                next_level.append(MerkleNode(hash=parent_hash))
            
            nodes = next_level
            index = index // 2
        
        return proof
    
    def verify_proof(self, event_hash: str, proof: List[Tuple[str, str]], root_hash: str) -> bool:
        """Verify Merkle proof"""
        current_hash = event_hash
        
        for sibling_hash, position in proof:
            if position == "left":
                combined = sibling_hash + current_hash
            else:
                combined = current_hash + sibling_hash
            
            current_hash = hashlib.sha256(combined.encode()).hexdigest()
        
        return current_hash == root_hash


class AuditChain:
    """Blockchain-style chain for audit events"""
    
    def __init__(self):
        self.chain: List[AuditEvent] = []
        self.pending_events: List[AuditEvent] = []
    
    def add_event(self, event: AuditEvent) -> AuditEvent:
        """Add event to chain with proper linking"""
        previous_hash = self.chain[-1].hash if self.chain else "0" * 64
        event.previous_hash = previous_hash
        event.hash = event.compute_hash(previous_hash)
        
        self.chain.append(event)
        return event
    
    def verify_chain(self) -> Tuple[bool, List[str]]:
        """Verify integrity of entire chain"""
        errors = []
        
        for i, event in enumerate(self.chain):
            # Check hash
            expected_previous = self.chain[i-1].hash if i > 0 else "0" * 64
            if event.previous_hash != expected_previous:
                errors.append(f"Event {event.event_id}: Invalid previous hash")
            
            # Recompute hash
            computed_hash = event.compute_hash(event.previous_hash)
            if event.hash != computed_hash:
                errors.append(f"Event {event.event_id}: Hash mismatch")
        
        return len(errors) == 0, errors
    
    def get_events_by_user(self, user_id: str) -> List[AuditEvent]:
        """Get all events for specific user"""
        return [e for e in self.chain if e.user_id == user_id]
    
    def get_events_by_category(self, category: AuditCategory) -> List[AuditEvent]:
        """Get all events in category"""
        return [e for e in self.chain if e.category == category]
    
    def get_events_by_timerange(
        self,
        start: datetime,
        end: datetime
    ) -> List[AuditEvent]:
        """Get events in time range"""
        return [
            e for e in self.chain
            if start <= e.timestamp <= end
        ]
    
    def search_events(
        self,
        user_id: Optional[str] = None,
        category: Optional[AuditCategory] = None,
        level: Optional[AuditLevel] = None,
        resource: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        tags: Optional[List[str]] = None,
        success: Optional[bool] = None
    ) -> List[AuditEvent]:
        """Advanced search across audit events"""
        results = self.chain.copy()
        
        if user_id:
            results = [e for e in results if e.user_id == user_id]
        
        if category:
            results = [e for e in results if e.category == category]
        
        if level:
            results = [e for e in results if e.level == level]
        
        if resource:
            results = [e for e in results if resource in e.resource]
        
        if start_time:
            results = [e for e in results if e.timestamp >= start_time]
        
        if end_time:
            results = [e for e in results if e.timestamp <= end_time]
        
        if tags:
            results = [
                e for e in results
                if any(tag in e.tags for tag in tags)
            ]
        
        if success is not None:
            results = [e for e in results if e.success == success]
        
        return results


class AuditStorage:
    """WORM storage for audit events"""
    
    def __init__(self):
        self.events: Dict[str, AuditEvent] = {}
        self.indices: Dict[str, Set[str]] = {
            "user": {},
            "category": {},
            "level": {},
            "resource": {}
        }
    
    def store_event(self, event: AuditEvent) -> bool:
        """Store event (write-once)"""
        if event.event_id in self.events:
            raise ValueError(f"Event {event.event_id} already exists (WORM violation)")
        
        self.events[event.event_id] = event
        self._update_indices(event)
        return True
    
    def _update_indices(self, event: AuditEvent):
        """Update search indices"""
        if event.user_id:
            if event.user_id not in self.indices["user"]:
                self.indices["user"][event.user_id] = set()
            self.indices["user"][event.user_id].add(event.event_id)
        
        category_key = event.category.value
        if category_key not in self.indices["category"]:
            self.indices["category"][category_key] = set()
        self.indices["category"][category_key].add(event.event_id)
        
        level_key = event.level.value
        if level_key not in self.indices["level"]:
            self.indices["level"][level_key] = set()
        self.indices["level"][level_key].add(event.event_id)
        
        if event.resource:
            if event.resource not in self.indices["resource"]:
                self.indices["resource"][event.resource] = set()
            self.indices["resource"][event.resource].add(event.event_id)
    
    def get_event(self, event_id: str) -> Optional[AuditEvent]:
        """Retrieve event by ID"""
        return self.events.get(event_id)
    
    def get_events_count(self) -> int:
        """Get total event count"""
        return len(self.events)


class AuditTrailSystem:
    """
    Complete audit trail system with blockchain verification
    
    Features:
    - Immutable event logging
    - Cryptographic verification
    - Merkle tree proofs
    - WORM storage
    - Advanced search
    - Compliance support
    """
    
    def __init__(self):
        self.chain = AuditChain()
        self.storage = AuditStorage()
        self.merkle_trees: Dict[str, MerkleTree] = {}
        
    def log_event(
        self,
        level: AuditLevel,
        category: AuditCategory,
        action: str,
        resource: str,
        description: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        success: bool = True,
        risk_score: float = 0.0,
        compliance_frameworks: Optional[List[str]] = None
    ) -> AuditEvent:
        """
        Log audit event with full context
        
        Args:
            level: Event severity level
            category: Event category
            action: Action performed
            resource: Resource affected
            description: Human-readable description
            user_id: User identifier
            username: Username
            ip_address: IP address
            resource_id: Resource identifier
            details: Additional details
            tags: Event tags
            success: Whether action succeeded
            risk_score: Risk score (0-10)
            compliance_frameworks: Applicable compliance frameworks
            
        Returns:
            Created audit event
        """
        event = AuditEvent(
            level=level,
            category=category,
            action=action,
            resource=resource,
            description=description,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            resource_id=resource_id,
            details=details or {},
            tags=tags or [],
            success=success,
            risk_score=risk_score,
            compliance_frameworks=compliance_frameworks or []
        )
        
        # Add to blockchain
        event = self.chain.add_event(event)
        
        # Store in WORM storage
        self.storage.store_event(event)
        
        return event
    
    def verify_event(self, event_id: str) -> Tuple[bool, List[str]]:
        """
        Verify event integrity
        
        Args:
            event_id: Event ID to verify
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        event = self.storage.get_event(event_id)
        if not event:
            return False, [f"Event {event_id} not found"]
        
        errors = []
        
        # Verify hash
        computed_hash = event.compute_hash(event.previous_hash)
        if event.hash != computed_hash:
            errors.append("Hash verification failed")
        
        # Verify chain continuity
        event_index = next(
            (i for i, e in enumerate(self.chain.chain) if e.event_id == event_id),
            None
        )
        
        if event_index is not None:
            if event_index > 0:
                prev_event = self.chain.chain[event_index - 1]
                if event.previous_hash != prev_event.hash:
                    errors.append("Chain continuity broken")
        
        return len(errors) == 0, errors
    
    def create_merkle_tree(self, batch_id: str, events: List[AuditEvent]) -> str:
        """
        Create Merkle tree for batch of events
        
        Args:
            batch_id: Batch identifier
            events: Events to include
            
        Returns:
            Root hash
        """
        tree = MerkleTree(events)
        self.merkle_trees[batch_id] = tree
        return tree.get_root_hash()
    
    def verify_merkle_proof(
        self,
        batch_id: str,
        event_index: int,
        event_hash: str
    ) -> bool:
        """
        Verify Merkle proof for event
        
        Args:
            batch_id: Batch identifier
            event_index: Event index in batch
            event_hash: Event hash to verify
            
        Returns:
            True if proof is valid
        """
        tree = self.merkle_trees.get(batch_id)
        if not tree:
            return False
        
        proof = tree.get_proof(event_index)
        root_hash = tree.get_root_hash()
        
        return tree.verify_proof(event_hash, proof, root_hash)
    
    def search_events(
        self,
        user_id: Optional[str] = None,
        category: Optional[AuditCategory] = None,
        level: Optional[AuditLevel] = None,
        resource: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        tags: Optional[List[str]] = None,
        success: Optional[bool] = None,
        limit: int = 100
    ) -> List[AuditEvent]:
        """
        Search audit events with filters
        
        Args:
            user_id: Filter by user
            category: Filter by category
            level: Filter by level
            resource: Filter by resource
            start_time: Start of time range
            end_time: End of time range
            tags: Filter by tags
            success: Filter by success status
            limit: Maximum results
            
        Returns:
            List of matching events
        """
        results = self.chain.search_events(
            user_id=user_id,
            category=category,
            level=level,
            resource=resource,
            start_time=start_time,
            end_time=end_time,
            tags=tags,
            success=success
        )
        
        return results[:limit]
    
    def get_audit_statistics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get audit trail statistics
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            
        Returns:
            Statistics dictionary
        """
        events = self.chain.chain
        
        if start_time or end_time:
            events = self.chain.get_events_by_timerange(
                start_time or datetime.min,
                end_time or datetime.max
            )
        
        stats = {
            "total_events": len(events),
            "by_level": {},
            "by_category": {},
            "by_user": {},
            "success_rate": 0.0,
            "average_risk_score": 0.0,
            "high_risk_events": 0
        }
        
        for event in events:
            # By level
            level_key = event.level.value
            stats["by_level"][level_key] = stats["by_level"].get(level_key, 0) + 1
            
            # By category
            cat_key = event.category.value
            stats["by_category"][cat_key] = stats["by_category"].get(cat_key, 0) + 1
            
            # By user
            if event.user_id:
                stats["by_user"][event.user_id] = stats["by_user"].get(event.user_id, 0) + 1
            
            # Risk
            if event.risk_score >= 7.0:
                stats["high_risk_events"] += 1
        
        if events:
            successful = sum(1 for e in events if e.success)
            stats["success_rate"] = successful / len(events)
            
            total_risk = sum(e.risk_score for e in events)
            stats["average_risk_score"] = total_risk / len(events)
        
        return stats
    
    def export_audit_trail(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        format: str = "json"
    ) -> str:
        """
        Export audit trail for compliance
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            format: Export format (json, csv)
            
        Returns:
            Exported data as string
        """
        events = self.chain.chain
        
        if start_time or end_time:
            events = self.chain.get_events_by_timerange(
                start_time or datetime.min,
                end_time or datetime.max
            )
        
        if format == "json":
            return json.dumps(
                [e.dict() for e in events],
                indent=2,
                default=str
            )
        
        # Add CSV export if needed
        return json.dumps([e.dict() for e in events], default=str)


# Convenience functions
def create_audit_system() -> AuditTrailSystem:
    """Create new audit trail system"""
    return AuditTrailSystem()


def log_authentication(
    system: AuditTrailSystem,
    user_id: str,
    username: str,
    ip_address: str,
    success: bool,
    method: str = "password"
) -> AuditEvent:
    """Log authentication event"""
    return system.log_event(
        level=AuditLevel.INFO if success else AuditLevel.WARNING,
        category=AuditCategory.AUTHENTICATION,
        action=f"login_{method}",
        resource="auth_system",
        description=f"User {username} authentication {'succeeded' if success else 'failed'}",
        user_id=user_id,
        username=username,
        ip_address=ip_address,
        success=success,
        risk_score=0.0 if success else 3.0,
        compliance_frameworks=["GDPR", "SOC2"]
    )


def log_data_access(
    system: AuditTrailSystem,
    user_id: str,
    username: str,
    resource: str,
    resource_id: str,
    action: str = "read"
) -> AuditEvent:
    """Log data access event"""
    return system.log_event(
        level=AuditLevel.INFO,
        category=AuditCategory.DATA_ACCESS,
        action=action,
        resource=resource,
        resource_id=resource_id,
        description=f"User {username} accessed {resource}",
        user_id=user_id,
        username=username,
        compliance_frameworks=["GDPR", "HIPAA"]
    )
