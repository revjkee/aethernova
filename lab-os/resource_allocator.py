"""Resource Allocator - интеллектуальное распределение ресурсов"""
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
import heapq

@dataclass
class AllocationRequest:
    id: str
    user_id: str
    resource_type: str
    duration_hours: float
    priority: int
    deadline: Optional[datetime] = None
    requirements: Dict = None

class ResourceAllocator:
    def __init__(self):
        self.requests = []
        self.allocations = {}
        
    def submit_request(self, request: AllocationRequest) -> str:
        heapq.heappush(self.requests, (-request.priority, request.id, request))
        return request.id
    
    def allocate_resources(self) -> List[Dict]:
        allocations = []
        while self.requests:
            _, req_id, request = heapq.heappop(self.requests)
            allocation = self._find_optimal_slot(request)
            if allocation:
                allocations.append(allocation)
                self.allocations[req_id] = allocation
        return allocations
    
    def _find_optimal_slot(self, request: AllocationRequest) -> Optional[Dict]:
        return {"request_id": request.id, "status": "allocated"}
    
    def get_allocation(self, request_id: str) -> Optional[Dict]:
        return self.allocations.get(request_id)
