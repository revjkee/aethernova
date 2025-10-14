"""
Inventory System - управление химикатами, материалами, расходниками
"""
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import uuid

@dataclass
class InventoryItem:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: str = ""
    quantity: float = 0.0
    unit: str = "unit"
    location: str = ""
    expiration_date: Optional[datetime] = None
    safety_info: Dict[str, str] = field(default_factory=dict)
    reorder_level: float = 10.0
    supplier: str = ""
    cost_per_unit: float = 0.0
    last_updated: datetime = field(default_factory=datetime.utcnow)

class InventorySystem:
    def __init__(self):
        self.items: Dict[str, InventoryItem] = {}
        self.transactions: List[Dict] = []
        
    def add_item(self, name: str, category: str, quantity: float, **kwargs) -> InventoryItem:
        item = InventoryItem(name=name, category=category, quantity=quantity, **kwargs)
        self.items[item.id] = item
        self._log_transaction(item.id, "add", quantity, "Initial stock")
        return item
    
    def update_quantity(self, item_id: str, delta: float, reason: str = "") -> bool:
        if item_id not in self.items:
            return False
        self.items[item_id].quantity += delta
        self.items[item_id].last_updated = datetime.utcnow()
        self._log_transaction(item_id, "update", delta, reason)
        return True
    
    def check_expiring_items(self, days: int = 30) -> List[InventoryItem]:
        threshold = datetime.utcnow() + timedelta(days=days)
        return [
            item for item in self.items.values()
            if item.expiration_date and item.expiration_date <= threshold
        ]
    
    def check_low_stock(self) -> List[InventoryItem]:
        return [
            item for item in self.items.values()
            if item.quantity <= item.reorder_level
        ]
    
    def generate_reorder_list(self) -> List[Dict[str, Any]]:
        low_stock = self.check_low_stock()
        return [
            {
                "item_id": item.id,
                "item_name": item.name,
                "current_quantity": item.quantity,
                "recommended_order": item.reorder_level * 2,
                "supplier": item.supplier,
                "estimated_cost": item.cost_per_unit * item.reorder_level * 2
            }
            for item in low_stock
        ]
    
    def _log_transaction(self, item_id: str, transaction_type: str, quantity: float, reason: str):
        self.transactions.append({
            "timestamp": datetime.utcnow().isoformat(),
            "item_id": item_id,
            "type": transaction_type,
            "quantity": quantity,
            "reason": reason
        })
    
    def get_item(self, item_id: str) -> Optional[InventoryItem]:
        return self.items.get(item_id)
    
    def search_items(self, query: str = "", category: str = "") -> List[InventoryItem]:
        items = list(self.items.values())
        if query:
            items = [i for i in items if query.lower() in i.name.lower()]
        if category:
            items = [i for i in items if i.category == category]
        return items
