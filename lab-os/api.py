"""
Lab OS REST API - comprehensive laboratory management API
"""
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
import uvicorn
import json

from lab_manager import LabManager, Lab, Equipment, Booking, LabStatus, ResourceType
from experiment_tracker import ExperimentTracker, Experiment, Protocol, ExperimentStatus
from resource_allocator import ResourceAllocator, AllocationRequest
from collaboration_hub import CollaborationHub, Team, Notification
from analysis_engine import AnalysisEngine, AnalysisResult
from inventory_system import InventorySystem, InventoryItem

app = FastAPI(
    title="Lab OS API",
    description="Comprehensive Laboratory Management System",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize managers
lab_manager = LabManager()
experiment_tracker = ExperimentTracker()
resource_allocator = ResourceAllocator()
collaboration_hub = CollaborationHub()
analysis_engine = AnalysisEngine()
inventory_system = InventorySystem()

# WebSocket connections
active_connections: List[WebSocket] = []

# Pydantic Models
class LabCreate(BaseModel):
    name: str
    location: str
    capacity: int = 10
    manager: str
    safety_level: int = 1

class EquipmentCreate(BaseModel):
    lab_id: str
    name: str
    type: str
    specifications: Dict[str, Any] = Field(default_factory=dict)

class BookingCreate(BaseModel):
    resource_id: str
    resource_type: str
    user_id: str
    start_time: datetime
    end_time: datetime
    purpose: str
    priority: int = 5

class ProtocolCreate(BaseModel):
    name: str
    description: str
    steps: List[Dict[str, Any]]
    created_by: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    safety_notes: List[str] = Field(default_factory=list)

class ExperimentCreate(BaseModel):
    title: str
    protocol_id: str
    researcher: str
    lab_id: str
    objectives: List[str] = Field(default_factory=list)
    materials: List[Dict[str, Any]] = Field(default_factory=list)

class ObservationAdd(BaseModel):
    observation: str
    data: Optional[Dict] = None

class TeamCreate(BaseModel):
    name: str
    creator: str

class InventoryItemCreate(BaseModel):
    name: str
    category: str
    quantity: float
    unit: str = "unit"
    location: str = ""
    expiration_date: Optional[datetime] = None
    reorder_level: float = 10.0
    supplier: str = ""
    cost_per_unit: float = 0.0

# ==================== LAB MANAGEMENT ENDPOINTS ====================

@app.post("/labs", response_model=Dict)
async def create_lab(lab: LabCreate):
    """Create a new laboratory"""
    new_lab = lab_manager.create_lab(
        name=lab.name,
        location=lab.location,
        capacity=lab.capacity,
        manager=lab.manager,
        safety_level=lab.safety_level
    )
    await broadcast_update({"type": "lab_created", "lab_id": new_lab.id})
    return {"id": new_lab.id, "name": new_lab.name, "status": "created"}

@app.get("/labs/{lab_id}")
async def get_lab(lab_id: str):
    """Get laboratory details"""
    lab = lab_manager.get_lab(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found")
    return lab

@app.get("/labs")
async def list_labs(status: Optional[str] = None):
    """List all laboratories"""
    labs = lab_manager.list_labs(LabStatus(status) if status else None)
    return {"labs": labs, "count": len(labs)}

@app.patch("/labs/{lab_id}/status")
async def update_lab_status(lab_id: str, status: str):
    """Update laboratory status"""
    success = lab_manager.update_lab_status(lab_id, LabStatus(status))
    if not success:
        raise HTTPException(status_code=404, detail="Lab not found")
    await broadcast_update({"type": "lab_status_updated", "lab_id": lab_id, "status": status})
    return {"status": "updated"}

@app.get("/labs/{lab_id}/utilization")
async def get_lab_utilization(lab_id: str, period_days: int = 30):
    """Get laboratory utilization statistics"""
    return lab_manager.get_lab_utilization(lab_id, period_days)

# ==================== EQUIPMENT ENDPOINTS ====================

@app.post("/equipment")
async def add_equipment(equipment: EquipmentCreate):
    """Add new equipment to laboratory"""
    new_equipment = lab_manager.add_equipment(
        lab_id=equipment.lab_id,
        name=equipment.name,
        equipment_type=equipment.type,
        specifications=equipment.specifications
    )
    return {"id": new_equipment.id, "name": new_equipment.name}

@app.get("/equipment/{equipment_id}")
async def get_equipment(equipment_id: str):
    """Get equipment details"""
    equipment = lab_manager.get_equipment(equipment_id)
    if not equipment:
        raise HTTPException(status_code=404, detail="Equipment not found")
    return equipment

@app.get("/equipment")
async def list_equipment(lab_id: Optional[str] = None, status: Optional[str] = None):
    """List equipment"""
    equipment = lab_manager.list_equipment(lab_id, status)
    return {"equipment": equipment, "count": len(equipment)}

# ==================== BOOKING ENDPOINTS ====================

@app.post("/bookings")
async def create_booking(booking: BookingCreate):
    """Create resource booking"""
    new_booking = lab_manager.create_booking(
        resource_id=booking.resource_id,
        resource_type=ResourceType(booking.resource_type),
        user_id=booking.user_id,
        start_time=booking.start_time,
        end_time=booking.end_time,
        purpose=booking.purpose,
        priority=booking.priority
    )
    if not new_booking:
        raise HTTPException(status_code=409, detail="Time slot not available")
    await broadcast_update({"type": "booking_created", "booking_id": new_booking.id})
    return {"id": new_booking.id, "status": "confirmed"}

@app.get("/bookings")
async def get_bookings(user_id: Optional[str] = None, resource_id: Optional[str] = None):
    """Get bookings"""
    bookings = lab_manager.get_bookings(user_id, resource_id)
    return {"bookings": bookings, "count": len(bookings)}

@app.delete("/bookings/{booking_id}")
async def cancel_booking(booking_id: str):
    """Cancel booking"""
    success = lab_manager.cancel_booking(booking_id)
    if not success:
        raise HTTPException(status_code=404, detail="Booking not found")
    await broadcast_update({"type": "booking_cancelled", "booking_id": booking_id})
    return {"status": "cancelled"}

# ==================== PROTOCOL ENDPOINTS ====================

@app.post("/protocols")
async def create_protocol(protocol: ProtocolCreate):
    """Create experiment protocol"""
    new_protocol = experiment_tracker.create_protocol(
        name=protocol.name,
        description=protocol.description,
        steps=protocol.steps,
        created_by=protocol.created_by,
        parameters=protocol.parameters,
        safety_notes=protocol.safety_notes
    )
    return {"id": new_protocol.id, "version": new_protocol.version, "hash": new_protocol.hash}

@app.get("/protocols/{protocol_id}")
async def get_protocol(protocol_id: str):
    """Get protocol details"""
    protocol = experiment_tracker.get_protocol(protocol_id)
    if not protocol:
        raise HTTPException(status_code=404, detail="Protocol not found")
    return protocol

# ==================== EXPERIMENT ENDPOINTS ====================

@app.post("/experiments")
async def create_experiment(experiment: ExperimentCreate):
    """Create new experiment"""
    new_experiment = experiment_tracker.create_experiment(
        title=experiment.title,
        protocol_id=experiment.protocol_id,
        researcher=experiment.researcher,
        lab_id=experiment.lab_id,
        objectives=experiment.objectives,
        materials=experiment.materials
    )
    await broadcast_update({"type": "experiment_created", "experiment_id": new_experiment.id})
    return {"id": new_experiment.id, "title": new_experiment.title}

@app.get("/experiments/{experiment_id}")
async def get_experiment(experiment_id: str):
    """Get experiment details"""
    experiment = experiment_tracker.get_experiment(experiment_id)
    if not experiment:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return experiment

@app.patch("/experiments/{experiment_id}/status")
async def update_experiment_status(experiment_id: str, status: str):
    """Update experiment status"""
    success = experiment_tracker.update_experiment_status(experiment_id, ExperimentStatus(status))
    if not success:
        raise HTTPException(status_code=404, detail="Experiment not found")
    await broadcast_update({"type": "experiment_status_updated", "experiment_id": experiment_id, "status": status})
    return {"status": "updated"}

@app.post("/experiments/{experiment_id}/observations")
async def add_observation(experiment_id: str, observation: ObservationAdd):
    """Add observation to experiment"""
    success = experiment_tracker.add_observation(experiment_id, observation.observation, observation.data)
    if not success:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return {"status": "added"}

@app.post("/experiments/{experiment_id}/results")
async def add_result(experiment_id: str, key: str, value: Any):
    """Add result to experiment"""
    success = experiment_tracker.add_result(experiment_id, key, value)
    if not success:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return {"status": "added"}

@app.get("/experiments")
async def search_experiments(
    query: Optional[str] = None,
    status: Optional[str] = None,
    researcher: Optional[str] = None
):
    """Search experiments"""
    experiments = experiment_tracker.search_experiments(
        query=query,
        status=ExperimentStatus(status) if status else None,
        researcher=researcher
    )
    return {"experiments": experiments, "count": len(experiments)}

@app.post("/experiments/{experiment_id}/clone")
async def clone_experiment(experiment_id: str, new_title: str, researcher: str):
    """Clone existing experiment"""
    new_experiment = experiment_tracker.clone_experiment(experiment_id, new_title, researcher)
    if not new_experiment:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return {"id": new_experiment.id, "title": new_experiment.title}

@app.get("/experiments/{experiment_id}/reproducibility")
async def verify_reproducibility(experiment_id: str):
    """Verify experiment reproducibility"""
    return experiment_tracker.verify_reproducibility(experiment_id)

# ==================== COLLABORATION ENDPOINTS ====================

@app.post("/teams")
async def create_team(team: TeamCreate):
    """Create collaboration team"""
    new_team = collaboration_hub.create_team(team.name, team.creator)
    return {"id": new_team.id, "name": new_team.name}

@app.post("/teams/{team_id}/members")
async def add_team_member(team_id: str, user_id: str):
    """Add member to team"""
    success = collaboration_hub.add_member(team_id, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="Team not found")
    return {"status": "added"}

@app.post("/teams/{team_id}/experiments")
async def share_experiment(team_id: str, experiment_id: str):
    """Share experiment with team"""
    success = collaboration_hub.share_experiment(team_id, experiment_id)
    if not success:
        raise HTTPException(status_code=404, detail="Team not found")
    return {"status": "shared"}

@app.get("/users/{user_id}/notifications")
async def get_notifications(user_id: str, unread_only: bool = False):
    """Get user notifications"""
    notifications = collaboration_hub.get_notifications(user_id, unread_only)
    return {"notifications": notifications, "count": len(notifications)}

@app.patch("/notifications/{notification_id}")
async def mark_notification_read(notification_id: str, user_id: str):
    """Mark notification as read"""
    success = collaboration_hub.mark_read(user_id, notification_id)
    if not success:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"status": "marked_read"}

# ==================== ANALYSIS ENDPOINTS ====================

@app.post("/experiments/{experiment_id}/analyze")
async def analyze_experiment(experiment_id: str, data: Dict[str, List[float]], analysis_types: Optional[List[str]] = None):
    """Analyze experiment data"""
    result = analysis_engine.analyze_experiment(experiment_id, data, analysis_types)
    return result

@app.get("/experiments/{experiment_id}/analysis")
async def get_analysis(experiment_id: str):
    """Get experiment analysis results"""
    result = analysis_engine.get_analysis(experiment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result

@app.post("/experiments/compare")
async def compare_experiments(experiment_ids: List[str]):
    """Compare multiple experiments"""
    return analysis_engine.compare_experiments(experiment_ids)

# ==================== INVENTORY ENDPOINTS ====================

@app.post("/inventory")
async def add_inventory_item(item: InventoryItemCreate):
    """Add item to inventory"""
    new_item = inventory_system.add_item(
        name=item.name,
        category=item.category,
        quantity=item.quantity,
        unit=item.unit,
        location=item.location,
        expiration_date=item.expiration_date,
        reorder_level=item.reorder_level,
        supplier=item.supplier,
        cost_per_unit=item.cost_per_unit
    )
    return {"id": new_item.id, "name": new_item.name}

@app.get("/inventory/{item_id}")
async def get_inventory_item(item_id: str):
    """Get inventory item details"""
    item = inventory_system.get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

@app.patch("/inventory/{item_id}/quantity")
async def update_inventory_quantity(item_id: str, delta: float, reason: str = ""):
    """Update item quantity"""
    success = inventory_system.update_quantity(item_id, delta, reason)
    if not success:
        raise HTTPException(status_code=404, detail="Item not found")
    await broadcast_update({"type": "inventory_updated", "item_id": item_id, "delta": delta})
    return {"status": "updated"}

@app.get("/inventory")
async def search_inventory(query: str = "", category: str = ""):
    """Search inventory items"""
    items = inventory_system.search_items(query, category)
    return {"items": items, "count": len(items)}

@app.get("/inventory/alerts/expiring")
async def get_expiring_items(days: int = 30):
    """Get items expiring soon"""
    items = inventory_system.check_expiring_items(days)
    return {"items": items, "count": len(items)}

@app.get("/inventory/alerts/low-stock")
async def get_low_stock_items():
    """Get low stock items"""
    items = inventory_system.check_low_stock()
    return {"items": items, "count": len(items)}

@app.get("/inventory/reorder-list")
async def generate_reorder_list():
    """Generate reorder recommendations"""
    return {"reorder_list": inventory_system.generate_reorder_list()}

# ==================== WEBSOCKET ENDPOINT ====================

@app.websocket("/ws/updates")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time updates"""
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"Echo: {data}")
    except WebSocketDisconnect:
        active_connections.remove(websocket)

async def broadcast_update(message: Dict):
    """Broadcast update to all WebSocket clients"""
    for connection in active_connections:
        try:
            await connection.send_json(message)
        except:
            pass

# ==================== HEALTH ENDPOINTS ====================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "components": {
            "labs": len(lab_manager.labs),
            "experiments": len(experiment_tracker.experiments),
            "inventory_items": len(inventory_system.items)
        }
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Lab OS API",
        "version": "1.0.0",
        "description": "Comprehensive Laboratory Management System",
        "docs": "/docs",
        "health": "/health"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
