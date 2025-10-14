"""Comprehensive tests for Lab OS"""
import pytest
from datetime import datetime, timedelta
from lab_manager import LabManager, LabStatus
from experiment_tracker import ExperimentTracker, ExperimentStatus
from resource_allocator import ResourceAllocator, AllocationRequest
from collaboration_hub import CollaborationHub
from analysis_engine import AnalysisEngine
from inventory_system import InventorySystem

class TestLabManager:
    def test_create_lab(self):
        manager = LabManager()
        lab = manager.create_lab("Test Lab", "Building A", 20, "manager1")
        assert lab.name == "Test Lab"
        assert lab.capacity == 20
    
    def test_add_equipment(self):
        manager = LabManager()
        lab = manager.create_lab("Lab1", "Location1", 10, "mgr1")
        equipment = manager.add_equipment(lab.id, "Microscope", "optical")
        assert equipment.name == "Microscope"
        assert equipment.lab_id == lab.id
    
    def test_booking_creation(self):
        manager = LabManager()
        lab = manager.create_lab("Lab1", "Loc1", 10, "mgr1")
        eq = manager.add_equipment(lab.id, "Device1", "type1")
        start = datetime.utcnow()
        end = start + timedelta(hours=2)
        from lab_manager import ResourceType
        booking = manager.create_booking(eq.id, ResourceType.EQUIPMENT, "user1", start, end, "test")
        assert booking is not None
        assert booking.user_id == "user1"
    
    def test_booking_conflict(self):
        manager = LabManager()
        lab = manager.create_lab("Lab1", "Loc1", 10, "mgr1")
        eq = manager.add_equipment(lab.id, "Device1", "type1")
        start = datetime.utcnow()
        end = start + timedelta(hours=2)
        from lab_manager import ResourceType
        booking1 = manager.create_booking(eq.id, ResourceType.EQUIPMENT, "user1", start, end, "test")
        booking2 = manager.create_booking(eq.id, ResourceType.EQUIPMENT, "user2", start, end, "test")
        assert booking1 is not None
        assert booking2 is None

class TestExperimentTracker:
    def test_create_protocol(self):
        tracker = ExperimentTracker()
        protocol = tracker.create_protocol(
            "Protocol 1", "Test protocol", [{"step": 1, "action": "mix"}], "researcher1"
        )
        assert protocol.name == "Protocol 1"
        assert len(protocol.steps) == 1
    
    def test_create_experiment(self):
        tracker = ExperimentTracker()
        protocol = tracker.create_protocol("P1", "Desc", [{"step": 1}], "r1")
        exp = tracker.create_experiment("Exp1", protocol.id, "researcher1", "lab1")
        assert exp.title == "Exp1"
        assert exp.status == ExperimentStatus.DRAFT
    
    def test_add_observation(self):
        tracker = ExperimentTracker()
        protocol = tracker.create_protocol("P1", "Desc", [{"step": 1}], "r1")
        exp = tracker.create_experiment("Exp1", protocol.id, "r1", "lab1")
        success = tracker.add_observation(exp.id, "Observation text", {"temp": 25})
        assert success is True
        assert len(exp.observations) == 1
    
    def test_experiment_cloning(self):
        tracker = ExperimentTracker()
        protocol = tracker.create_protocol("P1", "Desc", [{"step": 1}], "r1")
        exp1 = tracker.create_experiment("Original", protocol.id, "r1", "lab1", objectives=["goal1"])
        exp2 = tracker.clone_experiment(exp1.id, "Clone", "r2")
        assert exp2 is not None
        assert exp2.title == "Clone"
        assert exp2.parent_experiment_id == exp1.id

class TestCollaborationHub:
    def test_create_team(self):
        hub = CollaborationHub()
        team = hub.create_team("Team A", "creator1")
        assert team.name == "Team A"
        assert "creator1" in team.members
    
    def test_add_member(self):
        hub = CollaborationHub()
        team = hub.create_team("Team A", "creator1")
        success = hub.add_member(team.id, "member2")
        assert success is True
        assert "member2" in team.members
    
    def test_share_experiment(self):
        hub = CollaborationHub()
        team = hub.create_team("Team A", "creator1")
        success = hub.share_experiment(team.id, "exp123")
        assert success is True
        assert "exp123" in team.shared_experiments

class TestAnalysisEngine:
    def test_analyze_experiment(self):
        engine = AnalysisEngine()
        data = {"temperature": [20.0, 21.0, 22.0, 23.0], "pressure": [1.0, 1.1, 1.2, 1.3]}
        result = engine.analyze_experiment("exp1", data)
        assert result.experiment_id == "exp1"
        assert "temperature_mean" in result.statistics
    
    def test_statistical_analysis(self):
        engine = AnalysisEngine()
        data = {"x": [1.0, 2.0, 3.0, 4.0, 5.0], "y": [2.0, 4.0, 6.0, 8.0, 10.0]}
        result = engine.analyze_experiment("exp1", data, ["correlation"])
        assert "correlation" in result.statistics
        assert result.statistics["correlation"] > 0.9

class TestInventorySystem:
    def test_add_item(self):
        inventory = InventorySystem()
        item = inventory.add_item("Chemical A", "chemicals", 100.0, unit="ml")
        assert item.name == "Chemical A"
        assert item.quantity == 100.0
    
    def test_update_quantity(self):
        inventory = InventorySystem()
        item = inventory.add_item("Chemical A", "chemicals", 100.0)
        success = inventory.update_quantity(item.id, -20.0, "used in experiment")
        assert success is True
        assert item.quantity == 80.0
    
    def test_low_stock_detection(self):
        inventory = InventorySystem()
        item = inventory.add_item("Chemical A", "chemicals", 5.0, reorder_level=10.0)
        low_stock = inventory.check_low_stock()
        assert len(low_stock) == 1
        assert low_stock[0].id == item.id
    
    def test_expiring_items(self):
        inventory = InventorySystem()
        expiry = datetime.utcnow() + timedelta(days=15)
        item = inventory.add_item("Chemical B", "chemicals", 50.0, expiration_date=expiry)
        expiring = inventory.check_expiring_items(days=30)
        assert len(expiring) == 1

class TestResourceAllocator:
    def test_submit_request(self):
        allocator = ResourceAllocator()
        request = AllocationRequest(
            id="req1", user_id="user1", resource_type="equipment",
            duration_hours=2.0, priority=5
        )
        req_id = allocator.submit_request(request)
        assert req_id == "req1"
    
    def test_allocate_resources(self):
        allocator = ResourceAllocator()
        request = AllocationRequest(
            id="req1", user_id="user1", resource_type="equipment",
            duration_hours=2.0, priority=5
        )
        allocator.submit_request(request)
        allocations = allocator.allocate_resources()
        assert len(allocations) > 0

class TestIntegration:
    def test_full_experiment_workflow(self):
        lab_manager = LabManager()
        tracker = ExperimentTracker()
        
        # Create lab and equipment
        lab = lab_manager.create_lab("Lab1", "Building A", 10, "manager1")
        equipment = lab_manager.add_equipment(lab.id, "Microscope", "optical")
        
        # Create protocol and experiment
        protocol = tracker.create_protocol("Protocol1", "Test protocol", [{"step": 1}], "researcher1")
        experiment = tracker.create_experiment("Exp1", protocol.id, "researcher1", lab.id)
        
        # Update status and add observations
        tracker.update_experiment_status(experiment.id, ExperimentStatus.RUNNING)
        tracker.add_observation(experiment.id, "Started experiment")
        tracker.add_result(experiment.id, "result1", {"value": 42})
        tracker.update_experiment_status(experiment.id, ExperimentStatus.COMPLETED)
        
        assert experiment.status == ExperimentStatus.COMPLETED
        assert len(experiment.observations) == 1
        assert "result1" in experiment.results

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
