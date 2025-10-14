"""
Тесты для ядра Lab OS
"""
import pytest
from labos_core import LabOS, Experiment, ResourceManager

@pytest.fixture
def labos():
    return LabOS()

class TestExperimentManagement:
    def test_create_experiment(self, labos):
        exp = labos.create_experiment(
            name="Test Experiment",
            description="Basic experiment",
            owner="user1"
        )
        assert exp.id is not None
        assert exp.name == "Test Experiment"
        assert exp.status == "created"
    def test_start_experiment(self, labos):
        exp = labos.create_experiment(name="Exp2", description="Desc", owner="user2")
        labos.start_experiment(exp.id)
        assert exp.status == "running"
    def test_complete_experiment(self, labos):
        exp = labos.create_experiment(name="Exp3", description="Desc", owner="user3")
        labos.start_experiment(exp.id)
        labos.complete_experiment(exp.id)
        assert exp.status == "completed"
    def test_list_experiments(self, labos):
        for i in range(5):
            labos.create_experiment(name=f"Exp{i}", description="Desc", owner="user")
        exps = labos.list_experiments()
        assert len(exps) >= 5

class TestResourceManager:
    def test_allocate_resource(self, labos):
        res = labos.resource_manager.allocate("cpu", 4)
        assert res.type == "cpu"
        assert res.amount == 4
    def test_release_resource(self, labos):
        res = labos.resource_manager.allocate("gpu", 2)
        labos.resource_manager.release(res.id)
        assert res.status == "released"
    def test_resource_status(self, labos):
        res = labos.resource_manager.allocate("ram", 16)
        status = labos.resource_manager.status(res.id)
        assert status in ["allocated", "released"]

class TestCollaboration:
    def test_add_collaborator(self, labos):
        exp = labos.create_experiment(name="CollabExp", description="Desc", owner="user1")
        labos.add_collaborator(exp.id, "user2")
        assert "user2" in exp.collaborators
    def test_remove_collaborator(self, labos):
        exp = labos.create_experiment(name="CollabExp2", description="Desc", owner="user1")
        labos.add_collaborator(exp.id, "user2")
        labos.remove_collaborator(exp.id, "user2")
        assert "user2" not in exp.collaborators

class TestDataAnalysis:
    def test_run_analysis(self, labos):
        exp = labos.create_experiment(name="AnalysisExp", description="Desc", owner="user1")
        result = labos.run_analysis(exp.id, "basic_stats")
        assert result is not None
        assert "mean" in result
        assert "std" in result

class TestDashboard:
    def test_dashboard_metrics(self, labos):
        metrics = labos.dashboard.get_metrics()
        assert "experiments_total" in metrics
        assert "resources_allocated" in metrics
        assert "active_users" in metrics

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
