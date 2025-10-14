"""Тесты для Forensic Analyzer"""
import pytest
from datetime import datetime, timedelta
from forensic_analyzer import ForensicAnalyzer, Timeline, Pattern

@pytest.fixture
def analyzer():
    return ForensicAnalyzer()

class TestTimelineReconstruction:
    def test_build_timeline(self, analyzer):
        events = [
            {"timestamp": datetime.utcnow() - timedelta(hours=i), "type": f"event{i}"}
            for i in range(10)
        ]
        timeline = analyzer.build_timeline(events)
        assert len(timeline.events) == 10
        assert timeline.is_sorted is True
    
    def test_timeline_gap_detection(self, analyzer):
        events = [
            {"timestamp": datetime.utcnow() - timedelta(hours=1)},
            {"timestamp": datetime.utcnow() - timedelta(hours=10)},  # Gap
        ]
        timeline = analyzer.build_timeline(events)
        gaps = analyzer.detect_gaps(timeline, max_gap_hours=2)
        assert len(gaps) > 0

class TestPatternDetection:
    def test_detect_brute_force(self, analyzer):
        failed_logins = [
            {"user": "admin", "timestamp": datetime.utcnow() - timedelta(seconds=i)}
            for i in range(20)
        ]
        patterns = analyzer.detect_patterns(failed_logins)
        assert any(p.type == "brute_force" for p in patterns)
    
    def test_detect_data_exfiltration(self, analyzer):
        transfers = [
            {"bytes": 10_000_000, "timestamp": datetime.utcnow() - timedelta(minutes=i)}
            for i in range(5)
        ]
        patterns = analyzer.detect_patterns(transfers, pattern_type="exfiltration")
        assert len(patterns) > 0

class TestAnomalyDetection:
    def test_anomaly_detection(self, analyzer):
        normal_data = [{"value": 100 + i} for i in range(100)]
        anomalous_data = [{"value": 1000}]
        
        anomalies = analyzer.detect_anomalies(normal_data + anomalous_data)
        assert len(anomalies) > 0
        assert anomalies[0]["value"] == 1000

class TestChainOfCustody:
    def test_track_evidence(self, analyzer):
        evidence_id = analyzer.create_evidence(
            type="log_file",
            source="server-01",
            description="Suspicious access logs"
        )
        
        analyzer.update_custody(
            evidence_id=evidence_id,
            handler="investigator-1",
            action="collected",
            location="evidence-room"
        )
        
        chain = analyzer.get_custody_chain(evidence_id)
        assert len(chain) >= 1
        assert chain[0].handler == "investigator-1"

pytest.main([__file__, "-v"])
