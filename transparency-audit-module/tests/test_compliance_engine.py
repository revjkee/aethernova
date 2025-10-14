"""
Тесты для Compliance Engine
"""
import pytest
from datetime import datetime, timedelta
from compliance_engine import ComplianceEngine, ComplianceCheck, ComplianceStandard


@pytest.fixture
def engine():
    """Fixture для compliance engine"""
    return ComplianceEngine()


class TestGDPRCompliance:
    """Тесты для GDPR соответствия"""
    
    def test_data_retention_check(self, engine):
        """Тест проверки срока хранения данных"""
        result = engine.check_gdpr_compliance(
            data_type="personal_data",
            retention_days=365,
            max_retention_days=730
        )
        assert result.passed is True
    
    def test_data_retention_violation(self, engine):
        """Тест нарушения срока хранения"""
        result = engine.check_gdpr_compliance(
            data_type="personal_data",
            retention_days=1000,
            max_retention_days=730
        )
        assert result.passed is False
        assert "retention" in result.violations[0].lower()
    
    def test_consent_tracking(self, engine):
        """Тест отслеживания согласия"""
        result = engine.check_consent_status(
            user_id="user123",
            purpose="marketing",
            has_consent=True
        )
        assert result.passed is True
    
    def test_right_to_erasure(self, engine):
        """Тест права на удаление (Right to be forgotten)"""
        result = engine.verify_erasure_capability(
            user_id="user123",
            data_categories=["personal_data", "behavioral_data"]
        )
        assert result.erasure_possible is True
    
    def test_data_portability(self, engine):
        """Тест переносимости данных"""
        result = engine.check_data_portability(
            user_id="user123",
            export_format="json"
        )
        assert result.passed is True


class TestSOC2Compliance:
    """Тесты для SOC2 соответствия"""
    
    def test_access_controls(self, engine):
        """Тест контроля доступа"""
        result = engine.check_soc2_access_controls(
            user_id="admin1",
            required_mfa=True,
            has_mfa=True,
            last_review=datetime.utcnow() - timedelta(days=30)
        )
        assert result.passed is True
    
    def test_mfa_requirement(self, engine):
        """Тест требования MFA"""
        result = engine.check_soc2_access_controls(
            user_id="admin1",
            required_mfa=True,
            has_mfa=False
        )
        assert result.passed is False
        assert "mfa" in str(result.violations).lower()
    
    def test_audit_logging(self, engine):
        """Тест аудит-логирования"""
        result = engine.check_soc2_logging(
            log_retention_days=365,
            min_retention_days=180,
            log_integrity_verified=True
        )
        assert result.passed is True
    
    def test_change_management(self, engine):
        """Тест управления изменениями"""
        result = engine.check_soc2_change_management(
            change_id="CHG-001",
            has_approval=True,
            has_testing=True,
            has_rollback_plan=True
        )
        assert result.passed is True
    
    def test_incident_response(self, engine):
        """Тест реагирования на инциденты"""
        result = engine.check_soc2_incident_response(
            incident_id="INC-001",
            detection_time=datetime.utcnow() - timedelta(minutes=5),
            response_time=datetime.utcnow() - timedelta(minutes=3),
            max_response_minutes=15
        )
        assert result.passed is True


class TestISO27001Compliance:
    """Тесты для ISO 27001 соответствия"""
    
    def test_risk_assessment(self, engine):
        """Тест оценки рисков"""
        result = engine.check_iso27001_risk_assessment(
            asset_id="server-01",
            risk_level="medium",
            mitigation_plan_exists=True,
            last_assessment=datetime.utcnow() - timedelta(days=60)
        )
        assert result.passed is True
    
    def test_security_controls(self, engine):
        """Тест контролей безопасности"""
        result = engine.check_iso27001_controls(
            control_id="A.9.1.1",
            implemented=True,
            tested=True,
            last_test=datetime.utcnow() - timedelta(days=30)
        )
        assert result.passed is True
    
    def test_asset_management(self, engine):
        """Тест управления активами"""
        result = engine.check_iso27001_asset_management(
            asset_id="laptop-01",
            owner_assigned=True,
            classification="confidential",
            inventory_updated=True
        )
        assert result.passed is True


class TestHIPAACompliance:
    """Тесты для HIPAA соответствия"""
    
    def test_phi_encryption(self, engine):
        """Тест шифрования PHI"""
        result = engine.check_hipaa_phi_protection(
            data_id="patient-001",
            encrypted_at_rest=True,
            encrypted_in_transit=True,
            access_logged=True
        )
        assert result.passed is True
    
    def test_minimum_necessary(self, engine):
        """Тест минимально необходимого доступа"""
        result = engine.check_hipaa_minimum_necessary(
            user_id="doctor1",
            role="physician",
            data_accessed=["diagnosis", "treatment"],
            justified=True
        )
        assert result.passed is True
    
    def test_breach_notification(self, engine):
        """Тест уведомления о нарушении"""
        result = engine.check_hipaa_breach_notification(
            breach_id="BR-001",
            affected_records=100,
            notification_sent=True,
            notification_time=datetime.utcnow() - timedelta(hours=48)
        )
        assert result.passed is True


class TestPCIDSSCompliance:
    """Тесты для PCI DSS соответствия"""
    
    def test_cardholder_data_protection(self, engine):
        """Тест защиты данных держателя карты"""
        result = engine.check_pci_cardholder_protection(
            transaction_id="TXN-001",
            pan_masked=True,
            cvv_not_stored=True,
            encrypted=True
        )
        assert result.passed is True
    
    def test_network_segmentation(self, engine):
        """Тест сегментации сети"""
        result = engine.check_pci_network_segmentation(
            segment_id="cardholder-zone",
            firewall_configured=True,
            access_controlled=True,
            monitored=True
        )
        assert result.passed is True
    
    def test_vulnerability_management(self, engine):
        """Тест управления уязвимостями"""
        result = engine.check_pci_vulnerability_management(
            system_id="payment-gateway",
            last_scan=datetime.utcnow() - timedelta(days=15),
            critical_vulns=0,
            scan_frequency_days=30
        )
        assert result.passed is True


class TestAutomatedReporting:
    """Тесты для автоматической отчётности"""
    
    def test_generate_compliance_report(self, engine):
        """Тест генерации compliance отчёта"""
        report = engine.generate_compliance_report(
            standard="GDPR",
            start_date=datetime.utcnow() - timedelta(days=30),
            end_date=datetime.utcnow()
        )
        
        assert report is not None
        assert report.standard == "GDPR"
        assert report.total_checks > 0
        assert report.compliance_score >= 0
    
    def test_multi_standard_report(self, engine):
        """Тест отчёта по множеству стандартов"""
        report = engine.generate_multi_standard_report(
            standards=["GDPR", "SOC2", "ISO27001"],
            period_days=30
        )
        
        assert len(report.standards) == 3
        assert all(s in report.standards for s in ["GDPR", "SOC2", "ISO27001"])
    
    def test_compliance_trend_analysis(self, engine):
        """Тест анализа трендов соответствия"""
        trend = engine.analyze_compliance_trend(
            standard="SOC2",
            period_days=90,
            interval_days=30
        )
        
        assert len(trend.data_points) > 0
        assert all(0 <= dp.score <= 100 for dp in trend.data_points)


class TestComplianceViolations:
    """Тесты для нарушений соответствия"""
    
    def test_detect_violation(self, engine):
        """Тест обнаружения нарушения"""
        violations = engine.detect_violations(
            standard="GDPR",
            check_type="data_retention",
            threshold_days=730
        )
        
        assert isinstance(violations, list)
    
    def test_violation_severity(self, engine):
        """Тест серьёзности нарушения"""
        violation = engine.create_violation(
            standard="HIPAA",
            control="PHI_ENCRYPTION",
            description="Unencrypted PHI detected",
            affected_records=500
        )
        
        assert violation.severity in ["critical", "high", "medium", "low"]
        assert violation.severity == "critical"  # Должно быть критично для HIPAA
    
    def test_remediation_tracking(self, engine):
        """Тест отслеживания исправления"""
        violation_id = "VIO-001"
        
        # Создание нарушения
        violation = engine.create_violation(
            standard="SOC2",
            control="ACCESS_CONTROL",
            description="User without MFA"
        )
        
        # Отслеживание исправления
        remediation = engine.track_remediation(
            violation_id=violation.id,
            action="Enable MFA for user",
            assigned_to="security-team"
        )
        
        assert remediation.status in ["open", "in_progress", "resolved"]


class TestContinuousMonitoring:
    """Тесты для непрерывного мониторинга"""
    
    def test_realtime_compliance_check(self, engine):
        """Тест real-time проверки соответствия"""
        result = engine.perform_realtime_check(
            event_type="data_access",
            user_id="user123",
            resource="patient_records"
        )
        
        assert result.checked is True
        assert result.compliant in [True, False]
    
    def test_scheduled_compliance_scan(self, engine):
        """Тест запланированного скана соответствия"""
        scan_result = engine.run_scheduled_scan(
            standards=["GDPR", "SOC2"],
            scope="all_systems"
        )
        
        assert scan_result.completed is True
        assert scan_result.total_checks > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
