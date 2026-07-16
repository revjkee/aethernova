from __future__ import annotations

import json

import pytest

from agent_mash.core.system_auditor import (
    AuditStatus,
    ComponentState,
    SystemAuditor,
)


class HealthyComponent:
    state = ComponentState.HEALTHY

    def ping(self) -> bool:
        return True

    def health_check(self) -> dict[str, str]:
        return {
            "status": "pass",
            "message": "healthy",
        }

    def self_test(self) -> bool:
        return True

    def collect_metrics(self) -> dict[str, int]:
        return {
            "cpu": 10,
            "mem": 20,
        }


class DegradedComponent:
    state = ComponentState.DEGRADED

    def ping(self) -> bool:
        return True

    def health_check(self) -> dict[str, str]:
        return {
            "status": "warn",
            "message": "degraded",
        }

    def self_test(self) -> bool:
        return True

    def collect_metrics(self) -> dict[str, int]:
        return {
            "cpu": 70,
            "mem": 80,
        }


class MinimalComponent:
    state = ComponentState.HEALTHY


@pytest.mark.asyncio
async def test_run_full_audit_for_healthy_component() -> None:
    auditor = SystemAuditor()

    await auditor.register_component(
        component_id="component-1",
        name="Component 1",
        instance=HealthyComponent(),
        critical=True,
    )
    await auditor.mark_heartbeat("component-1")

    report = await auditor.run_full_audit()

    assert report.summary.total_components == 1
    assert len(report.components) == 1
    assert report.components[0].component_id == "component-1"
    assert report.components[0].summary_status == AuditStatus.PASS
    assert report.summary.global_status == AuditStatus.PASS
    assert report.summary.failed_checks == 0
    assert report.summary.errored_checks == 0


@pytest.mark.asyncio
async def test_missing_heartbeat_produces_warning() -> None:
    auditor = SystemAuditor()

    await auditor.register_component(
        component_id="component-1",
        name="Component 1",
        instance=HealthyComponent(),
        critical=False,
    )

    report = await auditor.run_full_audit()
    component_report = report.components[0]

    heartbeat_checks = [
        check for check in component_report.checks
        if check.check_name == "heartbeat"
    ]

    assert heartbeat_checks
    assert heartbeat_checks[0].status == AuditStatus.WARN
    assert component_report.summary_status == AuditStatus.WARN
    assert report.summary.global_status == AuditStatus.WARN


@pytest.mark.asyncio
async def test_missing_dependency_produces_fail_by_default_policy() -> None:
    auditor = SystemAuditor()

    await auditor.register_component(
        component_id="component-1",
        name="Component 1",
        instance=HealthyComponent(),
        dependencies=("missing-service",),
        critical=True,
    )
    await auditor.mark_heartbeat("component-1")

    report = await auditor.run_full_audit()
    component_report = report.components[0]

    dependency_checks = [
        check for check in component_report.checks
        if check.check_name == "dependencies"
    ]

    assert dependency_checks
    assert dependency_checks[0].status == AuditStatus.FAIL
    assert component_report.summary_status == AuditStatus.FAIL
    assert report.summary.global_status == AuditStatus.FAIL


@pytest.mark.asyncio
async def test_degraded_dependency_produces_warning() -> None:
    auditor = SystemAuditor()

    await auditor.register_component(
        component_id="dependency-1",
        name="Dependency 1",
        instance=DegradedComponent(),
        critical=False,
    )
    await auditor.register_component(
        component_id="component-1",
        name="Component 1",
        instance=HealthyComponent(),
        dependencies=("dependency-1",),
        critical=False,
    )

    await auditor.mark_heartbeat("dependency-1")
    await auditor.mark_heartbeat("component-1")

    report = await auditor.run_full_audit()
    component_reports = {component.component_id: component for component in report.components}

    assert component_reports["dependency-1"].summary_status == AuditStatus.WARN
    assert component_reports["component-1"].summary_status == AuditStatus.WARN
    assert report.summary.global_status == AuditStatus.WARN


@pytest.mark.asyncio
async def test_unregistered_component_returns_fail_report() -> None:
    auditor = SystemAuditor()

    report = await auditor.run_component_audit("missing-component")

    assert report.component_id == "missing-component"
    assert report.summary_status == AuditStatus.FAIL
    assert len(report.checks) == 1
    assert report.checks[0].check_name == "registration"
    assert report.checks[0].status == AuditStatus.FAIL


@pytest.mark.asyncio
async def test_export_report_to_file_creates_valid_json(tmp_path) -> None:
    auditor = SystemAuditor()

    await auditor.register_component(
        component_id="component-1",
        name="Component 1",
        instance=HealthyComponent(),
        critical=False,
    )
    await auditor.mark_heartbeat("component-1")

    report = await auditor.run_full_audit()

    output_file = tmp_path / "system_audit_report.json"
    await auditor.export_report_to_file(str(output_file), report)

    assert output_file.exists()

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["audit_id"] == report.audit_id
    assert payload["node_name"] == report.node_name
    assert "summary" in payload
    assert "components" in payload
    assert len(payload["components"]) == 1


@pytest.mark.asyncio
async def test_snapshot_registry_contains_registered_components() -> None:
    auditor = SystemAuditor()

    await auditor.register_component(
        component_id="component-1",
        name="Component 1",
        instance=HealthyComponent(),
        critical=False,
    )

    snapshot = await auditor.snapshot_registry()

    assert "node_name" in snapshot
    assert "policy" in snapshot
    assert "components" in snapshot
    assert "component-1" in snapshot["components"]


@pytest.mark.asyncio
async def test_clean_removes_registered_components_and_custom_checks() -> None:
    auditor = SystemAuditor()

    await auditor.register_component(
        component_id="component-1",
        name="Component 1",
        instance=HealthyComponent(),
        critical=False,
    )

    async def custom_check(_component):
        raise AssertionError("This custom check should not be executed after clean")

    await auditor.add_custom_check("component-1", custom_check)

    before_clean = await auditor.snapshot_registry()
    assert "component-1" in before_clean["components"]
    assert before_clean["custom_check_counts"]["component-1"] == 1

    await auditor.clean()

    after_clean = await auditor.snapshot_registry()
    assert after_clean["components"] == {}
    assert after_clean["custom_check_counts"] == {}


@pytest.mark.asyncio
async def test_component_with_minimal_api_skips_optional_checks() -> None:
    auditor = SystemAuditor()

    await auditor.register_component(
        component_id="component-1",
        name="Component 1",
        instance=MinimalComponent(),
        critical=False,
    )
    await auditor.mark_heartbeat("component-1")

    report = await auditor.run_full_audit()
    component_report = report.components[0]

    checks_by_name = {check.check_name: check for check in component_report.checks}

    assert checks_by_name["registration"].status == AuditStatus.PASS
    assert checks_by_name["connectivity"].status == AuditStatus.SKIP
    assert checks_by_name["health"].status == AuditStatus.SKIP
    assert checks_by_name["self_test"].status == AuditStatus.SKIP
    assert checks_by_name["metrics"].status == AuditStatus.SKIP