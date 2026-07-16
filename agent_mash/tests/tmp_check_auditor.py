from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent_mash.core.system_auditor import (
    AuditStatus,
    ComponentState,
    SystemAuditor,
)

class DemoHealthyComponent:
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
            "ok": 1,
            "cpu": 10,
            "mem": 20,
        }


class DemoDegradedDependency:
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
            "ok": 1,
        }


async def run_smoke_check() -> int:
    auditor = SystemAuditor()

    dependency = DemoDegradedDependency()
    main_component = DemoHealthyComponent()

    await auditor.register_component(
        component_id="dependency-1",
        name="Dependency 1",
        instance=dependency,
        critical=False,
    )

    await auditor.register_component(
        component_id="component-1",
        name="Component 1",
        instance=main_component,
        dependencies=("dependency-1",),
        critical=True,
        metadata={"started_at": "2026-01-01T00:00:00+00:00"},
    )

    await auditor.mark_heartbeat("dependency-1")
    await auditor.mark_heartbeat("component-1")

    report = await auditor.run_full_audit(
        metadata={
            "source": "tmp_check_auditor",
            "mode": "smoke",
        }
    )

    output_dir = Path("agent_mash/tests/artifacts")
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "system_audit_report.json"
    await auditor.export_report_to_file(str(output_file), report)

    print("=== AUDIT SUMMARY ===")
    print(json.dumps(report.summary.to_dict(), ensure_ascii=False, indent=2))
    print()
    print("=== COMPONENT STATUSES ===")
    for component in report.components:
        print(
            f"{component.component_id}: "
            f"state={component.state.value}, "
            f"summary_status={component.summary_status.value}, "
            f"risk_score={component.risk_score}"
        )

    print()
    print(f"Report exported to: {output_file}")

    assert report.summary.total_components == 2, "Expected exactly 2 audited components"
    assert len(report.components) == 2, "Report components count mismatch"
    assert report.summary.global_status in {
        AuditStatus.PASS,
        AuditStatus.WARN,
        AuditStatus.FAIL,
        AuditStatus.ERROR,
        AuditStatus.SKIP,
    }, "Unexpected global audit status"
    assert output_file.exists(), "Audit report file was not created"

    exported_payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert "audit_id" in exported_payload, "Exported report missing audit_id"
    assert "summary" in exported_payload, "Exported report missing summary"
    assert "components" in exported_payload, "Exported report missing components"

    component_ids = {component.component_id for component in report.components}
    assert "component-1" in component_ids, "Main component missing from report"
    assert "dependency-1" in component_ids, "Dependency component missing from report"

    return 0


def main() -> int:
    return asyncio.run(run_smoke_check())


if __name__ == "__main__":
    raise SystemExit(main())