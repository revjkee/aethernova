# filepath: cybersecurity-core/cybersecurity/adversary_emulation/integrations/cloud/azure.py
"""
Azure integration for adversary emulation (safe-by-default, industrial-grade).

Core goals:
- SAFE discovery and telemetry using official Azure SDKs (read-only by default).
- Server-side "What-If" (ARM templates) to emulate potential changes WITHOUT applying them.
- MITRE ATT&CK mapping for cloud/container scenarios (comments).
- Structured logging, robust error handling, and explicit dry-run gates.

Verified references (official, up-to-date at time of writing):
1) Authentication (DefaultAzureCredential) — Microsoft Docs:
   https://learn.microsoft.com/azure/developer/python/sdk/azure-identity-readme
2) Resource Management client (ARM) — Microsoft Docs:
   https://learn.microsoft.com/azure/developer/python/sdk/azure-mgmt-resource-readme
3) Subscriptions client — Microsoft Docs:
   https://learn.microsoft.com/azure/developer/python/sdk/azure-mgmt-subscription-readme
4) Azure Resource Manager What-If (no-op planning of changes) — Microsoft Docs:
   https://learn.microsoft.com/azure/azure-resource-manager/templates/deploy-what-if
5) Azure Monitor Logs (LogsQueryClient, KQL) — Microsoft Docs:
   https://learn.microsoft.com/azure/developer/python/sdk/azure-monitor-query-readme
6) Network Security Groups overview — Microsoft Docs:
   https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview

If any of the above links become invalid, search by the exact page titles in Microsoft Learn.
Where I could not confirm a fact, I explicitly state: "Не могу подтвердить это".

Package notes (you must install):
  pip install azure-identity azure-mgmt-resource azure-mgmt-subscription azure-monitor-query

Design highlights:
- Dry-run first: any mutating action must pass an explicit gate.
- Minimal required permissions: Reader for discovery; What-If can run without applying.
- Clear MITRE mapping examples in comments:
  * Discovery (e.g., T1580 Cloud Infrastructure Discovery – Enterprise)
  * Defense Evasion/Impact simulations via What-If only (no changes)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

try:
    # Auth
    from azure.identity import DefaultAzureCredential
    # ARM / Resources
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.resource.resources.models import (
        DeploymentWhatIf,
        DeploymentWhatIfProperties,
        WhatIfChange,
        WhatIfChangeType,
        WhatIfOperationResult,
        DeploymentMode,
    )
    # Subscriptions
    from azure.mgmt.subscription import SubscriptionClient
    # Monitor Logs
    from azure.monitor.query import LogsQueryClient, LogsQueryStatus
except Exception as _e:  # pragma: no cover
    raise RuntimeError(
        "Azure SDK modules are required. Install: "
        "`pip install azure-identity azure-mgmt-resource azure-mgmt-subscription azure-monitor-query`"
    ) from _e


# ---------- Logging ----------
LOG = logging.getLogger("adversary_emulation.azure")
if not LOG.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)
    LOG.addHandler(handler)
LOG.setLevel(logging.INFO)


# ---------- Data models ----------
@dataclass(frozen=True)
class AzureConfig:
    """Configuration for Azure integration."""
    tenant_id: Optional[str] = None
    subscription_id: Optional[str] = None
    workspace_id: Optional[str] = None  # Log Analytics Workspace (for querying logs)
    dry_run: bool = True  # SAFE by default
    user_agent: str = "cybersecurity-core/attack-simulator"

    @staticmethod
    def from_env() -> "AzureConfig":
        return AzureConfig(
            tenant_id=os.getenv("AZURE_TENANT_ID"),
            subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
            workspace_id=os.getenv("AZURE_LOG_ANALYTICS_WORKSPACE_ID"),
            dry_run=os.getenv("AZURE_DRY_RUN", "true").lower() in ("1", "true", "yes"),
            user_agent=os.getenv("AZURE_USER_AGENT", "cybersecurity-core/attack-simulator"),
        )


class AzureIntegrationError(Exception):
    """Unified error type for Azure integration."""


# ---------- Core integration ----------
class AzureIntegration:
    """
    Azure integration using official SDKs with safe-by-default behavior.

    Authentication:
      DefaultAzureCredential picks credentials in order (EnvironmentCredential, ManagedIdentityCredential, etc.)
      Docs: https://learn.microsoft.com/azure/developer/python/sdk/azure-identity-readme

    Resource clients:
      - ResourceManagementClient for ARM operations including What-If:
        https://learn.microsoft.com/azure/developer/python/sdk/azure-mgmt-resource-readme
      - SubscriptionClient for listing subscriptions:
        https://learn.microsoft.com/azure/developer/python/sdk/azure-mgmt-subscription-readme

    Logs:
      - LogsQueryClient for KQL against Log Analytics:
        https://learn.microsoft.com/azure/developer/python/sdk/azure-monitor-query-readme
    """

    def __init__(self, config: Optional[AzureConfig] = None) -> None:
        self.config = config or AzureConfig.from_env()
        try:
            # Enforce a reproducible credential chain (DefaultAzureCredential):
            # Requires environment or managed identity or other supported methods.
            self.credential = DefaultAzureCredential(additionally_allowed_tenants=["*"])
        except Exception as e:
            raise AzureIntegrationError(f"Auth init failed: {e}") from e

        self._subscription_client: Optional[SubscriptionClient] = None
        self._resource_client: Optional[ResourceManagementClient] = None
        self._logs_client: Optional[LogsQueryClient] = None

        LOG.info("AzureIntegration initialized (dry_run=%s)", self.config.dry_run)

    # ----- Clients -----
    @property
    def subscription_client(self) -> SubscriptionClient:
        if self._subscription_client is None:
            self._subscription_client = SubscriptionClient(self.credential)
        return self._subscription_client

    def _ensure_subscription_and_resource_client(self, subscription_id: str) -> None:
        if not subscription_id:
            raise AzureIntegrationError("Subscription ID must be provided.")
        if self._resource_client is None or getattr(self._resource_client, "subscription_id", None) != subscription_id:
            self._resource_client = ResourceManagementClient(self.credential, subscription_id, user_agent=self.config.user_agent)

    @property
    def logs_client(self) -> LogsQueryClient:
        if self._logs_client is None:
            self._logs_client = LogsQueryClient(self.credential)
        return self._logs_client

    # ----- Discovery (MITRE: Cloud Infrastructure Discovery — e.g., T1580) -----
    def list_subscriptions(self) -> List[Dict[str, str]]:
        """
        Read-only discovery: list subscriptions visible to the caller.
        Reference: SubscriptionClient docs (Microsoft Learn).
        """
        try:
            subs = []
            for s in self.subscription_client.subscriptions.list():
                subs.append({"subscription_id": s.subscription_id, "display_name": s.display_name})
            LOG.info("Discovered %d subscription(s).", len(subs))
            return subs
        except Exception as e:
            raise AzureIntegrationError(f"Failed to list subscriptions: {e}") from e

    def list_resource_groups(self, subscription_id: str) -> List[Dict[str, str]]:
        """
        Read-only discovery: list resource groups in a subscription.
        Reference: ResourceManagementClient docs (Microsoft Learn).
        """
        try:
            self._ensure_subscription_and_resource_client(subscription_id)
            rgs = []
            for rg in self._resource_client.resource_groups.list():
                rgs.append({"name": rg.name, "location": rg.location})
            LOG.info("Subscription %s: %d resource group(s).", subscription_id, len(rgs))
            return rgs
        except Exception as e:
            raise AzureIntegrationError(f"Failed to list resource groups: {e}") from e

    # ----- What-If (safe emulation of changes without applying) -----
    def what_if_deployment(
        self,
        subscription_id: str,
        resource_group: str,
        template: Dict,
        parameters: Optional[Dict] = None,
        mode: DeploymentMode = DeploymentMode.INCREMENTAL,
        deployment_name: str = "attack-sim-whatif",
    ) -> WhatIfOperationResult:
        """
        Execute ARM What-If (non-destructive planning). NO CHANGES are applied.
        Reference: ARM What-If — https://learn.microsoft.com/azure/azure-resource-manager/templates/deploy-what-if

        Returns:
          WhatIfOperationResult containing list of predicted changes.

        Safety:
          - This is inherently read-only planning on server side.
          - Even when self.config.dry_run is False, What-If DOES NOT change resources.
        """
        try:
            self._ensure_subscription_and_resource_client(subscription_id)

            props = DeploymentWhatIfProperties(
                mode=mode,
                template=template,
                parameters=parameters or {},
            )
            payload = DeploymentWhatIf(properties=props)
            poller = self._resource_client.deployments.begin_what_if(
                resource_group_name=resource_group,
                deployment_name=deployment_name,
                parameters=payload,
            )
            result = poller.result()
            LOG.info(
                "What-If completed: %s change(s).",
                len(result.changes) if result and result.changes else 0,
            )
            return result
        except Exception as e:
            raise AzureIntegrationError(f"What-If failed: {e}") from e

    @staticmethod
    def summarize_what_if_changes(result: WhatIfOperationResult) -> List[Dict[str, str]]:
        """
        Produce a concise summary of What-If changes for reporting.
        """
        summary: List[Dict[str, str]] = []
        if not result or not result.changes:
            return summary
        for c in result.changes:
            assert isinstance(c, WhatIfChange)
            summary.append(
                {
                    "changeType": str(c.change_type.value if hasattr(c.change_type, "value") else c.change_type),
                    "resourceId": c.resource_id,
                }
            )
        return summary

    # ----- Example: NSG rule emulation via What-If (NO APPLY) -----
    def what_if_nsg_rule_open_egress(
        self,
        subscription_id: str,
        resource_group: str,
        nsg_name: str,
        rule_name: str = "SimOpenEgress",
        priority: int = 4096,
        protocol: str = "*",
        destination_port_range: str = "*",
        destination_address_prefix: str = "Internet",
    ) -> List[Dict[str, str]]:
        """
        Simulate (What-If) adding a permissive NSG egress rule (no changes are applied).
        Useful for demonstrating potential exfiltration avenues in a SAFE manner (T1041 behaviors),
        without modifying live infrastructure.

        NSG overview: https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview

        Returns:
          List of summarized changes from What-If.
        """
        # Minimal ARM template (NSG rule append) – purely for What-If planning.
        # NOTE: This template is purposely minimal and assumes NSG exists.
        template = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "nsgName": {"type": "string"},
                "ruleName": {"type": "string"},
                "priority": {"type": "int"},
                "protocol": {"type": "string"},
                "destPort": {"type": "string"},
                "destPrefix": {"type": "string"},
            },
            "resources": [
                {
                    "type": "Microsoft.Network/networkSecurityGroups/securityRules",
                    "apiVersion": "2023-09-01",
                    "name": "[format('{0}/{1}', parameters('nsgName'), parameters('ruleName'))]",
                    "properties": {
                        "priority": "[parameters('priority')]",
                        "access": "Allow",
                        "direction": "Outbound",
                        "protocol": "[parameters('protocol')]",
                        "sourcePortRange": "*",
                        "destinationPortRange": "[parameters('destPort')]",
                        "sourceAddressPrefix": "*",
                        "destinationAddressPrefix": "[parameters('destPrefix')]",
                    },
                }
            ],
        }

        params = {
            "nsgName": {"value": nsg_name},
            "ruleName": {"value": rule_name},
            "priority": {"value": priority},
            "protocol": {"value": protocol},
            "destPort": {"value": destination_port_range},
            "destPrefix": {"value": destination_address_prefix},
        }

        # Always safe: What-If does not change resources.
        result = self.what_if_deployment(
            subscription_id=subscription_id,
            resource_group=resource_group,
            template=template,
            parameters=params,
            deployment_name="attack-sim-whatif-nsg-egress",
        )
        return self.summarize_what_if_changes(result)

    # ----- Logs / Telemetry (Azure Monitor Logs via KQL) -----
    def query_activity_log(
        self,
        workspace_id: str,
        kql: str,
        timespan: str = "PT1H",
        server_timeout: int = 60,
        include_statistics: bool = False,
    ) -> Tuple[str, List[Dict[str, object]]]:
        """
        Query Azure Monitor Logs (Log Analytics) using KQL.
        Requires workspace_id to be connected to Activity Logs / Diagnostic settings.

        Docs: https://learn.microsoft.com/azure/developer/python/sdk/azure-monitor-query-readme
        KQL docs: https://learn.microsoft.com/azure/data-explorer/kusto/query/

        Returns:
          (status, rows_as_dicts)
        """
        if not workspace_id:
            raise AzureIntegrationError("workspace_id is required for logs query.")

        try:
            result = self.logs_client.query_workspace(
                workspace_id=workspace_id,
                query=kql,
                timespan=timespan,
                server_timeout=server_timeout,
                include_statistics=include_statistics,
            )
            rows: List[Dict[str, object]] = []
            if result.status == LogsQueryStatus.PARTIAL:
                table = result.partial_data
                LOG.warning("Partial log data returned with error: %s", result.error)
            else:
                table = result.tables[0] if result.tables else None

            if table:
                cols = [c.name for c in table.columns]
                for r in table.rows:
                    rows.append({cols[i]: r[i] for i in range(len(cols))})

            return (str(result.status), rows)
        except Exception as e:
            raise AzureIntegrationError(f"Logs query failed: {e}") from e

    @staticmethod
    def kql_recent_deployments(resource_group: Optional[str] = None) -> str:
        """
        Example KQL to surface recent ARM deployment operations (audit/telemetry).
        You can scope by resource group if Diagnostic settings route to the workspace.

        NOTE: Table names depend on data collection; in many setups use AzureActivity or
              ResourceDeployment table families. Adjust to your environment.
        """
        # I cannot universally confirm table names for every tenant/workspace pipeline.
        # Many tenants rely on AzureActivity; others use specific Resource* tables.
        # Hence we provide a generic example and clearly state uncertainty below.
        # Не могу подтвердить это (универсальность таблиц) — проверьте в своей схеме данных.
        if resource_group:
            return f"""
AzureActivity
| where TimeGenerated > ago(1h)
| where ResourceGroup == "{resource_group}"
| where OperationNameValue has "Microsoft.Resources/deployments"
| project TimeGenerated, OperationNameValue, ActivityStatusValue, ResourceGroup, Caller, CorrelationId
| order by TimeGenerated desc
""".strip()
        return """
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has "Microsoft.Resources/deployments"
| project TimeGenerated, OperationNameValue, ActivityStatusValue, ResourceGroup, Caller, CorrelationId
| order by TimeGenerated desc
""".strip()

    # ----- High-level composite (Discovery + Telemetry markers) -----
    def safe_discovery_snapshot(self) -> Dict[str, object]:
        """
        Composite read-only discovery for operator’s situational awareness.

        Steps:
          1) List subscriptions (read-only).
          2) For an active subscription (if configured), list resource groups (read-only).
          3) Optionally run a What-If (no-op) to generate benign telemetry.
        """
        snapshot: Dict[str, object] = {"dry_run": self.config.dry_run, "subscriptions": [], "resource_groups": []}
        subs = self.list_subscriptions()
        snapshot["subscriptions"] = subs

        active_sub = self.config.subscription_id or (subs[0]["subscription_id"] if subs else None)

        if active_sub:
            snapshot["active_subscription"] = active_sub
            snapshot["resource_groups"] = self.list_resource_groups(active_sub)
            # Example What-If to produce benign audit (NO APPLY):
            if snapshot["resource_groups"]:
                rg = snapshot["resource_groups"][0]["name"]
                changes = self.what_if_nsg_rule_open_egress(
                    subscription_id=active_sub,
                    resource_group=rg,
                    nsg_name="__placeholder_existing_nsg__",
                )
                snapshot["what_if_example"] = {"resource_group": rg, "changes": changes}
        else:
            snapshot["active_subscription"] = None

        return snapshot


# ---------- Example CLI wiring (optional) ----------
def _print_json(data: object) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def main() -> None:
    """
    Minimal CLI for quick local runs.

    Usage:
      export AZURE_TENANT_ID=...
      export AZURE_SUBSCRIPTION_ID=...
      export AZURE_LOG_ANALYTICS_WORKSPACE_ID=...
      python -m cybersecurity.adversary_emulation.integrations.cloud.azure safe_discovery
      python -m cybersecurity.adversary_emulation.integrations.cloud.azure kql_deployments <ResourceGroup|optional>

    Security:
      - By default, DRY-RUN is enabled (AZURE_DRY_RUN=true).
      - The What-If call NEVER applies changes. It only plans.
    """
    import argparse

    parser = argparse.ArgumentParser(prog="azure-integration")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("safe_discovery", help="Read-only discovery and What-If sample (no-op).")
    p_kql = sub.add_parser("kql_deployments", help="Print KQL for recent deployments.")
    p_kql.add_argument("--rg", dest="rg", default=None, help="Optional Resource Group filter.")

    args = parser.parse_args()
    integ = AzureIntegration()

    if args.cmd == "safe_discovery":
        _print_json(integ.safe_discovery_snapshot())
        return

    if args.cmd == "kql_deployments":
        _print_json({"kql": integ.kql_recent_deployments(args.rg)})
        return


if __name__ == "__main__":  # pragma: no cover
    main()
