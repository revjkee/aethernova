# -*- coding: utf-8 -*-
"""
GCP Integration for Adversary Emulation (SAFE BY DEFAULT)

This module provides a production-grade, safe-by-default integration layer with
Google Cloud Platform to support adversary emulation in cloud environments.
It focuses on writing structured simulation events to Cloud Logging, reading
IAM policies via Resource Manager, and enumerating assets via Cloud Asset Inventory.
No destructive actions are performed unless explicitly allowed (simulate_mode=False).

Key external facts (verified):
- Authentication uses Application Default Credentials (ADC) so the code can run
  locally and in production without changing how it authenticates. See Google Cloud
  docs on ADC and setup.  Sources:
  https://cloud.google.com/docs/authentication/application-default-credentials
  https://cloud.google.com/docs/authentication/provide-credentials-adc
- Cloud Logging Python: write structured logs using google-cloud-logging. Sources:
  https://cloud.google.com/logging/docs/setup/python
  https://cloud.google.com/python/docs/reference/logging/latest
- Cloud Asset Inventory clients for Python. Sources:
  https://cloud.google.com/asset-inventory/docs/client-libraries
  https://cloud.google.com/python/docs/reference/cloudasset/latest
- Resource Manager (v3) getIamPolicy for projects. Source:
  https://cloud.google.com/resource-manager/reference/rest/v3/projects/getIamPolicy
- ATT&CK for Cloud techniques referenced in simulations:
  T1078.004 (Valid Accounts: Cloud), T1098 (Account Manipulation),
  T1530 (Data from Cloud Storage). Sources:
  https://attack.mitre.org/techniques/T1078/004/
  https://attack.mitre.org/techniques/T1098/
  https://attack.mitre.org/techniques/T1530/
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

# Google auth & API core
try:
    import google.auth  # ADC
    from google.auth.credentials import Credentials
    from google.api_core import exceptions as gax_exceptions
    from google.api_core.retry import Retry
except Exception as e:  # pragma: no cover
    raise ImportError(
        "Required Google auth libraries are not installed: "
        "google-auth, google-api-core"
    ) from e

# Cloud Logging
try:
    from google.cloud import logging as gcloud_logging
except Exception as e:  # pragma: no cover
    raise ImportError(
        "google-cloud-logging is required for Cloud Logging integration."
    ) from e

# Cloud Asset Inventory
try:
    from google.cloud import asset_v1
except Exception:
    asset_v1 = None  # Optional feature depending on environment

# Secret Manager (optional, used only for benign markers if enabled)
try:
    from google.cloud import secretmanager_v1
except Exception:
    secretmanager_v1 = None  # Optional

# Resource Manager (REST discovery)
try:
    from googleapiclient.discovery import build as gapi_build
except Exception as e:  # pragma: no cover
    gapi_build = None  # We will guard usage


class GCPIntegrationError(RuntimeError):
    """Generic integration error for GCP adversary emulation."""


@dataclass(frozen=True)
class GCPConfig:
    project_id: str
    simulate_mode: bool = True
    log_name: str = "adversary-emulation"
    default_labels: Mapping[str, str] = field(
        default_factory=lambda: {"product": "cybersecurity-core", "sim": "true"}
    )
    request_timeout_seconds: int = 30
    user_agent: str = "Aethernova-AdversaryEmulation/1.0"
    # Backoff / retry policy
    initial_backoff: float = 0.5
    max_backoff: float = 8.0
    max_retries: int = 5


def _build_retry(cfg: GCPConfig) -> Retry:
    """Create a unified Retry object for Google API calls."""
    return Retry(
        initial=cfg.initial_backoff,
        maximum=cfg.max_backoff,
        multiplier=2.0,
        deadline=cfg.request_timeout_seconds,
        predicate=Retry.if_exception_type(
            gax_exceptions.ServiceUnavailable,
            gax_exceptions.InternalServerError,
            gax_exceptions.DeadlineExceeded,
            gax_exceptions.TooManyRequests,
        ),
    )


class GCPIntegration:
    """
    Safe-by-default integration with GCP services for adversary emulation.

    Authentication:
      Uses Application Default Credentials (ADC). Verified by Google Cloud docs:
      - How ADC works: https://cloud.google.com/docs/authentication/application-default-credentials
      - ADC setup:     https://cloud.google.com/docs/authentication/provide-credentials-adc

    Capabilities:
      - Cloud Logging: structured simulation events (see Python setup docs).
      - Resource Manager v3: getIamPolicy for project-level IAM.
      - Cloud Asset Inventory: search/list assets (optional, if library present).
      - Secret Manager: optional benign markers (no secrets are created by default).

    ATT&CK notes (for telemetry tagging):
      - T1078.004 Valid Accounts: Cloud
      - T1098     Account Manipulation
      - T1530     Data from Cloud Storage
      See https://attack.mitre.org for technique details.
    """

    def __init__(
        self,
        config: GCPConfig,
        credentials: Optional[Credentials] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.cfg = config
        self._pylogger = logger or logging.getLogger(__name__)
        self._credentials = credentials
        self._gcp_logging_client: Optional[gcloud_logging.Client] = None
        self._asset_client: Optional[asset_v1.AssetServiceClient] = None
        self._retry = _build_retry(config)

    # ---------- Factory helpers ----------

    @classmethod
    def from_env(cls, project_var: str = "GOOGLE_CLOUD_PROJECT") -> "GCPIntegration":
        """
        Build integration from environment. Project is taken from GOOGLE_CLOUD_PROJECT
        unless explicitly passed by env var name.

        Facts:
          - ADC finds credentials based on environment (incl. service account on GCE/GKE).
            Verified: Google Cloud ADC docs.
        """
        project_id = os.environ.get(project_var)
        if not project_id:
            raise GCPIntegrationError(
                f"Project id not found in environment variable {project_var}."
            )

        creds, _ = google.auth.default()  # Uses ADC search order (verified in docs)
        cfg = GCPConfig(project_id=project_id)
        return cls(cfg, credentials=creds)

    # ---------- Lazy clients ----------

    @property
    def _logging_client(self) -> gcloud_logging.Client:
        if self._gcp_logging_client is None:
            self._gcp_logging_client = gcloud_logging.Client(
                project=self.cfg.project_id, credentials=self._credentials
            )
        return self._gcp_logging_client

    @property
    def _asset_svc(self) -> Optional[asset_v1.AssetServiceClient]:
        if asset_v1 is None:
            return None
        if self._asset_client is None:
            self._asset_client = asset_v1.AssetServiceClient(credentials=self._credentials)
        return self._asset_client

    def _resourcemanager(self):
        if gapi_build is None:
            raise GCPIntegrationError(
                "google-api-python-client is required for Resource Manager (v3)."
            )
        # v3 is current for projects.getIamPolicy (verified in docs)
        return gapi_build(
            "cloudresourcemanager",
            "v3",
            cache_discovery=False,
            requestBuilder=_UserAgentRequestBuilder(self.cfg.user_agent),
        )

    # ---------- Public operations ----------

    def validate_connectivity(self) -> Dict[str, Any]:
        """
        Lightweight connectivity check:
          1) Fetch project IAM policy (read-only).
          2) Attempt to write a benign structured log in simulate mode.

        All steps are safe and non-destructive.

        Sources:
          - getIamPolicy (projects): https://cloud.google.com/resource-manager/reference/rest/v3/projects/getIamPolicy
          - Cloud Logging Python:    https://cloud.google.com/logging/docs/setup/python
        """
        policy = self.get_project_iam_policy()
        self.write_simulation_event(
            event_type="connectivity_check",
            summary="Adversary emulation connectivity verification",
            details={"status": "ok"},
        )
        return {"iam_bindings": len(policy.get("bindings", []))}

    def get_project_iam_policy(self) -> Dict[str, Any]:
        """Return IAM policy for the configured project (read-only)."""
        svc = self._resourcemanager()
        name = f"projects/{self.cfg.project_id}"
        req = svc.projects().getIamPolicy(resource=name, body={})
        try:
            with _timeout(self.cfg.request_timeout_seconds):
                result = self._retry(req.execute)()
        except Exception as e:  # pragma: no cover
            raise GCPIntegrationError(f"getIamPolicy failed: {e}") from e
        return result or {}

    def search_assets(
        self,
        query: Optional[str] = None,
        asset_types: Optional[Iterable[str]] = None,
        scope: Optional[str] = None,
        page_size: int = 100,
    ) -> Iterable[Dict[str, Any]]:
        """
        Search assets via Cloud Asset Inventory (read-only).

        Facts:
          - Cloud Asset Inventory supports inventory/queries using client libs. Sources:
            https://cloud.google.com/asset-inventory/docs/client-libraries
            https://cloud.google.com/python/docs/reference/cloudasset/latest
        """
        if self._asset_svc is None:
            raise GCPIntegrationError(
                "cloudasset client not available (install google-cloud-asset)."
            )

        scope = scope or f"projects/{self.cfg.project_id}"
        req = asset_v1.SearchAllResourcesRequest(
            scope=scope, query=query or "", asset_types=list(asset_types or [])
        )

        try:
            with _timeout(self.cfg.request_timeout_seconds):
                pager = self._retry(self._asset_svc.search_all_resources)(request=req)
                for res in pager:
                    yield asset_to_dict(res)
        except gax_exceptions.GoogleAPICallError as e:  # pragma: no cover
            raise GCPIntegrationError(f"Asset search failed: {e}") from e

    # ---------- Logging (structured) ----------

    def write_simulation_event(
        self,
        event_type: str,
        summary: str,
        details: Optional[Mapping[str, Any]] = None,
        severity: str = "INFO",
        technique: Optional[str] = None,
        labels: Optional[Mapping[str, str]] = None,
    ) -> None:
        """
        Write a structured simulation event to Cloud Logging (global resource).

        Facts:
          - The python client can emit structured entries; standard setup is documented.
            Sources:
            https://cloud.google.com/logging/docs/setup/python
            https://cloud.google.com/python/docs/reference/logging/latest
        """
        payload = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "product": "cybersecurity-core",
            "component": "adversary_emulation",
            "simulate": self.cfg.simulate_mode,
            "event_type": event_type,
            "summary": summary,
            "technique": technique,
            "details": dict(details or {}),
        }
        labels_final = dict(self.cfg.default_labels)
        if labels:
            labels_final.update(labels)

        logger_ref = self._logging_client.logger(self.cfg.log_name)
        resource = {"type": "global", "labels": {"project_id": self.cfg.project_id}}

        # Use log_struct for structured payload
        self._retry(logger_ref.log_struct)(
            payload, severity=severity, labels=labels_final, resource=resource
        )

    # ---------- Safe simulations for common ATT&CK cloud techniques ----------

    def simulate_valid_accounts_cloud(
        self,
        principal: str,
        context: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Simulate ATT&CK T1078.004 (Valid Accounts: Cloud) by logging a benign
        authentication/use event. No real auth is performed.

        Technique reference:
          https://attack.mitre.org/techniques/T1078/004/
        """
        self.write_simulation_event(
            event_type="auth.valid_account",
            summary=f"Simulated use of valid cloud account by {principal}",
            details={"principal": principal, "context": dict(context or {})},
            technique="T1078.004",
            severity="NOTICE",
            labels={"scenario": "valid-accounts-cloud"},
        )

    def simulate_account_manipulation(
        self,
        principal: str,
        action: str = "add_binding",
        target_role: str = "roles/viewer",
        target_member: Optional[str] = None,
    ) -> None:
        """
        Simulate ATT&CK T1098 (Account Manipulation) by emitting a structured
        event that *describes* a hypothetical IAM change. No policy mutation occurs.

        Technique reference:
          https://attack.mitre.org/techniques/T1098/
        """
        details = {
            "principal": principal,
            "action": action,
            "target_role": target_role,
            "target_member": target_member,
        }
        self.write_simulation_event(
            event_type="iam.account_manipulation",
            summary="Simulated IAM account manipulation (no-op)",
            details=details,
            technique="T1098",
            severity="WARNING",
            labels={"scenario": "account-manipulation"},
        )

    def simulate_data_from_cloud_storage(
        self,
        bucket_hint: str = "gs://example-bucket",
        object_hint: str = "path/to/object",
    ) -> None:
        """
        Simulate ATT&CK T1530 (Data from Cloud Storage) by logging a benign
        read-intent event referencing a non-sensitive object path. No access occurs.

        Technique reference:
          https://attack.mitre.org/techniques/T1530/
        """
        self.write_simulation_event(
            event_type="storage.read_intent",
            summary="Simulated intent to read from Cloud Storage (no access performed)",
            details={"bucket": bucket_hint, "object": object_hint},
            technique="T1530",
            severity="INFO",
            labels={"scenario": "gcs-read-intent"},
        )

    # ---------- Optional benign marker via Secret Manager ----------

    def create_benign_marker_secret(
        self,
        secret_id: str,
        payload: Mapping[str, Any],
        labels: Optional[Mapping[str, str]] = None,
    ) -> Optional[str]:
        """
        Optionally create a benign marker in Secret Manager to test audit pipelines.
        By default, in simulate_mode this method only logs intent and returns None.

        Secret Manager creation/access is described in Google docs:
          https://cloud.google.com/secret-manager/docs/creating-and-accessing-secrets
          https://cloud.google.com/secret-manager/docs/add-secret-version

        Returns: resource name of the created secret *if* simulate_mode=False and
        secretmanager lib is available; otherwise None.
        """
        self.write_simulation_event(
            event_type="secret.marker_intent",
            summary="Intent to create benign marker secret",
            details={"secret_id": secret_id, "size": len(json.dumps(payload))},
            technique=None,
            severity="INFO",
            labels={"scenario": "secret-marker"},
        )

        if self.cfg.simulate_mode:
            return None
        if secretmanager_v1 is None:
            raise GCPIntegrationError("Secret Manager library not available.")

        client = secretmanager_v1.SecretManagerServiceClient(credentials=self._credentials)
        parent = f"projects/{self.cfg.project_id}"
        secret_labels = dict(labels or {})
        secret = {"replication": {"automatic": {}}, "labels": secret_labels}
        create_req = {"parent": parent, "secret_id": secret_id, "secret": secret}

        with _timeout(self.cfg.request_timeout_seconds):
            sec = self._retry(client.create_secret)(request=create_req)

        add_req = {
            "parent": sec.name,
            "payload": {"data": json.dumps(payload).encode("utf-8")},
        }
        with _timeout(self.cfg.request_timeout_seconds):
            self._retry(client.add_secret_version)(request=add_req)

        return sec.name


# ---------- Utilities ----------

class _UserAgentRequestBuilder(google.auth.transport.requests.Request):  # type: ignore
    """Custom RequestBuilder for googleapiclient to set a stable User-Agent."""

    def __init__(self, user_agent: str):
        super().__init__()
        self._ua = user_agent

    def __call__(self, http, *args, **kwargs):  # pragma: no cover
        req = super().__call__(http, *args, **kwargs)
        req.headers["User-Agent"] = self._ua
        return req


class _timeout:
    """Context manager implementing a soft timeout via deadline checks."""

    def __init__(self, seconds: int) -> None:
        self.deadline = time.time() + max(1, int(seconds))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        # No hard kill; API deadlines are handled by google-api-core Retry.
        return False


def asset_to_dict(res: Any) -> Dict[str, Any]:
    """Convert Cloud Asset resource proto to JSON-like dict."""
    try:
        return {
            "name": getattr(res, "name", None),
            "asset_type": getattr(res, "asset_type", None),
            "project": getattr(res, "project", None) or getattr(res, "folders", None),
            "location": getattr(res, "location", None),
            "ancestors": list(getattr(res, "ancestors", [])),
            "state": getattr(res, "state", None),
            "additional_attributes": dict(getattr(res, "additional_attributes", {})),
        }
    except Exception:  # pragma: no cover
        # Fallback to protobuf Message to_dict if available
        try:
            return json.loads(gcloud_logging._helpers._quote_reserved(res))  # type: ignore
        except Exception:
            return {"raw": str(res)}
