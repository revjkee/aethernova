# zero_trust/adapters/cilium_adapter.py
from __future__ import annotations

import dataclasses
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union, Generator, Callable

try:
    import yaml  # PyYAML
except Exception as e:  # pragma: no cover
    yaml = None  # type: ignore

# Kubernetes client is an optional dependency. We fail gracefully with clear errors.
try:
    from kubernetes import client, config, watch
    from kubernetes.client import ApiClient
    from kubernetes.client.rest import ApiException
except Exception:
    client = None  # type: ignore
    config = None  # type: ignore
    watch = None   # type: ignore
    ApiClient = None  # type: ignore
    ApiException = Exception  # type: ignore


# =========================
# Exceptions
# =========================

class CiliumAdapterError(Exception):
    """Base exception for Cilium adapter."""


class DependencyNotInstalledError(CiliumAdapterError):
    """Raised when required dependency is missing."""


class PolicyValidationError(CiliumAdapterError):
    """Raised when policy validation fails."""


class KubernetesAPIError(CiliumAdapterError):
    """Raised for Kubernetes API related failures."""


class CommandExecutionError(CiliumAdapterError):
    """Raised when CLI command fails."""


class TimeoutExceededError(CiliumAdapterError):
    """Raised when an operation exceeds its timeout."""


# =========================
# Constants
# =========================

CILIUM_GROUP = "cilium.io"
CILIUM_VERSION = "v2"
CNP_PLURAL = "ciliumnetworkpolicies"
CCNP_PLURAL = "ciliumclusterwidenetworkpolicies"

DEFAULT_TIMEOUT = 30.0  # seconds
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF_BASE = 0.5  # seconds

# =========================
# Utilities
# =========================

def _ensure_yaml() -> None:
    if yaml is None:
        raise DependencyNotInstalledError(
            "PyYAML is required but not installed. Install with: pip install PyYAML"
        )


def _check_k8s_available() -> None:
    if client is None or config is None:
        raise DependencyNotInstalledError(
            "kubernetes python client is required. Install with: pip install kubernetes"
        )


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def _is_tool_available(binary: str) -> bool:
    return _which(binary) is not None


def _safe_subprocess_exec(
    args: List[str],
    timeout: float = DEFAULT_TIMEOUT,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, str]:
    """
    Execute a subprocess command safely and return (returncode, stdout, stderr).
    """
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            raise TimeoutExceededError(
                f"Command timed out after {timeout} seconds: {' '.join(args)}"
            )
        return proc.returncode, stdout, stderr
    except FileNotFoundError:
        raise DependencyNotInstalledError(
            f"Binary not found: {args[0]}. Please install it or adjust PATH."
        )
    except Exception as e:
        raise CommandExecutionError(f"Failed to execute command: {e}") from e


def _now_ms() -> int:
    return int(time.time() * 1000)


def _retry(
    retries: int = DEFAULT_RETRIES,
    backoff_base: float = DEFAULT_BACKOFF_BASE,
    retry_on: Tuple[type, ...] = (KubernetesAPIError, CommandExecutionError),
) -> Callable:
    """
    Simple retry decorator with exponential backoff.
    """

    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            attempt = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except retry_on as e:
                    if attempt >= retries:
                        raise
                    sleep_for = backoff_base * (2 ** attempt)
                    logger: logging.Logger = kwargs.get("logger") or getattr(args[0], "logger", logging.getLogger(__name__))  # type: ignore
                    logger.warning(
                        "Operation failed (%s). Retrying in %.2fs (%d/%d)...",
                        e.__class__.__name__,
                        sleep_for,
                        attempt + 1,
                        retries,
                    )
                    time.sleep(sleep_for)
                    attempt += 1

        return wrapper

    return decorator


# =========================
# Data models
# =========================

@dataclass(frozen=True)
class KubernetesConfig:
    """
    Configuration for connecting to Kubernetes.
    """
    kubeconfig: Optional[str] = None
    context: Optional[str] = None
    namespace: Optional[str] = None
    in_cluster: bool = False


@dataclass
class HubbleFilter:
    """
    Filters for hubble observe command.
    """
    namespace: Optional[str] = None
    pod: Optional[str] = None
    identity: Optional[int] = None
    verdict: Optional[str] = None  # "FORWARDED", "DROPPED", etc.
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    l4_port: Optional[int] = None
    l4_protocol: Optional[str] = None  # "TCP" or "UDP"
    since: Optional[str] = None  # e.g., "5m", "1h"
    follow: bool = False
    limit: Optional[int] = 100

    def to_args(self) -> List[str]:
        args: List[str] = ["hubble", "observe", "-o", "json"]
        if self.namespace:
            args += ["--namespace", self.namespace]
        if self.pod:
            args += ["--pod", self.pod]
        if self.identity is not None:
            args += ["--identity", str(self.identity)]
        if self.verdict:
            args += ["--verdict", self.verdict]
        if self.http_method:
            args += ["--http-method", self.http_method]
        if self.http_path:
            args += ["--http-path", self.http_path]
        if self.l4_port is not None:
            args += ["--port", str(self.l4_port)]
        if self.l4_protocol:
            args += ["--protocol", self.l4_protocol]
        if self.since:
            args += ["--since", self.since]
        if self.follow:
            args += ["--follow"]
        if self.limit is not None and not self.follow:
            args += ["--last", str(self.limit)]
        return args


# =========================
# Cilium Adapter
# =========================

class CiliumAdapter:
    """
    Production-grade adapter to manage CiliumNetworkPolicy and Clusterwide policies
    and to integrate Zero Trust network controls with Cilium.

    Features:
      - Create, read, patch, delete CNP/CCNP via Kubernetes CustomObjectsApi
      - Server-side dry-run validation
      - Optional CLI validation via 'cilium policy validate'
      - Optional 'hubble observe' integration for flow telemetry
      - Baseline Zero-Trust helpers (default deny, HTTP allowlists)
      - Robust logging, retries, and timeouts
    """

    def __init__(
        self,
        k8s: KubernetesConfig,
        logger: Optional[logging.Logger] = None,
        request_timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.k8s_cfg = k8s
        self.logger = logger or self._build_default_logger()
        self.request_timeout = request_timeout

        self._api_client: Optional[ApiClient] = None
        self._custom_api: Optional[client.CustomObjectsApi] = None  # type: ignore
        self._core_api: Optional[client.CoreV1Api] = None  # type: ignore

    @staticmethod
    def _build_default_logger() -> logging.Logger:
        logger = logging.getLogger("CiliumAdapter")
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

    # ------------- Kubernetes session management -------------

    def connect(self) -> None:
        """
        Initialize Kubernetes client based on provided configuration.
        """
        _check_k8s_available()

        try:
            if self.k8s_cfg.in_cluster:
                config.load_incluster_config()
            else:
                if self.k8s_cfg.kubeconfig:
                    config.load_kube_config(
                        config_file=self.k8s_cfg.kubeconfig,
                        context=self.k8s_cfg.context,
                    )
                else:
                    config.load_kube_config(context=self.k8s_cfg.context)
        except Exception as e:
            raise KubernetesAPIError(f"Failed to load Kubernetes config: {e}") from e

        try:
            self._api_client = ApiClient()
            self._custom_api = client.CustomObjectsApi(self._api_client)  # type: ignore
            self._core_api = client.CoreV1Api(self._api_client)  # type: ignore
        except Exception as e:
            raise KubernetesAPIError(f"Failed to initialize Kubernetes clients: {e}") from e

        self.logger.info("Connected to Kubernetes cluster. Context=%s", self.k8s_cfg.context)

    def close(self) -> None:
        """
        Close ApiClient resources.
        """
        if self._api_client:
            try:
                self._api_client.close()
            except Exception:
                pass
            finally:
                self._api_client = None

    # ------------- Policy helpers -------------

    @staticmethod
    def _detect_kind(policy: Dict[str, Any]) -> Tuple[str, bool]:
        """
        Return (kind, clusterwide).
        """
        kind = policy.get("kind")
        if kind == "CiliumNetworkPolicy":
            return CNP_PLURAL, False
        if kind == "CiliumClusterwideNetworkPolicy":
            return CCNP_PLURAL, True
        raise PolicyValidationError(f"Unsupported policy kind: {kind}")

    def _policy_target_namespace(self, policy: Dict[str, Any]) -> str:
        """
        Resolve target namespace for namespaced policies.
        """
        meta = policy.get("metadata") or {}
        ns = meta.get("namespace") or self.k8s_cfg.namespace
        if not ns:
            raise PolicyValidationError("Namespace is required for namespaced policies")
        return ns

    # ------------- Validation -------------

    def validate_server_dry_run(self, policy: Dict[str, Any]) -> None:
        """
        Use Kubernetes server-side dry-run to validate policy.
        """
        if not self._custom_api:
            raise KubernetesAPIError("CustomObjectsApi is not initialized. Call connect().")

        plural, clusterwide = self._detect_kind(policy)
        metadata = policy.get("metadata") or {}
        name = metadata.get("name")
        if not name:
            raise PolicyValidationError("metadata.name is required")

        try:
            if clusterwide:
                # For clusterwide, there is no namespace
                self._custom_api.create_cluster_custom_object(
                    group=CILIUM_GROUP,
                    version=CILIUM_VERSION,
                    plural=plural,
                    body=policy,
                    _request_timeout=self.request_timeout,
                    dry_run="All",
                )
            else:
                namespace = self._policy_target_namespace(policy)
                self._custom_api.create_namespaced_custom_object(
                    group=CILIUM_GROUP,
                    version=CILIUM_VERSION,
                    plural=plural,
                    namespace=namespace,
                    body=policy,
                    _request_timeout=self.request_timeout,
                    dry_run="All",
                )
        except ApiException as e:  # type: ignore
            # Admission controllers and schema errors appear here
            raise PolicyValidationError(
                f"Server-side validation failed: {getattr(e, 'body', str(e))}"
            ) from e
        except Exception as e:
            raise KubernetesAPIError(f"Dry-run validation failed: {e}") from e

    def validate_cli(self, policy_yaml: str) -> None:
        """
        Optionally use 'cilium policy validate -f -' to validate policy locally.
        Requires 'cilium' binary accessible in PATH.
        """
        if not _is_tool_available("cilium"):
            self.logger.debug("cilium CLI not available; skipping CLI validation.")
            return

        cmd = ["cilium", "policy", "validate", "-f", "-"]
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = proc.communicate(policy_yaml, timeout=self.request_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            raise TimeoutExceededError(
                f"cilium policy validate timed out after {self.request_timeout}s"
            )

        if proc.returncode != 0:
            raise PolicyValidationError(
                f"cilium validate failed (exit {proc.returncode}): {stderr.strip() or stdout.strip()}"
            )

    # ------------- CRUD operations -------------

    @_retry()
    def apply_policy(self, policy: Dict[str, Any], validate: bool = True) -> Dict[str, Any]:
        """
        Create or patch a Cilium policy. If the object exists, patch is applied.
        """
        if not self._custom_api:
            raise KubernetesAPIError("CustomObjectsApi is not initialized. Call connect().")

        _ensure_yaml()
        plural, clusterwide = self._detect_kind(policy)
        metadata = policy.get("metadata") or {}
        name = metadata.get("name")
        if not name:
            raise PolicyValidationError("metadata.name is required")

        # Optional validation
        if validate:
            # server-side dry-run
            self.validate_server_dry_run(policy)
            # CLI validation if available
            try:
                yaml_str = yaml.safe_dump(policy, sort_keys=False)  # type: ignore
                self.validate_cli(yaml_str)
            except DependencyNotInstalledError:
                pass

        try:
            if clusterwide:
                # Try patch; if not found, create
                try:
                    existing = self._custom_api.get_cluster_custom_object(
                        group=CILIUM_GROUP, version=CILIUM_VERSION, plural=plural, name=name
                    )
                    # strategic merge patch may not be supported; fall back to replace
                    patched = self._custom_api.patch_cluster_custom_object(
                        group=CILIUM_GROUP,
                        version=CILIUM_VERSION,
                        plural=plural,
                        name=name,
                        body=policy,
                        _request_timeout=self.request_timeout,
                    )
                    self.logger.info("Patched CCNP '%s'.", name)
                    return patched
                except ApiException as e:  # type: ignore
                    if getattr(e, "status", None) == 404:
                        created = self._custom_api.create_cluster_custom_object(
                            group=CILIUM_GROUP,
                            version=CILIUM_VERSION,
                            plural=plural,
                            body=policy,
                            _request_timeout=self.request_timeout,
                        )
                        self.logger.info("Created CCNP '%s'.", name)
                        return created
                    raise
            else:
                namespace = self._policy_target_namespace(policy)
                try:
                    existing = self._custom_api.get_namespaced_custom_object(
                        group=CILIUM_GROUP,
                        version=CILIUM_VERSION,
                        plural=plural,
                        namespace=namespace,
                        name=name,
                    )
                    patched = self._custom_api.patch_namespaced_custom_object(
                        group=CILIUM_GROUP,
                        version=CILIUM_VERSION,
                        plural=plural,
                        namespace=namespace,
                        name=name,
                        body=policy,
                        _request_timeout=self.request_timeout,
                    )
                    self.logger.info("Patched CNP '%s' in ns '%s'.", name, namespace)
                    return patched
                except ApiException as e:  # type: ignore
                    if getattr(e, "status", None) == 404:
                        created = self._custom_api.create_namespaced_custom_object(
                            group=CILIUM_GROUP,
                            version=CILIUM_VERSION,
                            plural=plural,
                            namespace=namespace,
                            body=policy,
                            _request_timeout=self.request_timeout,
                        )
                        self.logger.info("Created CNP '%s' in ns '%s'.", name, namespace)
                        return created
                    raise
        except ApiException as e:  # type: ignore
            raise KubernetesAPIError(f"Kubernetes API error: {getattr(e, 'body', str(e))}") from e
        except Exception as e:
            raise KubernetesAPIError(f"Failed to apply policy: {e}") from e

    @_retry()
    def delete_policy(self, name: str, namespaced: bool = True, namespace: Optional[str] = None) -> None:
        """
        Delete a policy by name.
        """
        if not self._custom_api:
            raise KubernetesAPIError("CustomObjectsApi is not initialized. Call connect().")

        try:
            if namespaced:
                ns = namespace or self.k8s_cfg.namespace
                if not ns:
                    raise PolicyValidationError("Namespace must be provided to delete namespaced policy")
                self._custom_api.delete_namespaced_custom_object(
                    group=CILIUM_GROUP,
                    version=CILIUM_VERSION,
                    plural=CNP_PLURAL,
                    namespace=ns,
                    name=name,
                    _request_timeout=self.request_timeout,
                )
                self.logger.info("Deleted CNP '%s' in ns '%s'.", name, ns)
            else:
                self._custom_api.delete_cluster_custom_object(
                    group=CILIUM_GROUP,
                    version=CILIUM_VERSION,
                    plural=CCNP_PLURAL,
                    name=name,
                    _request_timeout=self.request_timeout,
                )
                self.logger.info("Deleted CCNP '%s'.", name)
        except ApiException as e:  # type: ignore
            if getattr(e, "status", None) == 404:
                self.logger.info("Policy '%s' not found; nothing to delete.", name)
                return
            raise KubernetesAPIError(f"Delete failed: {getattr(e, 'body', str(e))}") from e

    def get_policy(self, name: str, namespaced: bool = True, namespace: Optional[str] = None) -> Dict[str, Any]:
        """
        Get a policy by name.
        """
        if not self._custom_api:
            raise KubernetesAPIError("CustomObjectsApi is not initialized. Call connect().")
        try:
            if namespaced:
                ns = namespace or self.k8s_cfg.namespace
                if not ns:
                    raise PolicyValidationError("Namespace is required")
                return self._custom_api.get_namespaced_custom_object(  # type: ignore
                    group=CILIUM_GROUP,
                    version=CILIUM_VERSION,
                    plural=CNP_PLURAL,
                    namespace=ns,
                    name=name,
                )
            return self._custom_api.get_cluster_custom_object(  # type: ignore
                group=CILIUM_GROUP,
                version=CILIUM_VERSION,
                plural=CCNP_PLURAL,
                name=name,
            )
        except ApiException as e:  # type: ignore
            if getattr(e, "status", None) == 404:
                raise KubernetesAPIError(f"Policy '{name}' not found") from e
            raise KubernetesAPIError(f"Get failed: {getattr(e, 'body', str(e))}") from e

    def list_policies(self, namespace: Optional[str] = None) -> Dict[str, Any]:
        """
        List policies in a namespace or clusterwide.
        """
        if not self._custom_api:
            raise KubernetesAPIError("CustomObjectsApi is not initialized. Call connect().")
        try:
            if namespace:
                return self._custom_api.list_namespaced_custom_object(  # type: ignore
                    group=CILIUM_GROUP,
                    version=CILIUM_VERSION,
                    plural=CNP_PLURAL,
                    namespace=namespace,
                )
            # clusterwide
            return self._custom_api.list_cluster_custom_object(  # type: ignore
                group=CILIUM_GROUP,
                version=CILIUM_VERSION,
                plural=CCNP_PLURAL,
            )
        except ApiException as e:  # type: ignore
            raise KubernetesAPIError(f"List failed: {getattr(e, 'body', str(e))}") from e

    # ------------- Policy loaders -------------

    @staticmethod
    def load_policies_from_path(path: Union[str, Path]) -> List[Dict[str, Any]]:
        """
        Load one or multiple policies from a YAML or a directory of YAMLs.
        """
        _ensure_yaml()
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Path not found: {p}")

        docs: List[Dict[str, Any]] = []

        def _load_file(fp: Path) -> None:
            if fp.suffix.lower() not in {".yml", ".yaml"}:
                return
            with fp.open("r", encoding="utf-8") as f:
                for doc in yaml.safe_load_all(f):  # type: ignore
                    if not isinstance(doc, dict):
                        continue
                    docs.append(doc)

        if p.is_file():
            _load_file(p)
        else:
            for fp in sorted(p.rglob("*")):
                if fp.is_file():
                    _load_file(fp)

        if not docs:
            raise PolicyValidationError(f"No policy documents found in: {p}")

        return docs

    # ------------- Baseline Zero Trust policies -------------

    @staticmethod
    def build_default_deny(namespace: str, name: str = "ztp-default-deny") -> Dict[str, Any]:
        """
        Build a baseline default-deny policy for a namespace.
        Blocks all ingress and egress unless explicitly allowed.
        """
        return {
            "apiVersion": f"{CILIUM_GROUP}/{CILIUM_VERSION}",
            "kind": "CiliumNetworkPolicy",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {
                "endpointSelector": {"matchLabels": {}},
                "ingress": [],
                "egress": [],
            },
        }

    @staticmethod
    def build_http_allowlist(
        namespace: str,
        name: str,
        pod_selector: Dict[str, Any],
        http_rules: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Build an L7 HTTP allowlist policy using Cilium HTTP rules.
        http_rules example:
          [{"method": "GET", "path": "/healthz"}, {"method": "POST", "path": "/login"}]
        """
        l7_rules = [{"method": r["method"], "path": r["path"]} for r in http_rules]

        return {
            "apiVersion": f"{CILIUM_GROUP}/{CILIUM_VERSION}",
            "kind": "CiliumNetworkPolicy",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {
                "endpointSelector": {"matchLabels": pod_selector},
                "ingress": [
                    {
                        "fromEntities": ["all"],
                        "toPorts": [
                            {"ports": [{"port": "80", "protocol": "TCP"}], "rules": {"http": l7_rules}},
                            {"ports": [{"port": "443", "protocol": "TCP"}], "rules": {"http": l7_rules}},
                        ],
                    }
                ],
            },
        }

    # ------------- Cilium status and identities -------------

    def status(self) -> Dict[str, Any]:
        """
        Retrieve Cilium status using Kubernetes API and optionally cilium CLI if present.
        """
        status: Dict[str, Any] = {"time": _now_ms(), "components": {}}

        if self._core_api:
            try:
                pods = self._core_api.list_pod_for_all_namespaces(  # type: ignore
                    label_selector="k8s-app=cilium",
                    _request_timeout=self.request_timeout,
                )
                ready = []
                not_ready = []
                for p in pods.items:
                    cs_list = getattr(p.status, "container_statuses", None) or []
                    is_ready = all(getattr(cs, "ready", False) for cs in cs_list)
                    (ready if is_ready else not_ready).append(p.metadata.name)  # type: ignore
                status["components"]["cilium_pods_ready"] = ready
                status["components"]["cilium_pods_not_ready"] = not_ready
            except ApiException as e:  # type: ignore
                self.logger.warning("Failed to list cilium pods: %s", getattr(e, "body", str(e)))

        if _is_tool_available("cilium"):
            # Best-effort: cilium status
            try:
                code, out, err = _safe_subprocess_exec(["cilium", "status", "--verbose"], timeout=self.request_timeout)
                status["cli_status_code"] = code
                status["cli_status"] = out.strip() or err.strip()
            except Exception as e:
                status["cli_error"] = str(e)

        return status

    def list_identities(self, limit: int = 200) -> List[Dict[str, Any]]:
        """
        List Cilium identities if 'cilium' CLI is available.
        """
        if not _is_tool_available("cilium"):
            raise DependencyNotInstalledError("cilium CLI is not available")

        code, out, err = _safe_subprocess_exec(["cilium", "identity", "list", "-o", "json"], timeout=self.request_timeout)
        if code != 0:
            raise CommandExecutionError(err or out)

        try:
            identities = json.loads(out)
        except json.JSONDecodeError as e:
            raise CommandExecutionError(f"Invalid JSON from cilium identity list: {e}") from e

        if isinstance(identities, list):
            return identities[:limit]
        return identities  # type: ignore

    # ------------- Hubble integration -------------

    def observe_flows(self, filt: HubbleFilter) -> Generator[Dict[str, Any], None, None]:
        """
        Stream network flows using 'hubble observe -o json'.
        In follow mode yields indefinitely; otherwise yields up to filt.limit events.
        """
        if not _is_tool_available("hubble"):
            raise DependencyNotInstalledError("hubble CLI is not available")

        args = filt.to_args()
        self.logger.debug("Executing: %s", " ".join(args))

        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        yielded = 0
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                    yielded += 1
                    yield evt
                    if not filt.follow and filt.limit is not None and yielded >= filt.limit:
                        break
                except json.JSONDecodeError:
                    # Skip non-JSON lines
                    continue
        finally:
            try:
                proc.terminate()
            except Exception:
                pass

    # ------------- Async wrapper -------------

    # The async wrapper uses a thread pool for blocking I/O to avoid forcing async deps.
    # This provides ergonomic integration with async-only codebases.

    def _run_blocking(self, func: Callable, *args, **kwargs):
        return func(*args, **kwargs)


class AsyncCiliumAdapter:
    """
    Async wrapper over CiliumAdapter using thread executors for blocking calls.
    """

    def __init__(self, adapter: CiliumAdapter) -> None:
        import concurrent.futures
        import asyncio

        self._adapter = adapter
        self._loop = asyncio.get_event_loop()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4)

    # ------------- lifecycle -------------

    async def connect(self) -> None:
        await self._loop.run_in_executor(self._executor, self._adapter.connect)

    async def close(self) -> None:
        await self._loop.run_in_executor(self._executor, self._adapter.close)

    # ------------- CRUD -------------

    async def apply_policy(self, policy: Dict[str, Any], validate: bool = True) -> Dict[str, Any]:
        return await self._loop.run_in_executor(self._executor, self._adapter.apply_policy, policy, validate)

    async def delete_policy(self, name: str, namespaced: bool = True, namespace: Optional[str] = None) -> None:
        return await self._loop.run_in_executor(self._executor, self._adapter.delete_policy, name, namespaced, namespace)

    async def get_policy(self, name: str, namespaced: bool = True, namespace: Optional[str] = None) -> Dict[str, Any]:
        return await self._loop.run_in_executor(self._executor, self._adapter.get_policy, name, namespaced, namespace)

    async def list_policies(self, namespace: Optional[str] = None) -> Dict[str, Any]:
        return await self._loop.run_in_executor(self._executor, self._adapter.list_policies, namespace)

    # ------------- loaders -------------

    async def load_policies_from_path(self, path: Union[str, Path]) -> List[Dict[str, Any]]:
        return await self._loop.run_in_executor(self._executor, self._adapter.load_policies_from_path, path)

    # ------------- helpers -------------

    async def validate_server_dry_run(self, policy: Dict[str, Any]) -> None:
        return await self._loop.run_in_executor(self._executor, self._adapter.validate_server_dry_run, policy)

    async def validate_cli(self, policy_yaml: str) -> None:
        return await self._loop.run_in_executor(self._executor, self._adapter.validate_cli, policy_yaml)

    async def status(self) -> Dict[str, Any]:
        return await self._loop.run_in_executor(self._executor, self._adapter.status)

    async def list_identities(self, limit: int = 200) -> List[Dict[str, Any]]:
        return await self._loop.run_in_executor(self._executor, self._adapter.list_identities, limit)

    async def build_default_deny(self, namespace: str, name: str = "ztp-default-deny") -> Dict[str, Any]:
        # static method passthrough
        return CiliumAdapter.build_default_deny(namespace, name)

    async def build_http_allowlist(
        self,
        namespace: str,
        name: str,
        pod_selector: Dict[str, Any],
        http_rules: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        return CiliumAdapter.build_http_allowlist(namespace, name, pod_selector, http_rules)

    async def observe_flows(self, filt: HubbleFilter) -> List[Dict[str, Any]]:
        """
        Collect flows into a list (bounded if filt.limit is set and follow=False).
        """
        def _collect() -> List[Dict[str, Any]]:
            events: List[Dict[str, Any]] = []
            for evt in self._adapter.observe_flows(filt):
                events.append(evt)
            return events

        return await self._loop.run_in_executor(self._executor, _collect)
