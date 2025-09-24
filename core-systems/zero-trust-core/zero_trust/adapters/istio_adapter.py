# -*- coding: utf-8 -*-
"""
Istio Adapter — промышленный адаптер Zero-Trust для работы с Istio CRDs через Kubernetes API.

Возможности:
- Серверный apply (Server-Side Apply) для AuthorizationPolicy, PeerAuthentication,
  RequestAuthentication, DestinationRule, Sidecar.
- Асинхронный интерфейс с безопасным fallback на sync-клиент (через ThreadPoolExecutor).
- Dry-run, идемпотентность (аннотация с хэшем спецификации), строгая валидация входных правил.
- Экспоненциальные ретраи с джиттером, настраиваемые таймауты и fieldManager.
- Структурированные JSON-логи, безопасная нормализация имён/лейблов/аннотаций.

Зависимости (рекомендуемые):
    pip install kubernetes kubernetes-asyncio

Поддерживаемые Kind'ы:
- security.istio.io/v1: AuthorizationPolicy, PeerAuthentication, RequestAuthentication
- networking.istio.io/v1beta1|v1: DestinationRule, Sidecar

Автор: Aethernova / NeuroCity Zero-Trust Core
Лицензия: Apache-2.0
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import dataclasses
import functools
import hashlib
import json
import logging
import os
import random
import re
import time
from typing import Any, Dict, Iterable, List, Literal, Mapping, Optional, Tuple, Union

# Попытка подхватить async-клиент; при отсутствии — используем sync через executor.
_ASYNC_AVAILABLE = False
_SYNC_AVAILABLE = False
try:
    import kubernetes_asyncio  # type: ignore
    from kubernetes_asyncio import client as k8s_aio_client  # type: ignore
    from kubernetes_asyncio import config as k8s_aio_config  # type: ignore

    _ASYNC_AVAILABLE = True
except Exception:
    _ASYNC_AVAILABLE = False

try:
    import kubernetes  # type: ignore
    from kubernetes import client as k8s_client  # type: ignore
    from kubernetes import config as k8s_config  # type: ignore
    from kubernetes.client.exceptions import ApiException as K8sApiException  # type: ignore

    _SYNC_AVAILABLE = True
except Exception:
    _SYNC_AVAILABLE = False
    K8sApiException = Exception  # fallback

# --------------------------- Логирование ---------------------------


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "level": record.levelname,
            "ts": int(record.created * 1000),
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            payload.update(record.extra)  # type: ignore
        return json.dumps(payload, ensure_ascii=False)


def _setup_logger(name: str = "istio_adapter", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
    logger.propagate = False
    logger.setLevel(level)
    return logger


log = _setup_logger()

# --------------------------- Исключения ---------------------------


class IstioAdapterError(Exception):
    pass


class KubernetesClientUnavailable(IstioAdapterError):
    pass


class ValidationError(IstioAdapterError):
    pass


class ApplyError(IstioAdapterError):
    pass


class NotFoundError(IstioAdapterError):
    pass


# --------------------------- Конфигурация ---------------------------


@dataclasses.dataclass(frozen=True)
class IstioAdapterConfig:
    namespace: str = "default"
    in_cluster: bool = False
    kubeconfig_path: Optional[str] = None
    context: Optional[str] = None
    verify_ssl: bool = True
    request_timeout_seconds: int = 15
    field_manager: str = "zero-trust-core"
    max_retries: int = 5
    base_backoff_seconds: float = 0.5
    max_backoff_seconds: float = 8.0
    dry_run: bool = False
    force_apply: bool = True
    use_async_client: Optional[bool] = None  # None=auto, True=aio, False=sync


# --------------------------- Хелперы ---------------------------


_name_re = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


def _dns_label(name: str, *, max_len: int = 63) -> str:
    """
    Приводит имя к DNS-1123 label с обрезкой.
    """
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9-]", "-", name)
    name = re.sub(r"-{2,}", "-", name)
    name = name.strip("-")
    if not name:
        raise ValidationError("Имя ресурса пустое после нормализации.")
    if len(name) > max_len:
        name = name[:max_len].rstrip("-")
    if not _name_re.match(name):
        raise ValidationError(f"Имя '{name}' не соответствует DNS-1123.")
    return name


def _safe_labels(labels: Optional[Mapping[str, str]]) -> Dict[str, str]:
    if not labels:
        return {}
    out: Dict[str, str] = {}
    for k, v in labels.items():
        k = re.sub(r"[^a-z0-9A-Z./-]", "-", str(k)).strip(".-")
        v = re.sub(r"[^a-z0-9A-Z./_-]", "-", str(v)).strip(".-")
        if k and v:
            out[k] = v
    return out


def _safe_annotations(ann: Optional[Mapping[str, str]]) -> Dict[str, str]:
    if not ann:
        return {}
    out: Dict[str, str] = {}
    for k, v in ann.items():
        out[str(k)] = str(v)
    return out


def _hash_spec(obj: Mapping[str, Any]) -> str:
    m = hashlib.sha256()
    m.update(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return m.hexdigest()


def _parse_api_version(api_version: str) -> Tuple[str, str]:
    if "/" not in api_version:
        return "", api_version
    group, version = api_version.split("/", 1)
    return group, version


# kind -> (group, version, plural)
_KIND_MAP: Dict[str, Tuple[str, str, str]] = {
    "AuthorizationPolicy": ("security.istio.io", "v1", "authorizationpolicies"),
    "PeerAuthentication": ("security.istio.io", "v1", "peerauthentications"),
    "RequestAuthentication": ("security.istio.io", "v1", "requestauthentications"),
    "DestinationRule": ("networking.istio.io", "v1beta1", "destinationrules"),
    "Sidecar": ("networking.istio.io", "v1beta1", "sidecars"),
}


def _kind_to_gvk_plural(kind: str) -> Tuple[str, str, str]:
    if kind not in _KIND_MAP:
        raise ValidationError(f"Неподдерживаемый Kind: {kind}")
    return _KIND_MAP[kind]


def _sleep_jittered(base: float, attempt: int, max_backoff: float) -> float:
    expo = min(max_backoff, base * (2 ** (attempt - 1)))
    return random.uniform(expo / 2, expo)


# --------------------------- Валидация правил AuthorizationPolicy ---------------------------

OperationKey = Literal["hosts", "methods", "ports", "paths"]
WhenKey = Literal[
    "key", "values"
]  # key: request.auth.claims[iss], source.principal, request.headers[x], etc.


@dataclasses.dataclass(frozen=True)
class SourceRule:
    principals: Optional[List[str]] = None
    requestPrincipals: Optional[List[str]] = None
    namespaces: Optional[List[str]] = None
    ipBlocks: Optional[List[str]] = None
    notPrincipals: Optional[List[str]] = None


@dataclasses.dataclass(frozen=True)
class OperationRule:
    hosts: Optional[List[str]] = None
    methods: Optional[List[str]] = None
    ports: Optional[List[Union[str, int]]] = None
    paths: Optional[List[str]] = None


@dataclasses.dataclass(frozen=True)
class WhenCondition:
    key: str
    values: List[str]


@dataclasses.dataclass(frozen=True)
class AuthorizationRule:
    source: Optional[SourceRule] = None
    operation: Optional[OperationRule] = None
    when: Optional[List[WhenCondition]] = None


def _validate_authz_rules(rules: Iterable[AuthorizationRule]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in rules:
        rule: Dict[str, Any] = {}
        if r.source:
            src: Dict[str, Any] = {}
            for fld in ("principals", "requestPrincipals", "namespaces", "ipBlocks", "notPrincipals"):
                val = getattr(r.source, fld)
                if val:
                    if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
                        raise ValidationError(f"Source.{fld} должен быть списком строк.")
                    src[fld] = val
            if src:
                rule["from"] = [{"source": src}]
        if r.operation:
            op: Dict[str, Any] = {}
            if r.operation.hosts:
                op["hosts"] = r.operation.hosts
            if r.operation.methods:
                op["methods"] = r.operation.methods
            if r.operation.ports:
                # Приведение к строкам — Istio допускает int/str, но унифицируем
                op["ports"] = [str(p) for p in r.operation.ports]
            if r.operation.paths:
                op["paths"] = r.operation.paths
            if op:
                rule["to"] = [{"operation": op}]
        if r.when:
            conds: List[Dict[str, Any]] = []
            for w in r.when:
                if not w.key or not isinstance(w.values, list) or not all(isinstance(x, str) for x in w.values):
                    raise ValidationError("WhenCondition должен иметь key и список строк values.")
                conds.append({"key": w.key, "values": w.values})
            if conds:
                rule["when"] = conds
        if not rule:
            raise ValidationError("Пустое правило AuthorizationRule недопустимо.")
        out.append(rule)
    if not out:
        raise ValidationError("Список правил AuthorizationPolicy пуст.")
    return out


# --------------------------- Слой Kubernetes API ---------------------------


class _KubeClient:
    """
    Унифицированный слой доступа к Kubernetes CustomObjectsApi.
    Предпочитает kubernetes_asyncio; при отсутствии — sync через executor.
    """

    def __init__(self, cfg: IstioAdapterConfig):
        self.cfg = cfg
        self._use_async = cfg.use_async_client if cfg.use_async_client is not None else _ASYNC_AVAILABLE
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._aio_api = None
        self._sync_api = None

    async def startup(self) -> None:
        if self._use_async:
            if not _ASYNC_AVAILABLE:
                raise KubernetesClientUnavailable("kubernetes_asyncio недоступен.")
            # Загрузка конфигурации
            if self.cfg.in_cluster:
                await k8s_aio_config.load_incluster_config()  # type: ignore
            else:
                await k8s_aio_config.load_kube_config(
                    config_file=self.cfg.kubeconfig_path, context=self.cfg.context
                )  # type: ignore
            # Создадим API-клиента
            api_client = k8s_aio_client.ApiClient()  # type: ignore
            self._aio_api = k8s_aio_client.CustomObjectsApi(api_client)  # type: ignore
        else:
            if not _SYNC_AVAILABLE:
                raise KubernetesClientUnavailable("kubernetes (sync) недоступен.")
            if self.cfg.in_cluster:
                k8s_config.load_incluster_config()  # type: ignore
            else:
                k8s_config.load_kube_config(config_file=self.cfg.kubeconfig_path, context=self.cfg.context)  # type: ignore
            self._sync_api = k8s_client.CustomObjectsApi()  # type: ignore
            self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="k8s-sync")

    async def shutdown(self) -> None:
        if self._use_async and self._aio_api is not None:
            with contextlib.suppress(Exception):
                await self._aio_api.api_client.rest_client.pool_manager.close()  # type: ignore
        if self._executor:
            self._executor.shutdown(wait=True, cancel_futures=True)

    # --- Низкоуровневые операции над CustomObjects ---

    async def get(self, group: str, version: str, namespace: str, plural: str, name: str) -> Dict[str, Any]:
        if self._use_async:
            return await self._aio_api.get_namespaced_custom_object(  # type: ignore
                group=group, version=version, namespace=namespace, plural=plural, name=name
            )
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            functools.partial(
                self._sync_api.get_namespaced_custom_object,  # type: ignore
                group=group,
                version=version,
                namespace=namespace,
                plural=plural,
                name=name,
            ),
        )

    async def list(self, group: str, version: str, namespace: str, plural: str, label_selector: Optional[str] = None) -> Dict[str, Any]:
        if self._use_async:
            return await self._aio_api.list_namespaced_custom_object(  # type: ignore
                group=group, version=version, namespace=namespace, plural=plural, label_selector=label_selector
            )
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            functools.partial(
                self._sync_api.list_namespaced_custom_object,  # type: ignore
                group=group,
                version=version,
                namespace=namespace,
                plural=plural,
                label_selector=label_selector,
            ),
        )

    async def delete(self, group: str, version: str, namespace: str, plural: str, name: str) -> Dict[str, Any]:
        if self._use_async:
            return await self._aio_api.delete_namespaced_custom_object(  # type: ignore
                group=group, version=version, namespace=namespace, plural=plural, name=name
            )
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            functools.partial(
                self._sync_api.delete_namespaced_custom_object,  # type: ignore
                group=group,
                version=version,
                namespace=namespace,
                plural=plural,
                name=name,
            ),
        )

    async def server_side_apply(
        self,
        group: str,
        version: str,
        namespace: str,
        plural: str,
        name: str,
        body: Mapping[str, Any],
        *,
        field_manager: str,
        force: bool,
        dry_run: bool,
        timeout_seconds: int,
    ) -> Dict[str, Any]:
        """
        SSA через PATCH c content-type=application/apply-patch+yaml.
        """
        kwargs = dict(
            group=group,
            version=version,
            namespace=namespace,
            plural=plural,
            name=name,
            body=body,
            field_manager=field_manager,
            force=force,
            _request_timeout=timeout_seconds,
            _content_type="application/apply-patch+yaml",
            dry_run="All" if dry_run else None,
        )
        if self._use_async:
            return await self._aio_api.patch_namespaced_custom_object(**kwargs)  # type: ignore
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            functools.partial(self._sync_api.patch_namespaced_custom_object, **kwargs),  # type: ignore
        )


# --------------------------- IstioAdapter ---------------------------


class IstioAdapter:
    """
    Высокоуровневый адаптер для управления Istio-политиками.
    """

    SPEC_HASH_ANNOTATION = "aethernova.io/spec-hash"

    def __init__(self, cfg: Optional[IstioAdapterConfig] = None):
        self.cfg = cfg or IstioAdapterConfig()
        self._client = _KubeClient(self.cfg)
        self._started = False

    async def __aenter__(self) -> "IstioAdapter":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()

    async def start(self) -> None:
        if self._started:
            return
        await self._client.startup()
        self._started = True
        log.info("IstioAdapter started", extra={"extra": {"namespace": self.cfg.namespace, "async": True}})

    async def stop(self) -> None:
        if not self._started:
            return
        await self._client.shutdown()
        self._started = False
        log.info("IstioAdapter stopped")

    # ---------------------- Публичные методы: AuthorizationPolicy ----------------------

    async def apply_authorization_policy(
        self,
        *,
        name: str,
        namespace: Optional[str] = None,
        action: Literal["ALLOW", "DENY"] = "ALLOW",
        selector_labels: Optional[Mapping[str, str]] = None,
        rules: Iterable[AuthorizationRule],
        annotations: Optional[Mapping[str, str]] = None,
        labels: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        ns = namespace or self.cfg.namespace
        name = _dns_label(name)
        rules_list = _validate_authz_rules(rules)
        metadata = self._build_metadata(name, ns, labels, annotations)

        spec: Dict[str, Any] = {"action": action, "rules": rules_list}
        if selector_labels:
            spec["selector"] = {"matchLabels": _safe_labels(selector_labels)}

        manifest = self._manifest("AuthorizationPolicy", metadata, spec)

        return await self._apply_with_idempotency(manifest)

    async def delete_authorization_policy(self, *, name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        return await self._delete(kind="AuthorizationPolicy", name=name, namespace=namespace)

    async def list_authorization_policies(
        self, *, namespace: Optional[str] = None, label_selector: Optional[str] = None
    ) -> Dict[str, Any]:
        return await self._list(kind="AuthorizationPolicy", namespace=namespace, label_selector=label_selector)

    # ---------------------- Публичные методы: PeerAuthentication ----------------------

    async def apply_peer_authentication(
        self,
        *,
        name: str,
        namespace: Optional[str] = None,
        mtls_mode: Literal["STRICT", "PERMISSIVE", "DISABLE"] = "STRICT",
        selector_labels: Optional[Mapping[str, str]] = None,
        annotations: Optional[Mapping[str, str]] = None,
        labels: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        ns = namespace or self.cfg.namespace
        name = _dns_label(name)
        metadata = self._build_metadata(name, ns, labels, annotations)

        spec: Dict[str, Any] = {"mtls": {"mode": mtls_mode}}
        if selector_labels:
            spec["selector"] = {"matchLabels": _safe_labels(selector_labels)}

        manifest = self._manifest("PeerAuthentication", metadata, spec)
        return await self._apply_with_idempotency(manifest)

    async def delete_peer_authentication(self, *, name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        return await self._delete(kind="PeerAuthentication", name=name, namespace=namespace)

    # ---------------------- Публичные методы: RequestAuthentication ----------------------

    async def apply_request_authentication(
        self,
        *,
        name: str,
        namespace: Optional[str] = None,
        jwt_issuer: str,
        jwks_uri: str,
        audiences: Optional[List[str]] = None,
        selector_labels: Optional[Mapping[str, str]] = None,
        from_headers: Optional[List[Dict[str, str]]] = None,
        from_params: Optional[List[str]] = None,
        annotations: Optional[Mapping[str, str]] = None,
        labels: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        ns = namespace or self.cfg.namespace
        name = _dns_label(name)
        metadata = self._build_metadata(name, ns, labels, annotations)

        jwt_rule: Dict[str, Any] = {"issuer": jwt_issuer, "jwksUri": jwks_uri}
        if audiences:
            jwt_rule["audiences"] = audiences
        if from_headers:
            jwt_rule["fromHeaders"] = from_headers  # [{"name":"Authorization","prefix":"Bearer "}]
        if from_params:
            jwt_rule["fromParams"] = from_params

        spec: Dict[str, Any] = {"jwtRules": [jwt_rule]}
        if selector_labels:
            spec["selector"] = {"matchLabels": _safe_labels(selector_labels)}

        manifest = self._manifest("RequestAuthentication", metadata, spec)
        return await self._apply_with_idempotency(manifest)

    async def delete_request_authentication(self, *, name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        return await self._delete(kind="RequestAuthentication", name=name, namespace=namespace)

    # ---------------------- Публичные методы: DestinationRule ----------------------

    async def apply_destination_rule_tls_mutual(
        self,
        *,
        name: str,
        namespace: Optional[str] = None,
        host: str,
        sni: Optional[str] = None,
        labels: Optional[Mapping[str, str]] = None,
        annotations: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Создаёт DestinationRule с TLS ISTIO_MUTUAL (mTLS внутри mesh).
        """
        ns = namespace or self.cfg.namespace
        name = _dns_label(name)
        metadata = self._build_metadata(name, ns, labels, annotations)

        traffic_policy = {"tls": {"mode": "ISTIO_MUTUAL"}}
        if sni:
            traffic_policy["tls"]["sni"] = sni

        spec = {"host": host, "trafficPolicy": traffic_policy}
        manifest = self._manifest("DestinationRule", metadata, spec)
        return await self._apply_with_idempotency(manifest)

    async def delete_destination_rule(self, *, name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        return await self._delete(kind="DestinationRule", name=name, namespace=namespace)

    # ---------------------- Публичные методы: Sidecar ----------------------

    async def apply_sidecar_egress_whitelist(
        self,
        *,
        name: str,
        namespace: Optional[str] = None,
        selector_labels: Optional[Mapping[str, str]] = None,
        egress_hosts: Optional[List[str]] = None,
        capture_mode: Literal["DEFAULT", "IPTABLES", "NONE"] = "DEFAULT",
        outbound_traffic_policy_mode: Literal["ALLOW_ANY", "REGISTRY_ONLY"] = "REGISTRY_ONLY",
        labels: Optional[Mapping[str, str]] = None,
        annotations: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Sidecar с ограничением egress (регистровые/whitelist хосты).
        """
        ns = namespace or self.cfg.namespace
        name = _dns_label(name)
        metadata = self._build_metadata(name, ns, labels, annotations)

        spec: Dict[str, Any] = {
            "outboundTrafficPolicy": {"mode": outbound_traffic_policy_mode},
            "egress": [
                {
                    "captureMode": capture_mode,
                    "hosts": egress_hosts or ["./*"],  # по умолчанию — собственный ns
                }
            ],
        }
        if selector_labels:
            spec["workloadSelector"] = {"labels": _safe_labels(selector_labels)}

        manifest = self._manifest("Sidecar", metadata, spec)
        return await self._apply_with_idempotency(manifest)

    async def delete_sidecar(self, *, name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        return await self._delete(kind="Sidecar", name=name, namespace=namespace)

    # ---------------------- Общие CRUD ----------------------

    async def get(self, *, kind: str, name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        ns = namespace or self.cfg.namespace
        group, version, plural = _kind_to_gvk_plural(kind)
        try:
            return await self._client.get(group, version, ns, plural, _dns_label(name))
        except K8sApiException as e:  # type: ignore
            if getattr(e, "status", None) == 404:
                raise NotFoundError(f"{kind}/{name} не найден") from e
            raise

    async def _list(self, *, kind: str, namespace: Optional[str], label_selector: Optional[str]) -> Dict[str, Any]:
        ns = namespace or self.cfg.namespace
        group, version, plural = _kind_to_gvk_plural(kind)
        return await self._client.list(group, version, ns, plural, label_selector)

    async def _delete(self, *, kind: str, name: str, namespace: Optional[str]) -> Dict[str, Any]:
        ns = namespace or self.cfg.namespace
        group, version, plural = _kind_to_gvk_plural(kind)
        name = _dns_label(name)
        attempts = 0
        while True:
            attempts += 1
            try:
                res = await self._client.delete(group, version, ns, plural, name)
                log.info("Deleted", extra={"extra": {"kind": kind, "name": name, "namespace": ns}})
                return res
            except K8sApiException as e:  # type: ignore
                if getattr(e, "status", None) == 404:
                    raise NotFoundError(f"{kind}/{name} не найден") from e
                if attempts >= self.cfg.max_retries:
                    raise
                await asyncio.sleep(_sleep_jittered(self.cfg.base_backoff_seconds, attempts, self.cfg.max_backoff_seconds))

    # ---------------------- Внутренние билдеры ----------------------

    def _build_metadata(
        self,
        name: str,
        namespace: str,
        labels: Optional[Mapping[str, str]],
        annotations: Optional[Mapping[str, str]],
    ) -> Dict[str, Any]:
        meta = {
            "name": _dns_label(name),
            "namespace": _dns_label(namespace),
            "labels": _safe_labels(labels),
            "annotations": _safe_annotations(annotations),
        }
        # уберём пустые
        meta["labels"] = {k: v for k, v in meta["labels"].items() if v}
        meta["annotations"] = {k: v for k, v in meta["annotations"].items() if v}
        return meta

    def _manifest(self, kind: str, metadata: Mapping[str, Any], spec: Mapping[str, Any]) -> Dict[str, Any]:
        group, version, _ = _kind_to_gvk_plural(kind)
        api_version = f"{group}/{version}" if group else version
        # Чистим пустые поля в spec
        cleaned_spec = _purge_empty(spec)
        return {
            "apiVersion": api_version,
            "kind": kind,
            "metadata": dict(metadata),
            "spec": cleaned_spec,
        }

    async def _apply_with_idempotency(self, manifest: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Идемпотентный серверный apply с аннотацией хэша и ретраями.
        """
        kind: str = manifest["kind"]
        meta = manifest["metadata"]
        name: str = meta["name"]
        namespace: str = meta["namespace"]

        group, version, plural = _kind_to_gvk_plural(kind)

        # Расчёт хэша спецификации
        spec_hash = _hash_spec(manifest["spec"])
        annotations = meta.setdefault("annotations", {})
        annotations[self.SPEC_HASH_ANNOTATION] = spec_hash

        # Проверяем текущий объект: если хэш совпадает — no-op
        try:
            existing = await self._client.get(group, version, namespace, plural, name)
            existing_ann = (
                existing.get("metadata", {}).get("annotations", {}).get(self.SPEC_HASH_ANNOTATION)
            )
            if existing_ann == spec_hash and not self.cfg.force_apply:
                log.info(
                    "No changes detected; skipping apply",
                    extra={"extra": {"kind": kind, "name": name, "namespace": namespace}},
                )
                return existing
        except K8sApiException as e:  # type: ignore
            if getattr(e, "status", None) != 404:
                raise

        attempts = 0
        while True:
            attempts += 1
            try:
                res = await self._client.server_side_apply(
                    group=group,
                    version=version,
                    namespace=namespace,
                    plural=plural,
                    name=name,
                    body=manifest,
                    field_manager=self.cfg.field_manager,
                    force=self.cfg.force_apply,
                    dry_run=self.cfg.dry_run,
                    timeout_seconds=self.cfg.request_timeout_seconds,
                )
                log.info(
                    "Applied",
                    extra={
                        "extra": {
                            "kind": kind,
                            "name": name,
                            "namespace": namespace,
                            "dry_run": self.cfg.dry_run,
                            "attempt": attempts,
                        }
                    },
                )
                return res
            except K8sApiException as e:  # type: ignore
                # 409 — конфликт поля SSA; 429/5xx — ретраи
                status = getattr(e, "status", None)
                retriable = status in (409, 429, 500, 502, 503, 504) or status is None
                if not retriable or attempts >= self.cfg.max_retries:
                    raise ApplyError(f"Не удалось применить {kind}/{name}: {e}") from e
                delay = _sleep_jittered(self.cfg.base_backoff_seconds, attempts, self.cfg.max_backoff_seconds)
                log.warning(
                    "Apply retry",
                    extra={"extra": {"kind": kind, "name": name, "attempt": attempts, "delay_sec": round(delay, 3)}},
                )
                await asyncio.sleep(delay)


# --------------------------- Утилита очистки пустых полей ---------------------------


def _purge_empty(x: Any) -> Any:
    """
    Рекурсивно удаляет пустые dict/list/None из структуры.
    """
    if isinstance(x, dict):
        return {k: _purge_empty(v) for k, v in x.items() if v not in (None, "", [], {}, ())}
    if isinstance(x, list):
        cleaned = [_purge_empty(v) for v in x]
        return [v for v in cleaned if v not in (None, "", [], {}, ())]
    return x


# --------------------------- Пример использования (не исполняется при импорте) ---------------------------

if __name__ == "__main__":
    async def _demo() -> None:
        cfg = IstioAdapterConfig(
            namespace="production",
            in_cluster=bool(os.getenv("KUBERNETES_SERVICE_HOST")),
            kubeconfig_path=os.getenv("KUBECONFIG"),
            context=None,
            dry_run=False,
            force_apply=True,
            max_retries=5,
        )
        async with IstioAdapter(cfg) as istio:
            # Пример AuthorizationPolicy: разрешить только сервисному аккаунту и JWT-аудитории
            rules = [
                AuthorizationRule(
                    source=SourceRule(
                        principals=["cluster.local/ns/production/sa/payments-sa"],
                        namespaces=["production"],
                    ),
                    operation=OperationRule(
                        methods=["GET", "POST"],
                        paths=["/api/v1/payments", "/api/v1/refunds"],
                        ports=[8080],
                    ),
                    when=[
                        WhenCondition(key="request.auth.audiences", values=["payments-api"]),
                    ],
                )
            ]
            await istio.apply_authorization_policy(
                name="payments-allow",
                rules=rules,
                selector_labels={"app": "payments"},
                annotations={"owner": "security-team"},
                labels={"zero-trust": "true"},
            )

            # Пример включения STRICT mTLS
            await istio.apply_peer_authentication(
                name="default-mtls-strict",
                mtls_mode="STRICT",
            )

            # JWT проверка
            await istio.apply_request_authentication(
                name="jwt-payments",
                jwt_issuer="https://auth.example.com/",
                jwks_uri="https://auth.example.com/.well-known/jwks.json",
                audiences=["payments-api"],
                selector_labels={"app": "payments"},
            )

            # DestinationRule c ISTIO_MUTUAL
            await istio.apply_destination_rule_tls_mutual(
                name="payments-dr",
                host="payments.production.svc.cluster.local",
            )

            # Sidecar — egress whitelist внутри namespace
            await istio.apply_sidecar_egress_whitelist(
                name="payments-egress",
                selector_labels={"app": "payments"},
                egress_hosts=["./*", "istio-system/*"],
                outbound_traffic_policy_mode="REGISTRY_ONLY",
            )

    asyncio.run(_demo())
