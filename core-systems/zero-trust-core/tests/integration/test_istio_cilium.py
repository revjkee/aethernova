# -*- coding: utf-8 -*-
"""
Интеграционные тесты Istio + Cilium для Zero-Trust Core.

Предпосылки окружения:
- Доступен Kubernetes-кластер (in-cluster или по $KUBECONFIG).
- Установлены CRD:
  * security.istio.io/v1 AuthorizationPolicy, PeerAuthentication
  * cilium.io/v2 CiliumNetworkPolicy
- В кластере активен Istio sidecar injector (label istio-injection=enabled на ns обеспечит инъекцию).
- Тест НЕ создает Istio/Cilium, а только использует их API; при отсутствии — помечает тесты как skipped.

Запуск:
    pytest -q tests/integration/test_istio_cilium.py

Зависимости:
    pip install pytest pytest-asyncio kubernetes-asyncio
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import string
import time
from typing import Any, Dict, Optional

import pytest

try:
    import kubernetes_asyncio
    from kubernetes_asyncio import client as k8s
    from kubernetes_asyncio import config as kcfg
    from kubernetes_asyncio.client import ApiException
except Exception:  # pragma: no cover
    kubernetes_asyncio = None
    k8s = None
    kcfg = None
    ApiException = Exception  # type: ignore

pytestmark = pytest.mark.asyncio


# --------------------------- Утилиты ---------------------------

def _rand_suffix(n: int = 5) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


async def _load_kube() -> None:
    if "KUBERNETES_SERVICE_HOST" in os.environ:
        await kcfg.load_incluster_config()  # type: ignore
    else:
        await kcfg.load_kube_config(config_file=os.getenv("KUBECONFIG"))  # type: ignore


async def _ssa_patch_custom(
    api: k8s.CustomObjectsApi,
    *,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
    body: Dict[str, Any],
    field_manager: str = "zero-trust-tests",
    force: bool = True,
    dry_run: bool = False,
    timeout_seconds: int = 20,
) -> Dict[str, Any]:
    return await api.patch_namespaced_custom_object(
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


async def _wait_for_deployment_ready(api: k8s.AppsV1Api, ns: str, name: str, timeout: int = 180) -> None:
    t0 = time.time()
    while True:
        dep = await api.read_namespaced_deployment(name=name, namespace=ns)
        spec = dep.spec.replicas or 1
        ready = dep.status.ready_replicas or 0
        if ready >= spec:
            return
        if time.time() - t0 > timeout:
            raise AssertionError(f"Deployment {name} not ready after {timeout}s (ready={ready}/{spec})")
        await asyncio.sleep(2.0)


async def _wait_for_job_completed(api: k8s.BatchV1Api, ns: str, name: str, timeout: int = 120) -> bool:
    """Возвращает True при успехе (succeeded>=1), False при fail."""
    t0 = time.time()
    while True:
        job = await api.read_namespaced_job(name=name, namespace=ns)
        if (job.status.succeeded or 0) >= 1:
            return True
        if (job.status.failed or 0) >= 1:
            return False
        if time.time() - t0 > timeout:
            raise AssertionError(f"Job {name} not complete after {timeout}s")
        await asyncio.sleep(2.0)


async def _ensure_crd_present(discovery: k8s.ApisApi, group: str, version: str) -> bool:
    try:
        groups = await discovery.get_api_group(group)
        versions = [v.version for v in groups.versions]  # type: ignore
        return version in versions
    except ApiException:
        return False


# --------------------------- Фикстуры ---------------------------

@pytest.fixture(scope="module")
def _skip_if_no_k8s():
    if kubernetes_asyncio is None:
        pytest.skip("kubernetes_asyncio недоступен")


@pytest.fixture(scope="module")
async def k8s_clients(_skip_if_no_k8s):
    await _load_kube()
    api_client = k8s.ApiClient()
    return {
        "core": k8s.CoreV1Api(api_client),
        "apps": k8s.AppsV1Api(api_client),
        "batch": k8s.BatchV1Api(api_client),
        "co": k8s.CustomObjectsApi(api_client),
        "discovery": k8s.ApisApi(api_client),
        "rbac": k8s.RbacAuthorizationV1Api(api_client),
    }


@pytest.fixture(scope="module")
async def prereq(k8s_clients):
    # Проверим наличие CRD Istio и Cilium
    disc: k8s.ApisApi = k8s_clients["discovery"]
    has_istio = await _ensure_crd_present(disc, "security.istio.io", "v1")
    has_cilium = await _ensure_crd_present(disc, "cilium.io", "v2")
    if not has_istio:
        pytest.skip("Istio CRDs (security.istio.io/v1) недоступны")
    if not has_cilium:
        pytest.skip("Cilium CRDs (cilium.io/v2) недоступны")
    return True


@pytest.fixture
async def ns_isolated(k8s_clients, prereq):
    core: k8s.CoreV1Api = k8s_clients["core"]
    name = f"zt-it-{_rand_suffix(6)}"
    # Создадим namespace с автоподстановкой сайдкара
    body = k8s.V1Namespace(
        metadata=k8s.V1ObjectMeta(
            name=name,
            labels={"istio-injection": "enabled", "zero-trust-tests": "true"},
        )
    )
    await core.create_namespace(body)
    try:
        yield name
    finally:
        # Удалим namespace целиком (best-effort)
        with pytest.raises(Exception):
            pass
        try:
            await core.delete_namespace(name)
        except ApiException:
            pass


# --------------------------- Базовая развертка сервиса и клиента ---------------------------

async def _deploy_http_service(apps: k8s.AppsV1Api, core: k8s.CoreV1Api, ns: str, name: str = "svc-a") -> None:
    # NGINX как стенд сервиса
    labels = {"app": name}
    dep = k8s.V1Deployment(
        metadata=k8s.V1ObjectMeta(name=name, namespace=ns, labels=labels),
        spec=k8s.V1DeploymentSpec(
            replicas=1,
            selector=k8s.V1LabelSelector(match_labels=labels),
            template=k8s.V1PodTemplateSpec(
                metadata=k8s.V1ObjectMeta(labels=labels),
                spec=k8s.V1PodSpec(
                    containers=[
                        k8s.V1Container(
                            name="nginx",
                            image=os.getenv("NGINX_IMAGE", "nginx:1.25-alpine"),
                            ports=[k8s.V1ContainerPort(container_port=80)],
                            readiness_probe=k8s.V1Probe(
                                http_get=k8s.V1HTTPGetAction(path="/", port=80),
                                period_seconds=3,
                                initial_delay_seconds=2,
                            ),
                        )
                    ]
                ),
            ),
        ),
    )
    await apps.create_namespaced_deployment(ns, dep)

    svc = k8s.V1Service(
        metadata=k8s.V1ObjectMeta(name=name, namespace=ns, labels=labels),
        spec=k8s.V1ServiceSpec(
            type="ClusterIP",
            selector=labels,
            ports=[k8s.V1ServicePort(name="http", port=80, target_port=80)],
        ),
    )
    await core.create_namespaced_service(ns, svc)

    await _wait_for_deployment_ready(apps, ns, name)


async def _create_service_account(core: k8s.CoreV1Api, ns: str, name: str) -> None:
    sa = k8s.V1ServiceAccount(metadata=k8s.V1ObjectMeta(name=name, namespace=ns))
    await core.create_namespaced_service_account(ns, sa)


async def _run_curl_job(batch: k8s.BatchV1Api, ns: str, job_name: str, sa: Optional[str], pod_label: str, url: str, should_succeed: bool) -> None:
    """
    Запускает Job, который выполняет curl к указанному URL и:
      - при success ожидается код 200 (grep 200) => Job успешен
      - при блокировке Job должен завершиться с неуспехом
    """
    # image curl берём явный, чтобы не зависеть от busybox curl
    image = os.getenv("CURL_IMAGE", "curlimages/curl:8.10.1")
    labels = {"job": job_name, "role": pod_label}
    cmd = [
        "sh", "-c",
        'set -e; code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 {}); echo "HTTP:$code"; test "$code" = "200"'.format(url)
    ]
    job = k8s.V1Job(
        metadata=k8s.V1ObjectMeta(name=job_name, namespace=ns, labels=labels),
        spec=k8s.V1JobSpec(
            ttl_seconds_after_finished=60,
            backoff_limit=0,
            template=k8s.V1PodTemplateSpec(
                metadata=k8s.V1ObjectMeta(labels=labels),
                spec=k8s.V1PodSpec(
                    service_account_name=sa,
                    restart_policy="Never",
                    containers=[k8s.V1Container(name="curl", image=image, command=cmd)],
                ),
            ),
        ),
    )
    await batch.create_namespaced_job(ns, job)
    try:
        ok = await _wait_for_job_completed(batch, ns, job_name, timeout=180)
        if should_succeed and not ok:
            raise AssertionError(f"Ожидался успех Job {job_name}, но он завершился неуспехом")
        if not should_succeed and ok:
            raise AssertionError(f"Ожидался блок Job {job_name}, но он завершился успешно")
    finally:
        # best-effort удалить job
        try:
            await batch.delete_namespaced_job(job_name, ns, propagation_policy="Background")
        except ApiException:
            pass


# --------------------------- Политики Istio и Cilium ---------------------------

async def _apply_istio_policies(co: k8s.CustomObjectsApi, ns: str, selector_labels: Dict[str, str], allow_sa: str) -> None:
    """
    Включает STRICT mTLS namespace-wide и разрешает доступ к сервису только от указанного serviceAccount.
    """
    # PeerAuthentication STRICT (namespace scope)
    pa = {
        "apiVersion": "security.istio.io/v1",
        "kind": "PeerAuthentication",
        "metadata": {"name": "mtls-strict", "namespace": ns},
        "spec": {"mtls": {"mode": "STRICT"}},
    }
    await _ssa_patch_custom(co, group="security.istio.io", version="v1",
                            namespace=ns, plural="peerauthentications", name="mtls-strict", body=pa)

    # AuthorizationPolicy для pods с label selector_labels
    principal = f"cluster.local/ns/{ns}/sa/{allow_sa}"
    ap = {
        "apiVersion": "security.istio.io/v1",
        "kind": "AuthorizationPolicy",
        "metadata": {"name": "svc-allow-by-sa", "namespace": ns},
        "spec": {
            "selector": {"matchLabels": selector_labels},
            "action": "ALLOW",
            "rules": [
                {"from": [{"source": {"principals": [principal]}}]}
            ],
        },
    }
    await _ssa_patch_custom(co, group="security.istio.io", version="v1",
                            namespace=ns, plural="authorizationpolicies", name="svc-allow-by-sa", body=ap)


async def _apply_cilium_policy(co: k8s.CustomObjectsApi, ns: str, dst_selector: Dict[str, str], allowed_src_label: str, port: int = 80) -> None:
    """
    Разрешает трафик ТОЛЬКО от Pod'ов с меткой role=<allowed_src_label> к dst (dst_selector) на порт 80/TCP.
    Всё остальное — по умолчанию deny (в рамках политики).
    """
    cnp = {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "egress-whitelist-client", "namespace": ns},
        "spec": {
            "endpointSelector": {"matchLabels": dst_selector},
            "ingress": [
                {
                    "fromEndpoints": [{"matchLabels": {"role": allowed_src_label}}],
                    "toPorts": [{"ports": [{"port": str(port), "protocol": "TCP"}]}],
                }
            ],
        },
    }
    await _ssa_patch_custom(co, group="cilium.io", version="v2",
                            namespace=ns, plural="ciliumnetworkpolicies", name="egress-whitelist-client", body=cnp)


# --------------------------- Сами тесты ---------------------------

@pytest.mark.integration
async def test_istio_authorization_by_sa_allows_only_right_principal(k8s_clients, ns_isolated):
    """
    Проверка, что AuthorizationPolicy Istio пропускает только трафик от нужного ServiceAccount при STRICT mTLS.
    """
    apps: k8s.AppsV1Api = k8s_clients["apps"]
    core: k8s.CoreV1Api = k8s_clients["core"]
    batch: k8s.BatchV1Api = k8s_clients["batch"]
    co: k8s.CustomObjectsApi = k8s_clients["co"]
    ns = ns_isolated

    # Развернём сервис
    await _deploy_http_service(apps, core, ns, name="svc-a")
    selector = {"app": "svc-a"}

    # Создадим два SA: разрешённый и запрещённый
    await _create_service_account(core, ns, "client-allowed")
    await _create_service_account(core, ns, "client-denied")

    # Включим STRICT mTLS и политику «разрешить только от client-allowed»
    await _apply_istio_policies(co, ns, selector, allow_sa="client-allowed")

    # Небольшая пауза, чтобы sidecar/политики применились
    await asyncio.sleep(5)

    # Разрешённый клиент → должен пройти
    await _run_curl_job(
        batch, ns,
        job_name=f"curl-allow-{_rand_suffix()}",
        sa="client-allowed",
        pod_label="client-allow",
        url="http://svc-a.%s.svc.cluster.local" % ns,
        should_succeed=True,
    )

    # Запрещённый клиент (иной SA) → должен быть заблокирован (403/deny)
    await _run_curl_job(
        batch, ns,
        job_name=f"curl-deny-sa-{_rand_suffix()}",
        sa="client-denied",
        pod_label="client-allow",  # метка не важна для Istio‑rule
        url="http://svc-a.%s.svc.cluster.local" % ns,
        should_succeed=False,
    )


@pytest.mark.integration
async def test_cilium_network_policy_allows_label_blocks_others(k8s_clients, ns_isolated):
    """
    Проверка, что CiliumNetworkPolicy пропускает только клиентов с определённой меткой,
    блокируя остальных (даже при корректном SA и mTLS).
    """
    apps: k8s.AppsV1Api = k8s_clients["apps"]
    core: k8s.CoreV1Api = k8s_clients["core"]
    batch: k8s.BatchV1Api = k8s_clients["batch"]
    co: k8s.CustomObjectsApi = k8s_clients["co"]
    ns = ns_isolated

    # Развернуть сервис
    await _deploy_http_service(apps, core, ns, name="svc-a")
    selector = {"app": "svc-a"}

    # ServiceAccount для разрешённого клиента
    await _create_service_account(core, ns, "client-allowed")

    # Istio: STRICT + ALLOW по SA (как базовый слой)
    await _apply_istio_policies(co, ns, selector, allow_sa="client-allowed")

    # Добавим CiliumNetworkPolicy: разрешаем ТОЛЬКО от pod с role=client-allow
    await _apply_cilium_policy(co, ns, dst_selector=selector, allowed_src_label="client-allow", port=80)

    # Пауза чтобы CNP пропаганировалась
    await asyncio.sleep(5)

    svc_url = f"http://svc-a.{ns}.svc.cluster.local"

    # Клиент с нужной меткой → проходит
    await _run_curl_job(
        batch, ns,
        job_name=f"curl-allow-cnp-{_rand_suffix()}",
        sa="client-allowed",
        pod_label="client-allow",
        url=svc_url,
        should_succeed=True,
    )

    # Клиент с другой меткой → блок (Cilium)
    await _run_curl_job(
        batch, ns,
        job_name=f"curl-deny-cnp-{_rand_suffix()}",
        sa="client-allowed",            # SA корректный для Istio
        pod_label="client-other",       # но метка не соответствует CNP
        url=svc_url,
        should_succeed=False,
    )
