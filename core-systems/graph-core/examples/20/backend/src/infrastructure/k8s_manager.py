from kubernetes import client, config
from kubernetes.client.rest import ApiException
from typing import List, Optional

class K8sManager:
    def __init__(self, kubeconfig_path: Optional[str] = None):
        if kubeconfig_path:
            config.load_kube_config(config_file=kubeconfig_path)
        else:
            config.load_kube_config()  # По умолчанию из ~/.kube/config
        self.v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()

    def list_pods(self, namespace: str = "default") -> List[str]:
        try:
            pods = self.v1.list_namespaced_pod(namespace)
            return [pod.metadata.name for pod in pods.items]
        except ApiException as e:
            print(f"Exception when listing pods: {e}")
            return []

    def get_pod_status(self, pod_name: str, namespace: str = "default") -> Optional[str]:
        try:
            pod = self.v1.read_namespaced_pod_status(pod_name, namespace)
            return pod.status.phase
        except ApiException as e:
            print(f"Exception when getting pod status: {e}")
            return None

    def scale_deployment(self, deployment_name: str, replicas: int, namespace: str = "default") -> bool:
        try:
            deployment = self.apps_v1.read_namespaced_deployment(deployment_name, namespace)
            deployment.spec.replicas = replicas
            self.apps_v1.patch_namespaced_deployment(deployment_name, namespace, deployment)
            return True
        except ApiException as e:
            print(f"Exception when scaling deployment: {e}")
            return False

    def delete_pod(self, pod_name: str, namespace: str = "default") -> bool:
        try:
            self.v1.delete_namespaced_pod(pod_name, namespace)
            return True
        except ApiException as e:
            print(f"Exception when deleting pod: {e}")
            return False

    def list_services(self, namespace: str = "default") -> List[str]:
        try:
            services = self.v1.list_namespaced_service(namespace)
            return [svc.metadata.name for svc in services.items]
        except ApiException as e:
            print(f"Exception when listing services: {e}")
            return []

    def get_service_cluster_ip(self, service_name: str, namespace: str = "default") -> Optional[str]:
        try:
            svc = self.v1.read_namespaced_service(service_name, namespace)
            return svc.spec.cluster_ip
        except ApiException as e:
            print(f"Exception when getting service IP: {e}")
            return None
