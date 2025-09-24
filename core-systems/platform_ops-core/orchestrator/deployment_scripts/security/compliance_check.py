#!/usr/bin/env python3
"""
Compliance Check Script для Kubernetes кластера.
Проверяет соответствие кластера стандартам безопасности CIS Kubernetes Benchmark.
Использует Kubernetes Python client и YAML схемы CIS правил.
"""

import sys
import yaml
import json
from kubernetes import client, config
from kubernetes.client.rest import ApiException

# CIS Benchmark основные проверки (пример ограниченного набора)
CIS_CHECKS = [
    {
        "id": "1.1.1",
        "description": "Ensure that the API server pod specification file permissions are set to 644 or more restrictive",
        "check": lambda config_map: config_map.metadata.name == "kube-apiserver"
    },
    {
        "id": "1.2.1",
        "description": "Ensure that the --anonymous-auth argument is set to false",
        "check": lambda pod: "--anonymous-auth=false" in (pod.spec.containers[0].args or [])
    }
]

def load_kube_config():
    try:
        config.load_kube_config()
    except Exception:
        config.load_incluster_config()

def check_api_server_configs(v1):
    """
    Проверяем конфигурации API-сервера (ConfigMaps, Pods)
    """
    results = []
    try:
        pods = v1.list_pod_for_all_namespaces(label_selector="component=kube-apiserver")
        for pod in pods.items:
            for check in CIS_CHECKS:
                if check["id"] == "1.2.1":
                    res = check["check"](pod)
                    results.append({
                        "check_id": check["id"],
                        "description": check["description"],
                        "passed": res
                    })
        # Дополнительные проверки можно добавить здесь
    except ApiException as e:
        print(f"Ошибка API Kubernetes: {e}", file=sys.stderr)
        sys.exit(1)
    return results

def main():
    load_kube_config()
    v1 = client.CoreV1Api()

    compliance_results = check_api_server_configs(v1)

    passed = sum(1 for r in compliance_results if r["passed"])
    total = len(compliance_results)

    report = {
        "total_checks": total,
        "passed_checks": passed,
        "failed_checks": total - passed,
        "details": compliance_results
    }

    print(json.dumps(report, indent=2))

    if passed < total:
        sys.exit(2)  # Возвращаем код ошибки для CI/CD

if __name__ == "__main__":
    main()
