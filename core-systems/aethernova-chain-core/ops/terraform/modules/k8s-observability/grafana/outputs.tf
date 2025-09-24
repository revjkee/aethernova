// SPDX-License-Identifier: Apache-2.0
// Module: aethernova-chain-core/ops/terraform/modules/k8s-observability/grafana
// File:   outputs.tf
// Purpose:
//   Production-grade outputs for Grafana deployed via Helm (and optional k8s resources).
//   This file assumes (optionally) the following resources may exist in this module:
//     - helm_release.grafana
//     - kubernetes_service.grafana
//     - kubernetes_ingress_v1.grafana
//     - kubernetes_secret.grafana_admin
//     - kubernetes_service_account.grafana
//     - kubernetes_persistent_volume_claim.grafana
//     - kubernetes_config_map.grafana_dashboards[*]
//     - kubernetes_config_map.grafana_datasources[*]
//   If your resource names differ, adjust the references below accordingly.

// -----------------------------
// Helm release (core)
// -----------------------------
output "grafana_release" {
  description = "Метаданные Helm-релиза Grafana."
  value = {
    name       = try(helm_release.grafana.name, null)
    namespace  = try(helm_release.grafana.namespace, null)
    repository = try(helm_release.grafana.repository, null)
    chart      = try(helm_release.grafana.chart, null)
    version    = try(helm_release.grafana.version, null)
    status     = try(helm_release.grafana.status, null)
    revision   = try(helm_release.grafana.metadata.revision, null)
  }
}

output "grafana_namespace" {
  description = "Namespace, куда установлен Grafana (из Helm-релиза)."
  value       = try(helm_release.grafana.namespace, null)
}

// -----------------------------
// Service
// -----------------------------
output "grafana_service_name" {
  description = "Имя Service для Grafana."
  value       = try(kubernetes_service.grafana.metadata[0].name, null)
}

output "grafana_service_type" {
  description = "Тип Service (ClusterIP|NodePort|LoadBalancer)."
  value       = try(kubernetes_service.grafana.spec[0].type, null)
}

output "grafana_service_cluster_ip" {
  description = "ClusterIP Service (если применимо)."
  value       = try(kubernetes_service.grafana.spec[0].cluster_ip, null)
}

output "grafana_service_http_ports" {
  description = "Список HTTP/HTTPS портов, опубликованных Service."
  value = try([
    for p in kubernetes_service.grafana.spec[0].port :
    {
      name       = try(p.name, null)
      port       = try(p.port, null)
      targetPort = try(p.target_port, null)
      nodePort   = try(p.node_port, null)
      protocol   = try(p.protocol, null)
    }
  ], [])
}

output "grafana_service_load_balancer_ingress" {
  description = "Внешние адреса LoadBalancer (IP/hostname), если тип Service=LoadBalancer."
  value = try([
    for i in kubernetes_service.grafana.status[0].load_balancer[0].ingress :
    coalesce(try(i.hostname, null), try(i.ip, null))
  ], [])
}

// -----------------------------
// Ingress / URLs
// -----------------------------
output "grafana_ingress_enabled" {
  description = "Флаг наличия Ingress ресурса для Grafana."
  value       = length(try(kubernetes_ingress_v1.grafana.metadata, [])) > 0
}

output "grafana_ingress_class_name" {
  description = "IngressClassName, если задан."
  value       = try(kubernetes_ingress_v1.grafana.spec[0].ingress_class_name, null)
}

output "grafana_ingress_hosts" {
  description = "Список host-ов из правил Ingress."
  value = try([
    for r in kubernetes_ingress_v1.grafana.spec[0].rule : r.host
  ], [])
}

output "grafana_ingress_tls_hosts" {
  description = "Список host-ов, покрытых TLS в Ingress."
  value = try(flatten([
    for t in kubernetes_ingress_v1.grafana.spec[0].tls : try(t.hosts, [])
  ]), [])
}

output "grafana_urls" {
  description = "Итоговые URL (по Ingress, либо по Service LoadBalancer / NodePort)."
  value = distinct(compact(concat(
    // Ingress URLs
    try([
      for h in flatten([
        for r in kubernetes_ingress_v1.grafana.spec[0].rule : [r.host]
      ]) :
      // если хост также есть в TLS-секции — используем https, иначе http
      contains(try(flatten([for t in kubernetes_ingress_v1.grafana.spec[0].tls : t.hosts]), []), h)
        ? "https://${h}"
        : "http://${h}"
    ], []),
    // LoadBalancer endpoints
    try([
      for e in kubernetes_service.grafana.status[0].load_balancer[0].ingress :
      (try(e.hostname, null) != null ? "http://${e.hostname}" : "http://${e.ip}")
    ], []),
    // NodePort (HTTP) — если нет Ingress/LB (best-effort; требует внешнего знания узлов)
    []
  )))
}

// -----------------------------
// Admin Secret (only reference, never the value)
// -----------------------------
output "grafana_admin_secret_name" {
  description = "Имя Secret с административными учетными данными Grafana (содержимое не выводится)."
  value       = try(kubernetes_secret.grafana_admin.metadata[0].name, null)
  sensitive   = false
}

// -----------------------------
// ServiceAccount
// -----------------------------
output "grafana_service_account_name" {
  description = "Имя ServiceAccount, под которым работает Grafana."
  value       = try(kubernetes_service_account.grafana.metadata[0].name, null)
}

// -----------------------------
// Persistence (PVC)
// -----------------------------
output "grafana_pvc" {
  description = "Параметры PersistentVolumeClaim (если используется)."
  value = try({
    name          = kubernetes_persistent_volume_claim.grafana.metadata[0].name
    storage_class = try(kubernetes_persistent_volume_claim.grafana.spec[0].storage_class_name, null)
    access_modes  = try(kubernetes_persistent_volume_claim.grafana.spec[0].access_modes, null)
    requested     = try(kubernetes_persistent_volume_claim.grafana.spec[0].resources[0].requests.storage, null)
    volume_name   = try(kubernetes_persistent_volume_claim.grafana.spec[0].volume_name, null)
    status_phase  = try(kubernetes_persistent_volume_claim.grafana.status[0].phase, null)
  }, null)
}

// -----------------------------
// ConfigMaps (dashboards / datasources)
// -----------------------------
output "grafana_dashboard_configmaps" {
  description = "ConfigMap-ы с дашбордами Grafana, созданные модулем (если есть)."
  value = try([
    for cm in kubernetes_config_map.grafana_dashboards :
    cm.metadata[0].name
  ], [])
}

output "grafana_datasource_configmaps" {
  description = "ConfigMap-ы с источниками данных Grafana, созданные модулем (если есть)."
  value = try([
    for cm in kubernetes_config_map.grafana_datasources :
    cm.metadata[0].name
  ], [])
}

// -----------------------------
// Derived endpoint summary
// -----------------------------
output "grafana_endpoint_summary" {
  description = "Сводка конечных точек доступа к Grafana."
  value = {
    namespace     = try(helm_release.grafana.namespace, null)
    service_name  = try(kubernetes_service.grafana.metadata[0].name, null)
    service_type  = try(kubernetes_service.grafana.spec[0].type, null)
    ingress_hosts = try([for r in kubernetes_ingress_v1.grafana.spec[0].rule : r.host], [])
    urls          = try(output.grafana_urls.value, null)
  }
}
