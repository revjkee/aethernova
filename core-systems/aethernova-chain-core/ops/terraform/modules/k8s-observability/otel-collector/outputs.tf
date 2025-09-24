#############################################
# k8s-observability/otel-collector/outputs.tf
# Terraform >= 1.5 | kubernetes provider >= 2.x
# Все outputs безопасно используют try() для разных режимов
#############################################

# --------- Общие идентификаторы/метаданные ---------

output "otel_namespace" {
  description = "Namespace, в котором развернут OTEL Collector."
  value = try(
    kubernetes_namespace.otel[0].metadata[0].name,
    kubernetes_deployment.otel_collector[0].metadata[0].namespace,
    kubernetes_daemon_set.otel_agent[0].metadata[0].namespace,
    null
  )
}

output "otel_service_account_name" {
  description = "Имя ServiceAccount коллектора."
  value       = try(kubernetes_service_account.otel[0].metadata[0].name, null)
}

output "otel_configmap_name" {
  description = "Имя ConfigMap с конфигурацией OTEL."
  value       = try(kubernetes_config_map.otel_config[0].metadata[0].name, null)
}

output "otel_tls_secret_name" {
  description = "Имя Secret с TLS/credentials (если используется)."
  value       = try(kubernetes_secret.otel_tls[0].metadata[0].name, null)
  sensitive   = false
}

# --------- Режим развёртывания ---------

output "otel_deployment_name" {
  description = "Имя Deployment (gateway-режим)."
  value       = try(kubernetes_deployment.otel_collector[0].metadata[0].name, null)
}

output "otel_daemonset_name" {
  description = "Имя DaemonSet (agent-режим)."
  value       = try(kubernetes_daemon_set.otel_agent[0].metadata[0].name, null)
}

# --------- Сервисы: OTLP gRPC/HTTP и internal metrics ---------

# gRPC (4317)
output "otel_otlp_grpc_service_name" {
  description = "Service name для OTLP gRPC."
  value       = try(kubernetes_service.otel_grpc[0].metadata[0].name, null)
}

output "otel_otlp_grpc_service_port" {
  description = "Порт OTLP gRPC на Service (fallback 4317)."
  value = try(
    kubernetes_service.otel_grpc[0].spec[0].port[0].port,
    4317
  )
}

output "otel_otlp_grpc_endpoint" {
  description = "Полный DNS endpoint для OTLP gRPC."
  value = try(
    format(
      "dns:///%s.%s.svc.cluster.local:%d",
      kubernetes_service.otel_grpc[0].metadata[0].name,
      kubernetes_service.otel_grpc[0].metadata[0].namespace,
      try(kubernetes_service.otel_grpc[0].spec[0].port[0].port, 4317)
    ),
    null
  )
}

# HTTP (4318)
output "otel_otlp_http_service_name" {
  description = "Service name для OTLP HTTP."
  value       = try(kubernetes_service.otel_http[0].metadata[0].name, null)
}

output "otel_otlp_http_service_port" {
  description = "Порт OTLP HTTP на Service (fallback 4318)."
  value = try(
    kubernetes_service.otel_http[0].spec[0].port[0].port,
    4318
  )
}

output "otel_otlp_http_endpoint" {
  description = "Полный DNS endpoint для OTLP HTTP."
  value = try(
    format(
      "http://%s.%s.svc.cluster.local:%d",
      kubernetes_service.otel_http[0].metadata[0].name,
      kubernetes_service.otel_http[0].metadata[0].namespace,
      try(kubernetes_service.otel_http[0].spec[0].port[0].port, 4318)
    ),
    null
  )
}

# Internal metrics (8888)
output "otel_metrics_service_name" {
  description = "Service name для внутренних метрик коллектора."
  value       = try(kubernetes_service.otel_metrics[0].metadata[0].name, null)
}

output "otel_metrics_service_port" {
  description = "Порт метрик на Service (fallback 8888)."
  value = try(
    kubernetes_service.otel_metrics[0].spec[0].port[0].port,
    8888
  )
}

output "otel_metrics_endpoint" {
  description = "Полный DNS endpoint для внутренних метрик коллектора."
  value = try(
    format(
      "http://%s.%s.svc.cluster.local:%d/metrics",
      kubernetes_service.otel_metrics[0].metadata[0].name,
      kubernetes_service.otel_metrics[0].metadata[0].namespace,
      try(kubernetes_service.otel_metrics[0].spec[0].port[0].port, 8888)
    ),
    null
  )
}

# --------- Селекторы/лейблы ---------

output "otel_pod_selector_labels" {
  description = "Селектор подов коллектора (map)."
  value = try(
    kubernetes_deployment.otel_collector[0].spec[0].selector[0].match_labels,
    kubernetes_daemon_set.otel_agent[0].spec[0].selector[0].match_labels,
    {}
  )
}

output "otel_service_selector_labels" {
  description = "Селектор Service для роутинга трафика к коллекторам."
  value = try(
    kubernetes_service.otel_grpc[0].spec[0].selector,
    kubernetes_service.otel_http[0].spec[0].selector,
    kubernetes_service.otel_metrics[0].spec[0].selector,
    {}
  )
}

# --------- HPA / PDB / NetworkPolicy ---------

output "otel_hpa_name" {
  description = "Имя HorizontalPodAutoscaler (если включён)."
  value       = try(kubernetes_horizontal_pod_autoscaler_v2.otel_collector[0].metadata[0].name, null)
}

output "otel_hpa_bounds" {
  description = "Минимум и максимум реплик HPA."
  value = try({
    min = kubernetes_horizontal_pod_autoscaler_v2.otel_collector[0].spec[0].min_replicas
    max = kubernetes_horizontal_pod_autoscaler_v2.otel_collector[0].spec[0].max_replicas
  }, null)
}

output "otel_pdb_name" {
  description = "Имя PodDisruptionBudget (если включён)."
  value       = try(kubernetes_pod_disruption_budget.otel_collector[0].metadata[0].name, null)
}

output "otel_network_policy_name" {
  description = "Имя NetworkPolicy (если включена)."
  value       = try(kubernetes_network_policy.otel[0].metadata[0].name, null)
}

# --------- Мониторинг (ServiceMonitor/PodMonitor) ---------

output "otel_service_monitor_name" {
  description = "Имя ServiceMonitor (CRD kube-prometheus-stack), если создан."
  value       = try(kubernetes_manifest.service_monitor[0].manifest.metadata.name, null)
}

output "otel_pod_monitor_name" {
  description = "Имя PodMonitor (CRD kube-prometheus-stack), если создан."
  value       = try(kubernetes_manifest.pod_monitor[0].manifest.metadata.name, null)
}

# --------- Диагностика конфигурации ---------

output "otel_config_hash" {
  description = "Хэш (аннотация/лейбл) конфигурации, полезно для триггера перезапуска."
  value = try(
    kubernetes_deployment.otel_collector[0].spec[0].template[0].metadata[0].annotations["otel.aethernova.io/config-hash"],
    kubernetes_daemon_set.otel_agent[0].spec[0].template[0].metadata[0].annotations["otel.aethernova.io/config-hash"],
    null
  )
}

output "otel_image_info" {
  description = "Образ контейнера (repo:tag) активного пода коллектора (первый контейнер)."
  value = try(
    kubernetes_deployment.otel_collector[0].spec[0].template[0].spec[0].container[0].image,
    kubernetes_daemon_set.otel_agent[0].spec[0].template[0].spec[0].container[0].image,
    null
  )
}
