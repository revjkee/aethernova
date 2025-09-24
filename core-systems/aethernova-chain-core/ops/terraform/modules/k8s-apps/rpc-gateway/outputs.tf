# aethernova-chain-core/ops/terraform/modules/k8s-apps/rpc-gateway/outputs.tf
#
# Экспорт сводной информации о RPC Gateway.
# Примечание:
# - Имена ресурсов (kubernetes_deployment.rpc_gateway, kubernetes_service.rpc_gateway, и т.п.)
#   должны соответствовать реальным именам внутри модуля.
# - Используются try() и null для безопасной отдачи значений, которых может не быть
#   (например, ingress, HPA или LoadBalancer-адрес).
# - Секреты не раскрываются — отдаем только имена Secret/ConfigMap.

########################################
# Метаданные/идентификация
########################################
output "rpc_gateway_meta" {
  description = "Метаданные RPC Gateway (namespace, labels, annotations)"
  value = {
    name        = try(kubernetes_deployment.rpc_gateway.metadata[0].name, null)
    namespace   = try(kubernetes_deployment.rpc_gateway.metadata[0].namespace, null)
    labels      = try(kubernetes_deployment.rpc_gateway.metadata[0].labels, null)
    annotations = try(kubernetes_deployment.rpc_gateway.metadata[0].annotations, null)
  }
}

########################################
# Deployment
########################################
output "rpc_gateway_deployment" {
  description = "Состояние Deployment RPC Gateway"
  value = {
    name               = try(kubernetes_deployment.rpc_gateway.metadata[0].name, null)
    namespace          = try(kubernetes_deployment.rpc_gateway.metadata[0].namespace, null)
    replicas_desired   = try(kubernetes_deployment.rpc_gateway.spec[0].replicas, null)
    replicas_updated   = try(kubernetes_deployment.rpc_gateway.status[0].updated_replicas, null)
    replicas_ready     = try(kubernetes_deployment.rpc_gateway.status[0].ready_replicas, null)
    replicas_available = try(kubernetes_deployment.rpc_gateway.status[0].available_replicas, null)
    selector           = try(kubernetes_deployment.rpc_gateway.spec[0].selector[0].match_labels, null)
    strategy           = try(kubernetes_deployment.rpc_gateway.spec[0].strategy[0].type, null)
  }
}

########################################
# Service (ClusterIP / LoadBalancer)
########################################
locals {
  rpc_gateway_service_ports = try([
    for p in kubernetes_service.rpc_gateway.spec[0].port : {
      name        = try(p.name, null)
      protocol    = try(p.protocol, null)
      port        = try(p.port, null)
      target_port = try(tostring(p.target_port), null)
      node_port   = try(p.node_port, null)
    }
  ], null)

  # Поддержка и IP, и hostname для LoadBalancer
  rpc_gateway_service_lb_ip       = try(kubernetes_service.rpc_gateway.status[0].load_balancer[0].ingress[0].ip, null)
  rpc_gateway_service_lb_hostname = try(kubernetes_service.rpc_gateway.status[0].load_balancer[0].ingress[0].hostname, null)
}

output "rpc_gateway_service" {
  description = "Параметры Service RPC Gateway"
  value = {
    name        = try(kubernetes_service.rpc_gateway.metadata[0].name, null)
    namespace   = try(kubernetes_service.rpc_gateway.metadata[0].namespace, null)
    type        = try(kubernetes_service.rpc_gateway.spec[0].type, null)
    cluster_ip  = try(kubernetes_service.rpc_gateway.spec[0].cluster_ip, null)
    ports       = local.rpc_gateway_service_ports
    load_balancer = {
      ip       = local.rpc_gateway_service_lb_ip
      hostname = local.rpc_gateway_service_lb_hostname
    }
  }
}

########################################
# Ingress (если используется)
########################################
locals {
  rpc_gateway_ingress_hosts = try([
    for r in kubernetes_ingress_v1.rpc_gateway.spec[0].rule : r.host
  ], null)

  rpc_gateway_ingress_lb_ip       = try(kubernetes_ingress_v1.rpc_gateway.status[0].load_balancer[0].ingress[0].ip, null)
  rpc_gateway_ingress_lb_hostname = try(kubernetes_ingress_v1.rpc_gateway.status[0].load_balancer[0].ingress[0].hostname, null)
}

output "rpc_gateway_ingress" {
  description = "Параметры Ingress RPC Gateway"
  value = {
    name               = try(kubernetes_ingress_v1.rpc_gateway.metadata[0].name, null)
    namespace          = try(kubernetes_ingress_v1.rpc_gateway.metadata[0].namespace, null)
    ingress_class_name = try(kubernetes_ingress_v1.rpc_gateway.spec[0].ingress_class_name, null)
    hosts              = local.rpc_gateway_ingress_hosts
    load_balancer = {
      ip       = local.rpc_gateway_ingress_lb_ip
      hostname = local.rpc_gateway_ingress_lb_hostname
    }
  }
}

########################################
# Horizontal Pod Autoscaler (если используется)
########################################
output "rpc_gateway_hpa" {
  description = "Состояние HPA для RPC Gateway"
  value = {
    name             = try(kubernetes_horizontal_pod_autoscaler_v2.rpc_gateway.metadata[0].name, null)
    namespace        = try(kubernetes_horizontal_pod_autoscaler_v2.rpc_gateway.metadata[0].namespace, null)
    min_replicas     = try(kubernetes_horizontal_pod_autoscaler_v2.rpc_gateway.spec[0].min_replicas, null)
    max_replicas     = try(kubernetes_horizontal_pod_autoscaler_v2.rpc_gateway.spec[0].max_replicas, null)
    current_replicas = try(kubernetes_horizontal_pod_autoscaler_v2.rpc_gateway.status[0].current_replicas, null)
    desired_replicas = try(kubernetes_horizontal_pod_autoscaler_v2.rpc_gateway.status[0].desired_replicas, null)
    metrics          = try(kubernetes_horizontal_pod_autoscaler_v2.rpc_gateway.spec[0].metric, null)
  }
}

########################################
# Сервисный аккаунт, ConfigMap и Secret (только имена)
########################################
output "rpc_gateway_service_account_name" {
  description = "Имя ServiceAccount, используемого RPC Gateway"
  value       = try(kubernetes_service_account.rpc_gateway.metadata[0].name, null)
}

output "rpc_gateway_configmap_name" {
  description = "Имя ConfigMap с конфигурацией RPC Gateway"
  value       = try(kubernetes_config_map.rpc_gateway.metadata[0].name, null)
}

output "rpc_gateway_secret_name" {
  description = "Имя Secret, используемого RPC Gateway (без содержимого)"
  value       = try(kubernetes_secret.rpc_gateway.metadata[0].name, null)
  sensitive   = true
}

########################################
# Сводный JSON (удобно для автоматизаций)
########################################
output "rpc_gateway_summary_json" {
  description = "Сводная информация о RPC Gateway в формате JSON"
  value = jsonencode({
    meta      = {
      name        = try(kubernetes_deployment.rpc_gateway.metadata[0].name, null)
      namespace   = try(kubernetes_deployment.rpc_gateway.metadata[0].namespace, null)
      labels      = try(kubernetes_deployment.rpc_gateway.metadata[0].labels, null)
      annotations = try(kubernetes_deployment.rpc_gateway.metadata[0].annotations, null)
    }
    deployment = {
      replicas_desired   = try(kubernetes_deployment.rpc_gateway.spec[0].replicas, null)
      replicas_ready     = try(kubernetes_deployment.rpc_gateway.status[0].ready_replicas, null)
      replicas_available = try(kubernetes_deployment.rpc_gateway.status[0].available_replicas, null)
    }
    service = {
      name        = try(kubernetes_service.rpc_gateway.metadata[0].name, null)
      type        = try(kubernetes_service.rpc_gateway.spec[0].type, null)
      cluster_ip  = try(kubernetes_service.rpc_gateway.spec[0].cluster_ip, null)
      ports       = local.rpc_gateway_service_ports
      lb          = { ip = local.rpc_gateway_service_lb_ip, hostname = local.rpc_gateway_service_lb_hostname }
    }
    ingress = {
      class_name = try(kubernetes_ingress_v1.rpc_gateway.spec[0].ingress_class_name, null)
      hosts      = local.rpc_gateway_ingress_hosts
      lb         = { ip = local.rpc_gateway_ingress_lb_ip, hostname = local.rpc_gateway_ingress_lb_hostname }
    }
    hpa = {
      min_replicas     = try(kubernetes_horizontal_pod_autoscaler_v2.rpc_gateway.spec[0].min_replicas, null)
      max_replicas     = try(kubernetes_horizontal_pod_autoscaler_v2.rpc_gateway.spec[0].max_replicas, null)
      current_replicas = try(kubernetes_horizontal_pod_autoscaler_v2.rpc_gateway.status[0].current_replicas, null)
    }
    sa      = try(kubernetes_service_account.rpc_gateway.metadata[0].name, null)
    config  = try(kubernetes_config_map.rpc_gateway.metadata[0].name, null)
    secret  = try(kubernetes_secret.rpc_gateway.metadata[0].name, null)
  })
  sensitive = false
}
