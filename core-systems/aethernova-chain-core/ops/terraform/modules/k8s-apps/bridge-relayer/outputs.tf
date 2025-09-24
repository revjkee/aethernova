###############################################################################
# aethernova-chain-core/ops/terraform/modules/k8s-apps/bridge-relayer/outputs.tf
#
# Промышленный набор выходов для Kubernetes-приложения "bridge-relayer".
# Предполагаемые ресурсы внутри модуля:
#   - helm_release.bridge_relayer
#   - kubernetes_namespace.bridge_relayer
#   - kubernetes_service_account.bridge_relayer
#   - kubernetes_config_map.bridge_relayer
#   - kubernetes_secret.bridge_relayer
#   - kubernetes_deployment.bridge_relayer
#   - kubernetes_service.bridge_relayer
#   - kubernetes_horizontal_pod_autoscaler_v2.bridge_relayer
#   - kubernetes_pod_disruption_budget.bridge_relayer
#   - kubernetes_network_policy.bridge_relayer
#   - kubernetes_ingress_v1.bridge_relayer
###############################################################################

########################
# Helm release outputs #
########################

output "helm_release_name" {
  description = "Имя Helm-релиза bridge-relayer."
  value       = helm_release.bridge_relayer.name
}

output "helm_release_namespace" {
  description = "Namespace Helm-релиза bridge-relayer."
  value       = helm_release.bridge_relayer.namespace
}

output "helm_release_chart" {
  description = "Имя Helm-чарта."
  value       = helm_release.bridge_relayer.chart
}

output "helm_release_version" {
  description = "Версия Helm-чарта (semver)."
  value       = helm_release.bridge_relayer.version
}

output "helm_release_status" {
  description = "Статус Helm-релиза (deployed/superseded/failed и т.д.)."
  value       = helm_release.bridge_relayer.status
}

##########################
# Namespace / SA / RBAC  #
##########################

output "namespace_name" {
  description = "Имя Kubernetes Namespace приложения."
  value       = kubernetes_namespace.bridge_relayer.metadata[0].name
}

output "namespace_uid" {
  description = "UID Namespace для целей аудита/трассировки."
  value       = kubernetes_namespace.bridge_relayer.metadata[0].uid
}

output "service_account_name" {
  description = "Имя ServiceAccount приложения."
  value       = kubernetes_service_account.bridge_relayer.metadata[0].name
}

#####################################
# Config / Secrets (метаданные ONLY)#
#####################################

output "configmap_name" {
  description = "Имя ConfigMap с конфигурацией bridge-relayer."
  value       = kubernetes_config_map.bridge_relayer.metadata[0].name
}

output "configmap_resource_version" {
  description = "resourceVersion ConfigMap (для отслеживания изменений конфигурации)."
  value       = kubernetes_config_map.bridge_relayer.metadata[0].resource_version
}

output "secret_name" {
  description = "Имя Secret с чувствительными параметрами bridge-relayer."
  value       = kubernetes_secret.bridge_relayer.metadata[0].name
  sensitive   = true
}

#########################
# Deployment / Workload #
#########################

output "deployment_name" {
  description = "Имя Deployment bridge-relayer."
  value       = kubernetes_deployment.bridge_relayer.metadata[0].name
}

output "deployment_uid" {
  description = "UID Deployment для аудита."
  value       = kubernetes_deployment.bridge_relayer.metadata[0].uid
}

output "deployment_replicas" {
  description = "Настроенное число реплик Deployment."
  value       = kubernetes_deployment.bridge_relayer.spec[0].replicas
}

output "deployment_selector_match_labels" {
  description = "Selector.match_labels Deployment (map)."
  value       = kubernetes_deployment.bridge_relayer.spec[0].selector[0].match_labels
}

output "deployment_template_labels" {
  description = "Labels шаблона Pod'а в Deployment."
  value       = kubernetes_deployment.bridge_relayer.spec[0].template[0].metadata[0].labels
}

output "deployment_container_images" {
  description = "Список контейнерных образов (image) в Deployment."
  value = [
    for c in kubernetes_deployment.bridge_relayer.spec[0].template[0].spec[0].container : c.image
  ]
}

############
# Services #
############

output "service_name" {
  description = "Имя Service для bridge-relayer."
  value       = kubernetes_service.bridge_relayer.metadata[0].name
}

output "service_type" {
  description = "Тип Service (ClusterIP/NodePort/LoadBalancer)."
  value       = kubernetes_service.bridge_relayer.spec[0].type
}

output "service_cluster_ip" {
  description = "ClusterIP выделенный сервису (если применимо)."
  value       = kubernetes_service.bridge_relayer.spec[0].cluster_ip
}

output "service_ports" {
  description = "Порты/протоколы сервиса."
  value = [
    {
      name        = p.name
      port        = p.port
      target_port = p.target_port
      protocol    = p.protocol
    }
    for p in kubernetes_service.bridge_relayer.spec[0].port
  ]
}

#########################
# Autoscaling / Resiliency
#########################

output "hpa_name" {
  description = "Имя HorizontalPodAutoscaler (v2)."
  value       = kubernetes_horizontal_pod_autoscaler_v2.bridge_relayer.metadata[0].name
}

output "hpa_bounds" {
  description = "Границы масштабирования HPA (min/max)."
  value = {
    min_replicas = kubernetes_horizontal_pod_autoscaler_v2.bridge_relayer.spec[0].min_replicas
    max_replicas = kubernetes_horizontal_pod_autoscaler_v2.bridge_relayer.spec[0].max_replicas
  }
}

output "pdb_name" {
  description = "Имя PodDisruptionBudget."
  value       = kubernetes_pod_disruption_budget.bridge_relayer.metadata[0].name
}

output "pdb_policy" {
  description = "Политика PDB (minAvailable/maxUnavailable)."
  value = {
    min_available  = try(kubernetes_pod_disruption_budget.bridge_relayer.spec[0].min_available, null)
    max_unavailable = try(kubernetes_pod_disruption_budget.bridge_relayer.spec[0].max_unavailable, null)
  }
}

#################
# NetworkPolicy #
#################

output "network_policy_name" {
  description = "Имя NetworkPolicy, ограничивающей трафик bridge-relayer."
  value       = kubernetes_network_policy.bridge_relayer.metadata[0].name
}

################
# Ingress/GW   #
################

output "ingress_name" {
  description = "Имя Ingress (если используется)."
  value       = kubernetes_ingress_v1.bridge_relayer.metadata[0].name
}

output "ingress_hosts" {
  description = "Список хостов Ingress."
  value       = [for r in kubernetes_ingress_v1.bridge_relayer.spec[0].rule : r.host]
}

output "ingress_tls_secrets" {
  description = "Список TLS Secret'ов, привязанных к Ingress."
  value       = [for t in kubernetes_ingress_v1.bridge_relayer.spec[0].tls : t.secret_name]
  sensitive   = true
}

output "ingress_addresses" {
  description = "Внешние адреса/имена балансировщика для Ingress."
  value = [
    for i in kubernetes_ingress_v1.bridge_relayer.status[0].load_balancer[0].ingress : {
      ip       = try(i.ip, null)
      hostname = try(i.hostname, null)
    }
  ]
}

#########################
# Derived / Computed    #
#########################

locals {
  svc_dns = format(
    "%s.%s.svc.cluster.local",
    kubernetes_service.bridge_relayer.metadata[0].name,
    kubernetes_service.bridge_relayer.metadata[0].namespace
  )
}

output "relayer_endpoints" {
  description = "Вычислимые эндпоинты сервиса (FQDN и порты)."
  value = {
    fqdn  = local.svc_dns
    ports = [
      for p in kubernetes_service.bridge_relayer.spec[0].port : {
        name = p.name
        url  = format("%s:%d", local.svc_dns, p.port)
      }
    ]
  }
}

#############################
# Aggregated module summary #
#############################

output "bridge_relayer_summary" {
  description = "Агрегированная сводка по развернутому приложению bridge-relayer."
  value = {
    helm = {
      name      = helm_release.bridge_relayer.name
      namespace = helm_release.bridge_relayer.namespace
      chart     = helm_release.bridge_relayer.chart
      version   = helm_release.bridge_relayer.version
      status    = helm_release.bridge_relayer.status
    }
    k8s = {
      namespace = {
        name = kubernetes_namespace.bridge_relayer.metadata[0].name
        uid  = kubernetes_namespace.bridge_relayer.metadata[0].uid
      }
      service_account = {
        name = kubernetes_service_account.bridge_relayer.metadata[0].name
      }
      configmap = {
        name             = kubernetes_config_map.bridge_relayer.metadata[0].name
        resource_version = kubernetes_config_map.bridge_relayer.metadata[0].resource_version
      }
      secret = {
        name = kubernetes_secret.bridge_relayer.metadata[0].name
      }
      deployment = {
        name      = kubernetes_deployment.bridge_relayer.metadata[0].name
        uid       = kubernetes_deployment.bridge_relayer.metadata[0].uid
        replicas  = kubernetes_deployment.bridge_relayer.spec[0].replicas
        selector  = kubernetes_deployment.bridge_relayer.spec[0].selector[0].match_labels
        podLabels = kubernetes_deployment.bridge_relayer.spec[0].template[0].metadata[0].labels
        images    = [for c in kubernetes_deployment.bridge_relayer.spec[0].template[0].spec[0].container : c.image]
      }
      service = {
        name       = kubernetes_service.bridge_relayer.metadata[0].name
        type       = kubernetes_service.bridge_relayer.spec[0].type
        cluster_ip = kubernetes_service.bridge_relayer.spec[0].cluster_ip
        ports = [
          {
            name        = p.name
            port        = p.port
            target_port = p.target_port
            protocol    = p.protocol
          } for p in kubernetes_service.bridge_relayer.spec[0].port
        ]
        fqdn = local.svc_dns
      }
      autoscaling = {
        hpa = {
          name         = kubernetes_horizontal_pod_autoscaler_v2.bridge_relayer.metadata[0].name
          min_replicas = kubernetes_horizontal_pod_autoscaler_v2.bridge_relayer.spec[0].min_replicas
          max_replicas = kubernetes_horizontal_pod_autoscaler_v2.bridge_relayer.spec[0].max_replicas
        }
        pdb = {
          name           = kubernetes_pod_disruption_budget.bridge_relayer.metadata[0].name
          min_available  = try(kubernetes_pod_disruption_budget.bridge_relayer.spec[0].min_available, null)
          max_unavailable = try(kubernetes_pod_disruption_budget.bridge_relayer.spec[0].max_unavailable, null)
        }
      }
      network = {
        network_policy = kubernetes_network_policy.bridge_relayer.metadata[0].name
        ingress = {
          name       = kubernetes_ingress_v1.bridge_relayer.metadata[0].name
          hosts      = [for r in kubernetes_ingress_v1.bridge_relayer.spec[0].rule : r.host]
          tlsSecrets = [for t in kubernetes_ingress_v1.bridge_relayer.spec[0].tls : t.secret_name]
          addresses  = [
            for i in kubernetes_ingress_v1.bridge_relayer.status[0].load_balancer[0].ingress : {
              ip       = try(i.ip, null)
              hostname = try(i.hostname, null)
            }
          ]
        }
      }
    }
  }
  # Содержит имена и параметры, включая имена секретов; скрываем из логов.
  sensitive = true
}
