# aethernova-chain-core/ops/terraform/modules/_templates/outputs.tf
##############################################################
#  Standardized outputs template for Kubernetes Terraform    #
#  Copy into a module and ensure resource names match.       #
##############################################################

########################
# Common/anchor values #
########################

# Namespace anchor: ожидается, что модуль создаёт ns ресурс с именем "this".
# Если модуль не создаёт namespace, можно удалить этот output либо
# переименовать ссылку на свой ресурс.
output "namespace" {
  description = "Kubernetes namespace приложения."
  value       = try(kubernetes_namespace_v1.this.metadata[0].name, "default")
}

output "service_account_name" {
  description = "Имя ServiceAccount (если модуль его создаёт)."
  value       = try(kubernetes_service_account_v1.this.metadata[0].name, null)
}

#############################
# Services (main, metrics)  #
#############################

# Основной сервис приложения
output "service_main" {
  description = "Параметры основного Service (TCP/HTTP entrypoint)."
  value = {
    name        = try(kubernetes_service_v1.main.metadata[0].name, null)
    type        = try(kubernetes_service_v1.main.spec[0].type, null)
    cluster_ip  = try(kubernetes_service_v1.main.spec[0].cluster_ip, null)
    ports = try([
      for p in kubernetes_service_v1.main.spec[0].port : {
        name        = try(p.name, null)
        port        = p.port
        target_port = try(p.target_port, null)
        node_port   = try(p.node_port, null)
        protocol    = try(p.protocol, null)
      }
    ], [])
    # Внутрикластерный DNS по стандартной схеме service.namespace.svc
    cluster_dns = try(
      format("%s.%s.svc", kubernetes_service_v1.main.metadata[0].name, kubernetes_service_v1.main.metadata[0].namespace),
      null
    )
    # Внешние адреса (если type = LoadBalancer)
    load_balancer_ingress = try([
      for i in kubernetes_service_v1.main.status[0].load_balancer[0].ingress :
      coalesce(try(i.ip, null), try(i.hostname, null))
    ], [])
    annotations = try(kubernetes_service_v1.main.metadata[0].annotations, {})
    labels      = try(kubernetes_service_v1.main.metadata[0].labels, {})
  }
}

# Сервис метрик (если есть)
output "service_metrics" {
  description = "Параметры Service для метрик/проб."
  value = {
    name        = try(kubernetes_service_v1.metrics.metadata[0].name, null)
    type        = try(kubernetes_service_v1.metrics.spec[0].type, null)
    cluster_ip  = try(kubernetes_service_v1.metrics.spec[0].cluster_ip, null)
    ports = try([
      for p in kubernetes_service_v1.metrics.spec[0].port : {
        name        = try(p.name, null)
        port        = p.port
        target_port = try(p.target_port, null)
        node_port   = try(p.node_port, null)
        protocol    = try(p.protocol, null)
      }
    ], [])
    cluster_dns = try(
      format("%s.%s.svc", kubernetes_service_v1.metrics.metadata[0].name, kubernetes_service_v1.metrics.metadata[0].namespace),
      null
    )
    load_balancer_ingress = try([
      for i in kubernetes_service_v1.metrics.status[0].load_balancer[0].ingress :
      coalesce(try(i.ip, null), try(i.hostname, null))
    ], [])
  }
}

################
# Ingress (v1) #
################

output "ingress_main" {
  description = "Параметры Ingress (если задействован)."
  value = {
    name   = try(kubernetes_ingress_v1.main.metadata[0].name, null)
    class  = try(kubernetes_ingress_v1.main.spec[0].ingress_class_name, null)
    hosts  = try([for r in kubernetes_ingress_v1.main.spec[0].rule : r.host], [])
    tls = {
      hosts        = try(flatten([for t in kubernetes_ingress_v1.main.spec[0].tls : t.hosts]), [])
      secret_names = try([for t in kubernetes_ingress_v1.main.spec[0].tls : t.secret_name], [])
    }
    annotations = try(kubernetes_ingress_v1.main.metadata[0].annotations, {})
  }
}

##########################
# Workload: Deployment   #
##########################

output "deployment_status" {
  description = "Сводка по Deployment (если используется)."
  value = {
    name               = try(kubernetes_deployment_v1.main.metadata[0].name, null)
    replicas_desired   = try(kubernetes_deployment_v1.main.spec[0].replicas, null)
    replicas_ready     = try(kubernetes_deployment_v1.main.status[0].ready_replicas, 0)
    replicas_updated   = try(kubernetes_deployment_v1.main.status[0].updated_replicas, 0)
    replicas_available = try(kubernetes_deployment_v1.main.status[0].available_replicas, 0)
    selector_labels    = try(kubernetes_deployment_v1.main.spec[0].selector[0].match_labels, {})
    revision           = try(kubernetes_deployment_v1.main.metadata[0].annotations["deployment.kubernetes.io/revision"], null)
  }
}

##########################
# Workload: StatefulSet  #
##########################

output "statefulset_status" {
  description = "Сводка по StatefulSet (если используется)."
  value = {
    name               = try(kubernetes_stateful_set_v1.main.metadata[0].name, null)
    replicas_desired   = try(kubernetes_stateful_set_v1.main.spec[0].replicas, null)
    replicas_ready     = try(kubernetes_stateful_set_v1.main.status[0].ready_replicas, 0)
    replicas_updated   = try(kubernetes_stateful_set_v1.main.status[0].updated_replicas, 0)
    replicas_current   = try(kubernetes_stateful_set_v1.main.status[0].current_replicas, 0)
    current_revision   = try(kubernetes_stateful_set_v1.main.status[0].current_revision, null)
    update_revision    = try(kubernetes_stateful_set_v1.main.status[0].update_revision, null)
    selector_labels    = try(kubernetes_stateful_set_v1.main.spec[0].selector[0].match_labels, {})
  }
}

########################
# Workload: DaemonSet  #
########################

output "daemonset_status" {
  description = "Сводка по DaemonSet (если используется)."
  value = {
    name                     = try(kubernetes_daemon_set_v1.main.metadata[0].name, null)
    desired_number_scheduled = try(kubernetes_daemon_set_v1.main.status[0].desired_number_scheduled, 0)
    number_ready             = try(kubernetes_daemon_set_v1.main.status[0].number_ready, 0)
    updated_number_scheduled = try(kubernetes_daemon_set_v1.main.status[0].updated_number_scheduled, 0)
    number_available         = try(kubernetes_daemon_set_v1.main.status[0].number_available, 0)
    selector_labels          = try(kubernetes_daemon_set_v1.main.spec[0].selector[0].match_labels, {})
  }
}

#############################################
# Autoscaling: HorizontalPodAutoscaler (v2) #
#############################################

output "hpa_status" {
  description = "Сводка по HPA v2 (если используется)."
  value = {
    name              = try(kubernetes_horizontal_pod_autoscaler_v2.this.metadata[0].name, null)
    min_replicas      = try(kubernetes_horizontal_pod_autoscaler_v2.this.spec[0].min_replicas, null)
    max_replicas      = try(kubernetes_horizontal_pod_autoscaler_v2.this.spec[0].max_replicas, null)
    current_replicas  = try(kubernetes_horizontal_pod_autoscaler_v2.this.status[0].current_replicas, null)
    desired_replicas  = try(kubernetes_horizontal_pod_autoscaler_v2.this.status[0].desired_replicas, null)
    last_scale_time   = try(kubernetes_horizontal_pod_autoscaler_v2.this.status[0].last_scale_time, null)
  }
}

######################################
# Disruption: PodDisruptionBudget v1 #
######################################

output "pdb_status" {
  description = "Сводка по PodDisruptionBudget (если используется)."
  value = {
    name                 = try(kubernetes_pod_disruption_budget_v1.main.metadata[0].name, null)
    min_available        = try(kubernetes_pod_disruption_budget_v1.main.spec[0].min_available, null)
    max_unavailable      = try(kubernetes_pod_disruption_budget_v1.main.spec[0].max_unavailable, null)
    disruptions_allowed  = try(kubernetes_pod_disruption_budget_v1.main.status[0].disruptions_allowed, null)
    current_healthy      = try(kubernetes_pod_disruption_budget_v1.main.status[0].current_healthy, null)
    desired_healthy      = try(kubernetes_pod_disruption_budget_v1.main.status[0].desired_healthy, null)
  }
}

############################################
# Release metadata (ConfigMap, if provided) #
############################################

output "release_metadata" {
  description = "Технические метаданные релиза (ConfigMap), если создаются модулем."
  value = {
    name  = try(kubernetes_config_map_v1.release_meta.metadata[0].name, null)
    data  = try(kubernetes_config_map_v1.release_meta.data, {})
    labels = try(kubernetes_config_map_v1.release_meta.metadata[0].labels, {})
  }
  sensitive = false
}

############################################
# Convenience aggregated DNS endpoints     #
############################################

output "cluster_dns_endpoints" {
  description = "Удобные FQDN сервисов внутри кластера."
  value = compact([
    try(format("%s.%s.svc", kubernetes_service_v1.main.metadata[0].name, kubernetes_service_v1.main.metadata[0].namespace), null),
    try(format("%s.%s.svc", kubernetes_service_v1.metrics.metadata[0].name, kubernetes_service_v1.metrics.metadata[0].namespace), null),
  ])
}
