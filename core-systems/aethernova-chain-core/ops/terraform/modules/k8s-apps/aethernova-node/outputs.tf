# aethernova-chain-core/ops/terraform/modules/k8s-apps/aethernova-node/outputs.tf
#############################
# Industrial-grade outputs  #
#############################

# Вспомогательные локали: безопасное определение namespace.
locals {
  ns = try(kubernetes_namespace_v1.this.metadata[0].name, "default")
}

########################################
# Namespace и ServiceAccount (опцион.) #
########################################

output "namespace" {
  description = "Kubernetes namespace, в котором развернут узел."
  value       = local.ns
}

output "service_account_name" {
  description = "Имя ServiceAccount (если модуль его создаёт)."
  value       = try(kubernetes_service_account_v1.this.metadata[0].name, null)
}

#########################
# Сервис P2P (опцион.)  #
#########################

output "p2p_service" {
  description = "Параметры Service для p2p."
  value = {
    name        = try(kubernetes_service_v1.p2p.metadata[0].name, null)
    type        = try(kubernetes_service_v1.p2p.spec[0].type, null)
    cluster_ip  = try(kubernetes_service_v1.p2p.spec[0].cluster_ip, null)
    ports = try([
      for p in kubernetes_service_v1.p2p.spec[0].port : {
        name        = try(p.name, null)
        port        = p.port
        target_port = try(p.target_port, null)
        node_port   = try(p.node_port, null)
        protocol    = try(p.protocol, null)
      }
    ], [])
    # Внутрикластерный FQDN по стандартной схеме Service DNS.
    cluster_dns = try(
      format("%s.%s.svc", kubernetes_service_v1.p2p.metadata[0].name, local.ns),
      null
    )
    # Адреса LoadBalancer, если тип=LoadBalancer.
    load_balancer_ingress = try([
      for i in kubernetes_service_v1.p2p.status[0].load_balancer[0].ingress :
      coalesce(try(i.ip, null), try(i.hostname, null))
    ], [])
  }
}

#########################
# Сервис RPC (опцион.)  #
#########################

output "rpc_service" {
  description = "Параметры Service для RPC/API."
  value = {
    name        = try(kubernetes_service_v1.rpc.metadata[0].name, null)
    type        = try(kubernetes_service_v1.rpc.spec[0].type, null)
    cluster_ip  = try(kubernetes_service_v1.rpc.spec[0].cluster_ip, null)
    ports = try([
      for p in kubernetes_service_v1.rpc.spec[0].port : {
        name        = try(p.name, null)
        port        = p.port
        target_port = try(p.target_port, null)
        node_port   = try(p.node_port, null)
        protocol    = try(p.protocol, null)
      }
    ], [])
    cluster_dns = try(
      format("%s.%s.svc", kubernetes_service_v1.rpc.metadata[0].name, local.ns),
      null
    )
    load_balancer_ingress = try([
      for i in kubernetes_service_v1.rpc.status[0].load_balancer[0].ingress :
      coalesce(try(i.ip, null), try(i.hostname, null))
    ], [])
  }
}

############################
# Сервис Metrics (опцион.) #
############################

output "metrics_service" {
  description = "Параметры Service для метрик."
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
      format("%s.%s.svc", kubernetes_service_v1.metrics.metadata[0].name, local.ns),
      null
    )
    load_balancer_ingress = try([
      for i in kubernetes_service_v1.metrics.status[0].load_balancer[0].ingress :
      coalesce(try(i.ip, null), try(i.hostname, null))
    ], [])
  }
}

##########################
# Ingress для RPC (v1)   #
##########################

output "rpc_ingress" {
  description = "Параметры Ingress (если задействован для RPC)."
  value = {
    name  = try(kubernetes_ingress_v1.rpc.metadata[0].name, null)
    class = try(kubernetes_ingress_v1.rpc.spec[0].ingress_class_name, null)
    hosts = try([for r in kubernetes_ingress_v1.rpc.spec[0].rule : r.host], [])
    tls = {
      hosts        = try(flatten([for t in kubernetes_ingress_v1.rpc.spec[0].tls : t.hosts]), [])
      secret_names = try([for t in kubernetes_ingress_v1.rpc.spec[0].tls : t.secret_name], [])
    }
    annotations = try(kubernetes_ingress_v1.rpc.metadata[0].annotations, {})
  }
}

#########################################
# Статус StatefulSet узла (если он есть) #
#########################################

output "node_statefulset_status" {
  description = "Сводный статус StatefulSet узла."
  value = {
    name               = try(kubernetes_stateful_set_v1.node.metadata[0].name, null)
    replicas_desired   = try(kubernetes_stateful_set_v1.node.spec[0].replicas, null)
    replicas_ready     = try(kubernetes_stateful_set_v1.node.status[0].ready_replicas, 0)
    replicas_updated   = try(kubernetes_stateful_set_v1.node.status[0].updated_replicas, 0)
    replicas_available = try(kubernetes_stateful_set_v1.node.status[0].current_replicas, 0)
    current_revision   = try(kubernetes_stateful_set_v1.node.status[0].current_revision, null)
    update_revision    = try(kubernetes_stateful_set_v1.node.status[0].update_revision, null)
    selector_labels    = try(kubernetes_stateful_set_v1.node.spec[0].selector[0].match_labels, {})
  }
}

#########################################
# Удобные ссылки для Service DNS внутри #
#########################################

output "cluster_dns_endpoints" {
  description = "Удобные FQDN для сервисов внутри кластера (svc)."
  value = compact([
    try(format("%s.%s.svc", kubernetes_service_v1.p2p.metadata[0].name, local.ns), null),
    try(format("%s.%s.svc", kubernetes_service_v1.rpc.metadata[0].name, local.ns), null),
    try(format("%s.%s.svc", kubernetes_service_v1.metrics.metadata[0].name, local.ns), null),
  ])
}

###############################
# Техническая мета по релизу  #
###############################

output "release_metadata" {
  description = "Технические метаданные релиза модуля/приложения, если создаются."
  value = {
    configmap = try(kubernetes_config_map_v1.release_meta.metadata[0].name, null)
    labels    = try(kubernetes_config_map_v1.release_meta.metadata[0].labels, {})
    data      = try(kubernetes_config_map_v1.release_meta.data, {})
  }
  sensitive = false
}
