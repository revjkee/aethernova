#############################################
# k8s-apps/explorer — Outputs (Terraform)
# Промышленная версия: безопасные опции, устойчивые вычисления, без утечек секретов
#############################################

############################
# Опции выборки из кластера
############################
variable "namespace" {
  description = "Namespace, где развёрнут explorer."
  type        = string
}

variable "service_name" {
  description = "Имя Kubernetes Service для explorer (обычно 'explorer' или '<release>-server')."
  type        = string
  default     = "explorer"
}

variable "ingress_name" {
  description = "Имя Kubernetes Ingress для explorer (если используется)."
  type        = string
  default     = "explorer"
}

variable "lookup_service" {
  description = "Если true — читать атрибуты Service и LB для формирования выводов."
  type        = bool
  default     = true
}

variable "lookup_ingress" {
  description = "Если true — читать атрибуты Ingress (hostnames/правила/статус)."
  type        = bool
  default     = true
}

#################################
# Data sources: безопасные lookup
#################################
# Сервис (ClusterIP/NodePort/LB) — официальная схема данных service_v1
data "kubernetes_service_v1" "explorer" {
  count = var.lookup_service ? 1 : 0
  metadata {
    name      = var.service_name
    namespace = var.namespace
  }
}

# Ingress (hostname/правила/статус) — официальная схема данных ingress_v1
# Важно: некоторые кластеры/провайдеры возвращают status позднее; поле может быть null до готовности.
data "kubernetes_ingress_v1" "explorer" {
  count = var.lookup_ingress ? 1 : 0
  metadata {
    name      = var.ingress_name
    namespace = var.namespace
  }
}

#####################
# Локальные вычисления
#####################
locals {
  # Service details
  svc_type       = try(data.kubernetes_service_v1.explorer[0].spec[0].type, null)
  svc_cluster_ip = try(data.kubernetes_service_v1.explorer[0].spec[0].cluster_ip, null)
  svc_ports = [
    for p in try(data.kubernetes_service_v1.explorer[0].spec[0].port, []) : {
      name        = try(p.name, null)
      port        = p.port
      target_port = try(p.target_port, null)
      node_port   = try(p.node_port, null)
      protocol    = try(p.protocol, null)
    }
  ]

  # LoadBalancer ingress (если есть)
  lb_hostname = try(data.kubernetes_service_v1.explorer[0].status[0].load_balancer[0].ingress[0].hostname, null)
  lb_ip       = try(data.kubernetes_service_v1.explorer[0].status[0].load_balancer[0].ingress[0].ip, null)

  # Ingress hosts (из status и/или spec.rules)
  ing_status_hosts = try([
    for r in data.kubernetes_ingress_v1.explorer[0].status[0].load_balancer[0].ingress : r.hostname
  ], [])

  ing_rule_host  = try(data.kubernetes_ingress_v1.explorer[0].spec[0].rule[0].host, null)
  ingress_hosts  = length(local.ing_status_hosts) > 0 ? local.ing_status_hosts : compact([local.ing_rule_host])

  # Итоговый предпочитаемый host: Ingress → LB hostname → LB IP
  preferred_host = coalesce(
    (length(local.ingress_hosts) > 0 ? local.ingress_hosts[0] : null),
    local.lb_hostname,
    local.lb_ip
  )

  # Предполагаемый URL UI/API (HTTPS по умолчанию)
  explorer_url_guess = local.preferred_host != null ? format("https://%s", local.preferred_host) : null
}

############
# OUTPUTS
############

# Namespace приложения
output "explorer_namespace" {
  description = "Namespace, где установлен explorer."
  value       = var.namespace
}

# Сводные данные Service (тип/ClusterIP/порты) — null, если lookup выключен
output "explorer_service" {
  description = "K8s Service детали для explorer."
  value = var.lookup_service ? {
    type       = local.svc_type
    cluster_ip = local.svc_cluster_ip
    ports      = local.svc_ports
  } : null
}

# Внешний адрес LoadBalancer (если тип LB и адрес/hostname уже выдан)
output "explorer_service_lb" {
  description = "LoadBalancer ingress для Service explorer (hostname/ip), если доступно."
  value = var.lookup_service ? {
    hostname = local.lb_hostname
    ip       = local.lb_ip
  } : null
}

# Хосты Ingress (из status или spec.rules) — пустой список, если недоступно
output "explorer_ingress_hosts" {
  description = "Список хостов Ingress для explorer."
  value       = var.lookup_ingress ? local.ingress_hosts : []
}

# «Best-effort» URL входа (Ingress > LB hostname > LB IP)
output "explorer_url_guess" {
  description = "Предполагаемый внешний URL explorer."
  value       = local.explorer_url_guess
}
