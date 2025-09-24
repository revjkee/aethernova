terraform {
  required_version = ">= 1.4.0"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.10.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.1"
    }
  }
}

#########################
# Inputs (module vars)  #
#########################

variable "name" {
  description = "Имя релиза/полное имя ресурсов (fullnameOverride)."
  type        = string
}

variable "namespace" {
  description = "Namespace, в котором будет установлен Redis."
  type        = string
}

variable "create_namespace" {
  description = "Создавать namespace (true) или ожидать, что он уже существует (false)."
  type        = bool
  default     = false
}

variable "repository" {
  description = "Helm-репозиторий с чартом Redis."
  type        = string
  default     = "https://charts.bitnami.com/bitnami"
}

variable "chart_version" {
  description = "Версия чарта Bitnami/redis (рекомендуется зафиксировать). Если пусто, берётся latest."
  type        = string
  default     = ""
}

variable "architecture" {
  description = "Архитектура Redis: standalone или replication."
  type        = string
  default     = "replication"
  validation {
    condition     = contains(["standalone", "replication"], var.architecture)
    error_message = "architecture must be 'standalone' or 'replication'."
  }
}

variable "replica_count" {
  description = "Число реплик для режима replication."
  type        = number
  default     = 2
}

variable "storage_class" {
  description = "StorageClass для PVC; пустая строка — оставить по умолчанию в кластере."
  type        = string
  default     = ""
}

variable "master_persistence_size" {
  description = "Размер PVC для master."
  type        = string
  default     = "10Gi"
}

variable "replica_persistence_size" {
  description = "Размер PVC для replica (если replication)."
  type        = string
  default     = "10Gi"
}

variable "service_type" {
  description = "Тип Service (ClusterIP/NodePort/LoadBalancer)."
  type        = string
  default     = "ClusterIP"
  validation {
    condition     = contains(["ClusterIP", "NodePort", "LoadBalancer"], var.service_type)
    error_message = "service_type must be ClusterIP, NodePort, or LoadBalancer."
  }
}

variable "enable_metrics" {
  description = "Включить экспорт метрик (redis-exporter) и ServiceMonitor."
  type        = bool
  default     = true
}

variable "service_monitor_namespace" {
  description = "Namespace, где работает Prometheus Operator (если отличается). Пусто — в текущем."
  type        = string
  default     = ""
}

variable "service_monitor_interval" {
  description = "Интервал scrape для ServiceMonitor."
  type        = string
  default     = "30s"
}

variable "service_monitor_additional_labels" {
  description = "Дополнительные метки для ServiceMonitor."
  type        = map(string)
  default     = {}
}

variable "network_policy_enabled" {
  description = "Включить сетевые политики (ограниченный ingress)."
  type        = bool
  default     = true
}

variable "ingress_ns_match_labels" {
  description = "Метки namespace, из которых разрешён ingress к Redis (NetworkPolicy.ingressNSMatchLabels)."
  type        = map(string)
  default     = {}
}

variable "ingress_ns_pod_match_labels" {
  description = "Метки pod в разрешённых namespace для ingress (NetworkPolicy.ingressNSPodMatchLabels)."
  type        = map(string)
  default     = {}
}

variable "tls_enabled" {
  description = "Включить TLS для Redis."
  type        = bool
  default     = false
}

variable "tls_existing_secret" {
  description = "Имя существующего секрета с TLS (ключи: tls.crt, tls.key, ca.crt). Обязательно при tls_enabled=true."
  type        = string
  default     = ""
}

variable "manage_password_secret" {
  description = "Создавать секрет с паролем (true) или использовать существующий (false)."
  type        = bool
  default     = true
}

variable "password_secret_name" {
  description = "Имя секрета с паролем Redis. Если manage_password_secret=false, секрет должен существовать заранее."
  type        = string
  default     = "redis-auth"
}

variable "password_override" {
  description = "Необязательный переопределяемый пароль; если пусто — будет сгенерирован."
  type        = string
  default     = ""
  sensitive   = true
}

variable "labels" {
  description = "Единые метки для всех создаваемых ресурсов (commonLabels)."
  type        = map(string)
  default     = {}
}

variable "annotations" {
  description = "Единые аннотации для всех создаваемых ресурсов (commonAnnotations)."
  type        = map(string)
  default     = {}
}

variable "node_selector" {
  description = "NodeSelector для pod."
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Список tolerations."
  type        = list(any)
  default     = []
}

variable "affinity" {
  description = "Политики affinity/anti-affinity (переопределяют пресеты)."
  type        = any
  default     = {}
}

variable "master_resources" {
  description = "Ресурсы для master (requests/limits)."
  type = object({
    requests = optional(map(string), {})
    limits   = optional(map(string), {})
  })
  default = {
    requests = { cpu = "100m", memory = "256Mi" }
    limits   = { cpu = "500m", memory = "512Mi" }
  }
}

variable "replica_resources" {
  description = "Ресурсы для replica (requests/limits)."
  type = object({
    requests = optional(map(string), {})
    limits   = optional(map(string), {})
  })
  default = {
    requests = { cpu = "100m", memory = "256Mi" }
    limits   = { cpu = "500m", memory = "512Mi" }
  }
}

############################
# Namespace (optional)     #
############################

resource "kubernetes_namespace" "this" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name        = var.namespace
    labels      = var.labels
    annotations = var.annotations
  }
}

############################
# Password secret handling #
############################

resource "random_password" "redis" {
  length           = 32
  special          = true
  override_special = "_%@#^+-="
}

locals {
  resolved_password = length(var.password_override) > 0 ? var.password_override : random_password.redis.result
}

resource "kubernetes_secret" "auth" {
  count = var.manage_password_secret ? 1 : 0

  metadata {
    name      = var.password_secret_name
    namespace = var.namespace
    labels    = var.labels
  }

  data = {
    # ключ ожидается чартом Bitnami/redis
    "redis-password" = local.resolved_password
  }

  type = "Opaque"
}

#################################
# Helm values (Bitnami/redis)   #
#################################

locals {
  redis_values = {
    fullnameOverride = var.name
    architecture     = var.architecture

    commonLabels      = var.labels
    commonAnnotations = var.annotations

    auth = {
      enabled                     = true
      existingSecret              = var.password_secret_name
      existingSecretPasswordKey   = "redis-password"
    }

    master = {
      podSecurityContext = {
        enabled         = true
        runAsNonRoot    = true
        fsGroup         = 1001
        seccompProfile  = { type = "RuntimeDefault" }
      }
      containerSecurityContext = {
        enabled                   = true
        runAsUser                 = 1001
        allowPrivilegeEscalation  = false
        readOnlyRootFilesystem    = true
        capabilities              = { drop = ["ALL"] }
      }
      persistence = {
        enabled      = true
        size         = var.master_persistence_size
        storageClass = var.storage_class != "" ? var.storage_class : null
      }
      resources      = var.master_resources
      nodeSelector   = var.node_selector
      tolerations    = var.tolerations
      affinity       = var.affinity
      podAntiAffinityPreset = "hard"
      service = {
        type = var.service_type
      }
    }

    # параметры для реплик учитываются только при architecture = "replication"
    replica = {
      replicaCount = var.replica_count
      podSecurityContext = {
        enabled         = true
        runAsNonRoot    = true
        fsGroup         = 1001
        seccompProfile  = { type = "RuntimeDefault" }
      }
      containerSecurityContext = {
        enabled                   = true
        runAsUser                 = 1001
        allowPrivilegeEscalation  = false
        readOnlyRootFilesystem    = true
        capabilities              = { drop = ["ALL"] }
      }
      persistence = {
        enabled      = true
        size         = var.replica_persistence_size
        storageClass = var.storage_class != "" ? var.storage_class : null
      }
      resources      = var.replica_resources
      nodeSelector   = var.node_selector
      tolerations    = var.tolerations
      affinity       = var.affinity
      podAntiAffinityPreset = "hard"
    }

    networkPolicy = var.network_policy_enabled ? {
      enabled                  = true
      allowExternal            = false
      ingressNSMatchLabels     = var.ingress_ns_match_labels
      ingressNSPodMatchLabels  = var.ingress_ns_pod_match_labels
    } : {
      enabled = false
    }

    metrics = var.enable_metrics ? {
      enabled = true
      serviceMonitor = {
        enabled   = true
        namespace = var.service_monitor_namespace != "" ? var.service_monitor_namespace : null
        interval  = var.service_monitor_interval
        labels    = var.service_monitor_additional_labels
      }
    } : {
      enabled = false
    }

    tls = var.tls_enabled ? {
      enabled        = true
      authClients    = true
      autoGenerated  = false
      existingSecret = var.tls_existing_secret
      certFilename   = "tls.crt"
      certKeyFilename= "tls.key"
      caCertFilename = "ca.crt"
    } : {
      enabled = false
    }
  }
}

#########################
# Helm release (Redis)  #
#########################

resource "helm_release" "redis" {
  name       = var.name
  repository = var.repository
  chart      = "redis"
  namespace  = var.namespace

  # Если версия не указана (""), helm использует latest — рекомендуется передавать фиксированную версию снаружи.
  version = var.chart_version != "" ? var.chart_version : null

  # Установка после возможного создания namespace
  depends_on = [
    kubernetes_namespace.this,
    kubernetes_secret.auth
  ]

  values = [
    yamlencode(local.redis_values)
  ]

  # Консервативные таймауты/поведение
  atomic          = true
  cleanup_on_fail = true
  wait            = true
  timeout         = 900
  recreate_pods   = true
}

#########################
# Outputs               #
#########################

output "release_name" {
  description = "Имя Helm-релиза Redis."
  value       = helm_release.redis.name
}

output "namespace" {
  description = "Namespace, где установлен Redis."
  value       = var.namespace
}

output "password_secret_name" {
  description = "Секрет с паролем Redis."
  value       = var.password_secret_name
  sensitive   = false
}

output "redis_values_debug" {
  description = "Фактические values, поданные в чарт (для отладки)."
  value       = local.redis_values
  sensitive   = true
}
