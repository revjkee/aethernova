// aethernova-chain-core/ops/terraform/modules/k8s-observability/prometheus-stack/main.tf

terraform {
  required_version = ">= 1.6.0"

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
      version = ">= 3.5.0"
    }
  }
}

#################################
# Variables
#################################

variable "release_name" {
  type        = string
  description = "Имя релиза Helm."
  default     = "kube-prometheus-stack"
}

variable "namespace" {
  type        = string
  description = "Namespace для стека мониторинга."
  default     = "monitoring"
}

variable "chart_version" {
  type        = string
  description = "Версия чарта kube-prometheus-stack. Если null — будет установлена текущая в репозитории (не рекомендуется для prod)."
  default     = null
}

variable "repository" {
  type        = string
  description = "Helm-репозиторий prometheus-community."
  default     = "https://prometheus-community.github.io/helm-charts"
}

variable "cluster_name" {
  type        = string
  description = "Метка externalLabels.cluster для Prometheus."
  default     = "aethernova-cluster"
}

variable "grafana_enabled" {
  type        = bool
  description = "Включить встроенную Grafana (сабчарт grafana)."
  default     = true
}

variable "grafana_ingress_enabled" {
  type        = bool
  description = "Включить Ingress для Grafana."
  default     = false
}

variable "grafana_ingress_class_name" {
  type        = string
  description = "ingressClassName для Grafana."
  default     = null
}

variable "grafana_hosts" {
  type        = list(string)
  description = "Список хостнеймов для Ingress Grafana."
  default     = []
}

variable "grafana_admin_username" {
  type        = string
  description = "Admin username для Grafana (если используем Secret)."
  default     = "admin"
}

variable "grafana_admin_existing_secret" {
  type        = string
  description = "Если указан, модуль НЕ создаёт секрет и использует его (должны быть ключи admin-user/admin-password)."
  default     = ""
}

variable "grafana_persistence_enabled" {
  type        = bool
  description = "Включить PVC для Grafana."
  default     = true
}

variable "grafana_storage_class" {
  type        = string
  description = "StorageClass для PVC Grafana."
  default     = null
}

variable "grafana_storage_size" {
  type        = string
  description = "Размер PVC Grafana."
  default     = "10Gi"
}

variable "alertmanager_enabled" {
  type        = bool
  description = "Включить Alertmanager."
  default     = true
}

variable "prometheus_retention" {
  type        = string
  description = "Срок хранения метрик в Prometheus (напр. 15d)."
  default     = "15d"
}

variable "prometheus_retention_size" {
  type        = string
  description = "Максимальный размер TSDB (напр. 50GB). Пусто — не ограничивать."
  default     = null
}

variable "prometheus_storage_class" {
  type        = string
  description = "StorageClass для PVC Prometheus."
  default     = null
}

variable "prometheus_storage_size" {
  type        = string
  description = "Размер PVC Prometheus."
  default     = "50Gi"
}

variable "prometheus_resources" {
  type = object({
    limits = optional(map(string), {})
    requests = optional(map(string), {
      cpu    = "500m"
      memory = "2Gi"
    })
  })
  description = "Ресурсы Prometheus."
  default     = {}
}

variable "enable_cross_namespace_monitors" {
  type        = bool
  description = "Если true — Prometheus будет читать ServiceMonitor/PodMonitor/PrometheusRule из всех namespaces (namespace selectors = {})."
  default     = true
}

variable "remote_write_enabled" {
  type        = bool
  description = "Включить Prometheus remote_write (например, в Grafana Cloud)."
  default     = false
}

variable "remote_write_url" {
  type        = string
  description = "URL endpoint для remote_write."
  default     = ""
}

variable "remote_write_username" {
  type        = string
  description = "Имя пользователя для basicAuth remote_write. Игнорируется, если remote_write_enabled = false."
  default     = ""
}

variable "remote_write_password" {
  type        = string
  description = "Пароль/токен для basicAuth remote_write. Игнорируется, если remote_write_enabled = false."
  default     = ""
  sensitive   = true
}

variable "timeout_seconds" {
  type        = number
  description = "Таймаут ожидания установки Helm релиза."
  default     = 600
}

# Метки Pod Security Admission для namespace.
variable "psa_enforce_level" {
  type        = string
  description = "Уровень PSA для enforce (baseline|restricted|privileged). Рекомендуется baseline для совместимости с node-exporter."
  default     = "baseline"
}

variable "psa_warn_level" {
  type        = string
  description = "Уровень PSA для warn."
  default     = "restricted"
}

variable "psa_audit_level" {
  type        = string
  description = "Уровень PSA для audit."
  default     = "restricted"
}

#################################
# Namespace с PSA-метками
#################################

resource "kubernetes_namespace" "this" {
  metadata {
    name = var.namespace
    labels = {
      "pod-security.kubernetes.io/enforce"        = var.psa_enforce_level
      "pod-security.kubernetes.io/enforce-version" = "latest"
      "pod-security.kubernetes.io/warn"           = var.psa_warn_level
      "pod-security.kubernetes.io/warn-version"   = "latest"
      "pod-security.kubernetes.io/audit"          = var.psa_audit_level
      "pod-security.kubernetes.io/audit-version"  = "latest"
    }
  }
}

#################################
# Grafana admin Secret (если не передан существующий)
#################################

resource "random_password" "grafana_admin" {
  length           = 24
  special          = true
  override_special = "_!@#%^&*()-=+"
}

locals {
  grafana_admin_secret_name = var.grafana_enabled ? (
    var.grafana_admin_existing_secret != "" ?
    var.grafana_admin_existing_secret :
    "${var.release_name}-grafana-admin"
  ) : null
}

resource "kubernetes_secret" "grafana_admin" {
  count = var.grafana_enabled && var.grafana_admin_existing_secret == "" ? 1 : 0

  metadata {
    name      = local.grafana_admin_secret_name
    namespace = var.namespace
  }
  type = "Opaque"

  data = {
    "admin-user"     = base64encode(var.grafana_admin_username)
    "admin-password" = base64encode(random_password.grafana_admin.result)
  }
}

#################################
# Secret для remote_write (опционально)
#################################

locals {
  remote_write_secret_name = var.remote_write_enabled ? "${var.release_name}-prom-remote-write" : null
}

resource "kubernetes_secret" "remote_write" {
  count = var.remote_write_enabled ? 1 : 0

  metadata {
    name      = local.remote_write_secret_name
    namespace = var.namespace
  }
  type = "Opaque"

  data = {
    "username" = base64encode(var.remote_write_username)
    "password" = base64encode(var.remote_write_password)
  }
}

#################################
# Значения чарта через yamlencode(local.values)
#################################

locals {
  cross_ns_selector = var.enable_cross_namespace_monitors ? {} : null

  prometheus_spec = merge(
    {
      retention        = var.prometheus_retention
      walCompression   = true
      externalLabels   = { cluster = var.cluster_name }
      resources        = var.prometheus_resources
      storageSpec = {
        volumeClaimTemplate = {
          spec = {
            accessModes      = ["ReadWriteOnce"]
            storageClassName = var.prometheus_storage_class
            resources = {
              requests = {
                storage = var.prometheus_storage_size
              }
            }
          }
        }
      }
    },
    var.prometheus_retention_size != null ? { retentionSize = var.prometheus_retention_size } : {},
    var.enable_cross_namespace_monitors ? {
      serviceMonitorSelector        = {}
      serviceMonitorNamespaceSelector = {}
      podMonitorSelector            = {}
      podMonitorNamespaceSelector   = {}
      ruleSelector                  = {}
      ruleNamespaceSelector         = {}
    } : {}
  )

  grafana_values = var.grafana_enabled ? {
    enabled = true
    admin = {
      # Используем существующий/созданный Secret и стандартные ключи admin-user/admin-password
      existingSecret = local.grafana_admin_secret_name
      userKey        = "admin-user"
      passwordKey    = "admin-password"
    }
    persistence = {
      enabled          = var.grafana_persistence_enabled
      size             = var.grafana_storage_size
      storageClassName = var.grafana_storage_class
    }
    ingress = {
      enabled     = var.grafana_ingress_enabled
      className   = var.grafana_ingress_class_name
      hosts       = var.grafana_hosts
      path        = "/"
      pathType    = "Prefix"
    }
  } : {
    enabled = false
  }

  remote_write_block = var.remote_write_enabled ? [{
    url = var.remote_write_url
    basicAuth = {
      username = {
        name = local.remote_write_secret_name
        key  = "username"
      }
      password = {
        name = local.remote_write_secret_name
        key  = "password"
      }
    }
  }] : []

  values = {
    # Включаем ключевые компоненты стека
    kubeStateMetrics = { enabled = true }
    nodeExporter     = { enabled = true }

    alertmanager = {
      enabled = var.alertmanager_enabled
      alertmanagerSpec = {
        # Пример простой persistence (опционально можно добавить PVC)
        storage = {
          volumeClaimTemplate = {
            spec = {
              accessModes = ["ReadWriteOnce"]
              resources = {
                requests = { storage = "10Gi" }
              }
            }
          }
        }
      }
    }

    grafana = local.grafana_values

    prometheus = {
      prometheusSpec = merge(local.prometheus_spec, {
        remoteWrite = local.remote_write_block
      })
    }

    # Разрешаем создание CRD/ресурсов оператором (по умолчанию чарт содержит CRDs)
    prometheusOperator = {
      enabled = true
      # admissionWebhooks и прочие дефолты чартом включены
    }
  }
}

#################################
# Helm release kube-prometheus-stack
#################################

resource "helm_release" "kps" {
  name             = var.release_name
  repository       = var.repository
  chart            = "kube-prometheus-stack"
  version          = var.chart_version
  namespace        = var.namespace
  create_namespace = false

  atomic           = true
  cleanup_on_fail  = true
  dependency_update = true
  wait             = true
  timeout          = var.timeout_seconds

  values = [
    yamlencode(local.values)
  ]

  depends_on = [
    kubernetes_namespace.this,
    # Зависимости на секреты — только если они создаются в этом модуле
    kubernetes_secret.grafana_admin,
    kubernetes_secret.remote_write
  ]
}

#################################
# Outputs
#################################

output "release_name" {
  description = "Имя релиза Helm."
  value       = helm_release.kps.name
}

output "namespace" {
  description = "Namespace релиза."
  value       = var.namespace
}

output "chart_version_effective" {
  description = "Итоговая версия чарта (если не задана — вернёт установленную провайдером)."
  value       = try(helm_release.kps.version, var.chart_version)
}

output "grafana_admin_secret_name" {
  description = "Имя секрета с admin-учёткой Grafana (если grafana_enabled)."
  value       = local.grafana_admin_secret_name
  sensitive   = false
}

output "remote_write_secret_name" {
  description = "Имя секрета для Prometheus remote_write (если включено)."
  value       = local.remote_write_secret_name
  sensitive   = false
}
