terraform {
  required_version = ">= 1.6.0"
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12.1"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.22.0"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = ">= 1.14.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}

# -----------------------------
# Variables (все ключевые настраиваемы)
# -----------------------------
variable "name" {
  type        = string
  description = "Базовое имя релиза наблюдаемости."
  default     = "pic-observability"
}

variable "namespace" {
  type        = string
  description = "Namespace для стека наблюдаемости."
  default     = "observability"
}

variable "create_namespace" {
  type        = bool
  description = "Создавать namespace."
  default     = true
}

# Версию chart необходимо задавать явно на окружении (производственный контроль).
variable "kube_prometheus_stack_version" {
  type        = string
  description = "Версия chart prometheus-community/kube-prometheus-stack (обязательна)."
}

variable "grafana_enabled" {
  type        = bool
  description = "Включить Grafana."
  default     = true
}

variable "grafana_service_type" {
  type        = string
  description = "Тип сервиса Grafana (ClusterIP/NodePort/LoadBalancer)."
  default     = "ClusterIP"
}

variable "grafana_ingress_enabled" {
  type        = bool
  description = "Включить Ingress для Grafana."
  default     = false
}

variable "grafana_ingress_class_name" {
  type        = string
  description = "Класс ingress для Grafana (например, nginx/traefik)."
  default     = null
}

variable "grafana_hosts" {
  type        = list(string)
  description = "Список хостов для Ingress Grafana."
  default     = []
}

variable "grafana_path" {
  type        = string
  description = "Путь Ingress Grafana."
  default     = "/"
}

variable "grafana_annotations" {
  type        = map(string)
  description = "Аннотации Ingress Grafana."
  default     = {}
}

variable "grafana_resources" {
  type        = any
  description = "Ресурсы Grafana (k8s resources)."
  default = {
    requests = { cpu = "100m", memory = "256Mi" }
    limits   = { cpu = "500m", memory = "512Mi" }
  }
}

# Секреты Grafana: по умолчанию используйте существующий секрет (без хранения пароля в стейте).
variable "grafana_admin_existing_secret_name" {
  type        = string
  description = "Имя существующего секрета с admin логином/паролем Grafana."
  default     = ""
}

variable "grafana_admin_user_key" {
  type        = string
  description = "Ключ в секрете для имени пользователя Grafana."
  default     = "admin-user"
}

variable "grafana_admin_password_key" {
  type        = string
  description = "Ключ в секрете для пароля Grafana."
  default     = "admin-password"
}

variable "create_grafana_admin_secret" {
  type        = bool
  description = "Создать секрет для Grafana (пароль попадёт в state; для продакшна предпочтителен existingSecret)."
  default     = false
}

variable "grafana_admin_user" {
  type        = string
  description = "Admin user для создаваемого секрета Grafana."
  default     = "admin"
}

variable "grafana_admin_password_length" {
  type        = number
  description = "Длина генерируемого пароля Grafana."
  default     = 24
}

# Датасорсы и дашборды Grafana
variable "grafana_additional_datasources" {
  description = "Дополнительные data sources для Grafana (см. формат grafana.additionalDataSources)."
  type        = list(any)
  default     = []
}

variable "grafana_dashboards_json" {
  description = "Карта дашбордов Grafana: имя => JSON содержимое."
  type        = map(string)
  default     = {}
}

# Prometheus
variable "prometheus_retention" {
  type        = string
  description = "Период хранения метрик Prometheus (например, 15d)."
  default     = "15d"
}

variable "prometheus_retention_size" {
  type        = string
  description = "Ограничение размера хранилища Prometheus (например, 50Gi)."
  default     = null
}

variable "prometheus_storage_size" {
  type        = string
  description = "Размер PVC для Prometheus."
  default     = "100Gi"
}

variable "prometheus_storage_class" {
  type        = string
  description = "StorageClass для Prometheus (null для по умолчанию)."
  default     = null
}

variable "prometheus_resources" {
  type        = any
  description = "Ресурсы Prometheus."
  default = {
    requests = { cpu = "500m", memory = "2Gi" }
    limits   = { cpu = "2",    memory = "6Gi" }
  }
}

variable "prometheus_remote_write" {
  description = "remote_write конфигурация Prometheus (список объектов Prometheus remote_write)."
  type        = list(any)
  default     = []
}

# Alertmanager
variable "alertmanager_enabled" {
  type        = bool
  description = "Включить Alertmanager."
  default     = true
}

variable "alertmanager_config_yaml" {
  type        = string
  description = "Конфигурация Alertmanager в YAML (route/receivers). Пустая строка — без переопределения."
  default     = ""
}

variable "alertmanager_storage_size" {
  type        = string
  description = "Размер PVC для Alertmanager."
  default     = "10Gi"
}

variable "alertmanager_storage_class" {
  type        = string
  description = "StorageClass для Alertmanager."
  default     = null
}

variable "alertmanager_resources" {
  type        = any
  description = "Ресурсы Alertmanager."
  default = {
    requests = { cpu = "100m", memory = "256Mi" }
    limits   = { cpu = "500m", memory = "512Mi" }
  }
}

# Дополнительные конфиги Prometheus (scrape) — YAML, попадёт в Secret.
variable "prometheus_additional_scrape_configs_yaml" {
  type        = string
  description = "YAML для additionalScrapeConfigs."
  default     = ""
}

# CRD объекты: PrometheusRule и ServiceMonitor
variable "prometheus_rules_yaml" {
  type        = string
  description = "YAML манифест(ы) PrometheusRule (можно multi‑doc). Пусто — не применять."
  default     = ""
}

variable "create_service_monitor" {
  type        = bool
  description = "Создать ServiceMonitor для physical-integration-core."
  default     = true
}

variable "service_monitor_label_key" {
  type        = string
  description = "Ключ метки для селектора ServiceMonitor."
  default     = "app.kubernetes.io/part-of"
}

variable "service_monitor_label_value" {
  type        = string
  description = "Значение метки для селектора ServiceMonitor."
  default     = "physical-integration-core"
}

variable "service_monitor_port" {
  type        = string
  description = "Имя порта сервиса с метриками."
  default     = "http"
}

variable "service_monitor_path" {
  type        = string
  description = "HTTP путь метрик."
  default     = "/metrics"
}

variable "service_monitor_interval" {
  type        = string
  description = "Интервал опроса метрик ServiceMonitor."
  default     = "30s"
}

# Безопасность сети (по умолчанию выключено, чтобы не сломать трафик)
variable "enable_network_policies" {
  type        = bool
  description = "Создавать базовые NetworkPolicy (осторожно)."
  default     = false
}

# Дополнительные values для Helm (низкоуровневые тюнинги)
variable "extra_values" {
  type        = any
  description = "Дополнительные YAML values, которые будут мёрджиться последними."
  default     = {}
}

# -----------------------------
# Namespace
# -----------------------------
resource "kubernetes_namespace_v1" "this" {
  count = var.create_namespace ? 1 : 0
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "observability.stack"          = var.name
    }
  }
}

# -----------------------------
# Grafana admin secret (опционально; пароль в state!)
# -----------------------------
resource "random_password" "grafana_admin" {
  count   = var.create_grafana_admin_secret ? 1 : 0
  length  = var.grafana_admin_password_length
  special = true
}

resource "kubernetes_secret_v1" "grafana_admin" {
  count = var.create_grafana_admin_secret ? 1 : 0
  metadata {
    name      = "${var.name}-grafana-admin"
    namespace = var.namespace
    labels = {
      "app.kubernetes.io/name" = "grafana"
      "app.kubernetes.io/part-of" = "observability"
    }
  }
  string_data = {
    (var.grafana_admin_user_key)     = var.grafana_admin_user
    (var.grafana_admin_password_key) = random_password.grafana_admin[0].result
  }
}

# -----------------------------
# Locals: values для Helm
# -----------------------------
locals {
  grafana_admin_secret_name = (
    var.grafana_admin_existing_secret_name != "" ? var.grafana_admin_existing_secret_name :
    (var.create_grafana_admin_secret ? kubernetes_secret_v1.grafana_admin[0].metadata[0].name : null)
  )

  grafana_dashboards_mapped = {
    default = {
      for k, v in var.grafana_dashboards_json : k => { json = v }
    }
  }

  # Базовые values kube-prometheus-stack
  kube_prom_stack_values = {
    fullnameOverride  = var.name
    namespaceOverride = var.namespace

    grafana = merge(
      {
        enabled  = var.grafana_enabled
        service  = { type = var.grafana_service_type }
        resources = var.grafana_resources
        sidecar = {
          dashboards  = { enabled = true }
          datasources = { enabled = true }
        }
        dashboardProviders = {
          "dashboardproviders.yaml" = {
            apiVersion = 1
            providers = [
              {
                name             = "default"
                orgId            = 1
                folder           = ""
                type             = "file"
                disableDeletion  = false
                allowUiUpdates   = true
                options          = { path = "/var/lib/grafana/dashboards" }
              }
            ]
          }
        }
        dashboards = local.grafana_dashboards_mapped
        additionalDataSources = var.grafana_additional_datasources
        ingress = {
          enabled     = var.grafana_ingress_enabled
          className   = var.grafana_ingress_class_name
          annotations = var.grafana_annotations
          path        = var.grafana_path
          hosts       = var.grafana_hosts
        }
      },
      local.grafana_admin_secret_name == null ? {} : {
        admin = {
          existingSecret = local.grafana_admin_secret_name
          userKey        = var.grafana_admin_user_key
          passwordKey    = var.grafana_admin_password_key
        }
      }
    )

    alertmanager = var.alertmanager_enabled ? {
      enabled = true
      alertmanagerSpec = {
        resources = var.alertmanager_resources
        storage   = {
          volumeClaimTemplate = {
            spec = {
              accessModes = ["ReadWriteOnce"]
              resources   = { requests = { storage = var.alertmanager_storage_size } }
              storageClassName = var.alertmanager_storage_class
            }
          }
        }
      }
      # Если конфиг пуст — поле не навязываем
      # (helm провайдер игнорирует null через yamlencode)
      config = length(trimspace(var.alertmanager_config_yaml)) > 0 ? var.alertmanager_config_yaml : null
    } : {
      enabled = false
    }

    prometheus = {
      prometheusSpec = {
        retention     = var.prometheus_retention
        retentionSize = var.prometheus_retention_size
        resources     = var.prometheus_resources

        serviceMonitorSelectorNilUsesHelmValues = false
        podMonitorSelectorNilUsesHelmValues     = false
        ruleSelectorNilUsesHelmValues           = false

        storageSpec = {
          volumeClaimTemplate = {
            spec = {
              accessModes      = ["ReadWriteOnce"]
              storageClassName = var.prometheus_storage_class
              resources        = { requests = { storage = var.prometheus_storage_size } }
            }
          }
        }

        remoteWrite = length(var.prometheus_remote_write) > 0 ? var.prometheus_remote_write : null

        additionalScrapeConfigs = length(trimspace(var.prometheus_additional_scrape_configs_yaml)) > 0 ? {
          name = "${var.name}-prom-additional-scrape"
          key  = "additional-scrape-configs.yaml"
        } : null
      }
    }

    kubeStateMetrics = { enabled = true }
    nodeExporter     = { enabled = true }
  }

  merged_values = merge(local.kube_prom_stack_values, var.extra_values)
}

# Secret для additionalScrapeConfigs, если задан
resource "kubernetes_secret_v1" "prom_additional_scrape" {
  count = length(trimspace(var.prometheus_additional_scrape_configs_yaml)) > 0 ? 1 : 0
  metadata {
    name      = "${var.name}-prom-additional-scrape"
    namespace = var.namespace
    labels = {
      "app.kubernetes.io/part-of" = "observability"
      "app.kubernetes.io/name"    = "prometheus"
    }
  }
  data = {
    "additional-scrape-configs.yaml" = base64encode(var.prometheus_additional_scrape_configs_yaml)
  }
}

# -----------------------------
# Helm release: kube-prometheus-stack
# -----------------------------
resource "helm_release" "kube_prometheus_stack" {
  name       = var.name
  namespace  = var.namespace
  repository = "https://prometheus-community.g
