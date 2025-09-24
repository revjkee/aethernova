// neuroforge-core/ops/terraform/modules/observability/main.tf

terraform {
  required_version = ">= 1.4.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.22.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12.1"
    }
  }
}

############################
# Входные переменные
############################

variable "namespace" {
  description = "Namespace для стека наблюдаемости."
  type        = string
  default     = "observability"
}

variable "create_namespace" {
  description = "Создавать namespace (если false — ожидается существование)."
  type        = bool
  default     = true
}

variable "name_prefix" {
  description = "Префикс имён Helm-релизов (obs-kps, obs-loki, obs-grafana, ...)."
  type        = string
  default     = "obs"
}

# Фичефлаги развертывания
variable "enable_prometheus_stack" { type = bool, default = true }
variable "enable_loki"             { type = bool, default = true }
variable "enable_promtail"         { type = bool, default = true }
variable "enable_tempo"            { type = bool, default = true }
variable "enable_grafana"          { type = bool, default = true }

# Версии чартов (точные строки; null => взять "последнюю" в репо — небезопасно для продакшена)
variable "kps_chart_version"    { type = string, default = null } # prometheus-community/kube-prometheus-stack
variable "loki_chart_version"   { type = string, default = null } # grafana/loki
variable "promtail_chart_version" { type = string, default = null } # grafana/promtail
variable "tempo_chart_version"  { type = string, default = null } # grafana/tempo
variable "grafana_chart_version" { type = string, default = null } # grafana/grafana

# Хранилище и ретеншн
variable "storage_class"             { type = string, default = null }
variable "prometheus_storage_size"   { type = string, default = "50Gi" }
variable "loki_storage_size"         { type = string, default = "200Gi" }
variable "tempo_storage_size"        { type = string, default = "100Gi" }
variable "grafana_storage_size"      { type = string, default = "10Gi" }
variable "prometheus_retention"      { type = string, default = "15d" }
variable "loki_retention_period"     { type = string, default = "30d" }

# Ингресс Grafana
variable "grafana_ingress_enabled" { type = bool, default = false }
variable "grafana_ingress_class"   { type = string, default = null }
variable "grafana_ingress_host"    { type = string, default = null }
variable "grafana_tls_secret_name" { type = string, default = null }

# Grafana доступ
variable "grafana_admin_user"           { type = string, default = "admin" }
variable "grafana_admin_password"       { type = string, default = null }
variable "grafana_admin_existing_secret" {
  description = "Имя Secret c ключом admin-password; если задан — пароль из него."
  type        = string
  default     = null
}

# Доп. параметры для чартов (могут переопределять дефолты)
variable "kps_extra_values"     { type = any, default = {} }
variable "loki_extra_values"    { type = any, default = {} }
variable "promtail_extra_values"{ type = any, default = {} }
variable "tempo_extra_values"   { type = any, default = {} }
variable "grafana_extra_values" { type = any, default = {} }

############################
# Локальные значения
############################

locals {
  labels_common = {
    "app.kubernetes.io/part-of" = "neuroforge-core"
    "app.kubernetes.io/managed-by" = "terraform"
  }

  # Имена релизов и сервисов
  rel = {
    kps     = "${var.name_prefix}-kps"
    loki    = "${var.name_prefix}-loki"
    promtail= "${var.name_prefix}-promtail"
    tempo   = "${var.name_prefix}-tempo"
    grafana = "${var.name_prefix}-grafana"
  }

  # Эндпойнты для Grafana datasources и Promtail
  urls = {
    prometheus = "http://${local.rel.kps}-prometheus:9090"
    loki       = "http://${local.rel.loki}:3100"
    tempo      = "http://${local.rel.tempo}:3100"
  }

  # kube-prometheus-stack values
  kps_values = merge({
    fullnameOverride = local.rel.kps
    crds = {
      enabled = true
    }
    defaultRules = {
      create = true
    }
    kubeScheduler = { enabled = true }
    kubeControllerManager = { enabled = true }
    kubeEtcd = { enabled = false } // выключите/включите под свой кластер
    prometheusOperator = {
      tls = { enabled = false }
      admissionWebhooks = { enabled = true }
    }
    prometheus = {
      service = { type = "ClusterIP" }
      prometheusSpec = {
        retention  = var.prometheus_retention
        replicas   = 1
        resources  = {}
        storageSpec = {
          volumeClaimTemplate = {
            spec = {
              accessModes = ["ReadWriteOnce"]
              resources = { requests = { storage = var.prometheus_storage_size } }
              storageClassName = var.storage_class
            }
          }
        }
        # Включить ServiceMonitor для Grafana, Loki, Tempo — собираем метрики подсистем
        additionalScrapeConfigs = []
      }
    }
    alertmanager = {
      enabled = true
      alertmanagerSpec = {
        replicas = 1
        storage  = {
          volumeClaimTemplate = {
            spec = {
              accessModes = ["ReadWriteOnce"]
              resources = { requests = { storage = "10Gi" } }
              storageClassName = var.storage_class
            }
          }
        }
      }
    }
    grafana = { enabled = false } // Grafana ставим отдельным релизом
  }, var.kps_extra_values)

  # Loki values (single-binary chart)
  loki_values = merge({
    fullnameOverride = local.rel.loki
    deploymentMode   = "SingleBinary"
    loki = {
      auth_enabled = false
      commonConfig = { replication_factor = 1 }
      storage = {
        type = "filesystem"
        filesystem = { chunks_directory = "/var/loki/chunks", rules_directory = "/var/loki/rules" }
      }
      schemaConfig = {
        configs = [{
          from        = "2024-01-01"
          store       = "tsdb"
          object_store= "filesystem"
          schema      = "v13"
          index       = { prefix = "loki_index_", period = "24h" }
        }]
      }
      ruler = { storage = { type = "local", local = { directory = "/var/loki/rules" } } }
      limits_config = {
        retention_period = var.loki_retention_period
      }
    }
    persistence = {
      enabled          = true
      size             = var.loki_storage_size
      storageClassName = var.storage_class
      accessModes      = ["ReadWriteOnce"]
    }
    serviceMonitor = { enabled = true }
  }, var.loki_extra_values)

  # Promtail values
  promtail_values = merge({
    fullnameOverride = local.rel.promtail
    serviceMonitor = { enabled = true }
    config = {
      snippets = {
        extraScrapeConfigs = []
      }
      clients = [{
        url = "${local.urls.loki}/loki/api/v1/push"
      }]
    }
  }, var.promtail_extra_values)

  # Tempo values (single)
  tempo_values = merge({
    fullnameOverride = local.rel.tempo
    tempo = {
      storage = {
        trace = {
          backend = "local"
          local   = { path = "/var/tempo/traces" }
        }
      }
      metricsGenerator = { enabled = true }
      server = { http_listen_port = 3100 }
    }
    persistence = {
      enabled          = true
      size             = var.tempo_storage_size
      storageClassName = var.storage_class
      accessModes      = ["ReadWriteOnce"]
    }
    serviceMonitor = { enabled = true }
  }, var.tempo_extra_values)

  # Grafana values
  grafana_values = merge({
    fullnameOverride = local.rel.grafana
    service = { type = "ClusterIP" }
    persistence = {
      enabled          = true
      size             = var.grafana_storage_size
      storageClassName = var.storage_class
      accessModes      = ["ReadWriteOnce"]
    }
    adminUser = var.grafana_admin_user
    # Если admin_password не задан и есть secret — используем его
    adminPassword        = var.grafana_admin_existing_secret == null ? var.grafana_admin_password : null
    admin = {
      existingSecret      = var.grafana_admin_existing_secret
      existingSecretKey   = var.grafana_admin_existing_secret == null ? null : "admin-password"
    }
    ingress = {
      enabled = var.grafana_ingress_enabled
      ingressClassName = var.grafana_ingress_class
      hosts  = var.grafana_ingress_host == null ? [] : [var.grafana_ingress_host]
      tls    = var.grafana_tls_secret_name == null ? [] : [{
        secretName = var.grafana_tls_secret_name
        hosts      = [var.grafana_ingress_host]
      }]
    }
    serviceMonitor = { enabled = true }
    datasources = {
      "datasources.yaml" = {
        apiVersion = 1
        datasources = [
          {
            name      = "Prometheus"
            type      = "prometheus"
            access    = "proxy"
            url       = local.urls.prometheus
            isDefault = true
            jsonData  = { timeInterval = "15s" }
          },
          {
            name   = "Loki"
            type   = "loki"
            access = "proxy"
            url    = local.urls.loki
          },
          {
            name   = "Tempo"
            type   = "tempo"
            access = "proxy"
            url    = local.urls.tempo
            jsonData = {
              httpMethod = "GET"
              tracesToMetrics = { datasourceUid = "loki" }
            }
          }
        ]
      }
    }
    dashboardProviders = {
      "dashboardproviders.yaml" = {
        apiVersion = 1
        providers = [{
          name = "default"
          orgId = 1
          folder = ""
          type = "file"
          disableDeletion = false
          editable = true
          options = { path = "/var/lib/grafana/dashboards/default" }
        }]
      }
    }
    dashboardsConfigMaps = {
      default = [] // Можно подтягивать свои ConfigMap с дашбордами
    }
  }, var.grafana_extra_values)
}

############################
# Namespace
############################

resource "kubernetes_namespace" "this" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name = var.namespace
    labels = local.labels_common
  }
}

############################
# kube-prometheus-stack
############################

resource "helm_release" "kps" {
  count      = var.enable_prometheus_stack ? 1 : 0
  name       = local.rel.kps
  namespace  = var.namespace
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  version    = var.kps_chart_version
  timeout    = 1200
  atomic     = true
  wait       = true
  lint       = true

  values = [yamlencode(local.kps_values)]

  depends_on = [kubernetes_namespace.this]
}

############################
# Loki
############################

resource "helm_release" "loki" {
  count      = var.enable_loki ? 1 : 0
  name       = local.rel.loki
  namespace  = var.namespace
  repository = "https://grafana.github.io/helm-charts"
  chart      = "loki"
  version    = var.loki_chart_version
  timeout    = 900
  atomic     = true
  wait       = true
  lint       = true

  values = [yamlencode(local.loki_values)]

  depends_on = [kubernetes_namespace.this]
}

############################
# Promtail (агент логов)
############################

resource "helm_release" "promtail" {
  count      = var.enable_promtail ? 1 : 0
  name       = local.rel.promtail
  namespace  = var.namespace
  repository = "https://grafana.github.io/helm-charts"
  chart      = "promtail"
  version    = var.promtail_chart_version
  timeout    = 600
  atomic     = true
  wait       = true
  lint       = true

  values = [yamlencode(local.promtail_values)]

  depends_on = [
    kubernetes_namespace.this,
    helm_release.loki
  ]
}

############################
# Tempo (трейсинг)
############################

resource "helm_release" "tempo" {
  count      = var.enable_tempo ? 1 : 0
  name       = local.rel.tempo
  namespace  = var.namespace
  repository = "https://grafana.github.io/helm-charts"
  chart      = "tempo"
  version    = var.tempo_chart_version
  timeout    = 900
  atomic     = true
  wait       = true
  lint       = true

  values = [yamlencode(local.tempo_values)]

  depends_on = [kubernetes_namespace.this]
}

############################
# Grafana
############################

resource "helm_release" "grafana" {
  count      = var.enable_grafana ? 1 : 0
  name       = local.rel.grafana
  namespace  = var.namespace
  repository = "https://grafana.github.io/helm-charts"
  chart      = "grafana"
  version    = var.grafana_chart_version
  timeout    = 900
  atomic     = true
  wait       = true
  lint       = true

  values = [yamlencode(local.grafana_values)]

  depends_on = [
    kubernetes_namespace.this,
    helm_release.kps,
    helm_release.loki,
    helm_release.tempo
  ]
}

############################
# Выходные значения
############################

output "namespace" {
  value       = var.namespace
  description = "Namespace, куда развернут стек наблюдаемости."
}

output "prometheus_url" {
  value       = local.urls.prometheus
  description = "Внутрикластерный URL Prometheus (ClusterIP)."
  depends_on  = [helm_release.kps]
}

output "loki_url" {
  value       = local.urls.loki
  description = "Внутрикластерный URL Loki (ClusterIP)."
  depends_on  = [helm_release.loki]
}

output "tempo_url" {
  value       = local.urls.tempo
  description = "Внутрикластерный URL Tempo (ClusterIP)."
  depends_on  = [helm_release.tempo]
}

output "grafana_release_name" {
  value       = local.rel.grafana
  description = "Имя Helm-релиза Grafana."
  depends_on  = [helm_release.grafana]
}
