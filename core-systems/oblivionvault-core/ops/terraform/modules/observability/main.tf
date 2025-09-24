terraform {
  required_version = ">= 1.5.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.29.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.13.2"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.2"
    }
  }
}

############################
# Providers (cluster inputs)
############################

variable "kubeconfig" {
  type        = string
  description = "Путь к kubeconfig. Если задан, используется как основной способ подключения."
  default     = null
}

variable "kube_context" {
  type        = string
  description = "Имя контекста в kubeconfig."
  default     = null
}

variable "kubernetes_host" {
  type        = string
  description = "Адрес API Kubernetes (если не используется kubeconfig)."
  default     = null
}

variable "kubernetes_token" {
  type        = string
  description = "Bearer token для доступа к API (если не используется kubeconfig)."
  default     = null
  sensitive   = true
}

variable "kubernetes_ca_cert" {
  type        = string
  description = "CA сертификат кластера (PEM), если не используется kubeconfig."
  default     = null
}

provider "kubernetes" {
  host                   = var.kubernetes_host
  token                  = var.kubernetes_token
  cluster_ca_certificate = var.kubernetes_ca_cert
  load_config_file       = var.kubeconfig != null
  config_path            = var.kubeconfig
  config_context         = var.kube_context
}

provider "helm" {
  kubernetes {
    host                   = var.kubernetes_host
    token                  = var.kubernetes_token
    cluster_ca_certificate = var.kubernetes_ca_cert
    load_config_file       = var.kubeconfig != null
    config_path            = var.kubeconfig
    config_context         = var.kube_context
  }
  experiments {
    manifest = true
  }
}

##########################
# Core variables & flags
##########################

variable "namespace" {
  type        = string
  description = "Namespace для стека наблюдаемости."
  default     = "observability"
  validation {
    condition     = length(var.namespace) > 0 && length(var.namespace) <= 63
    error_message = "Namespace должен быть непустым и <= 63 символов."
  }
}

variable "labels" {
  type        = map(string)
  description = "Дополнительные метки для namespace и релизов."
  default     = {}
}

variable "annotations" {
  type        = map(string)
  description = "Дополнительные аннотации для namespace."
  default     = {}
}

variable "enable_kube_prometheus_stack" {
  type        = bool
  description = "Установить kube-prometheus-stack (Prometheus, Alertmanager, Grafana)."
  default     = true
}

variable "enable_loki" {
  type        = bool
  description = "Установить Loki (по умолчанию mono/standard)."
  default     = true
}

variable "loki_mode" {
  type        = string
  description = "Режим Loki: standard | distributed."
  default     = "standard"
  validation {
    condition     = contains(["standard", "distributed"], var.loki_mode)
    error_message = "loki_mode должен быть 'standard' или 'distributed'."
  }
}

variable "enable_tempo" {
  type        = bool
  description = "Установить Tempo."
  default     = true
}

variable "enable_promtail" {
  type        = bool
  description = "Установить Promtail (для отправки логов в Loki)."
  default     = true
}

variable "enable_otel_collector" {
  type        = bool
  description = "Установить OpenTelemetry Collector."
  default     = false
}

########################
# Chart versions / repo
########################

variable "chart_repo_prometheus" {
  type        = string
  default     = "https://prometheus-community.github.io/helm-charts"
  description = "Helm repo для kube-prometheus-stack."
}
variable "chart_name_prometheus" {
  type        = string
  default     = "kube-prometheus-stack"
}
variable "chart_version_prometheus" {
  type        = string
  # Зафиксированная стабильная версия; обновляйте осознанно.
  default     = "60.3.0"
}

variable "chart_repo_grafana" {
  type        = string
  default     = "https://grafana.github.io/helm-charts"
  description = "Helm repo для Loki, Tempo, Promtail, Grafana-операторов и т.п."
}

variable "chart_name_loki" {
  type        = string
  description = "Имя чарта Loki."
  default     = "loki"
}
variable "chart_version_loki" {
  type        = string
  description = "Версия чарта Loki."
  default     = "6.6.3"
}

variable "chart_name_loki_distributed" {
  type        = string
  description = "Имя чарта Loki distributed."
  default     = "loki-distributed"
}
variable "chart_version_loki_distributed" {
  type        = string
  description = "Версия чарта Loki distributed."
  default     = "0.78.3"
}

variable "chart_name_promtail" {
  type        = string
  default     = "promtail"
}
variable "chart_version_promtail" {
  type        = string
  default     = "6.15.3"
}

variable "chart_name_tempo" {
  type        = string
  default     = "tempo"
}
variable "chart_version_tempo" {
  type        = string
  default     = "1.10.1"
}

variable "chart_name_otel_collector" {
  type        = string
  default     = "opentelemetry-collector"
}
variable "chart_version_otel_collector" {
  type        = string
  default     = "0.108.0"
}

########################
# Storage / persistence
########################

variable "storage_class" {
  type        = string
  description = "StorageClass по умолчанию для PVC (если требуется)."
  default     = null
}

variable "prometheus_retention" {
  type        = string
  description = "Срок хранения метрик Prometheus (например, 15d)."
  default     = "15d"
}

variable "prometheus_pvc_size" {
  type        = string
  description = "Размер PVC для Prometheus."
  default     = "50Gi"
}

variable "alertmanager_pvc_size" {
  type        = string
  description = "Размер PVC для Alertmanager."
  default     = "5Gi"
}

variable "grafana_pvc_size" {
  type        = string
  description = "Размер PVC для Grafana (если persistence включена)."
  default     = "10Gi"
}

# Loki object storage (S3-compatible)
variable "loki_enable_object_storage" {
  type        = bool
  description = "Включить объектное хранилище для Loki."
  default     = false
}
variable "loki_object_storage_endpoint" {
  type        = string
  default     = null
}
variable "loki_object_storage_bucket" {
  type        = string
  default     = null
}
variable "loki_object_storage_region" {
  type        = string
  default     = "us-east-1"
}
variable "loki_object_storage_access_key" {
  type        = string
  default     = null
  sensitive   = true
}
variable "loki_object_storage_secret_key" {
  type        = string
  default     = null
  sensitive   = true
}

# Tempo object storage (S3-compatible)
variable "tempo_enable_object_storage" {
  type        = bool
  description = "Включить объектное хранилище для Tempo."
  default     = false
}
variable "tempo_object_storage_endpoint" {
  type        = string
  default     = null
}
variable "tempo_object_storage_bucket" {
  type        = string
  default     = null
}
variable "tempo_object_storage_region" {
  type        = string
  default     = "us-east-1"
}
variable "tempo_object_storage_access_key" {
  type        = string
  default     = null
  sensitive   = true
}
variable "tempo_object_storage_secret_key" {
  type        = string
  default     = null
  sensitive   = true
}

########################
# Ingress / security
########################

variable "enable_ingress" {
  type        = bool
  description = "Включить Ingress для Grafana/Prometheus/Alertmanager."
  default     = false
}

variable "ingress_class_name" {
  type        = string
  description = "Имя IngressClass."
  default     = null
}

variable "hosts" {
  description = <<EOT
Хосты для Ingress:
{
  grafana      = "grafana.example.com"
  prometheus   = "prom.example.com"
  alertmanager = "alert.example.com"
}
EOT
  type = object({
    grafana      = optional(string)
    prometheus   = optional(string)
    alertmanager = optional(string)
  })
  default = {}
}

variable "ingress_tls" {
  description = "TLS-секции для ingress (общий список)."
  type = list(object({
    hosts      = list(string)
    secretName = string
  }))
  default = []
}

variable "network_policies_enabled" {
  type        = bool
  description = "Включить базовые NetworkPolicy для namespace."
  default     = true
}

########################
# Scheduling (node sets)
########################

variable "tolerations" {
  type        = list(map(string))
  description = "Общие tolerations для компонентов."
  default     = []
}

variable "node_selector" {
  type        = map(string)
  description = "Общий nodeSelector для компонентов."
  default     = {}
}

variable "affinity" {
  type        = any
  description = "Произвольный affinity для компонентов."
  default     = null
}

########################
# Namespace
########################

resource "kubernetes_namespace_v1" "this" {
  metadata {
    name        = var.namespace
    labels      = merge({ "app.kubernetes.io/part-of" = "oblivionvault-core" }, var.labels)
    annotations = var.annotations
  }
}

########################
# Locals: Helm values
########################

locals {
  common_persistence = var.storage_class == null ? {} : {
    storageClassName = var.storage_class
  }

  kube_prometheus_values = yamlencode({
    fullnameOverride = "kube-prometheus"
    defaultRules = {
      create = true
    }
    alertmanager = {
      enabled    = true
      ingress    = var.enable_ingress ? {
        enabled          = true
        ingressClassName = var.ingress_class_name
        hosts            = var.hosts.alertmanager == null ? [] : [var.hosts.alertmanager]
        tls              = var.ingress_tls
      } : {}
      alertmanagerSpec = {
        storage = {
          volumeClaimTemplate = {
            spec = merge({
              accessModes = ["ReadWriteOnce"]
              resources = { requests = { storage = var.alertmanager_pvc_size } }
            }, local.common_persistence)
          }
        }
      }
    }
    prometheus = {
      ingress    = var.enable_ingress ? {
        enabled          = true
        ingressClassName = var.ingress_class_name
        hosts            = var.hosts.prometheus == null ? [] : [var.hosts.prometheus]
        tls              = var.ingress_tls
      } : {}
      prometheusSpec = {
        retention                   = var.prometheus_retention
        walCompression              = true
        enableAdminAPI              = false
        externalLabels              = { cluster = "primary" }
        storageSpec = {
          volumeClaimTemplate = {
            spec = merge({
              accessModes = ["ReadWriteOnce"]
              resources = { requests = { storage = var.prometheus_pvc_size } }
            }, local.common_persistence)
          }
        }
        podMetadata = {
          labels = { "app.kubernetes.io/managed-by" = "terraform-helm" }
        }
        tolerations  = var.tolerations
        nodeSelector = var.node_selector
        affinity     = var.affinity
      }
    }
    grafana = {
      enabled   = true
      ingress   = var.enable_ingress ? {
        enabled          = true
        ingressClassName = var.ingress_class_name
        hosts            = var.hosts.grafana == null ? [] : [var.hosts.grafana]
        tls              = var.ingress_tls
      } : {}
      persistence = {
        enabled = true
        size    = var.grafana_pvc_size
        type    = "pvc"
        existingClaim = null
        storageClassName = var.storage_class
      }
      defaultDashboardsEnabled = true
      admin = { existingSecret = null } # Используйте внешние секреты при необходимости
      serviceMonitor = { enabled = true }
      sidecar = {
        dashboards = { enabled = true, label = "grafana_dashboard" }
        datasources = { enabled = true }
      }
      tolerations  = var.tolerations
      nodeSelector = var.node_selector
      affinity     = var.affinity
    }
    kubeStateMetrics = { enabled = true }
    nodeExporter    = { enabled = true }
  })

  loki_object_storage = var.loki_enable_object_storage ? {
    storage = {
      type = "s3"
      s3 = {
        s3              = "s3"
        endpoint        = var.loki_object_storage_endpoint
        bucketnames     = var.loki_object_storage_bucket
        region          = var.loki_object_storage_region
        access_key_id   = var.loki_object_storage_access_key
        secret_access_key= var.loki_object_storage_secret_key
        s3forcepathstyle= true
        insecure        = false
      }
    }
  } : {}

  loki_standard_values = yamlencode({
    fullnameOverride = "loki"
    loki = merge({
      auth_enabled = false
      commonConfig = {
        replication_factor = 1
      }
      storage = var.loki_enable_object_storage ? {
        type = "s3"
        bucketNames = {
          chunks = var.loki_object_storage_bucket
          ruler  = var.loki_object_storage_bucket
          admin  = var.loki_object_storage_bucket
        }
        s3 = {
          endpoint  = var.loki_object_storage_endpoint
          region    = var.loki_object_storage_region
          secretAccessKey = var.loki_object_storage_secret_key
          accessKeyId     = var.loki_object_storage_access_key
          s3ForcePathStyle = true
        }
      } : {}
      schemaConfig = {
        configs = [{
          from         = "2024-01-01"
          store        = var.loki_enable_object_storage ? "boltdb-shipper" : "boltdb-shipper"
          object_store = var.loki_enable_object_storage ? "s3" : "filesystem"
          schema       = "v13"
          index        = { prefix = "loki_index_", period = "24h" }
        }]
      }
    }, {})

    singleBinary = {
      replicas = 1
      persistence = {
        enabled = true
        size    = "50Gi"
        storageClass = var.storage_class
      }
    }

    gateway = {
      enabled = true
      tolerations  = var.tolerations
      nodeSelector = var.node_selector
      affinity     = var.affinity
    }

    chunksCache = { enabled = false }
  })

  loki_distributed_values = yamlencode({
    fullnameOverride = "loki"
    loki = merge({
      auth_enabled = false
      commonConfig = {
        replication_factor = 2
      }
      schemaConfig = {
        configs = [{
          from         = "2024-01-01"
          store        = "boltdb-shipper"
          object_store = var.loki_enable_object_storage ? "s3" : "filesystem"
          schema       = "v13"
          index        = { prefix = "loki_index_", period = "24h" }
        }]
      }
    }, {})

    gateway = {
      enabled = true
      replicas = 2
    }

    write = {
      replicas = 2
      persistence = {
        enabled = true
        size    = "50Gi"
        storageClass = var.storage_class
      }
    }
    read = {
      replicas = 2
      persistence = {
        enabled = true
        size    = "50Gi"
        storageClass = var.storage_class
      }
    }
    backend = {
      replicas = 2
      persistence = {
        enabled = true
        size    = "50Gi"
        storageClass = var.storage_class
      }
    }

    memcached = {
      chunks = { enabled = true, replicas = 2 }
      frontend = { enabled = true, replicas = 2 }
      indexQueries = { enabled = true, replicas = 2 }
      indexWrites  = { enabled = true, replicas = 2 }
      results      = { enabled = true, replicas = 2 }
    }
  })

  promtail_values = yamlencode({
    fullnameOverride = "promtail"
    config = {
      clients = [{
        url = "http://loki-gateway.observability.svc.cluster.local/loki/api/v1/push"
      }]
    }
    tolerations  = var.tolerations
    nodeSelector = var.node_selector
    affinity     = var.affinity
  })

  tempo_values = yamlencode({
    fullnameOverride = "tempo"
    tempo = {
      metricsGenerator = { enabled = true }
      storage = var.tempo_enable_object_storage ? {
        trace = {
          backend = "s3"
          s3 = {
            endpoint = var.tempo_object_storage_endpoint
            region   = var.tempo_object_storage_region
            bucket   = var.tempo_object_storage_bucket
            access_key = var.tempo_object_storage_access_key
            secret_key = var.tempo_object_storage_secret_key
            insecure   = false
            s3forcepathstyle = true
          }
        }
      } : {
        trace = {
          backend = "local"
          local = { path = "/var/tempo" }
        }
      }
    }
    persistence = {
      enabled = var.tempo_enable_object_storage ? false : true
      size    = "50Gi"
      storageClass = var.storage_class
    }
    tolerations  = var.tolerations
    nodeSelector = var.node_selector
    affinity     = var.affinity
  })

  otel_values = yamlencode({
    fullnameOverride = "otel-collector"
    mode = "deployment"
    presets = {
      kubernetesAttributes = { enabled = true }
      kubeletMetrics       = { enabled = true }
      kubeletLogs          = { enabled = false }
      hostMetrics          = { enabled = true }
    }
    config = {
      receivers = {
        otlp = { protocols = { http = {}, grpc = {} } }
        prometheus = {
          config = {
            scrape_configs = [
              { job_name = "kubernetes-nodes", kubernetes_sd_configs = [{ role = "node" }] }
            ]
          }
        }
      }
      exporters = {
        prometheusremotewrite = {
          endpoint = "http://kube-prometheus-prometheus.observability.svc.cluster.local:9090/api/v1/write"
        }
        otlp = {
          endpoint = "tempo-distributor.observability.svc.cluster.local:4317"
          tls = { insecure = true }
        }
      }
      service = {
        pipelines = {
          metrics = { receivers = ["prometheus"], exporters = ["prometheusremotewrite"] }
          traces  = { receivers = ["otlp"],      exporters = ["otlp"] }
        }
      }
    }
    tolerations  = var.tolerations
    nodeSelector = var.node_selector
    affinity     = var.affinity
  })
}

########################
# Network Policies (base)
########################

resource "kubernetes_network_policy_v1" "default_deny_egress" {
  count = var.network_policies_enabled ? 1 : 0
  metadata {
    name      = "default-deny-egress"
    namespace = var.namespace
  }
  spec {
    pod_selector {}
    policy_types = ["Egress"]
  }
  depends_on = [kubernetes_namespace_v1.this]
}

resource "kubernetes_network_policy_v1" "allow_dns_egress" {
  count = var.network_policies_enabled ? 1 : 0
  metadata {
    name      = "allow-dns-egress"
    namespace = var.namespace
  }
  spec {
    pod_selector {}
    policy_types = ["Egress"]
    egress {
      to {
        namespace_selector {}
      }
      ports {
        port     = 53
        protocol = "UDP"
      }
      ports {
        port     = 53
        protocol = "TCP"
      }
    }
  }
  depends_on = [kubernetes_namespace_v1.this]
}

########################
# Helm Releases
########################

resource "helm_release" "kube_prometheus_stack" {
  count      = var.enable_kube_prometheus_stack ? 1 : 0
  name       = "kube-prometheus-stack"
  namespace  = var.namespace
  repository = var.chart_repo_prometheus
  chart      = var.chart_name_prometheus
  version    = var.chart_version_prometheus
  values     = [local.kube_prometheus_values]

  create_namespace = false
  timeout          = 1200
  atomic           = true
  cleanup_on_fail  = true

  depends_on = [kubernetes_namespace_v1.this]
}

resource "helm_release" "loki_standard" {
  count      = var.enable_loki && var.loki_mode == "standard" ? 1 : 0
  name       = "loki"
  namespace  = var.namespace
  repository = var.chart_repo_grafana
  chart      = var.chart_name_loki
  version    = var.chart_version_loki
  values     = [
    local.loki_standard_values,
    yamlencode(local.loki_object_storage)
  ]

  create_namespace = false
  timeout          = 1200
  atomic           = true
  cleanup_on_fail  = true

  depends_on = [kubernetes_namespace_v1.this]
}

resource "helm_release" "loki_distributed" {
  count      = var.enable_loki && var.loki_mode == "distributed" ? 1 : 0
  name       = "loki"
  namespace  = var.namespace
  repository = var.chart_repo_grafana
  chart      = var.chart_name_loki_distributed
  version    = var.chart_version_loki_distributed
  values     = [
    local.loki_distributed_values,
  ]

  create_namespace = false
  timeout          = 1800
  atomic           = true
  cleanup_on_fail  = true

  depends_on = [kubernetes_namespace_v1.this]
}

resource "helm_release" "promtail" {
  count      = var.enable_promtail ? 1 : 0
  name       = "promtail"
  namespace  = var.namespace
  repository = var.chart_repo_grafana
  chart      = var.chart_name_promtail
  version    = var.chart_version_promtail
  values     = [local.promtail_values]

  create_namespace = false
  timeout          = 900
  atomic           = true
  cleanup_on_fail  = true

  depends_on = [
    kubernetes_namespace_v1.this,
    helm_release.loki_standard,
    helm_release.loki_distributed
  ]
}

resource "helm_release" "tempo" {
  count      = var.enable_tempo ? 1 : 0
  name       = "tempo"
  namespace  = var.namespace
  repository = var.chart_repo_grafana
  chart      = var.chart_name_tempo
  version    = var.chart_version_tempo
  values     = [local.tempo_values]

  create_namespace = false
  timeout          = 1200
  atomic           = true
  cleanup_on_fail  = true

  depends_on = [kubernetes_namespace_v1.this]
}

resource "helm_release" "otel_collector" {
  count      = var.enable_otel_collector ? 1 : 0
  name       = "opentelemetry-collector"
  namespace  = var.namespace
  repository = var.chart_repo_grafana
  chart      = var.chart_name_otel_collector
  version    = var.chart_version_otel_collector
  values     = [local.otel_values]

  create_namespace = false
  timeout          = 900
  atomic           = true
  cleanup_on_fail  = true

  depends_on = [
    kubernetes_namespace_v1.this,
    helm_release.kube_prometheus_stack
  ]
}

########################
# Outputs
########################

output "namespace" {
  value       = var.namespace
  description = "Namespace стека наблюдаемости."
}

output "grafana_ingress_host" {
  description = "Хост Grafana (если включён Ingress)."
  value       = try(var.hosts.grafana, null)
}

output "prometheus_ingress_host" {
  description = "Хост Prometheus (если включён Ingress)."
  value       = try(var.hosts.prometheus, null)
}

output "alertmanager_ingress_host" {
  description = "Хост Alertmanager (если включён Ingress)."
  value       = try(var.hosts.alertmanager, null)
}

output "loki_mode" {
  value       = var.loki_mode
  description = "Активный режим Loki."
}
