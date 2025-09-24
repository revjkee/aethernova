terraform {
  required_version = ">= 1.5.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25.2"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12.1"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.2"
    }
  }
}

############################################
# VARIABLES
############################################
variable "namespace" {
  description = "Namespace для стека наблюдаемости"
  type        = string
  default     = "observability"
}

variable "labels" {
  description = "Дополнительные метки для всех ресурсов"
  type        = map(string)
  default     = {}
}

variable "enable_kube_prometheus_stack" {
  description = "Включить установку kube-prometheus-stack"
  type        = bool
  default     = true
}

variable "enable_loki" {
  description = "Включить установку Loki"
  type        = bool
  default     = true
}

variable "enable_promtail" {
  description = "Включить установку Promtail"
  type        = bool
  default     = true
}

variable "enable_tempo" {
  description = "Включить установку Tempo"
  type        = bool
  default     = false
}

variable "enable_otel_collector" {
  description = "Включить установку OpenTelemetry Collector"
  type        = bool
  default     = true
}

variable "storage_class" {
  description = "StorageClass для PVC (если null — используется по умолчанию кластера)"
  type        = string
  default     = null
}

variable "prometheus_retention" {
  description = "Срок хранения метрик Prometheus"
  type        = string
  default     = "15d"
}

variable "grafana_admin_user" {
  description = "Имя администратора Grafana"
  type        = string
  default     = "admin"
}

variable "grafana_hostname" {
  description = "FQDN хоста для Grafana Ingress (опционально)"
  type        = string
  default     = null
}

variable "grafana_ingress_enabled" {
  description = "Включить Ingress для Grafana"
  type        = bool
  default     = false
}

variable "grafana_ingress_class" {
  description = "Имя IngressClass для Grafana (ingress-nginx/istio/traefik)"
  type        = string
  default     = null
}

variable "grafana_tls_secret_name" {
  description = "Имя TLS-секрета для Ingress Grafana (если TLS нужен)"
  type        = string
  default     = null
}

variable "loki_pvc_size" {
  description = "Размер PVC для Loki"
  type        = string
  default     = "50Gi"
}

variable "loki_storage_mode" {
  description = "Хранилище Loki: filesystem | s3"
  type        = string
  default     = "filesystem"
  validation {
    condition     = contains(["filesystem", "s3"], var.loki_storage_mode)
    error_message = "loki_storage_mode должен быть filesystem или s3."
  }
}

variable "loki_s3" {
  description = "Параметры S3 для Loki (используются при loki_storage_mode = s3)"
  type = object({
    endpoint            = string
    region              = string
    bucket              = string
    access_key_id       = string
    secret_access_key   = string
    s3_force_path_style = optional(bool, true)
    tls_insecure        = optional(bool, false)
  })
  default = {
    endpoint            = ""
    region              = ""
    bucket              = ""
    access_key_id       = ""
    secret_access_key   = ""
    s3_force_path_style = true
    tls_insecure        = false
  }
  sensitive = true
}

variable "tempo_pvc_size" {
  description = "Размер PVC для Tempo"
  type        = string
  default     = "20Gi"
}

variable "tempo_storage_mode" {
  description = "Хранилище Tempo: filesystem | s3"
  type        = string
  default     = "filesystem"
  validation {
    condition     = contains(["filesystem", "s3"], var.tempo_storage_mode)
    error_message = "tempo_storage_mode должен быть filesystem или s3."
  }
}

variable "tempo_s3" {
  description = "Параметры S3 для Tempo (используются при tempo_storage_mode = s3)"
  type = object({
    endpoint            = string
    region              = string
    bucket              = string
    access_key_id       = string
    secret_access_key   = string
    s3_force_path_style = optional(bool, true)
    tls_insecure        = optional(bool, false)
  })
  default = {
    endpoint            = ""
    region              = ""
    bucket              = ""
    access_key_id       = ""
    secret_access_key   = ""
    s3_force_path_style = true
    tls_insecure        = false
  }
  sensitive = true
}

variable "otel_collector_config_override" {
  description = "Полный YAML-конфиг для OpenTelemetry Collector (если задан — заменяет конфиг по умолчанию)"
  type        = string
  default     = null
  sensitive   = true
}

############################################
# LOCALS
############################################
locals {
  ns_name = var.namespace

  common_labels = merge({
    "app.kubernetes.io/part-of" = "policy-core"
    "app.kubernetes.io/component" = "observability"
    "policy.aethernova.io/profile" = "baseline"
  }, var.labels)

  grafana_secret_name = "grafana-admin"

  # Loki config (в Secret), если используется S3
  loki_config_yaml = var.loki_storage_mode == "s3" ? yamlencode({
    auth_enabled = false
    server = {
      http_listen_port = 3100
    }
    common = {
      compactor_address = "http://loki:3100"
      storage = {
        s3 = {
          s3       = "s3://${var.loki_s3.access_key_id}:${var.loki_s3.secret_access_key}@${var.loki_s3.endpoint}"
          bucket   = var.loki_s3.bucket
          endpoint = var.loki_s3.endpoint
          region   = var.loki_s3.region
          s3forcepathstyle = try(var.loki_s3.s3_force_path_style, true)
          insecure = try(var.loki_s3.tls_insecure, false)
        }
      }
    }
    limits_config = {
      ingestion_rate_mb = 8
      ingestion_burst_size_mb = 16
      reject_old_samples = true
      reject_old_samples_max_age = "168h"
    }
    schema_config = {
      configs = [{
        from = "2024-01-01"
        store = "boltdb-shipper"
        object_store = "s3"
        schema = "v13"
        index = {
          prefix = "loki_index_"
          period = "24h"
        }
      }]
    }
    storage_config = {
      aws = {
        bucketnames = var.loki_s3.bucket
        endpoint    = var.loki_s3.endpoint
        region      = var.loki_s3.region
        s3forcepathstyle = try(var.loki_s3.s3_force_path_style, true)
        insecure         = try(var.loki_s3.tls_insecure, false)
        access_key_id     = var.loki_s3.access_key_id
        secret_access_key = var.loki_s3.secret_access_key
      }
      boltdb_shipper = {
        shared_store = "s3"
        active_index_directory = "/data/loki/index"
        cache_location          = "/data/loki/boltdb-cache"
      }
    }
    chunk_store_config = {
      max_look_back_period = "720h"
    }
    table_manager = {
      retention_deletes_enabled = true
      retention_period = "720h"
    }
  }) : ""

  # Tempo config (в Secret), если используется S3
  tempo_config_yaml = var.tempo_storage_mode == "s3" ? yamlencode({
    server = { http_listen_port = 3200, grpc_listen_port = 4317 }
    distributor = { receivers = { otlp = { protocols = { http = {}, grpc = {} } } } }
    storage = {
      trace = {
        backend = "s3"
        s3 = {
          bucket          = var.tempo_s3.bucket
          endpoint        = var.tempo_s3.endpoint
          region          = var.tempo_s3.region
          access_key      = var.tempo_s3.access_key_id
          secret_key      = var.tempo_s3.secret_access_key
          insecure        = try(var.tempo_s3.tls_insecure, false)
          force_path_style = try(var.tempo_s3.s3_force_path_style, true)
        }
      }
    }
    compactor = { compaction = { block_retention = "168h" } }
    querier = { frontend_worker = { frontend_address = "query-frontend:9095" } }
    query_frontend = { max_outstanding_per_tenant = 2048 }
  }) : ""

  grafana_ingress_hosts = var.grafana_hostname == null ? [] : [var.grafana_hostname]

  otel_default_config = yamlencode({
    receivers = {
      otlp = {
        protocols = { grpc = { endpoint = "0.0.0.0:4317" }, http = { endpoint = "0.0.0.0:4318" } }
      }
      hostmetrics = {
        collection_interval = "60s"
        scrapers = { cpu = {}, disk = {}, filesystem = {}, memory = {}, network = {}, load = {} }
      }
    }
    processors = {
      batch = { timeout = "10s", send_batch_size = 8192 }
      memory_limiter = { check_interval = "5s", limit_percentage = 80, spike_limit_percentage = 25 }
      resourcedetection = { detectors = ["env", "system"] }
    }
    exporters = {
      otlp = { endpoint = "tempo:4317", tls = { insecure = true } }
      logging = { loglevel = "warn" }
      prometheus = { endpoint = "0.0.0.0:9464" }
    }
    service = {
      telemetry = { logs = { level = "info" } }
      pipelines = {
        metrics = { receivers = ["hostmetrics"], processors = ["memory_limiter","batch"], exporters = ["prometheus"] }
        traces  = { receivers = ["otlp"], processors = ["memory_limiter","batch"], exporters = ["otlp"] }
        logs    = { receivers = ["otlp"], processors = ["memory_limiter","batch"], exporters = ["logging"] }
      }
    }
  })
}

############################################
# NAMESPACE
############################################
resource "kubernetes_namespace_v1" "ns" {
  metadata {
    name   = local.ns_name
    labels = local.common_labels
  }
}

############################################
# GRAFANA ADMIN SECRET
############################################
resource "random_password" "grafana" {
  length           = 24
  special          = true
  min_special      = 2
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  override_char_set = "!@#$%^&*()-_=+[]{}:,./?"
}

resource "kubernetes_secret_v1" "grafana_admin" {
  metadata {
    name      = local.grafana_secret_name
    namespace = kubernetes_namespace_v1.ns.metadata[0].name
    labels    = local.common_labels
  }
  type = "Opaque"
  data = {
    "admin-user"     = var.grafana_admin_user
    "admin-password" = random_password.grafana.result
  }
}

############################################
# (OPTIONAL) LOKI/ TEMPO CONFIG SECRETS FOR S3
############################################
resource "kubernetes_secret_v1" "loki_config" {
  count = var.enable_loki && var.loki_storage_mode == "s3" ? 1 : 0
  metadata {
    name      = "loki-config"
    namespace = kubernetes_namespace_v1.ns.metadata[0].name
    labels    = local.common_labels
  }
  type = "Opaque"
  data = {
    "loki.yaml" = local.loki_config_yaml
  }
}

resource "kubernetes_secret_v1" "tempo_config" {
  count = var.enable_tempo && var.tempo_storage_mode == "s3" ? 1 : 0
  metadata {
    name      = "tempo-config"
    namespace = kubernetes_namespace_v1.ns.metadata[0].name
    labels    = local.common_labels
  }
  type = "Opaque"
  data = {
    "tempo.yaml" = local.tempo_config_yaml
  }
}

############################################
# HELM: KUBE-PROMETHEUS-STACK
############################################
resource "helm_release" "kps" {
  count      = var.enable_kube_prometheus_stack ? 1 : 0
  name       = "kube-prometheus-stack"
  namespace  = kubernetes_namespace_v1.ns.metadata[0].name
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  # version  =  (опционально зафиксировать)

  create_namespace = false
  wait             = true
  timeout          = 600

  values = [
    yamlencode({
      fullnameOverride = "kube-prometheus-stack"
      commonLabels     = local.common_labels

      grafana = {
        enabled       = true
        admin = {
          existingSecret = kubernetes_secret_v1.grafana_admin.metadata[0].name
        }
        service = {
          type = "ClusterIP"
          port = 80
        }
        ingress = {
          enabled          = var.grafana_ingress_enabled
          ingressClassName = var.grafana_ingress_class
          hosts            = local.grafana_ingress_hosts
          tls = var.grafana_tls_secret_name == null ? [] : [{
            secretName = var.grafana_tls_secret_name
            hosts      = local.grafana_ingress_hosts
          }]
          annotations = {}
        }
      }

      alertmanager = {
        enabled = true
      }

      prometheus = {
        enabled = true
        service = { type = "ClusterIP" }
        prometheusSpec = {
          retention                 = var.prometheus_retention
          walCompression            = true
          enableAdminAPI            = false
          scrapeInterval            = "30s"
          evaluationInterval        = "30s"
          externalLabels            = { cluster = "policy-core" }
          podMonitorSelectorNilUsesHelmValues = false
          serviceMonitorSelectorNilUsesHelmValues = false
          ruleNamespaceSelector = {}
        }
      }
    })
  ]

  depends_on = [kubernetes_secret_v1.grafana_admin]
}

############################################
# HELM: LOKI
############################################
resource "helm_release" "loki" {
  count      = var.enable_loki ? 1 : 0
  name       = "loki"
  namespace  = kubernetes_namespace_v1.ns.metadata[0].name
  repository = "https://grafana.github.io/helm-charts"
  chart      = "loki"

  create_namespace = false
  wait             = true
  timeout          = 600

  values = [
    var.loki_storage_mode == "filesystem" ? yamlencode({
      fullnameOverride = "loki"
      commonLabels     = local.common_labels
      persistence = {
        enabled          = true
        size             = var.loki_pvc_size
        storageClassName = var.storage_class
      }
      serviceMonitor = { enabled = true }
      loki = {
        commonConfig = { replication_factor = 1 }
        auth_enabled = false
        schemaConfig = {
          configs = [{
            from        = "2024-01-01"
            store       = "boltdb-shipper"
            object_store = "filesystem"
            schema      = "v13"
            index       = { prefix = "loki_index_", period = "24h" }
          }]
        }
        storage = {
          type = "filesystem"
        }
      }
    }) : yamlencode({
      fullnameOverride = "loki"
      commonLabels     = local.common_labels
      persistence = {
        enabled          = true
        size             = var.loki_pvc_size
        storageClassName = var.storage_class
      }
      serviceMonitor = { enabled = true }
      loki = {
        existingSecretForConfig = kubernetes_secret_v1.loki_config[0].metadata[0].name
      }
    })
  ]

  depends_on = [
    kubernetes_namespace_v1.ns,
    kubernetes_secret_v1.loki_config
  ]
}

############################################
# HELM: PROMTAIL
############################################
resource "helm_release" "promtail" {
  count      = var.enable_promtail ? 1 : 0
  name       = "promtail"
  namespace  = kubernetes_namespace_v1.ns.metadata[0].name
  repository = "https://grafana.github.io/helm-charts"
  chart      = "promtail"

  create_namespace = false
  wait             = true
  timeout          = 600

  values = [
    yamlencode({
      fullnameOverride = "promtail"
      commonLabels     = local.common_labels
      serviceMonitor   = { enabled = true }
      config = {
        clients = [{
          url = "http://loki:3100/loki/api/v1/push"
        }]
      }
    })
  ]

  depends_on = [helm_release.loki]
}

############################################
# HELM: TEMPO (опционально)
############################################
resource "helm_release" "tempo" {
  count      = var.enable_tempo ? 1 : 0
  name       = "tempo"
  namespace  = kubernetes_namespace_v1.ns.metadata[0].name
  repository = "https://grafana.github.io/helm-charts"
  chart      = "tempo"

  create_namespace = false
  wait             = true
  timeout          = 600

  values = [
    var.tempo_storage_mode == "filesystem" ? yamlencode({
      fullnameOverride = "tempo"
      commonLabels     = local.common_labels
      persistence = {
        enabled          = true
        size             = var.tempo_pvc_size
        storageClassName = var.storage_class
      }
      serviceMonitor = { enabled = true }
      tempo = {
        receivers = { otlp = { protocols = { http = {}, grpc = {} } } }
        storage   = { trace = { backend = "local" } }
      }
    }) : yamlencode({
      fullnameOverride = "tempo"
      commonLabels     = local.common_labels
      persistence = {
        enabled          = true
        size             = var.tempo_pvc_size
        storageClassName = var.storage_class
      }
      serviceMonitor = { enabled = true }
      tempo = {
        existingSecret = kubernetes_secret_v1.tempo_config[0].metadata[0].name
      }
    })
  ]

  depends_on = [
    kubernetes_namespace_v1.ns,
    kubernetes_secret_v1.tempo_config
  ]
}

############################################
# HELM: OPENTELEMETRY COLLECTOR (опционально)
############################################
resource "helm_release" "otelcol" {
  count      = var.enable_otel_collector ? 1 : 0
  name       = "otel-collector"
  namespace  = kubernetes_namespace_v1.ns.metadata[0].name
  repository = "https://open-telemetry.github.io/opentelemetry-helm-charts"
  chart      = "opentelemetry-collector"

  create_namespace = false
  wait             = true
  timeout          = 600

  values = [
    yamlencode({
      fullnameOverride = "otel-collector"
      commonLabels     = local.common_labels
      mode             = "deployment"
      presets = {
        logsCollection = { enabled = false }
        kubernetesAttributes = { enabled = true }
      }
      service = {
        type = "ClusterIP"
        ports = [{
          name = "otlp-grpc", port = 4317, targetPort = 4317, protocol = "TCP"
        },{
          name = "otlp-http", port = 4318, targetPort = 4318, protocol = "TCP"
        },{
          name = "metrics", port = 9464, targetPort = 9464, protocol = "TCP"
        }]
      }
      serviceMonitor = { enabled = true }
      config = var.otel_collector_config_override == null ? local.otel_default_config : var.otel_collector_config_override
    })
  ]

  depends_on = [
    kubernetes_namespace_v1.ns,
    helm_release.kps,
    helm_release.tempo
  ]
}

############################################
# OUTPUTS
############################################
output "namespace" {
  description = "Namespace стека наблюдаемости"
  value       = kubernetes_namespace_v1.ns.metadata[0].name
}

output "grafana_admin_user" {
  description = "Логин администратора Grafana"
  value       = var.grafana_admin_user
}

output "grafana_admin_password" {
  description = "Пароль администратора Grafana (секрет)"
  value       = random_password.grafana.result
  sensitive   = true
}

output "grafana_ingress_host" {
  description = "Ingress-хост Grafana (если настроен)"
  value       = var.grafana_hostname
}

output "enabled_components" {
  description = "Какие компоненты включены"
  value = {
    kube_prometheus_stack = var.enable_kube_prometheus_stack
    loki                  = var.enable_loki
    promtail              = var.enable_promtail
    tempo                 = var.enable_tempo
    otel_collector        = var.enable_otel_collector
  }
}
