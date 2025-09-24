#########################################
# Observability Module (Kubernetes/EKS) #
#########################################
# Providers aws/kubernetes/helm ожидаются в корне.
# В модуле нет backend и provider блоков.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.60" }
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.29" }
    helm = { source = "hashicorp/helm", version = "~> 2.13" }
  }
}

################
# Input vars   #
################

variable "namespace" {
  description = "Kubernetes namespace для инструментов наблюдаемости"
  type        = string
  default     = "observability"
}

variable "labels" {
  description = "Дополнительные метки для объектов"
  type        = map(string)
  default = {
    "app.kubernetes.io/part-of" = "zero-trust-core"
    "app.kubernetes.io/component" = "observability"
    "app.kubernetes.io/managed-by" = "terraform"
  }
}

variable "annotations" {
  description = "Дополнительные аннотации для namespace"
  type        = map(string)
  default     = {}
}

# Feature flags
variable "enable_kube_prometheus_stack" {
  description = "Устанавливать kube-prometheus-stack"
  type        = bool
  default     = true
}

variable "enable_otel_collector" {
  description = "Устанавливать OpenTelemetry Collector (gateway/agent)"
  type        = bool
  default     = true
}

# Опциональные компоненты подключаются только при наличии корректных values
variable "enable_loki" {
  description = "Устанавливать Loki (требуются корректные values)"
  type        = bool
  default     = false
}
variable "enable_promtail" {
  description = "Устанавливать Promtail (требуются корректные values)"
  type        = bool
  default     = false
}
variable "enable_tempo" {
  description = "Устанавливать Tempo (требуются корректные values)"
  type        = bool
  default     = false
}

# Управление версиями Helm‑чартов
variable "kps_chart_version" {
  description = "Версия чартa kube-prometheus-stack"
  type        = string
  default     = "60.0.1" # пример совместимой версии; уточняйте под ваш реестр
}

variable "otel_chart_version" {
  description = "Версия чартa opentelemetry-collector"
  type        = string
  default     = "0.97.1"
}

# Репозитории чартов (переопределяемые)
variable "repo_prometheus" {
  type        = string
  default     = "https://prometheus-community.github.io/helm-charts"
}
variable "repo_opentelemetry" {
  type        = string
  default     = "https://open-telemetry.github.io/opentelemetry-helm-charts"
}
variable "repo_grafana" {
  type        = string
  default     = "https://grafana.github.io/helm-charts"
}

# Безопасные дефолт‑values (можно переопределить)
variable "kps_values" {
  description = "Дополнительные values для kube-prometheus-stack (map мерджится поверх базовых)"
  type        = any
  default     = {}
}

variable "otel_mode" {
  description = "Режим OTel Collector: gateway или daemonset"
  type        = string
  default     = "gateway"
  validation {
    condition     = contains(["gateway", "daemonset"], var.otel_mode)
    error_message = "otel_mode должен быть gateway или daemonset."
  }
}

variable "otel_values" {
  description = "Дополнительные values для OpenTelemetry Collector (map мерджится поверх базовых)"
  type        = any
  default     = {}
}

# Подключение Loki/Tempo/Promtail через ваши values (строгая передача)
variable "loki_values" {
  description = "Полные values для установки Loki (если enable_loki=true)"
  type        = any
  default     = {}
}
variable "tempo_values" {
  description = "Полные values для установки Tempo (если enable_tempo=true)"
  type        = any
  default     = {}
}
variable "promtail_values" {
  description = "Полные values для установки Promtail (если enable_promtail=true)"
  type        = any
  default     = {}
}

################
# Locals       #
################

locals {
  common_labels = merge({
    "app.kubernetes.io/name" = "observability"
  }, var.labels)

  # Базовые values для kube-prometheus-stack с безопасными дефолтами
  kps_base_values = {
    fullnameOverride = "kube-prometheus"
    namespaceOverride = var.namespace

    crds = {
      enabled = true
    }

    alertmanager = {
      enabled = true
      alertmanagerSpec = {
        replicas = 2
        retention = "168h"
        resources = {
          requests = { cpu = "50m", memory = "128Mi" }
          limits   = { cpu = "500m", memory = "512Mi" }
        }
        securityContext = {
          runAsNonRoot = true
          runAsUser    = 65534
          fsGroup      = 65534
          readOnlyRootFilesystem = true
        }
      }
    }

    prometheus = {
      enabled = true
      prometheusSpec = {
        replicas = 2
        retention = "15d"
        retentionSize = "50GiB"
        resources = {
          requests = { cpu = "500m", memory = "1Gi" }
          limits   = { cpu = "2", memory = "4Gi" }
        }
        enableAdminAPI = false
        walCompression = true
        podMonitorSelectorNilUsesHelmValues  = false
        serviceMonitorSelectorNilUsesHelmValues = false
        securityContext = {
          runAsNonRoot = true
          runAsUser    = 65534
          fsGroup      = 65534
          readOnlyRootFilesystem = true
        }
      }
    }

    grafana = {
      enabled = true
      defaultDashboardsEnabled = true
      admin = {
        existingSecret = "" # используйте Secret в прод
      }
      grafana.ini = {
        server = {
          root_url = "%(protocol)s://%(domain)s/"
        }
        security = {
          allow_embedding = false
          cookie_secure   = true
          cookie_samesite = "strict"
          x_content_type_options = true
        }
      }
      resources = {
        requests = { cpu = "100m", memory = "256Mi" }
        limits   = { cpu = "1", memory = "1Gi" }
      }
      securityContext = {
        runAsNonRoot = true
        runAsUser    = 472
        fsGroup      = 472
        readOnlyRootFilesystem = true
      }
    }

    kube-state-metrics = {
      resources = {
        requests = { cpu = "50m", memory = "128Mi" }
        limits   = { cpu = "500m", memory = "512Mi" }
      }
      securityContext = {
        runAsNonRoot = true
        runAsUser    = 65534
        fsGroup      = 65534
        readOnlyRootFilesystem = true
      }
    }

    nodeExporter = {
      resources = {
        requests = { cpu = "50m", memory = "64Mi" }
        limits   = { cpu = "500m", memory = "256Mi" }
      }
    }

    prometheusOperator = {
      resources = {
        requests = { cpu = "100m", memory = "256Mi" }
        limits   = { cpu = "1", memory = "1Gi" }
      }
      admissionWebhooks = {
        enabled = true
        patch = {
          enabled = true
        }
      }
    }
  }

  # Базовые values для OpenTelemetry Collector (gateway/daemonset)
  otel_base_values = {
    mode = var.otel_mode
    namespaceOverride = var.namespace
    fullnameOverride  = "otel-collector"
    image = { pullPolicy = "IfNotPresent" }

    # Общие безопасные настройки контейнера
    securityContext = {
      runAsNonRoot = true
      runAsUser    = 10001
      runAsGroup   = 10001
      readOnlyRootFilesystem = true
      allowPrivilegeEscalation = false
      capabilities = { drop = ["ALL"] }
    }

    resources = {
      limits   = { cpu = "1", memory = "1Gi" }
      requests = { cpu = "200m", memory = "256Mi" }
    }

    # Простейшая конфигурация: прием OTLP и экспорт метрик в Prometheus
    # (подхватывается ServiceMonitor из kube-prometheus-stack)
    config = {
      receivers = {
        otlp = {
          protocols = {
            http = {}
            grpc = {}
          }
        }
      }
      processors = {
        batch = {}
        memory_limiter = {
          check_interval = "5s"
          limit_mib      = 800
        }
        resourcedetection = { detectors = ["env", "system"] }
      }
      exporters = {
        prometheus = { endpoint = "0.0.0.0:9464" }
        # Для трассировок к Tempo раскомментируйте и передайте values через var.otel_values
        # otlp/tempo = { endpoint = "tempo:4317", tls = { insecure = true } }
      }
      service = {
        telemetry = {
          metrics = { address = "0.0.0.0:8888" }
          logs    = {}
        }
        pipelines = {
          metrics = {
            receivers  = ["otlp"]
            processors = ["memory_limiter", "batch", "resourcedetection"]
            exporters  = ["prometheus"]
          }
          # traces = { receivers=["otlp"], processors=["batch"], exporters=["otlp/tempo"] }
        }
      }
    }
    service = {
      enabled = true
      type    = "ClusterIP"
      ports   = {
        otlp-grpc = { port = 4317, targetPort = 4317, protocol = "TCP" }
        otlp-http = { port = 4318, targetPort = 4318, protocol = "TCP" }
        metrics   = { port = 8888, targetPort = 8888, protocol = "TCP" }
        prom      = { port = 9464, targetPort = 9464, protocol = "TCP" }
      }
    }
    serviceMonitor = { enabled = true }
    podMonitor     = { enabled = false }
  }

  # Мердж values: базовые + пользовательские
  kps_values_merged  = merge(local.kps_base_values, try(var.kps_values, {}))
  otel_values_merged = merge(local.otel_base_values, try(var.otel_values, {}))
}

########################
# Namespace            #
########################

resource "kubernetes_namespace" "observability" {
  metadata {
    name        = var.namespace
    labels      = local.common_labels
    annotations = var.annotations
  }
}

########################
# Helm: kube-prometheus-stack
########################

resource "helm_release" "kube_prometheus_stack" {
  count      = var.enable_kube_prometheus_stack ? 1 : 0
  name       = "kube-prometheus-stack"
  namespace  = kubernetes_namespace.observability.metadata[0].name
  repository = var.repo_prometheus
  chart      = "kube-prometheus-stack"
  version    = var.kps_chart_version
  timeout    = 1200
  wait       = true
  recreate_pods = false
  cleanup_on_fail = true

  values = [ yamlencode(local.kps_values_merged) ]

  # Обеспечиваем порядок CRDs -> релиз
  depends_on = [ kubernetes_namespace.observability ]
}

########################
# Helm: OpenTelemetry Collector
########################

resource "helm_release" "otel_collector" {
  count      = var.enable_otel_collector ? 1 : 0
  name       = "opentelemetry-collector"
  namespace  = kubernetes_namespace.observability.metadata[0].name
  repository = var.repo_opentelemetry
  chart      = "opentelemetry-collector"
  version    = var.otel_chart_version
  timeout    = 900
  wait       = true
  recreate_pods = false
  cleanup_on_fail = true

  values = [ yamlencode(local.otel_values_merged) ]

  depends_on = [
    kubernetes_namespace.observability,
    # Если хотим чтобы ServiceMonitor был готов — ждём оператора
    helm_release.kube_prometheus_stack
  ]
}

########################
# Helm: Loki / Promtail / Tempo (опционально)
# Передавайте ПОЛНЫЕ корректные values через соответствующие переменные.
########################

resource "helm_release" "loki" {
  count      = var.enable_loki ? 1 : 0
  name       = "loki"
  namespace  = kubernetes_namespace.observability.metadata[0].name
  repository = var.repo_grafana
  chart      = "loki"
  # Версию задайте через loki_values, чтобы не нарушить совместимость
  # (пример): version = "6.6.3"
  timeout    = 900
  wait       = true

  values = [ yamlencode(var.loki_values) ]

  depends_on = [ kubernetes_namespace.observability ]
}

resource "helm_release" "promtail" {
  count      = var.enable_promtail ? 1 : 0
  name       = "promtail"
  namespace  = kubernetes_namespace.observability.metadata[0].name
  repository = var.repo_grafana
  chart      = "promtail"
  timeout    = 600
  wait       = true

  values = [ yamlencode(var.promtail_values) ]

  depends_on = [ kubernetes_namespace.observability ]
}

resource "helm_release" "tempo" {
  count      = var.enable_tempo ? 1 : 0
  name       = "tempo"
  namespace  = kubernetes_namespace.observability.metadata[0].name
  repository = var.repo_grafana
  chart      = "tempo"
  timeout    = 900
  wait       = true

  values = [ yamlencode(var.tempo_values) ]

  depends_on = [ kubernetes_namespace.observability ]
}

############
# Outputs  #
############

output "namespace" {
  description = "Namespace для инструментов наблюдаемости"
  value       = kubernetes_namespace.observability.metadata[0].name
}

output "kube_prometheus_stack_release" {
  description = "Имя релиза kube-prometheus-stack (если установлен)"
  value       = var.enable_kube_prometheus_stack ? helm_release.kube_prometheus_stack[0].name : null
}

output "otel_collector_service" {
  description = "Service OpenTelemetry Collector (если установлен)"
  value = var.enable_otel_collector ? {
    name      = "otel-collector"
    namespace = kubernetes_namespace.observability.metadata[0].name
    otlp_grpc = 4317
    otlp_http = 4318
    prometheus_exporter = 9464
  } : null
}

output "installed_optional" {
  description = "Какие дополнительные компоненты включены"
  value = {
    loki     = var.enable_loki
    promtail = var.enable_promtail
    tempo    = var.enable_tempo
  }
}
