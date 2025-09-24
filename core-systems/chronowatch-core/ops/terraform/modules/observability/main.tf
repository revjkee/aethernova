terraform {
  required_version = ">= 1.5.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.27.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12.1"
    }
  }
}

############################
# Variables
############################
variable "namespace" {
  description = "Namespace для стека наблюдаемости (kube-prometheus-stack)"
  type        = string
  default     = "monitoring"
}

variable "release_name" {
  description = "Имя Helm-релиза kube-prometheus-stack"
  type        = string
  default     = "kps"
}

variable "kps_repo" {
  description = "Helm-репозиторий kube-prometheus-stack"
  type        = string
  default     = "https://prometheus-community.github.io/helm-charts"
}

variable "kps_chart_version" {
  description = "Версия чарта kube-prometheus-stack (строго задавайте в root-модуле)"
  type        = string
}

variable "create_namespace" {
  description = "Создавать namespace мониторинга"
  type        = bool
  default     = true
}

variable "helm_timeout_sec" {
  description = "Таймаут ожидания установки Helm-релиза"
  type        = number
  default     = 600
}

variable "prometheus_retention" {
  description = "Срок хранения метрик Prometheus"
  type        = string
  default     = "15d"
}

variable "prometheus_resources" {
  description = "Ресурсы Prometheus"
  type = object({
    requests = map(string)
    limits   = map(string)
  })
  default = {
    requests = { cpu = "200m", memory = "1Gi" }
    limits   = { cpu = "2",    memory = "4Gi" }
  }
}

variable "grafana_admin_password" {
  description = "Пароль администратора Grafana (если пусто — генерится чартом/секретом)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "enable_alertmanager" {
  description = "Включить Alertmanager в kube-prometheus-stack"
  type        = bool
  default     = true
}

# Параметры приложения chronowatch-core, которое нужно скрейпить
variable "app_namespace" {
  description = "Namespace приложения chronowatch-core"
  type        = string
  default     = "chronowatch-prod"
}

variable "app_service_match_labels" {
  description = "Селектор меток Service приложения для ServiceMonitor"
  type        = map(string)
  default = {
    "app.kubernetes.io/name"     = "chronowatch-core"
    "app.kubernetes.io/instance" = "chronowatch-core-prod"
  }
}

variable "metrics_port_name" {
  description = "Имя порта в Service, по которому отдаются метрики"
  type        = string
  default     = "http"
}

variable "metrics_path" {
  description = "HTTP-путь метрик приложения"
  type        = string
  default     = "/metrics"
}

variable "scrape_interval" {
  description = "Интервал скрейпа метрик приложения"
  type        = string
  default     = "15s"
}

# Пороги алертов
variable "alert_failed_rate_threshold" {
  description = "Пороговая скорость ошибок (FAILED executions) в секундах^-1"
  type        = number
  default     = 0.05
}

variable "alert_no_leader_minutes" {
  description = "Минут без лидера chronowatch_leader для алерта"
  type        = number
  default     = 5
}

variable "alert_latency_p95_seconds" {
  description = "Порог P95 latency по выполнению задач"
  type        = number
  default     = 5
}

# NetworkPolicy egress из monitoring к приложениям (по меткам ns)
variable "app_namespace_label_selector" {
  description = "Селектор меток namespace приложений для egress Grafana/Prometheus"
  type        = map(string)
  default = {
    env = "prod"
  }
}

############################
# Namespace (optional)
############################
resource "kubernetes_namespace" "monitoring" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name = var.namespace
    labels = {
      name = var.namespace
    }
  }
}

############################
# Helm: kube-prometheus-stack
############################
locals {
  grafana_admin_pw = length(var.grafana_admin_password) > 0 ? var.grafana_admin_password : null

  helm_values = yamlencode({
    crds = {
      enabled = true
    }

    kube-state-metrics = {
      enabled = true
    }

    nodeExporter = {
      enabled = true
    }

    prometheus = {
      enabled = true
      service = {
        type = "ClusterIP"
      }
      prometheusSpec = {
        retention = var.prometheus_retention

        # Разрешаем подбирать все ServiceMonitor/PodMonitor без привязки к label 'release'
        serviceMonitorSelectorNilUsesHelmValues = false
        podMonitorSelectorNilUsesHelmValues     = false

        resources = var.prometheus_resources
      }
    }

    alertmanager = {
      enabled = var.enable_alertmanager
      service = {
        type = "ClusterIP"
      }
    }

    grafana = {
      enabled               = true
      defaultDashboardsEnabled = false
      adminPassword         = local.grafana_admin_pw
      service = {
        type = "ClusterIP"
      }
      sidecar = {
        dashboards = {
          enabled = true
          label   = "grafana_dashboard"
        }
      }
    }
  })
}

resource "helm_release" "kps" {
  name             = var.release_name
  namespace        = var.namespace
  repository       = var.kps_repo
  chart            = "kube-prometheus-stack"
  version          = var.kps_chart_version
  timeout          = var.helm_timeout_sec
  wait             = true
  cleanup_on_fail  = true
  create_namespace = false

  # Убедимся, что ns существует до релиза
  depends_on = [
    kubernetes_namespace.monitoring
  ]

  values = [
    local.helm_values
  ]
}

############################
# ServiceMonitor для chronowatch-core
############################
resource "kubernetes_manifest" "chronowatch_servicemonitor" {
  manifest = {
    apiVersion = "monitoring.coreos.com/v1"
    kind       = "ServiceMonitor"
    metadata = {
      name      = "chronowatch-core"
      namespace = var.namespace
      labels = {
        # Совместимость со старыми настройками селектора по релизу
        release = var.release_name
      }
    }
    spec = {
      selector = {
        matchLabels = var.app_service_match_labels
      }
      namespaceSelector = {
        matchNames = [var.app_namespace]
      }
      endpoints = [
        {
          port     = var.metrics_port_name
          path     = var.metrics_path
          interval = var.scrape_interval
          scheme   = "http"
        }
      ]
    }
  }

  depends_on = [helm_release.kps]
}

############################
# Правила алертов (PrometheusRule)
############################
resource "kubernetes_manifest" "chronowatch_rules" {
  manifest = {
    apiVersion = "monitoring.coreos.com/v1"
    kind       = "PrometheusRule"
    metadata = {
      name      = "chronowatch-core-rules"
      namespace = var.namespace
      labels = {
        release = var.release_name
      }
    }
    spec = {
      groups = [
        {
          name  = "chronowatch.core.availability"
          rules = [
            {
              alert = "ChronowatchNoLeader"
              expr  = "avg_over_time(chronowatch_leader[${var.alert_no_leader_minutes}m]) < 0.5"
              for   = "2m"
              labels = {
                severity = "critical"
                service  = "chronowatch-core"
              }
              annotations = {
                summary     = "Нет стабильного лидера у планировщика"
                description = "chronowatch_leader < 0.5 более ${var.alert_no_leader_minutes} минут."
              }
            }
          ]
        },
        {
          name  = "chronowatch.core.reliability"
          rules = [
            {
              alert = "ChronowatchHighFailedRate"
              expr  = "rate(chronowatch_executions_total{status=\"FAILED\"}[5m]) > ${var.alert_failed_rate_threshold}"
              for   = "5m"
              labels = {
                severity = "warning"
                service  = "chronowatch-core"
              }
              annotations = {
                summary     = "Повышенная скорость ошибок задач"
                description = "Скорость ошибок FAILED превышает ${var.alert_failed_rate_threshold}/s в течение 5m."
              }
            },
            {
              alert = "ChronowatchNoExecutions"
              expr  = "rate(chronowatch_executions_total[15m]) == 0"
              for   = "15m"
              labels = {
                severity = "warning"
                service  = "chronowatch-core"
              }
              annotations = {
                summary     = "Отсутствуют выполнения задач"
                description = "Не зафиксировано ни одного выполнения задач в течение ≥15m."
              }
            }
          ]
        },
        {
          name  = "chronowatch.core.latency"
          rules = [
            {
              alert = "ChronowatchP95LatencyHigh"
              expr  = "histogram_quantile(0.95, sum(rate(chronowatch_execution_seconds_bucket[5m])) by (le)) > ${var.alert_latency_p95_seconds}"
              for   = "10m"
              labels = {
                severity = "warning"
                service  = "chronowatch-core"
              }
              annotations = {
                summary     = "Высокая P95 латентность выполнения задач"
                description = "P95 > ${var.alert_latency_p95_seconds}s в течение 10m."
              }
            }
          ]
        }
      ]
    }
  }

  depends_on = [helm_release.kps]
}

############################
# Grafana Dashboard (ConfigMap)
############################
locals {
  grafana_dashboard_chronowatch = jsonencode({
    annotations = { list = [] }
    editable    = true
    schemaVersion = 38
    version       = 1
    title         = "Chronowatch Core Overview"
    tags          = ["chronowatch", "scheduler"]
    time = { from = "now-6h", to = "now" }
    panels = [
      {
        type  = "stat"
        title = "Leader State (avg over 5m)"
        gridPos = { x = 0, y = 0, w = 8, h = 4 }
        targets = [
          {
            expr = "avg_over_time(chronowatch_leader[5m])"
            refId = "A"
          }
        ]
      },
      {
        type  = "graph"
        title = "Executions rate (SUCCESS/FAILED)"
        gridPos = { x = 0, y = 4, w = 24, h = 8 }
        targets = [
          {
            expr  = "rate(chronowatch_executions_total{status=\"SUCCESS\"}[5m])"
            legendFormat = "success"
            refId = "A"
          },
          {
            expr  = "rate(chronowatch_executions_total{status=\"FAILED\"}[5m])"
            legendFormat = "failed"
            refId = "B"
          }
        ]
      },
      {
        type  = "graph"
        title = "Execution latency (p95)"
        gridPos = { x = 0, y = 12, w = 24, h = 8 }
        targets = [
          {
            expr  = "histogram_quantile(0.95, sum(rate(chronowatch_execution_seconds_bucket[5m])) by (le))"
            legendFormat = "p95"
            refId = "A"
          }
        ]
      }
    ]
  })
}

resource "kubernetes_config_map" "grafana_dashboard" {
  metadata {
    name      = "grafana-dashboard-chronowatch"
    namespace = var.namespace
    labels = {
      grafana_dashboard = "1"
      app               = "grafana"
    }
  }

  data = {
    "chronowatch-overview.json" = local.grafana_dashboard_chronowatch
  }

  depends_on = [helm_release.kps]
}

############################
# NetworkPolicy (egress) из monitoring в приложения (порт метрик 8080/TCP)
############################
resource "kubernetes_manifest" "monitoring_egress_to_apps" {
  manifest = {
    apiVersion = "networking.k8s.io/v1"
    kind       = "NetworkPolicy"
    metadata = {
      name      = "allow-egress-to-app-metrics"
      namespace = var.namespace
    }
    spec = {
      podSelector = {} # все поды в monitoring
      policyTypes = ["Egress"]
      egress = [
        {
          to = [
            {
              namespaceSelector = {
                matchLabels = var.app_namespace_label_selector
              }
            }
          ]
          ports = [
            {
              protocol = "TCP"
              port     = 8080
            }
          ]
        }
      ]
    }
  }

  depends_on = [helm_release.kps]
}

############################
# Outputs
############################
output "namespace" {
  description = "Namespace стека наблюдаемости"
  value       = var.namespace
}

output "kps_release_name" {
  description = "Имя релиза kube-prometheus-stack"
  value       = helm_release.kps.name
}

output "grafana_admin_password_effective" {
  description = "Установленный пароль Grafana (если был задан)"
  value       = var.grafana_admin_password != "" ? var.grafana_admin_password : "(managed by chart Secret)"
  sensitive   = true
}

output "servicemonitor_name" {
  description = "Имя созданного ServiceMonitor для chronowatch-core"
  value       = kubernetes_manifest.chronowatch_servicemonitor.manifest.metadata.name
}
