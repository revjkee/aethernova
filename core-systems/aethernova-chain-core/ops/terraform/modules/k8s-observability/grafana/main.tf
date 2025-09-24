#############################################
# aethernova-chain-core/ops/terraform/modules/k8s-observability/grafana/main.tf
# - Устанавливает Grafana через Helm (ClusterIP, без PVC в dev/profiles по умолчанию)
# - Создаёт секрет с админ-логином/паролем и передаёт его в чарт (admin.existingSecret)
# - Конфигурирует Grafana через Terraform-провайдер: папки, data sources, пример dashboard
#############################################

terraform {
  required_version = ">= 1.5.0, < 2.0.0"
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.29.0"
    }
    grafana = {
      source  = "grafana/grafana"
      version = ">= 2.11.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}

#############################################
# Входные параметры модуля
#############################################

variable "namespace" {
  description = "Namespace для компонентов Grafana."
  type        = string
  default     = "observability"
}

variable "release_name" {
  description = "Имя релиза Helm для Grafana."
  type        = string
  default     = "grafana"
}

variable "grafana_chart_version" {
  description = "Версия чарта grafana/grafana (опционально фиксируйте)."
  type        = string
  default     = null # если null — возьмётся latest из репозитория
}

# URL, по которому Terraform сможет достучаться до Grafana API.
# Обычно это Ingress/ALB/LoadBalancer или локальный порт-форвардинг.
variable "grafana_url" {
  description = "Базовый URL Grafana для провайдера (например, https://grafana.example.com)."
  type        = string
}

variable "prometheus_url" {
  description = "HTTP URL Prometheus (например, http://prometheus-operated.monitoring.svc:9090)."
  type        = string
}

variable "loki_url" {
  description = "HTTP URL Loki (например, http://loki-gateway.loki.svc:80)."
  type        = string
  default     = null
}

variable "tempo_url" {
  description = "HTTP URL Tempo (например, http://tempo-distributor.tempo.svc:3100)."
  type        = string
  default     = null
}

#############################################
# Namespace и учётные данные администратора
#############################################

resource "kubernetes_namespace" "this" {
  metadata {
    name = var.namespace
  }
}

# Безопасный пароль администратора
resource "random_password" "grafana_admin" {
  length           = 24
  special          = true
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
  override_special = "!#$%&*+-=?@^_"
}

# Секрет с логином/паролем для чарта Grafana
resource "kubernetes_secret" "grafana_admin" {
  metadata {
    name      = "${var.release_name}-admin"
    namespace = var.namespace
    labels = {
      "app.kubernetes.io/name" = "grafana"
    }
  }
  type = "Opaque"

  data = {
    # Ключи должны называться admin-user и admin-password согласно значениям чарта
    # (см. admin.userKey/admin.passwordKey в values).
    "admin-user"     = base64encode("admin")
    "admin-password" = base64encode(random_password.grafana_admin.result)
  }
}

#############################################
# Установка Grafana через Helm
#############################################

resource "helm_release" "grafana" {
  name       = var.release_name
  namespace  = var.namespace
  repository = "https://grafana.github.io/helm-charts"
  chart      = "grafana"
  version    = var.grafana_chart_version

  # Значения Helm: используем существующий секрет для админа, ClusterIP, без ingress/persistence по умолчанию
  values = [
    yamlencode({
      admin = {
        existingSecret = kubernetes_secret.grafana_admin.metadata[0].name
        userKey        = "admin-user"
        passwordKey    = "admin-password"
      }
      service = {
        type = "ClusterIP"
        port = 80
      }
      ingress = {
        enabled = false
      }
      persistence = {
        enabled = false
      }
      grafana.ini = {
        "server" = {
          "root_url" = var.grafana_url
        }
      }
    })
  ]

  # Делаем развёртывание детерминированным для дальнейшей конфигурации API
  timeout          = 600
  recreate_pods    = false
  atomic           = true
  cleanup_on_fail  = true
  dependency_update = true
}

#############################################
# Провайдер Grafana — подключение к только что установленной Grafana
# Требуется доступность URL (ingress/LB/порт-форвардинг).
#############################################

provider "grafana" {
  url = var.grafana_url
  # Базовая авторизация username:password. Допустим также API key в auth.
  # Для ряда административных операций (org-scoped) требуется именно basic auth.
  auth = "admin:${random_password.grafana_admin.result}"
}

#############################################
# Папки в Grafana
#############################################

resource "grafana_folder" "platform" {
  title      = "Kubernetes / Platform"
  depends_on = [helm_release.grafana]
}

resource "grafana_folder" "apps" {
  title      = "Applications"
  depends_on = [helm_release.grafana]
}

#############################################
# Источники данных Grafana
#############################################

# Prometheus (обязателен для большинства дашбордов)
resource "grafana_data_source" "prometheus" {
  type      = "prometheus"
  name      = "Prometheus"
  url       = var.prometheus_url
  is_default = true

  json_data = jsonencode({
    httpMethod = "POST"
    manageAlerts = true
  })

  depends_on = [helm_release.grafana]
}

# Loki (опционально)
resource "grafana_data_source" "loki" {
  count = var.loki_url == null ? 0 : 1

  type = "loki"
  name = "Loki"
  url  = var.loki_url

  json_data = jsonencode({
    maxLines = 1000
  })

  depends_on = [helm_release.grafana]
}

# Tempo (опционально)
resource "grafana_data_source" "tempo" {
  count = var.tempo_url == null ? 0 : 1

  type = "tempo"
  name = "Tempo"
  url  = var.tempo_url

  json_data = jsonencode({
    httpMethod = "GET"
    search    = { hide = false }
    tracesToLogsV2 = {
      datasourceUid = try(grafana_data_source.loki[0].uid, null)
      spanStartTimeShift = "1h"
      spanEndTimeShift   = "1h"
      tags               = ["job","instance","pod","namespace"]
      mappedTags         = [{ key = "service.name", value = "service_name" }]
      lokiSearch = {
        tags = ["container","pod"]
      }
    }
  })

  depends_on = [helm_release.grafana]
}

#############################################
# Пример дашборда (минимальный), использует Prometheus
#############################################

resource "grafana_dashboard" "k8s_health" {
  folder     = grafana_folder.platform.id
  overwrite  = true
  depends_on = [grafana_data_source.prometheus]

  # Конструируем JSON через jsonencode, чтобы подставить UID источника данных
  config_json = jsonencode({
    title         = "Kubernetes: Cluster Health (minimal)"
    uid           = "k8s-health-min"
    timezone      = "browser"
    schemaVersion = 39
    version       = 1
    refresh       = "30s"
    panels = [
      {
        type    = "timeseries"
        title   = "Kube API availability (up)"
        targets = [
          {
            expr = "avg(up)"
            datasource = { type = "prometheus", uid = grafana_data_source.prometheus.uid }
            legendFormat = "up"
          }
        ]
        gridPos = { x = 0, y = 0, w = 24, h = 8 }
      }
    ]
  })
}
