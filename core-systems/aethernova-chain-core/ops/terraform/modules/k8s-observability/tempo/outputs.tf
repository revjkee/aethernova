# aethernova-chain-core/ops/terraform/modules/k8s-observability/tempo/outputs.tf
#
# Назначение:
# - Экспортирует стабильные артефакты интеграции Grafana Tempo в Kubernetes.
# - Не зависит от внутренних ресурсов напрямую: все вычисляется из var.*,
#   чтобы не ломать сборку при изменениях реализации (Helm/K8s).
#
# Ожидаемые входные переменные (должны быть объявлены в variables.tf модуля):
#   - namespace (string)                      # неймспейс установки Tempo
#   - release_name (string)                   # префикс релиза/ресурсов Tempo
#   - cluster_domain (string, default "cluster.local")
#   - distributor_service_name (string, default = "${release_name}-distributor")
#   - query_frontend_service_name (string, default = "${release_name}-query-frontend")
#   - querier_service_name (string, default = "${release_name}-querier")
#   - monolith_service_name (string, default = "${release_name}") # если одиночный сервис
#   - otlp_grpc_port (number, default 4317)
#   - otlp_http_port (number, default 4318)
#   - query_frontend_http_port (number, default 3100) # чаще 3100/80/3200 по чарте — выровняйте с values
#   - tempo_http_api_port (number, default 3200)      # tempo HTTP API (optional)
#   - grafana_tempo_datasource_name (string, default "Tempo")
#   - grafana_tempo_datasource_uid (string, default "tempo")
#   - enable_monolith (bool, default = false)         # если true — использовать monolith_service_name
#
# Примечание:
# - FQDN сервисов формируется через <svc>.<ns>.svc.<clusterDomain>.
# - Значения портов и имен сервисов должны соответствовать вашему Helm values.yaml.

###############################################################################
# LOCALS
###############################################################################

locals {
  ns             = var.namespace
  rel            = var.release_name
  domain         = var.cluster_domain
  svc_distrib    = coalesce(var.distributor_service_name, "${var.release_name}-distributor")
  svc_qf         = coalesce(var.query_frontend_service_name, "${var.release_name}-query-frontend")
  svc_querier    = coalesce(var.querier_service_name, "${var.release_name}-querier")
  svc_monolith   = coalesce(var.monolith_service_name, var.release_name)

  fqdn = {
    distributor      = "${local.svc_distrib}.${local.ns}.svc.${local.domain}"
    query_frontend   = "${local.svc_qf}.${local.ns}.svc.${local.domain}"
    querier          = "${local.svc_querier}.${local.ns}.svc.${local.domain}"
    monolith         = "${local.svc_monolith}.${local.ns}.svc.${local.domain}"
  }

  # Выбор конечной точки для OTLP (monolith vs distributor)
  otlp_host = var.enable_monolith ? local.fqdn.monolith : local.fqdn.distributor

  # Типичные эндпойнты для агентов/экспортёров
  otlp = {
    grpc = "${local.otlp_host}:${var.otlp_grpc_port}"
    http = "http://${local.otlp_host}:${var.otlp_http_port}"
  }

  # URL для UI/прокси Query Frontend (HTTP)
  query_frontend = {
    host = local.fqdn.query_frontend
    url  = "http://${local.fqdn.query_frontend}:${var.query_frontend_http_port}"
  }

  tempo_http_api = {
    host = var.enable_monolith ? local.fqdn.monolith : local.fqdn.querier
    url  = "http://${var.enable_monolith ? local.fqdn.monolith : local.fqdn.querier}:${var.tempo_http_api_port}"
  }

  grafana_ds = {
    name = var.grafana_tempo_datasource_name
    uid  = var.grafana_tempo_datasource_uid
    json = jsonencode({
      apiVersion = 1
      datasources = [
        {
          name      = var.grafana_tempo_datasource_name
          type      = "tempo"
          uid       = var.grafana_tempo_datasource_uid
          access    = "proxy"
          url       = local.query_frontend.url
          isDefault = false
          jsonData = {
            httpMethod        = "GET"
            serviceMap        = { datasourceUid = var.grafana_tempo_datasource_uid }
            nodeGraph         = { enabled = true }
            search            = { query = "" }
            tracesToLogs      = {
              datasourceUid = "loki" # скорректируйте при необходимости
              mappedTags    = ["service.name", "service_namespace"]
              mapTagNamesEnabled = true
              spanStartTimeShift = "1h"
              spanEndTimeShift   = "1h"
            }
            tracesToMetrics   = {
              datasourceUid = "prometheus" # скорректируйте
              spanStartTimeShift = "1h"
              spanEndTimeShift   = "1h"
              tags = [{ key = "service.name", value = "service" }]
            }
          }
        }
      ]
    })
  }
}

###############################################################################
# CORE OUTPUTS
###############################################################################

output "namespace" {
  description = "Kubernetes namespace, где развернут Grafana Tempo."
  value       = local.ns
}

output "release_name" {
  description = "Имя релиза Tempo (префикс ресурсов)."
  value       = local.rel
}

output "cluster_domain" {
  description = "Kubernetes cluster domain, используемый для FQDN сервисов."
  value       = local.domain
}

###############################################################################
# SERVICE FQDN/URL OUTPUTS
###############################################################################

output "tempo_distributor_service_fqdn" {
  description = "FQDN сервиса distributor (если используется распределенная схема)."
  value       = local.fqdn.distributor
}

output "tempo_query_frontend_service_fqdn" {
  description = "FQDN сервиса query-frontend."
  value       = local.fqdn.query_frontend
}

output "tempo_querier_service_fqdn" {
  description = "FQDN сервиса querier (в распределенной схеме) либо API-хост при enable_monolith=false."
  value       = local.fqdn.querier
}

output "tempo_monolith_service_fqdn" {
  description = "FQDN монолитного сервиса Tempo (если enable_monolith=true)."
  value       = local.fqdn.monolith
}

output "tempo_query_frontend_http_url" {
  description = "HTTP URL Query Frontend (для UI/прокси запросов)."
  value       = local.query_frontend.url
}

output "tempo_http_api_url" {
  description = "HTTP API Tempo (querier или monolith, в зависимости от enable_monolith)."
  value       = local.tempo_http_api.url
}

###############################################################################
# OTLP ENDPOINTS (для агентов/экспортёров)
###############################################################################

output "otlp_grpc_endpoint" {
  description = "OTLP gRPC endpoint (host:port), используйте в OpenTelemetry Collector/SDK."
  value       = local.otlp.grpc
}

output "otlp_http_endpoint" {
  description = "OTLP HTTP endpoint, используйте для OTLP/HTTP."
  value       = local.otlp.http
}

###############################################################################
# GRAFANA DATASOURCE ARTIFACTS
###############################################################################

output "grafana_tempo_datasource_name" {
  description = "Рекомендуемое имя Grafana Tempo datasource."
  value       = local.grafana_ds.name
}

output "grafana_tempo_datasource_uid" {
  description = "UID Grafana Tempo datasource (стабильный идентификатор)."
  value       = local.grafana_ds.uid
}

output "grafana_tempo_datasource_provisioning_json" {
  description = "Готовый JSON для провижининга Grafana Tempo datasource (apiVersion=1)."
  value       = local.grafana_ds.json
  sensitive   = false
}

###############################################################################
# INTEGRATION HINTS (строго как значения, без внешних фактов)
###############################################################################

output "integration_endpoints" {
  description = "Сводные эндпойнты для быстрой интеграции сторонних модулей."
  value = {
    namespace                  = local.ns
    query_frontend_http_url    = local.query_frontend.url
    tempo_http_api_url         = local.tempo_http_api.url
    otlp_grpc_endpoint         = local.otlp.grpc
    otlp_http_endpoint         = local.otlp.http
    distributor_service_fqdn   = local.fqdn.distributor
    querier_service_fqdn       = local.fqdn.querier
    monolith_service_fqdn      = local.fqdn.monolith
    grafana_datasource_name    = local.grafana_ds.name
    grafana_datasource_uid     = local.grafana_ds.uid
  }
}
