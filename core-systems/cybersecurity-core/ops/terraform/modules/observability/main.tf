// cybersecurity-core/ops/terraform/modules/observability/main.tf

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.28.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.13.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}

############################
# Variables
############################

variable "namespace" {
  description = "Namespace for observability stack"
  type        = string
  default     = "observability"
}

variable "create_namespace" {
  description = "Create namespace if true"
  type        = bool
  default     = true
}

variable "enable_kube_prometheus_stack" {
  description = "Install kube-prometheus-stack"
  type        = bool
  default     = true
}

variable "enable_loki" {
  description = "Install Loki"
  type        = bool
  default     = true
}

variable "enable_promtail" {
  description = "Install Promtail"
  type        = bool
  default     = true
}

variable "enable_tempo" {
  description = "Install Tempo"
  type        = bool
  default     = true
}

variable "enable_otel_collector" {
  description = "Install OpenTelemetry Collector (contrib)"
  type        = bool
  default     = true
}

variable "prometheus_retention" {
  description = "Prometheus retention window (e.g. 15d)"
  type        = string
  default     = "15d"
}

variable "prometheus_storage_size" {
  description = "Prometheus PVC size"
  type        = string
  default     = "50Gi"
}

variable "grafana_storage_size" {
  description = "Grafana PVC size"
  type        = string
  default     = "10Gi"
}

variable "loki_storage_size" {
  description = "Loki PVC size (single binary mode)"
  type        = string
  default     = "200Gi"
}

variable "tempo_storage_size" {
  description = "Tempo PVC size (monolithic)"
  type        = string
  default     = "100Gi"
}

variable "grafana_admin_user" {
  description = "Grafana admin user (stored in secret at higher layer)"
  type        = string
  default     = "admin"
}

variable "grafana_admin_password_secret_name" {
  description = "Kubernetes secret name in the same namespace that holds key 'admin-password'"
  type        = string
  default     = null
}

variable "pod_security_context_fs_group" {
  description = "fsGroup for stateful pods"
  type        = number
  default     = 2000
}

variable "node_selector" {
  description = "Optional nodeSelector for observability workloads"
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Optional tolerations for observability workloads"
  type = list(object({
    key      = string
    operator = string
    value    = optional(string)
    effect   = optional(string)
  }))
  default = []
}

variable "extra_grafana_datasources" {
  description = "Additional Grafana datasources (YAML text fragments)"
  type        = list(string)
  default     = []
}

############################
# Locals
############################

locals {
  labels = {
    "app.kubernetes.io/part-of" = "observability"
    "security.aethernova.io/tier" = "core"
  }

  grafana_secret_ref_enabled = var.grafana_admin_password_secret_name != null && var.grafana_admin_password_secret_name != ""

  // Common hardening for Helm charts via values
  common_security_values = <<-YAML
    podSecurityContext:
      fsGroup: ${var.pod_security_context_fs_group}
      seccompProfile:
        type: RuntimeDefault
    containerSecurityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    nodeSelector: ${jsonencode(var.node_selector)}
    tolerations: ${jsonencode(var.tolerations)}
  YAML
}

############################
# Namespace
############################

resource "kubernetes_namespace" "this" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name   = var.namespace
    labels = merge(local.labels, { "kubernetes.io/metadata.name" = var.namespace })
  }
}

############################
# Helm Repositories
############################

resource "helm_repository" "prometheus_community" {
  name = "prometheus-community"
  url  = "https://prometheus-community.github.io/helm-charts"
}

resource "helm_repository" "grafana" {
  name = "grafana"
  url  = "https://grafana.github.io/helm-charts"
}

resource "helm_repository" "opentelemetry" {
  name = "opentelemetry"
  url  = "https://open-telemetry.github.io/opentelemetry-helm-charts"
}

############################
# NetworkPolicies (baseline)
############################

resource "kubernetes_network_policy_v1" "default_deny_egress" {
  metadata {
    name      = "default-deny-egress"
    namespace = var.namespace
    labels    = local.labels
  }
  spec {
    pod_selector {}
    policy_types = ["Egress"]
    // Allow only DNS and in-namespace communication by default
    egress {
      to {
        namespace_selector {
          match_labels = { "kubernetes.io/metadata.name" = var.namespace }
        }
      }
    }
    egress {
      // kube-dns in kube-system
      to {
        namespace_selector {
          match_labels = { "kubernetes.io/metadata.name" = "kube-system" }
        }
        pod_selector {
          match_labels = { "k8s-app" = "kube-dns" }
        }
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
}

############################
# kube-prometheus-stack (Prometheus/Alertmanager/Grafana)
############################

resource "random_password" "grafana_admin_password" {
  length  = 24
  special = false
}

data "kubernetes_secret_v1" "grafana_admin" {
  count = local.grafana_secret_ref_enabled ? 1 : 0

  metadata {
    name      = var.grafana_admin_password_secret_name
    namespace = var.namespace
  }
}

resource "helm_release" "kps" {
  count            = var.enable_kube_prometheus_stack ? 1 : 0
  name             = "kube-prometheus-stack"
  namespace        = var.namespace
  repository       = helm_repository.prometheus_community.url
  chart            = "kube-prometheus-stack"
  create_namespace = false
  timeout          = 600

  values = [
    // Prometheus
    <<-YAML
    prometheus:
      ${local.common_security_values}
      prometheusSpec:
        retention: ${var.prometheus_retention}
        enableAdminAPI: false
        logFormat: json
        storageSpec:
          volumeClaimTemplate:
            spec:
              accessModes: ["ReadWriteOnce"]
              resources:
                requests:
                  storage: ${var.prometheus_storage_size}
    YAML
    ,
    // Grafana
    <<-YAML
    grafana:
      ${local.common_security_values}
      enabled: true
      adminUser: ${var.grafana_admin_user}
      adminPassword: ${local.grafana_secret_ref_enabled ? (base64decode(data.kubernetes_secret_v1.grafana_admin[0].data["admin-password"])) : random_password.grafana_admin_password.result}
      persistence:
        enabled: true
        size: ${var.grafana_storage_size}
        type: pvc
        accessModes: ["ReadWriteOnce"]
      grafana.ini:
        server:
          root_url: "%(protocol)s://%(domain)s/"
        security:
          disable_initial_admin_creation: true
          cookie_secure: true
        analytics:
          reporting_enabled: false
        users:
          allow_sign_up: false
      sidecar:
        datasources:
          enabled: true
        dashboards:
          enabled: true
      additionalDataSources:
        - name: Loki
          type: loki
          access: proxy
          url: http://loki.${var.namespace}.svc.cluster.local:3100
          isDefault: false
          jsonData:
            timeout: 60
            maxLines: 1000
        - name: Tempo
          type: tempo
          access: proxy
          url: http://tempo.${var.namespace}.svc.cluster.local:3100
          jsonData:
            httpMethod: GET
            tracesToLogsV2:
              datasourceUid: "Loki"
              spanStartTimeShift: "5m"
              spanEndTimeShift: "5m"
              tags: ["job", "instance", "pod", "namespace"]
              filterBySpanID: true
              filterByTraceID: true
              customQuery: false
    YAML
    ,
    // Alertmanager hardening
    <<-YAML
    alertmanager:
      ${local.common_security_values}
      alertmanagerSpec:
        useExistingSecret: false
        storage:
          volumeClaimTemplate:
            spec:
              accessModes: ["ReadWriteOnce"]
              resources:
                requests:
                  storage: 10Gi
    YAML
    ,
    // Disable components we don't need by default (tune per environment)
    <<-YAML
    kubeScheduler:
      enabled: true
    kubeControllerManager:
      enabled: true
    kubeEtcd:
      enabled: true
    kubeProxy:
      enabled: true
    YAML
  ]

  depends_on = [
    kubernetes_namespace.this,
    kubernetes_network_policy_v1.default_deny_egress
  ]
}

############################
# Loki (single binary) + PVC
############################

resource "helm_release" "loki" {
  count            = var.enable_loki ? 1 : 0
  name             = "loki"
  namespace        = var.namespace
  repository       = helm_repository.grafana.url
  chart            = "loki"
  create_namespace = false
  timeout          = 600

  values = [
    <<-YAML
    ${local.common_security_values}
    loki:
      commonConfig:
        replication_factor: 1
      auth_enabled: false
      server:
        log_format: json
      storage:
        type: filesystem
      schemaConfig:
        configs:
          - from: "2024-01-01"
            store: tsdb
            object_store: filesystem
            schema: v13
            index:
              prefix: index_
              period: 24h
    singleBinary:
      replicas: 1
      persistence:
        enabled: true
        size: ${var.loki_storage_size}
        storageClassName: null
    gateway:
      enabled: false
    serviceMonitor:
      enabled: true
    YAML
  ]

  depends_on = [kubernetes_namespace.this]
}

############################
# Promtail -> Loki
############################

resource "helm_release" "promtail" {
  count            = var.enable_promtail ? 1 : 0
  name             = "promtail"
  namespace        = var.namespace
  repository       = helm_repository.grafana.url
  chart            = "promtail"
  create_namespace = false
  timeout          = 600

  values = [
    <<-YAML
    ${local.common_security_values}
    config:
      clients:
        - url: http://loki.${var.namespace}.svc.cluster.local:3100/loki/api/v1/push
      snippets:
        pipelineStages:
          - cri: {}
          - match:
              selector: '{job="varlogs"}'
              stages:
                - regex:
                    expression: '(?i)(password|authorization|apikey|token)[=:]\\s*\\S+'
                - replace:
                    expression: '(?i)(password|authorization|apikey|token)[=:]\\s*\\S+'
                    replace: '$1=<redacted>'
    tolerations: ${jsonencode(var.tolerations)}
    YAML
  ]

  depends_on = [
    kubernetes_namespace.this,
    helm_release.loki
  ]
}

############################
# Tempo (monolithic)
############################

resource "helm_release" "tempo" {
  count            = var.enable_tempo ? 1 : 0
  name             = "tempo"
  namespace        = var.namespace
  repository       = helm_repository.grafana.url
  chart            = "tempo"
  create_namespace = false
  timeout          = 600

  values = [
    <<-YAML
    ${local.common_security_values}
    tempo:
      storage:
        trace:
          backend: local
      server:
        http_listen_port: 3100
        log_level: info
      metricsGenerator:
        enabled: true
    persistence:
      enabled: true
      size: ${var.tempo_storage_size}
    serviceMonitor:
      enabled: true
    YAML
  ]

  depends_on = [kubernetes_namespace.this]
}

############################
# OpenTelemetry Collector (contrib build)
############################

resource "helm_release" "otel_collector" {
  count            = var.enable_otel_collector ? 1 : 0
  name             = "otel-collector"
  namespace        = var.namespace
  repository       = helm_repository.opentelemetry.url
  chart            = "opentelemetry-collector"
  create_namespace = false
  timeout          = 600

  values = [
    <<-YAML
    ${local.common_security_values}
    mode: deployment
    replicaCount: 2
    image:
      repository: otel/opentelemetry-collector-contrib
    presets:
      logsCollection:
        enabled: false
    config:
      receivers:
        otlp:
          protocols:
            grpc:
              endpoint: 0.0.0.0:4317
            http:
              endpoint: 0.0.0.0:4318
      processors:
        batch:
          send_batch_size: 8192
          timeout: 2s
        memory_limiter:
          check_interval: 1s
          limit_percentage: 80
      exporters:
        otlp/tempo:
          endpoint: tempo.${var.namespace}.svc.cluster.local:4317
          tls:
            insecure: true
        loki:
          endpoint: http://loki.${var.namespace}.svc.cluster.local:3100/loki/api/v1/push
          labels:
            resource:
              k8s.namespace.name: "namespace"
              k8s.pod.name: "pod"
              service.name: "service"
        prometheus:
          endpoint: 0.0.0.0:8889
      service:
        telemetry:
          logs:
            level: "info"
        pipelines:
          traces:
            receivers: [otlp]
            processors: [memory_limiter, batch]
            exporters: [otlp/tempo]
          metrics:
            receivers: [otlp]
            processors: [memory_limiter, batch]
            exporters: [prometheus]
          logs:
            receivers: [otlp]
            processors: [memory_limiter, batch]
            exporters: [loki]
    service:
      enabled: true
      type: ClusterIP
      ports:
        otlp-grpc:
          enabled: true
          port: 4317
        otlp-http:
          enabled: true
          port: 4318
        metrics:
          enabled: true
          port: 8889
    serviceMonitor:
      enabled: true
    YAML
  ]

  depends_on = [
    kubernetes_namespace.this,
    helm_release.loki,
    helm_release.tempo
  ]
}
