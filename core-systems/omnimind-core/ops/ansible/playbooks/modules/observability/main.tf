terraform {
  required_version = ">= 1.5.0"
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.23.0" }
    helm       = { source = "hashicorp/helm",       version = ">= 2.12.1" }
    random     = { source = "hashicorp/random",     version = ">= 3.6.0" }
  }
}

# --------------------------- Variables ---------------------------

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

variable "annotations" {
  description = "Дополнительные аннотации для всех ресурсов"
  type        = map(string)
  default     = {}
}

variable "cluster_id" {
  description = "Внешняя метка кластера для Prometheus externalLabels"
  type        = string
  default     = "omnimind-cluster"
}

variable "enable_network_policy" {
  description = "Включить сетевые политики у чартов (если поддерживается)"
  type        = bool
  default     = true
}

variable "enable_persistence" {
  description = "Включить PVC для компонентов"
  type        = bool
  default     = true
}

variable "storage_class" {
  description = "Имя StorageClass для PVC"
  type        = string
  default     = "standard"
}

variable "prometheus_retention" {
  description = "Срок хранения метрик Prometheus"
  type        = string
  default     = "15d"
}

variable "prometheus_storage_size" {
  description = "Размер PVC Prometheus"
  type        = string
  default     = "50Gi"
}

variable "alertmanager_storage_size" {
  description = "Размер PVC Alertmanager"
  type        = string
  default     = "10Gi"
}

variable "grafana_ingress_enabled" {
  description = "Включить Ingress для Grafana"
  type        = bool
  default     = false
}

variable "grafana_host" {
  description = "DNS-хост для Grafana Ingress"
  type        = string
  default     = ""
}

variable "ingress_class_name" {
  description = "Имя IngressClass (например, nginx, traefik)"
  type        = string
  default     = "nginx"
}

variable "tls_secret_name" {
  description = "Имя k8s-секрета с TLS для Ingress"
  type        = string
  default     = ""
}

variable "create_kube_prometheus_stack" {
  description = "Устанавливать kube-prometheus-stack"
  type        = bool
  default     = true
}

variable "create_loki" {
  description = "Устанавливать Loki"
  type        = bool
  default     = true
}

variable "create_tempo" {
  description = "Устанавливать Tempo"
  type        = bool
  default     = true
}

variable "create_otel_collector" {
  description = "Устанавливать OpenTelemetry Collector"
  type        = bool
  default     = true
}

variable "kps_chart_version" {
  description = "Версия чарта kube-prometheus-stack"
  type        = string
  # Зафиксированная версия — обновляйте осознанно
  default     = "61.3.0"
}

variable "loki_chart_version" {
  description = "Версия чарта Loki"
  type        = string
  default     = "6.6.2"
}

variable "tempo_chart_version" {
  description = "Версия чарта Tempo"
  type        = string
  default     = "1.10.1"
}

variable "otelcol_chart_version" {
  description = "Версия чарта OpenTelemetry Collector"
  type        = string
  default     = "0.98.0"
}

variable "loki_retention_period" {
  description = "Срок хранения логов Loki"
  type        = string
  default     = "168h" # 7d
}

variable "loki_storage_size" {
  description = "Размер PVC Loki (filesystem)"
  type        = string
  default     = "100Gi"
}

variable "tempo_storage_size" {
  description = "Размер PVC Tempo (filesystem WAL/blocks)"
  type        = string
  default     = "100Gi"
}

variable "grafana_admin_user" {
  description = "Имя администратора Grafana"
  type        = string
  default     = "admin"
}

variable "grafana_admin_password" {
  description = "Пароль администратора Grafana (если пусто — сгенерируем)"
  type        = string
  default     = ""
  sensitive   = true
}

# --------------------------- Locals ---------------------------

locals {
  common_labels = merge({
    "app.kubernetes.io/part-of" = "omnimind-platform",
    "app.kubernetes.io/managed-by" = "terraform",
  }, var.labels)

  common_annotations = var.annotations

  grafana_secret_name = "grafana-admin"
}

# --------------------------- Namespace ---------------------------

resource "kubernetes_namespace" "ns" {
  metadata {
    name        = var.namespace
    labels      = local.common_labels
    annotations = local.common_annotations
  }
}

# --------------------------- Grafana admin secret ---------------------------

resource "random_password" "grafana_admin" {
  length           = 20
  special          = true
  override_characters = "!@#%^*-_=+.?"
  keepers = {
    user_input = var.grafana_admin_password
  }
}

locals {
  effective_grafana_password = var.grafana_admin_password != "" ? var.grafana_admin_password : random_password.grafana_admin.result
}

resource "kubernetes_secret" "grafana_admin" {
  metadata {
    name      = local.grafana_secret_name
    namespace = kubernetes_namespace.ns.metadata[0].name
    labels    = local.common_labels
  }
  data = {
    "admin-user"     = base64encode(var.grafana_admin_user)
    "admin-password" = base64encode(local.effective_grafana_password)
  }
  type = "Opaque"
}

# --------------------------- kube-prometheus-stack ---------------------------

resource "helm_release" "kps" {
  count      = var.create_kube_prometheus_stack ? 1 : 0
  name       = "kube-prometheus-stack"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  version    = var.kps_chart_version
  namespace  = kubernetes_namespace.ns.metadata[0].name
  timeout    = 900
  cleanup_on_fail = true
  atomic          = true

  values = [<<-YAML
    fullnameOverride: kube-prometheus-stack
    commonLabels: ${jsonencode(local.common_labels)}

    networkPolicy:
      enabled: ${var.enable_network_policy}

    grafana:
      enabled: true
      admin:
        existingSecret: ${local.grafana_secret_name}
        userKey: admin-user
        passwordKey: admin-password
      grafana.ini:
        server:
          root_url: %(protocol)s://%(domain)s/
      persistence:
        enabled: ${var.enable_persistence}
        type: pvc
        storageClassName: ${var.storage_class}
        accessModes: ["ReadWriteOnce"]
        size: 10Gi
      service:
        type: ClusterIP
      ingress:
        enabled: ${var.grafana_ingress_enabled}
        ingressClassName: ${var.ingress_class_name}
        hosts: ${var.grafana_host != "" ? yamlencode([var.grafana_host]) : "[]"}
        tls:
        ${var.grafana_ingress_enabled && var.tls_secret_name != "" && var.grafana_host != "" ?
          indent(8, yamlencode([{ secretName = var.tls_secret_name, hosts = [var.grafana_host] }])) : "          []"}
      sidecar:
        dashboards:
          enabled: true
        datasources:
          enabled: true

    prometheus:
      prometheusSpec:
        retention: ${var.prometheus_retention}
        externalLabels:
          cluster_id: ${var.cluster_id}
        storageSpec:
          volumeClaimTemplate:
            spec:
              storageClassName: ${var.storage_class}
              accessModes: ["ReadWriteOnce"]
              resources:
                requests:
                  storage: ${var.prometheus_storage_size}

    alertmanager:
      alertmanagerSpec:
        storage:
          volumeClaimTemplate:
            spec:
              storageClassName: ${var.storage_class}
              accessModes: ["ReadWriteOnce"]
              resources:
                requests:
                  storage: ${var.alertmanager_storage_size}

    kubeControllerManager:
      enabled: true
    kubeScheduler:
      enabled: true
    kubeProxy:
      enabled: true

    YAML
  ]

  depends_on = [kubernetes_secret.grafana_admin]
}

# --------------------------- Loki ---------------------------

resource "helm_release" "loki" {
  count      = var.create_loki ? 1 : 0
  name       = "loki"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "loki"
  version    = var.loki_chart_version
  namespace  = kubernetes_namespace.ns.metadata[0].name
  timeout    = 600
  atomic     = true

  values = [<<-YAML
    fullnameOverride: loki
    commonLabels: ${jsonencode(local.common_labels)}

    deploymentMode: SingleBinary

    loki:
      auth_enabled: false
      commonConfig:
        replication_factor: 1
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
      compactor:
        working_directory: /var/loki/compactor
        compaction_interval: 5m
      limits_config:
        retention_period: ${var.loki_retention_period}

    persistence:
      enabled: ${var.enable_persistence}
      storageClassName: ${var.storage_class}
      size: ${var.loki_storage_size}
      accessModes: ["ReadWriteOnce"]

    serviceMonitor:
      enabled: true

    YAML
  ]

  depends_on = [helm_release.kps]
}

# --------------------------- Tempo ---------------------------

resource "helm_release" "tempo" {
  count      = var.create_tempo ? 1 : 0
  name       = "tempo"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "tempo"
  version    = var.tempo_chart_version
  namespace  = kubernetes_namespace.ns.metadata[0].name
  timeout    = 600
  atomic     = true

  values = [<<-YAML
    fullnameOverride: tempo
    commonLabels: ${jsonencode(local.common_labels)}

    tempo:
      storage:
        trace:
          backend: filesystem
          wal:
            path: /var/tempo/wal
          local:
            path: /var/tempo/traces
      metricsGenerator:
        enabled: true

    persistence:
      enabled: ${var.enable_persistence}
      storageClassName: ${var.storage_class}
      size: ${var.tempo_storage_size}
      accessModes: ["ReadWriteOnce"]

    serviceMonitor:
      enabled: true

    YAML
  ]

  depends_on = [helm_release.kps]
}

# --------------------------- OpenTelemetry Collector ---------------------------

resource "helm_release" "otelcol" {
  count      = var.create_otel_collector ? 1 : 0
  name       = "otel-collector"
  repository = "https://open-telemetry.github.io/opentelemetry-helm-charts"
  chart      = "opentelemetry-collector"
  version    = var.otelcol_chart_version
  namespace  = kubernetes_namespace.ns.metadata[0].name
  timeout    = 600
  atomic     = true

  values = [<<-YAML
    fullnameOverride: otel-collector
    commonLabels: ${jsonencode(local.common_labels)}

    mode: deployment
    replicaCount: 2

    resources:
      limits:
        cpu: 500m
        memory: 512Mi
      requests:
        cpu: 200m
        memory: 256Mi

    service:
      type: ClusterIP

    ingress:
      enabled: false

    config:
      receivers:
        otlp:
          protocols:
            grpc:
            http:
      processors:
        batch:
          timeout: 2s
          send_batch_size: 8192
        memory_limiter:
          check_interval: 2s
          limit_percentage: 75
          spike_limit_percentage: 15
      exporters:
        otlp/tempo:
          endpoint: "tempo:4317"
          tls:
            insecure: true
        prometheus:
          endpoint: "0.0.0.0:8889"
      service:
        pipelines:
          traces:
            receivers: [otlp]
            processors: [memory_limiter, batch]
            exporters: [otlp/tempo]
          metrics:
            receivers: [otlp]
            processors: [batch]
            exporters: [prometheus]

    serviceMonitor:
      enabled: true

    YAML
  ]

  depends_on = [helm_release.tempo, helm_release.kps]
}

# --------------------------- Outputs ---------------------------

output "namespace" {
  description = "Namespace стека наблюдаемости"
  value       = kubernetes_namespace.ns.metadata[0].name
}

output "grafana_admin_user" {
  description = "Имя администратора Grafana"
  value       = var.grafana_admin_user
}

output "grafana_admin_password" {
  description = "Пароль администратора Grafana"
  value       = local.effective_grafana_password
  sensitive   = true
}

output "grafana_url_hint" {
  description = "Подсказка по доступу к Grafana (Ingress или порт-форвардинг)"
  value       = var.grafana_ingress_enabled && var.grafana_host != "" ?
                "https://${var.grafana_host}" :
                "kubectl -n ${kubernetes_namespace.ns.metadata[0].name} port-forward svc/kube-prometheus-stack-grafana 3000:80"
}

output "prometheus_service" {
  description = "Имя сервиса Prometheus"
  value       = var.create_kube_prometheus_stack ? "kube-prometheus-stack-prometheus" : ""
}

output "alertmanager_service" {
  description = "Имя сервиса Alertmanager"
  value       = var.create_kube_prometheus_stack ? "kube-prometheus-stack-alertmanager" : ""
}

output "loki_service" {
  description = "Имя сервиса Loki"
  value       = var.create_loki ? "loki" : ""
}

output "tempo_service" {
  description = "Имя сервиса Tempo (OTLP gRPC 4317)"
  value       = var.create_tempo ? "tempo" : ""
}
