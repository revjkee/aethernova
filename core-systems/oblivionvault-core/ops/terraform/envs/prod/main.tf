terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "~> 1.14"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

############################
# Provider configuration
############################
variable "kubeconfig_path" {
  description = "Путь к kubeconfig prod-кластера"
  type        = string
  default     = ""
}

variable "kubernetes_host" {
  description = "Опционально: адрес API сервера, если kubeconfig не используется"
  type        = string
  default     = ""
}

variable "kubernetes_cluster_ca" {
  description = "Опционально: base64 CA, если kubeconfig не используется"
  type        = string
  default     = ""
}

variable "kubernetes_token" {
  description = "Опционально: токен, если kubeconfig не используется"
  type        = string
  default     = ""
  sensitive   = true
}

provider "kubernetes" {
  host                   = var.kubernetes_host != "" ? var.kubernetes_host : null
  cluster_ca_certificate = var.kubernetes_cluster_ca != "" ? base64decode(var.kubernetes_cluster_ca) : null
  token                  = var.kubernetes_token != "" ? var.kubernetes_token : null
  config_path            = var.kubeconfig_path != "" ? var.kubeconfig_path : null
  # Тайм-ауты по умолчанию
  experiments {
    manifest_resource = true
  }
}

provider "helm" {
  kubernetes {
    host                   = var.kubernetes_host != "" ? var.kubernetes_host : null
    cluster_ca_certificate = var.kubernetes_cluster_ca != "" ? base64decode(var.kubernetes_cluster_ca) : null
    token                  = var.kubernetes_token != "" ? var.kubernetes_token : null
    config_path            = var.kubeconfig_path != "" ? var.kubeconfig_path : null
  }
}

provider "kubectl" {
  host                   = var.kubernetes_host != "" ? var.kubernetes_host : null
  cluster_ca_certificate = var.kubernetes_cluster_ca != "" ? base64decode(var.kubernetes_cluster_ca) : null
  token                  = var.kubernetes_token != "" ? var.kubernetes_token : null
  config_path            = var.kubeconfig_path != "" ? var.kubeconfig_path : null
  load_config_file       = var.kubeconfig_path != "" ? true : false
  apply_retry_count      = 20
}

############################
# Globals
############################
variable "cluster_name" {
  type        = string
  default     = "oblivionvault-prod"
  description = "Имя кластера"
}

variable "default_domain" {
  type        = string
  default     = "example.com"
  description = "Базовый домен (для ingress и ACME HTTP-01)"
}

variable "dns_provider" {
  type        = string
  description = "Тип DNS для external-dns (route53, cloudflare, google, azure)"
  default     = "cloudflare"
}

# Секреты/токены DNS-провайдеров
variable "external_dns_secret_data" {
  type        = map(string)
  description = "Карта ключей для external-dns (например, CF_API_TOKEN)"
  default     = {}
  sensitive   = true
}

variable "letsencrypt_email" {
  type        = string
  description = "Email для ACME регистрации"
  default     = "security@oblivionvault.io"
}

variable "enable_gatekeeper" {
  type        = bool
  default     = true
}

variable "enable_kyverno" {
  type        = bool
  default     = true
}

variable "s3_backup" {
  description = "Настройки Velero S3 (endpoint/bucket/creds)"
  type = object({
    endpoint        = string
    bucket          = string
    region          = string
    access_key_id   = string
    secret_access_key = string
    use_ssl         = optional(bool, true)
  })
  default = {
    endpoint           = "https://s3.example.local"
    bucket             = "ov-prod-velero"
    region             = "us-east-1"
    access_key_id      = ""
    secret_access_key  = ""
    use_ssl            = true
  }
}

# Версии чартов (переопределяйте в *.tfvars при необходимости)
locals {
  common_labels = {
    "app.kubernetes.io/managed-by" = "terraform"
    "app.kubernetes.io/part-of"    = "oblivionvault-core"
    "env"                          = "prod"
    "cluster"                      = var.cluster_name
  }

  charts = {
    ingress_nginx           = { repo = "https://kubernetes.github.io/ingress-nginx",          name = "ingress-nginx",               chart = "ingress-nginx",              version = "4.11.2", ns = "ingress" }
    cert_manager            = { repo = "https://charts.jetstack.io",                           name = "cert-manager",                chart = "cert-manager",               version = "v1.15.3", ns = "cert-manager" }
    external_dns            = { repo = "https://kubernetes-sigs.github.io/external-dns/",      name = "external-dns",                chart = "external-dns",               version = "1.15.0", ns = "networking" }
    prom_stack              = { repo = "https://prometheus-community.github.io/helm-charts",   name = "kube-prometheus-stack",       chart = "kube-prometheus-stack",      version = "62.7.0", ns = "observability" }
    loki_stack              = { repo = "https://grafana.github.io/helm-charts",                name = "loki-stack",                  chart = "loki-stack",                 version = "2.10.3", ns = "observability" }
    tempo                   = { repo = "https://grafana.github.io/helm-charts",                name = "tempo",                       chart = "tempo",                      version = "1.11.1", ns = "observability" }
    promtail                = { repo = "https://grafana.github.io/helm-charts",                name = "promtail",                    chart = "promtail",                   version = "6.16.6", ns = "observability" }
    otel_operator           = { repo = "https://open-telemetry.github.io/opentelemetry-helm-charts", name = "opentelemetry-operator", chart = "opentelemetry-operator",     version = "0.58.2", ns = "observability" }
    sealed_secrets          = { repo = "https://bitnami-labs.github.io/sealed-secrets",         name = "sealed-secrets",              chart = "sealed-secrets",             version = "2.16.2", ns = "security" }
    velero                  = { repo = "https://vmware-tanzu.github.io/helm-charts",            name = "velero",                      chart = "velero",                     version = "6.6.0", ns = "backup" }
    kyverno                 = { repo = "https://kyverno.github.io/kyverno",                      name = "kyverno",                     chart = "kyverno",                    version = "3.3.4", ns = "policy" }
    gatekeeper              = { repo = "https://open-policy-agent.github.io/gatekeeper/charts",  name = "gatekeeper",                  chart = "gatekeeper",                 version = "3.16.3", ns = "policy" }
    metrics_server          = { repo = "https://kubernetes-sigs.github.io/metrics-server/",      name = "metrics-server",              chart = "metrics-server",             version = "3.12.1", ns = "kube-system" }
  }
}

############################
# Namespaces
############################
resource "kubernetes_namespace" "core" {
  for_each = toset(["ingress", "cert-manager", "networking", "observability", "security", "backup", "policy"])
  metadata {
    name   = each.key
    labels = local.common_labels
  }
}

############################
# external-dns secret (по провайдеру)
############################
resource "kubernetes_secret" "external_dns" {
  metadata {
    name      = "external-dns-credentials"
    namespace = local.charts.external_dns.ns
    labels    = local.common_labels
  }
  data      = { for k, v in var.external_dns_secret_data : k => base64encode(v) }
  type      = "Opaque"
  depends_on = [kubernetes_namespace.core]
}

############################
# Ingress NGINX
############################
resource "helm_release" "ingress_nginx" {
  name       = local.charts.ingress_nginx.name
  repository = local.charts.ingress_nginx.repo
  chart      = local.charts.ingress_nginx.chart
  version    = local.charts.ingress_nginx.version
  namespace  = local.charts.ingress_nginx.ns
  create_namespace = false

  values = [<<-YAML
    controller:
      replicaCount: 3
      metrics:
        enabled: true
      admissionWebhooks:
        enabled: true
      config:
        use-forwarded-headers: "true"
        enable-brotli: "true"
        server-tokens: "false"
        proxy-body-size: "64m"
      service:
        annotations:
          external-dns.alpha.kubernetes.io/hostname: "ingress.${var.default_domain}"
    defaultBackend:
      enabled: true
  YAML
  ]

  depends_on = [kubernetes_namespace.core]
}

############################
# cert-manager (+ CRDs)
############################
resource "helm_release" "cert_manager" {
  name       = local.charts.cert_manager.name
  repository = local.charts.cert_manager.repo
  chart      = local.charts.cert_manager.chart
  version    = local.charts.cert_manager.version
  namespace  = local.charts.cert_manager.ns
  create_namespace = false

  set {
    name  = "installCRDs"
    value = "true"
  }

  values = [<<-YAML
    resources:
      requests:
        cpu: "100m"
        memory: "128Mi"
      limits:
        cpu: "500m"
        memory: "512Mi"
  YAML
  ]

  depends_on = [kubernetes_namespace.core]
}

# ClusterIssuer (Let's Encrypt) — HTTP-01 через ingress
resource "kubectl_manifest" "cluster_issuer" {
  yaml_body = <<-YAML
    apiVersion: cert-manager.io/v1
    kind: ClusterIssuer
    metadata:
      name: letsencrypt-prod
      labels: #{jsonencode(local.common_labels)}
    spec:
      acme:
        email: ${var.letsencrypt_email}
        server: https://acme-v02.api.letsencrypt.org/directory
        privateKeySecretRef:
          name: letsencrypt-prod-key
        solvers:
          - http01:
              ingress:
                class: nginx
  YAML

  depends_on = [helm_release.cert_manager]
}

############################
# external-dns
############################
resource "helm_release" "external_dns" {
  name       = local.charts.external_dns.name
  repository = local.charts.external_dns.repo
  chart      = local.charts.external_dns.chart
  version    = local.charts.external_dns.version
  namespace  = local.charts.external_dns.ns
  create_namespace = false

  values = [<<-YAML
    provider: ${var.dns_provider}
    logLevel: debug
    interval: 1m
    txtOwnerId: "${var.cluster_name}"
    policy: sync
    serviceAccount:
      create: true
      name: external-dns
    extraEnvVars:
      - name: CF_API_TOKEN
        valueFrom:
          secretKeyRef:
            name: external-dns-credentials
            key: CF_API_TOKEN
    podAnnotations:
      prometheus.io/scrape: "true"
      prometheus.io/port: "7979"
  YAML
  ]

  depends_on = [kubernetes_secret.external_dns]
}

############################
# kube-prometheus-stack
############################
resource "helm_release" "prom_stack" {
  name       = local.charts.prom_stack.name
  repository = local.charts.prom_stack.repo
  chart      = local.charts.prom_stack.chart
  version    = local.charts.prom_stack.version
  namespace  = local.charts.prom_stack.ns
  create_namespace = false

  values = [<<-YAML
    grafana:
      enabled: true
      defaultDashboardsTimezone: "UTC"
      ingress:
        enabled: true
        ingressClassName: nginx
        hosts: ["grafana.${var.default_domain}"]
        tls:
          - hosts: ["grafana.${var.default_domain}"]
            secretName: grafana-tls
      adminPassword: "CHANGE_ME_SECURELY"
    prometheus:
      prometheusSpec:
        retention: "15d"
        scrapeInterval: "15s"
        podMonitorNamespaceSelector: {}
        serviceMonitorNamespaceSelector: {}
        additionalScrapeConfigs:
          - job_name: 'tempo'
            static_configs:
              - targets: ['tempo.observability.svc.cluster.local:3200']
  YAML
  ]

  depends_on = [kubernetes_namespace.core, helm_release.ingress_nginx, kubectl_manifest.cluster_issuer]
}

############################
# Loki + Promtail
############################
resource "helm_release" "loki" {
  name       = local.charts.loki_stack.name
  repository = local.charts.loki_stack.repo
  chart      = local.charts.loki_stack.chart
  version    = local.charts.loki_stack.version
  namespace  = local.charts.loki_stack.ns
  create_namespace = false

  values = [<<-YAML
    loki:
      auth_enabled: false
      commonConfig:
        replication_factor: 1
      storage:
        type: filesystem
    grafana:
      enabled: false
    promtail:
      enabled: false
  YAML
  ]

  depends_on = [helm_release.prom_stack]
}

resource "helm_release" "promtail" {
  name       = local.charts.promtail.name
  repository = local.charts.promtail.repo
  chart      = local.charts.promtail.chart
  version    = local.charts.promtail.version
  namespace  = local.charts.promtail.ns
  create_namespace = false

  values = [<<-YAML
    config:
      clients:
        - url: http://loki-headless.observability.svc.cluster.local:3100/loki/api/v1/push
      snippets:
        pipelineStages:
          - docker: {}
          - cri: {}
  YAML
  ]

  depends_on = [helm_release.loki]
}

############################
# Tempo (трейсы)
############################
resource "helm_release" "tempo" {
  name       = local.charts.tempo.name
  repository = local.charts.tempo.repo
  chart      = local.charts.tempo.chart
  version    = local.charts.tempo.version
  namespace  = local.charts.tempo.ns
  create_namespace = false

  values = [<<-YAML
    persistence:
      enabled: true
      storageClassName: ""
      accessModes: ["ReadWriteOnce"]
      size: 20Gi
    tempo:
      receivers:
        otlp:
          protocols:
            http:
            grpc:
      storage:
        trace:
          backend: local
  YAML
  ]

  depends_on = [helm_release.prom_stack]
}

############################
# OpenTelemetry Operator
############################
resource "helm_release" "otel_operator" {
  name       = local.charts.otel_operator.name
  repository = local.charts.otel_operator.repo
  chart      = local.charts.otel_operator.chart
  version    = local.charts.otel_operator.version
  namespace  = local.charts.otel_operator.ns
  create_namespace = false

  values = [<<-YAML
    manager:
      collectorImage:
        repository: "otel/opentelemetry-collector"
      resources:
        limits:
          cpu: 1000m
          memory: 1Gi
        requests:
          cpu: 200m
          memory: 256Mi
  YAML
  ]

  depends_on = [helm_release.tempo]
}

############################
# Sealed-Secrets (для безопасных секретов в Git)
############################
resource "helm_release" "sealed_secrets" {
  name       = local.charts.sealed_secrets.name
  repository = local.charts.sealed_secrets.repo
  chart      = local.charts.sealed_secrets.chart
  version    = local.charts.sealed_secrets.version
  namespace  = local.charts.sealed_secrets.ns
  create_namespace = false

  depends_on = [kubernetes_namespace.core]
}

############################
# Velero (бэкап)
############################
resource "kubernetes_secret" "velero_s3" {
  metadata {
    name      = "velero-s3-credentials"
    namespace = local.charts.velero.ns
    labels    = local.common_labels
  }
  data = {
    "cloud" = base64encode(<<-EOT
      [default]
      aws_access_key_id = ${var.s3_backup.access_key_id}
      aws_secret_access_key = ${var.s3_backup.secret_access_key}
    EOT
    )
  }
  type = "Opaque"
  depends_on = [kubernetes_namespace.core]
}

resource "helm_release" "velero" {
  name       = local.charts.velero.name
  repository = local.charts.velero.repo
  chart      = local.charts.velero.chart
  version    = local.charts.velero.version
  namespace  = local.charts.velero.ns
  create_namespace = false

  values = [<<-YAML
    configuration:
      provider: aws
      backupStorageLocation:
        - name: default
          bucket: ${var.s3_backup.bucket}
          prefix: "velero"
          config:
            region: ${var.s3_backup.region}
            s3Url: ${var.s3_backup.endpoint}
            s3ForcePathStyle: true
    credentials:
      useSecret: true
      existingSecret: velero-s3-credentials
    initContainers:
      - name: velero-plugin-for-aws
        image: velero/velero-plugin-for-aws:v1.9.1
        imagePullPolicy: IfNotPresent
        volumeMounts:
          - name: plugins
            mountPath: /target
  YAML
  ]

  depends_on = [kubernetes_secret.velero_s3]
}

############################
# Политики: Kyverno / Gatekeeper
############################
resource "helm_release" "kyverno" {
  count      = var.enable_kyverno ? 1 : 0
  name       = local.charts.kyverno.name
  repository = local.charts.kyverno.repo
  chart      = local.charts.kyverno.chart
  version    = local.charts.kyverno.version
  namespace  = local.charts.kyverno.ns
  create_namespace = false

  values = [<<-YAML
    replicaCount: 3
    admissionController:
      resources:
        requests:
          cpu: 100m
          memory: 256Mi
  YAML
  ]

  depends_on = [kubernetes_namespace.core]
}

resource "helm_release" "gatekeeper" {
  count      = var.enable_gatekeeper ? 1 : 0
  name       = local.charts.gatekeeper.name
  repository = local.charts.gatekeeper.repo
  chart      = local.charts.gatekeeper.chart
  version    = local.charts.gatekeeper.version
  namespace  = local.charts.gatekeeper.ns
  create_namespace = false

  values = [<<-YAML
    replicas: 3
    enableExternalData: true
  YAML
  ]

  depends_on = [kubernetes_namespace.core]
}

############################
# metrics-server
############################
resource "helm_release" "metrics_server" {
  name       = local.charts.metrics_server.name
  repository = local.charts.metrics_server.repo
  chart      = local.charts.metrics_server.chart
  version    = local.charts.metrics_server.version
  namespace  = local.charts.metrics_server.ns
  create_namespace = false

  values = [<<-YAML
    args:
      - --kubelet-insecure-tls
  YAML
  ]
}

############################
# Outputs
############################
output "grafana_url" {
  value       = "https://grafana.${var.default_domain}"
  description = "URL Grafana"
}

output "tempo_otlp_grpc" {
  value       = "tempo.observability.svc.cluster.local:4317"
  description = "OTLP gRPC endpoint Tempo"
}

output "loki_push_url" {
  value       = "http://loki-headless.observability.svc.cluster.local:3100/loki/api/v1/push"
  description = "Loki push endpoint"
}
