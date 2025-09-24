// ledger-core/ops/terraform/modules/observability/main.tf
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.29"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.13"
    }
  }
}

############################
# Variables (key excerpts) #
############################

variable "cluster_name"            { type = string }
variable "namespace"               { type = string  default = "observability" }
variable "tags"                    { type = map(string) default = {} }

variable "enable_prometheus_stack" { type = bool default = true }
variable "enable_loki"             { type = bool default = true }
variable "enable_promtail"         { type = bool default = true }
variable "enable_otel_collector"   { type = bool default = true }
variable "enable_tempo"            { type = bool default = false }

# Helm chart versions (pin!)
variable "chart_versions" {
  type = object({
    kube_prometheus_stack = string # e.g. "58.3.2"
    loki                  = string # e.g. "6.6.2"
    promtail              = string # e.g. "6.15.5"
    tempo                 = string # e.g. "1.11.0"
    otel_collector        = string # e.g. "0.96.1"
  })
}

# Storage / Retention
variable "prometheus_retention"        { type = string default = "15d" }
variable "prometheus_storage_size"     { type = string default = "100Gi" }
variable "prometheus_storage_class"    { type = string default = null }

variable "loki_retention_period"       { type = string default = "30d" }
variable "loki_table_manager_period"   { type = string default = "168h" } // 7d, если используется table manager
variable "loki_storage_class"          { type = string default = null }   // для файлового режима (не S3)
variable "loki_mode"                   { type = string default = "s3" }   // "s3" | "filesystem"

# S3 + KMS for Loki
variable "create_s3_bucket"            { type = bool default = true }
variable "loki_s3_bucket_name"         { type = string default = null }    // если create_s3_bucket=false — укажите существующее имя
variable "s3_force_destroy"            { type = bool   default = false }
variable "create_kms_key"              { type = bool   default = true }
variable "kms_key_arn"                 { type = string default = null }    // если create_kms_key=false — укажите внешний ключ
variable "s3_bucket_policy_additional_statements" {
  type    = list(any)
  default = []
}

# IRSA (IAM Roles for Service Accounts)
variable "irsa_oidc_provider_arn" { type = string } // arn:aws:iam::123456789012:oidc-provider/...
variable "irsa_oidc_provider_url" { type = string } // e.g. "oidc.eks.eu-central-1.amazonaws.com/id/XXXX"

# Secrets
variable "grafana_admin_password"      { type = string sensitive = true default = null }
variable "alertmanager_slack_webhook"  { type = string sensitive = true default = null }

# Grafana ingress (optional)
variable "grafana_ingress" {
  type = object({
    enabled        = bool
    class_name     = string
    hosts          = list(string)
    tls_secret     = string
    annotations    = map(string)
    additional_ids = list(string) // e.g. ALB cert ARNs for AWS ingress controllers
  })
  default = {
    enabled        = false
    class_name     = null
    hosts          = []
    tls_secret     = null
    annotations    = {}
    additional_ids = []
  }
}

locals {
  ns_labels = merge({
    "app.kubernetes.io/part-of" = "ledger-core"
    "app.kubernetes.io/managed-by" = "terraform"
    "observability" = "true"
  }, var.tags)

  # Loki bucket name resolution
  loki_bucket_name = coalesce(var.loki_s3_bucket_name, "${var.cluster_name}-loki")
}

#########################
# Kubernetes Namespace  #
#########################

resource "kubernetes_namespace" "this" {
  metadata {
    name   = var.namespace
    labels = local.ns_labels
  }
}

###############################
# AWS KMS + S3 for Loki (opt) #
###############################

resource "aws_kms_key" "loki" {
  count                   = var.enable_loki && var.create_kms_key ? 1 : 0
  description             = "KMS key for Loki bucket (ledger-core observability)"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = var.tags
}

resource "aws_s3_bucket" "loki" {
  count         = var.enable_loki && var.create_s3_bucket && var.loki_mode == "s3" ? 1 : 0
  bucket        = local.loki_bucket_name
  force_destroy = var.s3_force_destroy
  tags          = var.tags
}

resource "aws_s3_bucket_versioning" "loki" {
  count  = length(aws_s3_bucket.loki) == 1 ? 1 : 0
  bucket = aws_s3_bucket.loki[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "loki" {
  count  = length(aws_s3_bucket.loki) == 1 ? 1 : 0
  bucket = aws_s3_bucket.loki[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.create_kms_key ? "aws:kms" : (var.kms_key_arn != null ? "aws:kms" : "AES256")
      kms_master_key_id = var.create_kms_key ? aws_kms_key.loki[0].arn : var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "loki" {
  count  = length(aws_s3_bucket.loki) == 1 ? 1 : 0
  bucket = aws_s3_bucket.loki[0].id
  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls  = true
  restrict_public_buckets = true
}

##############################################
# IRSA for Loki (S3 access) and (optionally) #
# Tempo (S3/GCS not included by default)     #
##############################################

data "aws_iam_policy_document" "loki_assume_role" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.irsa_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.irsa_oidc_provider_url}:sub"
      values   = ["system:serviceaccount:${var.namespace}:loki"]
    }
  }
}

resource "aws_iam_role" "loki" {
  count              = var.enable_loki && var.loki_mode == "s3" ? 1 : 0
  name               = "${var.cluster_name}-${var.namespace}-loki-irsa"
  assume_role_policy = data.aws_iam_policy_document.loki_assume_role.json
  tags               = var.tags
}

data "aws_iam_policy_document" "loki_s3" {
  count = length(aws_iam_role.loki)
  statement {
    sid     = "LokiS3Access"
    effect  = "Allow"
    actions = ["s3:ListBucket"]
    resources = [
      length(aws_s3_bucket.loki) == 1 ? aws_s3_bucket.loki[0].arn : "arn:aws:s3:::${local.loki_bucket_name}"
    ]
  }
  statement {
    sid     = "LokiS3Objects"
    effect  = "Allow"
    actions = [
      "s3:PutObject","s3:GetObject","s3:DeleteObject","s3:AbortMultipartUpload","s3:ListBucketMultipartUploads"
    ]
    resources = [
      "${length(aws_s3_bucket.loki) == 1 ? aws_s3_bucket.loki[0].arn : "arn:aws:s3:::${local.loki_bucket_name}"}/*"
    ]
  }

  dynamic "statement" {
    for_each = var.create_kms_key || var.kms_key_arn != null ? [1] : []
    content {
      sid     = "LokiKMS"
      effect  = "Allow"
      actions = ["kms:Encrypt","kms:Decrypt","kms:GenerateDataKey*","kms:DescribeKey"]
      resources = [
        var.create_kms_key ? aws_kms_key.loki[0].arn : var.kms_key_arn
      ]
    }
  }

  dynamic "statement" {
    for_each = var.s3_bucket_policy_additional_statements
    content  = statement.value
  }
}

resource "aws_iam_policy" "loki_s3" {
  count  = length(data.aws_iam_policy_document.loki_s3)
  name   = "${var.cluster_name}-${var.namespace}-loki-s3"
  policy = data.aws_iam_policy_document.loki_s3[0].json
  tags   = var.tags
}

resource "aws_iam_role_policy_attachment" "loki" {
  count      = length(aws_iam_role.loki)
  role       = aws_iam_role.loki[0].name
  policy_arn = aws_iam_policy.loki_s3[0].arn
}

#########################################
# Kubernetes Secrets (Grafana/Alerting) #
#########################################

resource "kubernetes_secret" "grafana_admin" {
  count = var.enable_prometheus_stack && var.grafana_admin_password != null ? 1 : 0
  metadata {
    name      = "grafana-admin"
    namespace = var.namespace
  }
  data = {
    admin-user     = "admin"
    admin-password = var.grafana_admin_password
  }
  type = "Opaque"
}

resource "kubernetes_secret" "alertmanager_slack" {
  count = var.enable_prometheus_stack && var.alertmanager_slack_webhook != null ? 1 : 0
  metadata {
    name      = "alertmanager-slack"
    namespace = var.namespace
  }
  data = {
    webhook_url = var.alertmanager_slack_webhook
  }
  type = "Opaque"
}

########################
# Helm: Repositories   #
########################

data "helm_repository" "grafana" {
  name = "grafana"
  url  = "https://grafana.github.io/helm-charts"
}

data "helm_repository" "prom" {
  name = "prometheus-community"
  url  = "https://prometheus-community.github.io/helm-charts"
}

data "helm_repository" "otel" {
  name = "open-telemetry"
  url  = "https://open-telemetry.github.io/opentelemetry-helm-charts"
}

#############################
# Helm: kube-prometheus     #
#############################

resource "helm_release" "kube_prometheus_stack" {
  count      = var.enable_prometheus_stack ? 1 : 0
  name       = "kps"
  namespace  = var.namespace
  repository = data.helm_repository.prom.url
  chart      = "kube-prometheus-stack"
  version    = var.chart_versions.kube_prometheus_stack
  timeout    = 600
  create_namespace = false
  atomic     = true
  values = [
    yamlencode({
      fullnameOverride = "kube-prometheus-stack"
      defaultRules = { create = true }
      alertmanager = {
        enabled = true
        config  = {
          global = { resolve_timeout = "5m" }
          route  = {
            receiver = "default"
            group_by = ["alertname", "cluster", "service"]
          }
          receivers = [
            { name = "default" }
          ] ++ (
            var.alertmanager_slack_webhook != null ? [
              {
                name = "slack"
                slack_configs = [{
                  api_url = "{{- (index .Secrets \"alertmanager-slack\").Data.webhook_url | b64dec -}}"
                  channel = "#alerts-ledger"
                  send_resolved = true
                }]
              }
            ] : []
          )
          route = {
            receiver = var.alertmanager_slack_webhook != null ? "slack" : "default"
          }
        }
        ingress = { enabled = false }
      }
      grafana = {
        enabled = true
        admin = {
          existingSecret = kubernetes_secret.grafana_admin[0].metadata[0].name
        }
        ingress = {
          enabled = var.grafana_ingress.enabled
          ingressClassName = var.grafana_ingress.class_name
          annotations = var.grafana_ingress.annotations
          hosts = var.grafana_ingress.hosts
          tls = var.grafana_ingress.tls_secret != null ? [{
            secretName = var.grafana_ingress.tls_secret
            hosts      = var.grafana_ingress.hosts
          }] : []
        }
        sidecar = {
          dashboards = { enabled = true, searchNamespace = var.namespace }
          datasources = { enabled = true }
        }
      }
      prometheus = {
        prometheusSpec = {
          retention        = var.prometheus_retention
          retentionSize    = null
          replicas         = 2
          shards           = 1
          enableAdminAPI   = false
          walCompression   = true
          storageSpec = {
            volumeClaimTemplate = {
              spec = merge(
                {
                  accessModes = ["ReadWriteOnce"]
                  resources   = { requests = { storage = var.prometheus_storage_size } }
                },
                var.prometheus_storage_class != null ? { storageClassName = var.prometheus_storage_class } : {}
              )
            }
          }
        }
      }
      kubeEtcd  = { enabled = false } // включайте только при наличии доступа
      kubeProxy = { enabled = false }
      kubeScheduler = { enabled = false }
      kubeControllerManager = { enabled = false }
    })
  ]

  depends_on = [kubernetes_namespace.this]
}

#############################
# Helm: Loki (single/remote)#
#############################

resource "helm_release" "loki" {
  count      = var.enable_loki ? 1 : 0
  name       = "loki"
  namespace  = var.namespace
  repository = data.helm_repository.grafana.url
  chart      = "loki"
  version    = var.chart_versions.loki
  timeout    = 600
  atomic     = true

  values = [
    yamlencode(
      var.loki_mode == "s3" ? {
        fullnameOverride = "loki"
        serviceAccount = {
          create      = true
          name        = "loki"
          annotations = {
            "eks.amazonaws.com/role-arn" = aws_iam_role.loki[0].arn
          }
        }
        loki = {
          auth_enabled = false
          commonConfig = {
            replication_factor = 1
          }
          storage = {
            type = "s3"
            bucketNames = {
              chunks = local.loki_bucket_name
              ruler  = local.loki_bucket_name
              admin  = local.loki_bucket_name
            }
            s3 = {
              s3               = "s3://${local.loki_bucket_name}"
              s3ForcePathStyle = true
              insecure         = false
              http_config = {
                idle_conn_timeout = "90s"
                response_header_timeout = "2m"
              }
              sse_encryption = true
              sse = {
                type = (var.create_kms_key || var.kms_key_arn != null) ? "SSE-KMS" : "AES256"
                kms_key_id = var.create_kms_key ? aws_kms_key.loki[0].arn : var.kms_key_arn
              }
            }
          }
          schemaConfig = {
            configs = [{
              from         = "2020-10-24"
              store        = "boltdb-shipper"
              object_store = "s3"
              schema       = "v13"
              index = { prefix = "loki_index_", period = "24h" }
            }]
          }
          ruler = {
            storage = { type = "s3" }
            rule_path = "/rules"
          }
          table_manager = { retention_deletes_enabled = true, retention_period = var.loki_retention_period }
        }
        persistence = { enabled = false } // S3 backend
      } : {
        fullnameOverride = "loki"
        loki = {
          auth_enabled = false
          table_manager = { retention_deletes_enabled = true, retention_period = var.loki_retention_period }
        }
        persistence = {
          enabled = true
          size    = "100Gi"
          storageClassName = var.loki_storage_class
          accessModes = ["ReadWriteOnce"]
        }
      }
    )
  ]

  depends_on = [
    kubernetes_namespace.this,
    aws_iam_role.loki,
    aws_s3_bucket.loki,
    aws_kms_key.loki
  ]
}

#################
# Helm: Promtail#
#################

resource "helm_release" "promtail" {
  count      = var.enable_promtail ? 1 : 0
  name       = "promtail"
  namespace  = var.namespace
  repository = data.helm_repository.grafana.url
  chart      = "promtail"
  version    = var.chart_versions.promtail
  timeout    = 600
  atomic     = true
  values = [
    yamlencode({
      config = {
        clients = [{
          url = "http://loki:3100/loki/api/v1/push"
        }]
        snippets = {
          pipelineStages = [
            { docker = {} },
            { cri = {} },
            { regex = { expression = "^(?P<ts>[^ ]+) (?P<level>[A-Z]+) (?P<msg>.*)$" } },
            { labels = { level = "", app = "ledger-core" } }
          ]
        }
      }
      tolerations = [
        { key = "node-role.kubernetes.io/control-plane", operator = "Exists", effect = "NoSchedule" }
      ]
    })
  ]
  depends_on = [kubernetes_namespace.this, helm_release.loki]
}

######################################
# Helm: OpenTelemetry Collector (DA) #
######################################

resource "helm_release" "otel_collector" {
  count      = var.enable_otel_collector ? 1 : 0
  name       = "otel-collector"
  namespace  = var.namespace
  repository = data.helm_repository.otel.url
  chart      = "opentelemetry-collector"
  version    = var.chart_versions.otel_collector
  timeout    = 600
  atomic     = true

  values = [
    yamlencode({
      mode = "deployment"
      fullnameOverride = "otel-collector"
      replicaCount = 2
      config = {
        receivers = {
          otlp = {
            protocols = { http = { endpoint = "0.0.0.0:4318" }, grpc = { endpoint = "0.0.0.0:4317" } }
          }
        }
        processors = {
          batch = { timeout = "2s" }
          memory_limiter = { check_interval = "1s", limit_mib = 1024, spike_limit_mib = 512 }
          k8sattributes = { extract = { metadata = ["k8s.pod.name","k8s.namespace.name","k8s.node.name","k8s.pod.uid"] } }
        }
        exporters = {
          prometheusremotewrite = {
            endpoint = "http://kube-prometheus-stack-prometheus:9090/api/v1/write"
          }
          loki = var.enable_loki ? {
            endpoint = "http://loki:3100/loki/api/v1/push"
            labels = { resource = { "k8s.pod.name" = "pod", "k8s.namespace.name" = "namespace" } }
          } : null
        }
        service = {
          pipelines = {
            metrics = {
              receivers  = ["otlp"]
              processors = ["memory_limiter","batch"]
              exporters  = ["prometheusremotewrite"]
            }
            logs = var.enable_loki ? {
              receivers  = ["otlp"]
              processors = ["k8sattributes","batch"]
              exporters  = ["loki"]
            } : null
          }
        }
      }
      resources = {
        limits = { cpu = "1", memory = "1Gi" }
        requests = { cpu = "200m", memory = "256Mi" }
      }
    })
  ]

  depends_on = [kubernetes_namespace.this, helm_release.kube_prometheus_stack]
}

####################
# Helm: Tempo (opt)#
####################

resource "helm_release" "tempo" {
  count      = var.enable_tempo ? 1 : 0
  name       = "tempo"
  namespace  = var.namespace
  repository = data.helm_repository.grafana.url
  chart      = "tempo"
  version    = var.chart_versions.tempo
  timeout    = 600
  atomic     = true
  values = [
    yamlencode({
      fullnameOverride = "tempo"
      persistence = { enabled = false } // для прод-хранилища интегрируйте S3/Block в values
      tempo = {
        receivers = { otlp = { protocols = { grpc = {}, http = {} } } }
        metricsGenerator = { enabled = true }
      }
      service = { type = "ClusterIP" }
    })
  ]
  depends_on = [kubernetes_namespace.this]
}

################
# Outputs      #
################

output "namespace" {
  value = kubernetes_namespace.this.metadata[0].name
}

output "loki_bucket_name" {
  value       = var.enable_loki && var.loki_mode == "s3" ? local.loki_bucket_name : null
  description = "Имя S3‑бакета для Loki (если включён и режим s3)."
}

output "grafana_url_hint" {
  value       = var.grafana_ingress.enabled && length(var.grafana_ingress.hosts) > 0 ? "https://${var.grafana_ingress.hosts[0]}" : "Grafana Ingress выключен"
  description = "Подсказка по URL Grafana при включённом ingress."
}
