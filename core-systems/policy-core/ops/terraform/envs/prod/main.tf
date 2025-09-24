# path: policy-core/ops/terraform/envs/prod/main.tf
terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  # Backend вынесен в -backend-config для CI/CD.
  # Пример:
  #   terraform init \
  #     -backend-config="bucket=YOUR_BUCKET" \
  #     -backend-config="key=policy-core/prod/terraform.tfstate" \
  #     -backend-config="region=eu-central-1" \
  #     -backend-config="encrypt=true"
  backend "s3" {}

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.22.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12.1"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
    # aws провайдер загружается опционально (для бэкенда/интеграций),
    # но в этом файле напрямую не используется.
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60.0"
    }
  }
}

###############################################################################
# Locals, naming, tags
###############################################################################
locals {
  project     = "policy-core"
  environment = var.environment
  namespace   = var.namespace
  labels = {
    "app.kubernetes.io/name"       = local.project
    "app.kubernetes.io/instance"   = "${local.project}-${local.environment}"
    "app.kubernetes.io/managed-by" = "terraform"
    "app.kubernetes.io/part-of"    = local.project
    "env"                           = local.environment
  }
}

###############################################################################
# Providers
###############################################################################
# Kubernetes/Helm из локального kubeconfig (или переменных CI)
provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = var.kube_context
}

provider "helm" {
  kubernetes {
    config_path    = var.kubeconfig_path
    config_context = var.kube_context
  }
}

# Опциональный AWS (например, для data-источников/доп.ресурсов)
provider "aws" {
  region                      = var.aws_region
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  # Провайдер не обязателен к использованию в данном файле.
}

###############################################################################
# Preconditions
###############################################################################
# Валидация входных переменных для минимальной безопасности.
resource "null_resource" "preflight" {
  lifecycle {
    precondition {
      condition     = length(var.kubeconfig_path) > 0
      error_message = "kubeconfig_path must be provided"
    }
    precondition {
      condition     = length(var.kube_context) > 0
      error_message = "kube_context must be provided"
    }
    precondition {
      condition     = can(regex("^[a-z0-9-]+$", var.namespace))
      error_message = "namespace must match ^[a-z0-9-]+$"
    }
  }
}

###############################################################################
# Kubernetes namespace
###############################################################################
resource "kubernetes_namespace" "ns" {
  metadata {
    name   = local.namespace
    labels = local.labels
  }
}

###############################################################################
# Secrets: детерминированный JWT ключ и базовые параметры приложения
###############################################################################
# Генерация ключа подписи JWT, если не передан извне.
resource "random_password" "jwt_signing_key" {
  length           = 48
  special          = true
  override_char_set = "!@#$%^&*()-_=+[]{}:,<.>/?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
}

locals {
  effective_jwt_key = coalesce(var.jwt_signing_key, random_password.jwt_signing_key.result)
}

resource "kubernetes_secret" "app_secrets" {
  metadata {
    name      = "${local.project}-secrets"
    namespace = kubernetes_namespace.ns.metadata[0].name
    labels    = local.labels
    annotations = {
      "kubernetes.io/change-cause" = "bootstrap application secrets"
    }
  }
  immutable   = true
  type        = "Opaque"
  string_data = {
    DB_URL           = var.db_url
    OIDC_CLIENT_ID   = var.oidc_client_id
    OIDC_CLIENT_SECRET = var.oidc_client_secret
    JWT_SIGNING_KEY  = local.effective_jwt_key
    OPA_BUNDLE_TOKEN = var.opa_bundle_token
    SENTRY_DSN       = var.sentry_dsn
  }
}

###############################################################################
# Helm release: deploy policy-core chart из репозитория
###############################################################################
# Путь к чарту: policy-core/ops/helm/policy-core
# Текущий main.tf лежит в: policy-core/ops/terraform/envs/prod
# Относительный путь на 2 уровня вверх, затем в helm/policy-core
locals {
  chart_path = "${path.module}/../../helm/policy-core"
}

resource "helm_release" "policy_core" {
  count      = var.enable_release ? 1 : 0
  name       = local.project
  namespace  = kubernetes_namespace.ns.metadata[0].name
  repository = ""                  # используем локальный путь
  chart      = local.chart_path
  version    = var.chart_version   # позволяет фиксировать версию чарт-артефакта
  timeout    = 600
  wait       = true
  atomic     = true
  recreate_pods   = false
  cleanup_on_fail = true
  dependency_update = true

  # Значения для чарта: объединяем базовые и пользовательские.
  values = [
    yamlencode({
      image = {
        repository = var.image_repository
        tag        = var.image_tag
        pullPolicy = var.image_pull_policy
      }
      replicaCount = var.replica_count
      ingress = {
        enabled   = var.ingress_enabled
        className = var.ingress_class_name
        hosts = [
          for h in var.ingress_hosts : {
            host  = h.host
            paths = [for p in h.paths : {
              path      = p.path
              pathType  = coalesce(p.path_type, "Prefix")
              service = {
                name = coalesce(p.service_name, local.project)
                port = coalesce(p.service_port, "http")
              }
            }]
          }
        ]
        tls = var.ingress_tls
      }
      monitoring = {
        enabled = var.monitoring_enabled
        serviceMonitor = {
          enabled = var.servicemonitor_enabled
        }
      }
      resources = var.resources
      nodeSelector = var.node_selector
      tolerations  = var.tolerations
      affinity     = var.affinity
    }),
    # Пользовательский слой значений
    yamlencode(var.helm_values)
  ]

  # Чувствительные значения (переопределения)
  set_sensitive {
    name  = "secrets.jwtSigningKey"
    value = local.effective_jwt_key
  }

  # Привязка к секретам и namespace
  depends_on = [
    kubernetes_secret.app_secrets
  ]
}

###############################################################################
# Outputs
###############################################################################
output "namespace" {
  description = "Namespace where policy-core is deployed"
  value       = kubernetes_namespace.ns.metadata[0].name
}

output "helm_release_name" {
  description = "Helm release name"
  value       = try(helm_release.policy_core[0].name, null)
}

output "chart_path" {
  description = "Path to local Helm chart used for deployment"
  value       = local.chart_path
}

###############################################################################
# Variables
###############################################################################
variable "environment" {
  description = "Environment name (e.g., prod, staging)"
  type        = string
  default     = "prod"
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.environment))
    error_message = "environment must match ^[a-z0-9-]+$"
  }
}

variable "namespace" {
  description = "Kubernetes namespace for policy-core"
  type        = string
  default     = "policy-core"
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.namespace))
    error_message = "namespace must match ^[a-z0-9-]+$"
  }
}

variable "kubeconfig_path" {
  description = "Path to kubeconfig file"
  type        = string
}

variable "kube_context" {
  description = "Kubeconfig context name to use"
  type        = string
}

variable "aws_region" {
  description = "AWS region for optional AWS provider and S3 backend (if used)"
  type        = string
  default     = "eu-central-1"
}

# App secrets (can be provided via TF_VAR_* or CI secret store)
variable "db_url" {
  description = "Database URL for policy-core"
  type        = string
  default     = ""
  sensitive   = true
}

variable "oidc_client_id" {
  description = "OIDC client id"
  type        = string
  default     = ""
  sensitive   = true
}

variable "oidc_client_secret" {
  description = "OIDC client secret"
  type        = string
  default     = ""
  sensitive   = true
}

variable "jwt_signing_key" {
  description = "Optional override for JWT signing key; if empty, random will be generated"
  type        = string
  default     = ""
  sensitive   = true
}

variable "opa_bundle_token" {
  description = "OPA bundle token for pulling policy bundles"
  type        = string
  default     = ""
  sensitive   = true
}

variable "sentry_dsn" {
  description = "Sentry DSN"
  type        = string
  default     = ""
  sensitive   = true
}

# Helm deployment controls
variable "enable_release" {
  description = "Create Helm release for policy-core"
  type        = bool
  default     = true
}

variable "chart_version" {
  description = "Chart version constraint or exact version; optional for local chart"
  type        = string
  default     = ""
}

variable "image_repository" {
  description = "Container image repository"
  type        = string
  default     = "registry.local/policy-core"
}

variable "image_tag" {
  description = "Container image tag"
  type        = string
  default     = "latest"
}

variable "image_pull_policy" {
  description = "Image pull policy"
  type        = string
  default     = "IfNotPresent"
}

variable "replica_count" {
  description = "Number of replicas"
  type        = number
  default     = 2
}

variable "ingress_enabled" {
  description = "Enable Ingress in Helm chart"
  type        = bool
  default     = true
}

variable "ingress_class_name" {
  description = "IngressClass name (e.g., nginx)"
  type        = string
  default     = "nginx"
}

variable "ingress_hosts" {
  description = "List of ingress hosts with paths"
  type = list(object({
    host  = string
    paths = list(object({
      path         = string
      path_type    = optional(string)
      service_name = optional(string)
      service_port = optional(any) # string or number
    }))
  }))
  default = []
}

variable "ingress_tls" {
  description = "TLS blocks for ingress"
  type = list(object({
    secretName = string
    hosts      = list(string)
  }))
  default = []
}

variable "monitoring_enabled" {
  description = "Toggle monitoring in chart"
  type        = bool
  default     = true
}

variable "servicemonitor_enabled" {
  description = "Create ServiceMonitor via chart"
  type        = bool
  default     = true
}

variable "resources" {
  description = "Pod resources map passed to chart"
  type        = any
  default     = {}
}

variable "node_selector" {
  description = "Node selector map"
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Tolerations list"
  type        = any
  default     = []
}

variable "affinity" {
  description = "Affinity rules"
  type        = any
  default     = {}
}

variable "helm_values" {
  description = "Arbitrary values map to merge into Helm chart"
  type        = map(any)
  default     = {}
}
