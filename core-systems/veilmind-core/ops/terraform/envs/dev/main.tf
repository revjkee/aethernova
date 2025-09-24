terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.29"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Рекомендуемый удалённый backend (раскомментируйте и настройте)
  # backend "s3" {
  #   bucket         = "CHANGEME-terraform-state"
  #   key            = "veilmind-core/dev/terraform.tfstate"
  #   region         = "CHANGEME"
  #   dynamodb_table = "CHANGEME-terraform-locks"
  #   encrypt        = true
  # }
}

# ---------------------- Параметры среды ----------------------

variable "kubeconfig_path" {
  description = "Путь к kubeconfig"
  type        = string
  default     = "~/.kube/config"
}

variable "kube_context" {
  description = "Имя контекста kubeconfig"
  type        = string
  default     = "CHANGEME-dev"
}

variable "namespace" {
  description = "Namespace для dev"
  type        = string
  default     = "veilmind-dev"
}

variable "image_registry" {
  description = "Регистр образов (без имени репозитория)"
  type        = string
  default     = "ghcr.io/CHANGEME-org"
}

variable "image_repository" {
  description = "Имя репозитория образа"
  type        = string
  default     = "veilmind-core"
}

variable "image_tag" {
  description = "Tag образа для dev"
  type        = string
  default     = "dev-CHANGEME"
}

variable "image_digest" {
  description = "Опциональный digest для иммутабельности (sha256:...)"
  type        = string
  default     = ""
}

variable "registry_username" {
  description = "Логин реестра"
  type        = string
  sensitive   = true
  default     = ""
}

variable "registry_password" {
  description = "Пароль/токен реестра"
  type        = string
  sensitive   = true
  default     = ""
}

variable "chart_repo" {
  description = "Helm chart repo URL или пусто для локального chart"
  type        = string
  default     = "https://CHANGEME.github.io/veilmind-helm"
}

variable "chart_name" {
  description = "Имя Helm‑чарта"
  type        = string
  default     = "veilmind-core"
}

variable "chart_version" {
  description = "Версия Helm‑чарта"
  type        = string
  default     = "0.1.0"
}

# ---------------------- Провайдеры ----------------------

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

# ---------------------- Локальные значения ----------------------

locals {
  app_name   = "veilmind-core"
  env        = "dev"
  full_image = var.image_digest != "" ?
    "${var.image_registry}/${var.image_repository}@${var.image_digest}" :
    "${var.image_registry}/${var.image_repository}:${var.image_tag}"

  common_labels = {
    "app.kubernetes.io/name"       = local.app_name
    "app.kubernetes.io/instance"   = "${local.app_name}-${local.env}"
    "app.kubernetes.io/part-of"    = "veilmind"
    "app.kubernetes.io/component"  = "backend"
    "app.kubernetes.io/environment"= local.env
    "managed-by"                   = "terraform"
  }

  psa_annotations = {
    "pod-security.kubernetes.io/enforce"        = "restricted"
    "pod-security.kubernetes.io/enforce-version"= "latest"
    "pod-security.kubernetes.io/audit"          = "restricted"
    "pod-security.kubernetes.io/warn"           = "restricted"
  }

  # Значения для Helm, безопасные по умолчанию
  helm_values = {
    replicaCount = 1
    image = {
      repository      = "${var.image_registry}/${var.image_repository}"
      tag             = var.image_tag
      digest          = var.image_digest
      pullPolicy      = "Always"
    }
    serviceAccount = {
      create                        = true
      name                          = local.app_name
      automountServiceAccountToken  = false
      annotations                   = {}
    }
    podAnnotations = {
      "environment" = local.env
    }
    podSecurityContext = {
      runAsNonRoot = true
      runAsUser    = 10001
      runAsGroup   = 10001
      fsGroup      = 10001
      seccompProfile = {
        type = "RuntimeDefault"
      }
    }
    containerSecurityContext = {
      allowPrivilegeEscalation = false
      readOnlyRootFilesystem   = true
      capabilities = {
        drop = ["ALL"]
      }
    }
    resources = {
      requests = { cpu = "100m", memory = "128Mi" }
      limits   = { cpu = "500m", memory = "256Mi" }
    }
    env = [
      { name = "APP_ENV",  value = local.env },
      { name = "LOG_LEVEL", value = "DEBUG" }
    ]
  }
}

# ---------------------- Базовые объекты кластера ----------------------

resource "kubernetes_namespace" "ns" {
  metadata {
    name        = var.namespace
    labels      = local.common_labels
    annotations = local.psa_annotations
  }
}

# Pull-secret для приватного реестра (если заданы учётные данные)
resource "kubernetes_secret" "regcred" {
  count = (var.registry_username != "" && var.registry_password != "") ? 1 : 0

  metadata {
    name      = "regcred"
    namespace = kubernetes_namespace.ns.metadata[0].name
    labels    = local.common_labels
  }

  type = "kubernetes.io/dockerconfigjson"

  data = {
    ".dockerconfigjson" = jsonencode({
      auths = {
        "${var.image_registry}" = {
          username = var.registry_username
          password = var.registry_password
          auth     = base64encode("${var.registry_username}:${var.registry_password}")
        }
      }
    })
  }
}

# Квоты ресурсов для dev‑пространства
resource "kubernetes_resource_quota" "rq" {
  metadata {
    name      = "rq-default"
    namespace = kubernetes_namespace.ns.metadata[0].name
    labels    = local.common_labels
  }
  spec {
    hard = {
      "pods"                       = "20"
      "requests.cpu"              = "2"
      "requests.memory"           = "4Gi"
      "limits.cpu"                = "4"
      "limits.memory"             = "8Gi"
      "persistentvolumeclaims"    = "5"
      "requests.storage"          = "50Gi"
      "count/configmaps"          = "50"
      "count/secrets"             = "50"
    }
    scope_selector {
      match_expression {
        operator = "In"
        scope_name = "PriorityClass"
        values = ["", "null"] # без приоритетного класса
      }
    }
  }
}

# LimitRange на контейнер
resource "kubernetes_limit_range" "lr" {
  metadata {
    name      = "limits-default"
    namespace = kubernetes_namespace.ns.metadata[0].name
    labels    = local.common_labels
  }
  spec {
    limit {
      type = "Container"
      default = {
        cpu    = "500m"
        memory = "256Mi"
      }
      default_request = {
        cpu    = "100m"
        memory = "128Mi"
      }
      max = {
        cpu    = "1000m"
        memory = "512Mi"
      }
      min = {
        cpu    = "50m"
        memory = "64Mi"
      }
    }
  }
}

# NetworkPolicy: default deny ingress/egress
resource "kubernetes_network_policy" "default_deny" {
  metadata {
    name      = "default-deny-all"
    namespace = kubernetes_namespace.ns.metadata[0].name
    labels    = local.common_labels
  }
  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

# Разрешить egress на kube-dns (UDP/TCP 53) и HTTPS в интернет (при необходимости)
resource "kubernetes_network_policy" "egress_baseline" {
  metadata {
    name      = "egress-baseline"
    namespace = kubernetes_namespace.ns.metadata[0].name
    labels    = local.common_labels
  }
  spec {
    pod_selector {}
    policy_types = ["Egress"]

    # kube-dns
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
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

    # Разрешить HTTPS наружу (опционально; ограничьте egress по CIDR/Service вместо 0.0.0.0/0)
    egress {
      to {
        ip_block {
          cidr = "0.0.0.0/0"
        }
      }
      ports {
        port     = 443
        protocol = "TCP"
      }
    }
  }
}

# ---------------------- Установка приложения через Helm ----------------------

# Если используете приватный chart‑repo с Basic/OIDC — добавьте repo_auth.
data "helm_repository" "repo" {
  count = var.chart_repo != "" ? 1 : 0

  name = "veilmind"
  url  = var.chart_repo
}

resource "helm_release" "app" {
  name       = local.app_name
  repository = var.chart_repo != "" ? data.helm_repository.repo[0].url : null
  chart      = var.chart_name
  version    = var.chart_version

  namespace           = kubernetes_namespace.ns.metadata[0].name
  create_namespace    = false
  cleanup_on_fail     = true
  atomic              = true
  wait                = true
  timeout             = 600

  # Пробрасываем лейблы/аннотации через values (предполагается поддержка в чарте)
  values = [
    yamlencode({
      fullnameOverride = "${local.app_name}"
      commonLabels     = local.common_labels

      image = {
        repository = "${var.image_registry}/${var.image_repository}"
        tag        = var.image_tag
        digest     = var.image_digest
        pullPolicy = "Always"
      }

      replicaCount = local.helm_values.replicaCount

      serviceAccount = local.helm_values.serviceAccount
      podAnnotations = local.helm_values.podAnnotations

      podSecurityContext       = local.helm_values.podSecurityContext
      containerSecurityContext = local.helm_values.containerSecurityContext
      resources                = local.helm_values.resources

      env = local.helm_values.env

      extraSecrets = (length(kubernetes_secret.regcred) > 0 ? [{
        name = kubernetes_secret.regcred[0].metadata[0].name
        type = "kubernetes.io/dockerconfigjson"
      }] : [])

      # Пример включения NetworkPolicy в чарте (если поддерживается)
      networkPolicy = {
        enabled = true
      }
    })
  ]

  depends_on = [
    kubernetes_resource_quota.rq,
    kubernetes_limit_range.lr,
    kubernetes_network_policy.default_deny,
    kubernetes_network_policy.egress_baseline
  ]
}

# ---------------------- Outputs ----------------------

output "namespace" {
  value       = kubernetes_namespace.ns.metadata[0].name
  description = "Имя Namespace для dev"
}

output "release_name" {
  value       = helm_release.app.name
  description = "Имя Helm‑релиза"
}

output "image_effective" {
  value       = local.full_image
  description = "Эффективный образ (учитывая digest)"
}

output "service_account" {
  value       = local.helm_values.serviceAccount.name
  description = "ServiceAccount приложения"
}
