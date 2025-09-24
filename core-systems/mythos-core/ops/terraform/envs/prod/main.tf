// mythos-core/ops/terraform/envs/prod/main.tf
terraform {
  required_version = ">= 1.7.0, < 2.0.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.31"
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

  # Рекомендуется вынести backend в отдельный backend.tf или Terraform Cloud/Enterprise.
  # Пример (НЕ активирован здесь):
  # backend "s3" {
  #   bucket = "your-tfstate-prod"
  #   key    = "mythos-core/prod/terraform.tfstate"
  #   region = "eu-central-1"
  #   dynamodb_table = "your-tflock"
  #   encrypt = true
  # }
}

############################
# ВАРИАНТЫ/ЛОКАЛИ
############################
variable "kubeconfig_path" {
  type        = string
  description = "Путь к kubeconfig для prod кластера"
  default     = "~/.kube/config"
}

variable "kube_context" {
  type        = string
  description = "Kube context для prod кластера"
}

variable "namespace" {
  type        = string
  description = "Namespace для mythos-core (prod)"
  default     = "mythos-prod"
}

variable "release_name" {
  type        = string
  description = "Helm release name"
  default     = "mythos-core"
}

variable "image_repository" {
  type        = string
  description = "Docker image repository"
  default     = "ghcr.io/yourorg/mythos-core"
}

variable "image_tag" {
  type        = string
  description = "Docker image tag для продакшена"
  default     = "v0.1.0"
}

variable "replicas" {
  type        = number
  description = "Количество реплик в продакшене"
  default     = 5
}

variable "monitoring_namespace" {
  type        = string
  description = "Namespace, из которого Prometheus будет скрапить метрики"
  default     = "monitoring"
}

variable "create_registry_secret" {
  type        = bool
  description = "Создавать ли imagePullSecret для приватного реестра"
  default     = false
}

variable "registry_server" {
  type        = string
  description = "Адрес Docker Registry (для pull-secret)"
  default     = "ghcr.io"
}

variable "registry_username" {
  type        = string
  description = "Логин для Docker Registry"
  default     = ""
  sensitive   = true
}

variable "registry_password" {
  type        = string
  description = "Пароль/токен для Docker Registry"
  default     = ""
  sensitive   = true
}

locals {
  labels = {
    "app.kubernetes.io/name"       = "mythos-core"
    "app.kubernetes.io/instance"   = var.release_name
    "app.kubernetes.io/part-of"    = "mythos"
    "app.kubernetes.io/component"  = "api"
    "app.kubernetes.io/managed-by" = "terraform"
    "app.kubernetes.io/environment"= "prod"
    "environment"                  = "prod"
  }

  chart_path = abspath("${path.module}/../../../helm/mythos-core")

  # Значения Helm для продакшена
  values = {
    image = {
      repository = var.image_repository
      tag        = var.image_tag
      pullPolicy = "IfNotPresent"
    }
    replicaCount = var.replicas

    resources = {
      requests = {
        cpu    = "500m"
        memory = "512Mi"
      }
      limits = {
        cpu    = "2"
        memory = "2Gi"
      }
    }

    # Пробы и тайминги
    podDisruptionBudget = {
      enabled = false # PDB создаём terrafrom-ресурсом ниже
    }

    service = {
      type = "ClusterIP"
      ports = {
        http    = 8080
        grpc    = 50051
        metrics = 9090
      }
    }

    metrics = {
      enabled = true
      serviceMonitor = {
        enabled = true
        namespace = var.monitoring_namespace
      }
    }

    podLabels = local.labels
    podAnnotations = {
      "prometheus.io/scrape" = "true"
      "prometheus.io/port"   = "9090"
      "prometheus.io/path"   = "/metrics"
    }

    # ServiceAccount и imagePullSecrets будут подставлены ниже через set-списки
  }
}

############################
# ПРОВАЙДЕРЫ
############################
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

############################
# ИНФРА ПРОД-НЕЙМСПЕЙСА
############################

resource "kubernetes_namespace_v1" "ns" {
  metadata {
    name   = var.namespace
    labels = local.labels
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "kubernetes_resource_quota_v1" "rq" {
  metadata {
    name      = "rq-mythos-core"
    namespace = kubernetes_namespace_v1.ns.metadata[0].name
    labels    = local.labels
  }
  spec {
    hard = {
      "requests.cpu"               = "6"
      "requests.memory"            = "8Gi"
      "limits.cpu"                 = "12"
      "limits.memory"              = "16Gi"
      "pods"                       = "50"
      "services"                   = "10"
      "configmaps"                 = "50"
      "secrets"                    = "50"
      "persistentvolumeclaims"     = "0"
      "services.loadbalancers"     = "0"
      "services.nodeports"         = "0"
    }
    scope_selector {
      # без дополнительных scope — применимо ко всем
    }
  }
}

resource "kubernetes_limit_range_v1" "lr" {
  metadata {
    name      = "lr-mythos-core"
    namespace = kubernetes_namespace_v1.ns.metadata[0].name
    labels    = local.labels
  }
  spec {
    limit {
      type = "Container"
      default = {
        cpu    = "1000m"
        memory = "1Gi"
      }
      default_request = {
        cpu    = "250m"
        memory = "256Mi"
      }
      max = {
        cpu    = "4"
        memory = "4Gi"
      }
      min = {
        cpu    = "100m"
        memory = "128Mi"
      }
    }
  }
}

# Default deny + разрешения DNS и Prometheus из monitoring-namespace
resource "kubernetes_network_policy_v1" "default_deny" {
  metadata {
    name      = "np-default-deny"
    namespace = kubernetes_namespace_v1.ns.metadata[0].name
    labels    = local.labels
  }
  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
    ingress {}
    egress {}
  }
}

resource "kubernetes_network_policy_v1" "allow_dns" {
  metadata {
    name      = "np-allow-dns"
    namespace = kubernetes_namespace_v1.ns.metadata[0].name
    labels    = local.labels
  }
  spec {
    pod_selector {}
    policy_types = ["Egress"]
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
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
  }
}

resource "kubernetes_network_policy_v1" "allow_prometheus" {
  metadata {
    name      = "np-allow-prometheus"
    namespace = kubernetes_namespace_v1.ns.metadata[0].name
    labels    = local.labels
  }
  spec {
    pod_selector {}
    policy_types = ["Ingress"]
    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.monitoring_namespace
          }
        }
      }
      ports {
        port     = 9090
        protocol = "TCP"
      }
    }
  }
}

# PDB — непрерывность при эвикциях
resource "kubernetes_pod_disruption_budget_v1" "pdb" {
  metadata {
    name      = "pdb-mythos-core"
    namespace = kubernetes_namespace_v1.ns.metadata[0].name
    labels    = local.labels
  }
  spec {
    max_unavailable = "20%"
    selector {
      match_labels = {
        "app.kubernetes.io/name"     = "mythos-core"
        "app.kubernetes.io/instance" = var.release_name
      }
    }
  }
}

############################
# OПЦИОНАЛЬНЫЙ PULL-SECRET + SERVICEACCOUNT
############################

# dockerconfigjson создаётся только при необходимости
locals {
  dockerconfigjson = jsonencode({
    auths = {
      (var.registry_server) = {
        username = var.registry_username
        password = var.registry_password
        auth     = base64encode("${var.registry_username}:${var.registry_password}")
      }
    }
  })
}

resource "kubernetes_secret_v1" "registry" {
  count = var.create_registry_secret ? 1 : 0

  metadata {
    name      = "regcred"
    namespace = kubernetes_namespace_v1.ns.metadata[0].name
    labels    = local.labels
  }
  type = "kubernetes.io/dockerconfigjson"
  data = {
    ".dockerconfigjson" = base64encode(local.dockerconfigjson)
  }
}

resource "kubernetes_service_account_v1" "sa" {
  metadata {
    name      = "mythos-core"
    namespace = kubernetes_namespace_v1.ns.metadata[0].name
    labels    = local.labels
  }
  automount_service_account_token = true

  dynamic "image_pull_secret" {
    for_each = var.create_registry_secret ? ["regcred"] : []
    content {
      name = image_pull_secret.value
    }
  }
}

############################
# HELM-РЕЛИЗ ЛОКАЛЬНОГО ЧАРТА
############################

resource "helm_release" "mythos_core" {
  name       = var.release_name
  namespace  = kubernetes_namespace_v1.ns.metadata[0].name
  repository = ""                # локальный чарт
  chart      = local.chart_path  # ops/helm/mythos-core
  version    = ""                # для локального чарта не требуется
  create_namespace = false
  timeout    = 600
  wait       = true
  atomic     = true
  lint       = true
  max_history = 20

  # Базовые values
  values = [yamlencode(local.values)]

  # ServiceAccount и imagePullSecrets пробрасываем через set
  set {
    name  = "serviceAccount.create"
    value = "false"
  }
  set {
    name  = "serviceAccount.name"
    value = kubernetes_service_account_v1.sa.metadata[0].name
  }

  dynamic "set" {
    for_each = var.create_registry_secret ? { "image.pullSecrets[0].name" = "regcred" } : {}
    content {
      name  = set.key
      value = set.value
    }
  }

  depends_on = [
    kubernetes_namespace_v1.ns,
    kubernetes_service_account_v1.sa,
    kubernetes_secret_v1.registry,
    kubernetes_resource_quota_v1.rq,
    kubernetes_limit_range_v1.lr,
    kubernetes_network_policy_v1.default_deny,
    kubernetes_network_policy_v1.allow_dns,
    kubernetes_network_policy_v1.allow_prometheus,
  ]
}

############################
# OUTPUTS
############################

output "namespace" {
  value       = kubernetes_namespace_v1.ns.metadata[0].name
  description = "Namespace прод-окружения"
}

output "helm_release_name" {
  value       = helm_release.mythos_core.name
  description = "Имя Helm релиза"
}

output "service_account" {
  value       = kubernetes_service_account_v1.sa.metadata[0].name
  description = "ServiceAccount, используемый релизом"
}

output "image" {
  value       = "${var.image_repository}:${var.image_tag}"
  description = "Образ приложения, задеплоенный в prod"
}
