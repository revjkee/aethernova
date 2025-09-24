#############################################
# zero-trust-core — dev main.tf (industrial)
# Path: zero-trust-core/ops/terraform/envs/dev/main.tf
#############################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.29"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
  }

  # Dev окружение использует локальный backend по умолчанию.
  backend "local" {
    path = "terraform.tfstate"
  }
}

#####################
# Входные переменные
#####################

variable "kubeconfig" {
  description = "Путь к kubeconfig (если пусто — провайдер попытается использовать окружение)."
  type        = string
  default     = ""
}

variable "kube_context" {
  description = "Kube context (опционально)."
  type        = string
  default     = ""
}

variable "namespace" {
  description = "Namespace dev-среды."
  type        = string
  default     = "zero-trust-dev"
}

variable "labels_common" {
  description = "Общие метки для всех ресурсов."
  type        = map(string)
  default = {
    "app.kubernetes.io/part-of" = "zero-trust-core"
    "zero-trust.aethernova.io/env" = "dev"
  }
}

variable "image_pull_secrets" {
  description = "Список Secret-ов с docker creds."
  type        = list(string)
  default     = []
}

variable "enable_network_policy" {
  type        = bool
  description = "Включить базовые NetworkPolicy (deny-all + DNS egress)."
  default     = true
}

variable "enable_limit_range" {
  type        = bool
  description = "Включить LimitRange c безопасными дефолтами."
  default     = true
}

variable "enable_resource_quota" {
  type        = bool
  description = "Включить ResourceQuota для dev."
  default     = true
}

variable "enable_kyverno" {
  type        = bool
  description = "Установить Kyverno (admission policies)."
  default     = true
}

variable "kyverno_chart_version" {
  type        = string
  description = "Версия чарта Kyverno (semver). Пусто = последняя стабильная."
  default     = ""
}

variable "enable_trivy_operator" {
  type        = bool
  description = "Установить Trivy Operator (сканер уязвимостей/секретов)."
  default     = false
}

variable "trivy_chart_version" {
  type        = string
  description = "Версия чарта Trivy Operator (semver)."
  default     = ""
}

variable "trivy_severity" {
  type        = string
  description = "Уровни серьёзности для Trivy."
  default     = "CRITICAL,HIGH"
}

################
# Локальные данные
################

locals {
  pss_labels = {
    "pod-security.kubernetes.io/enforce"         = "restricted"
    "pod-security.kubernetes.io/enforce-version" = "latest"
    "pod-security.kubernetes.io/audit"           = "restricted"
    "pod-security.kubernetes.io/warn"            = "restricted"
  }

  labels_ns = merge(var.labels_common, local.pss_labels)

  # Безопасные дефолты лимитов для dev
  default_requests = { cpu = "50m", memory = "64Mi" }
  default_limits   = { cpu = "500m", memory = "512Mi" }

  # Таймаут для Helm релизов
  helm_timeout = 600
}

######################
# Провайдеры Kubernetes/Helm
######################

provider "kubernetes" {
  config_path    = var.kubeconfig != "" ? var.kubeconfig : null
  config_context = var.kube_context != "" ? var.kube_context : null
}

provider "helm" {
  kubernetes {
    config_path    = var.kubeconfig != "" ? var.kubeconfig : null
    config_context = var.kube_context != "" ? var.kube_context : null
  }
}

#############################
# Namespace с PSS restricted
#############################

resource "kubernetes_namespace" "dev" {
  metadata {
    name        = var.namespace
    labels      = local.labels_ns
    annotations = {}
  }
}

####################################
# ServiceAccount с imagePullSecrets
####################################

resource "kubernetes_service_account_v1" "zt_core" {
  metadata {
    name      = "zero-trust-core"
    namespace = kubernetes_namespace.dev.metadata[0].name
    labels    = var.labels_common
  }

  automount_service_account_token = false

  dynamic "image_pull_secrets" {
    for_each = var.image_pull_secrets
    content {
      name = image_pull_secrets.value
    }
  }
}

###############################
# NetworkPolicy: default deny + DNS
###############################

resource "kubernetes_network_policy_v1" "default_deny_all" {
  count = var.enable_network_policy ? 1 : 0

  metadata {
    name      = "zt-default-deny-all"
    namespace = kubernetes_namespace.dev.metadata[0].name
    labels    = var.labels_common
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy_v1" "allow_dns_egress" {
  count = var.enable_network_policy ? 1 : 0

  metadata {
    name      = "zt-allow-dns-egress"
    namespace = kubernetes_namespace.dev.metadata[0].name
    labels    = var.labels_common
  }

  spec {
    pod_selector {}
    policy_types = ["Egress"]

    # Разрешаем трафик к CoreDNS в kube-system
    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_expressions {
            key      = "k8s-app"
            operator = "In"
            values   = ["kube-dns", "coredns"]
          }
        }
      }
      ports { port = 53 protocol = "UDP" }
      ports { port = 53 protocol = "TCP" }
    }
  }
}

###############################
# LimitRange и ResourceQuota
###############################

resource "kubernetes_limit_range_v1" "defaults" {
  count = var.enable_limit_range ? 1 : 0

  metadata {
    name      = "zt-defaults"
    namespace = kubernetes_namespace.dev.metadata[0].name
    labels    = var.labels_common
  }

  spec {
    limit {
      type = "Container"

      default_request = local.default_requests
      default         = local.default_limits

      max = {
        cpu    = "2"
        memory = "2Gi"
      }
    }
  }
}

resource "kubernetes_resource_quota_v1" "rq" {
  count = var.enable_resource_quota ? 1 : 0

  metadata {
    name      = "zt-quota"
    namespace = kubernetes_namespace.dev.metadata[0].name
    labels    = var.labels_common
  }

  spec {
    hard = {
      "requests.cpu"    = "4"
      "requests.memory" = "8Gi"
      "limits.cpu"      = "8"
      "limits.memory"   = "16Gi"
      "pods"            = "100"
      "services"        = "50"
      "secrets"         = "200"
      "configmaps"      = "200"
    }
    scope_selector {
      match_expression {
        operator = "In"
        scope_name = "PriorityClass"
        values     = ["", ""] # заглушка — без фильтра по приоритету
      }
    }
  }
}

############################
# Kyverno (Admission Policy)
############################

resource "helm_release" "kyverno" {
  count      = var.enable_kyverno ? 1 : 0
  name       = "kyverno"
  repository = "https://kyverno.github.io/kyverno/"
  chart      = "kyverno"
  version    = var.kyverno_chart_version != "" ? var.kyverno_chart_version : null
  namespace  = "kyverno"
  create_namespace = true
  timeout    = local.helm_timeout
  atomic     = true

  values = [
    yamlencode({
      replicaCount = 2
      image = { pullPolicy = "IfNotPresent" }
      resources = {
        requests = { cpu = "50m", memory = "64Mi" }
        limits   = { cpu = "300m", memory = "384Mi" }
      }
    })
  ]

  depends_on = [kubernetes_namespace.dev]
}

##################################
# Trivy Operator (опционально)
##################################

resource "helm_release" "trivy" {
  count      = var.enable_trivy_operator ? 1 : 0
  name       = "trivy-operator"
  repository = "https://aquasecurity.github.io/helm-charts/"
  chart      = "trivy-operator"
  version    = var.trivy_chart_version != "" ? var.trivy_chart_version : null
  namespace  = "trivy-system"
  create_namespace = true
  timeout    = local.helm_timeout
  atomic     = true

  values = [
    yamlencode({
      trivy = {
        ignoreUnfixed   = true
        severity        = var.trivy_severity
        securityChecks  = "vuln,config,secret"
      }
      operator = {
        scanJobsConcurrentLimit = 2
      }
      resources = {
        requests = { cpu = "50m", memory = "64Mi" }
        limits   = { cpu = "300m", memory = "384Mi" }
      }
    })
  ]

  depends_on = [kubernetes_namespace.dev, helm_release.kyverno]
}

##############################
# Технические задержки/ожидания
##############################

resource "time_sleep" "after_ns" {
  depends_on      = [kubernetes_namespace.dev]
  create_duration = "5s"
}

##############################
# Дымовые проверки (инфо)
##############################

data "kubernetes_pod" "kyverno" {
  count = var.enable_kyverno ? 1 : 0
  metadata {
    namespace = "kyverno"
    labels = {
      "app.kubernetes.io/name" = "kyverno"
    }
  }
  depends_on = [helm_release.kyverno]
}

data "kubernetes_pod" "trivy" {
  count = var.enable_trivy_operator ? 1 : 0
  metadata {
    namespace = "trivy-system"
    labels = {
      "app.kubernetes.io/name" = "trivy-operator"
    }
  }
  depends_on = [helm_release.trivy]
}

##############################
# Выходные значения
##############################

output "namespace" {
  value       = kubernetes_namespace.dev.metadata[0].name
  description = "Dev namespace."
}

output "kyverno_installed" {
  value       = var.enable_kyverno
  description = "Флаг установки Kyverno."
}

output "trivy_installed" {
  value       = var.enable_trivy_operator
  description = "Флаг установки Trivy Operator."
}
