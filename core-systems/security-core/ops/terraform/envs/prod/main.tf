#############################################
# Aethernova / security-core — prod main.tf #
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

  # Пример backend для прод-а (замените на ваш)
  backend "s3" {
    bucket         = "REPLACE_ME-security-core-tfstate"
    key            = "prod/security-core/terraform.tfstate"
    region         = "eu-north-1"
    dynamodb_table = "REPLACE_ME-security-core-tflock"
    encrypt        = true
  }
}

#####################
# Входные переменные
#####################

variable "kubeconfig" {
  description = "Путь к kubeconfig, если не используется in-cluster."
  type        = string
  default     = ""
}

variable "namespace" {
  description = "Namespace для security-core."
  type        = string
  default     = "security-core"
}

variable "image_pull_secrets" {
  description = "Список Secret-ов для pull образов."
  type        = list(string)
  default     = []
}

variable "labels_common" {
  description = "Общие метки для всех ресурсов."
  type        = map(string)
  default = {
    "app.kubernetes.io/part-of" = "security-core"
    "security.aethernova.io/profile" = "baseline"
  }
}

variable "enable_network_policy" {
  type        = bool
  description = "Включить базовые NetworkPolicy."
  default     = true
}

variable "enable_kyverno" {
  type        = bool
  description = "Установить Kyverno."
  default     = true
}

variable "enable_falco" {
  type        = bool
  description = "Установить Falco."
  default     = true
}

variable "enable_trivy_operator" {
  type        = bool
  description = "Установить Trivy Operator."
  default     = true
}

variable "enable_kube_bench" {
  type        = bool
  description = "Запуск kube-bench по расписанию."
  default     = true
}

variable "kyverno_version" {
  type        = string
  description = "Версия чарта Kyverno (semver). Пусто = последняя стабильная."
  default     = ""
}

variable "falco_version" {
  type        = string
  description = "Версия чарта Falco (semver). Пусто = последняя стабильная."
  default     = ""
}

variable "trivy_operator_version" {
  type        = string
  description = "Версия чарта Trivy Operator (semver). Пусто = последняя стабильная."
  default     = ""
}

variable "trivy_severity" {
  type        = string
  description = "Уровни серьёзности для Trivy."
  default     = "CRITICAL,HIGH"
}

variable "kube_bench_schedule" {
  type        = string
  description = "CRON-расписание для kube-bench."
  default     = "0 2 * * *"
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

  # Общие таймауты Helm
  helm_timeout = 600
}

######################
# Провайдеры Kubernetes/Helm
######################

provider "kubernetes" {
  config_path = var.kubeconfig != "" ? var.kubeconfig : null
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig != "" ? var.kubeconfig : null
  }
}

#############################
# Namespace с PSS restricted
#############################

resource "kubernetes_namespace" "security_core" {
  metadata {
    name        = var.namespace
    labels      = local.labels_ns
    annotations = {}
  }
}

####################################
# ServiceAccount с imagePullSecrets
####################################

resource "kubernetes_service_account_v1" "security_core" {
  count = length(var.image_pull_secrets) > 0 ? 1 : 0

  metadata {
    name      = "security-core-sa"
    namespace = kubernetes_namespace.security_core.metadata[0].name
    labels    = var.labels_common
  }

  image_pull_secrets = [for s in var.image_pull_secrets : { name = s }]
}

###############################
# NetworkPolicy: default deny
###############################

# Полный запрет Ingress/Egress
resource "kubernetes_network_policy_v1" "default_deny_all" {
  count = var.enable_network_policy ? 1 : 0

  metadata {
    name      = "security-core-default-deny-all"
    namespace = kubernetes_namespace.security_core.metadata[0].name
    labels    = var.labels_common
  }

  spec {
    pod_selector {} # все Pod'ы в namespace
    policy_types = ["Ingress", "Egress"]
    # Отсутствие правил = deny-all
  }
}

# Разрешение только DNS egress к CoreDNS (TCP/UDP 53) в kube-system
resource "kubernetes_network_policy_v1" "allow_dns_egress" {
  count = var.enable_network_policy ? 1 : 0

  metadata {
    name      = "security-core-allow-dns-egress"
    namespace = kubernetes_namespace.security_core.metadata[0].name
    labels    = var.labels_common
  }

  spec {
    pod_selector {}
    policy_types = ["Egress"]

    # Вариант 1: фильтрация по namespaceSelector + podSelector
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

      ports {
        port     = 53
        protocol = "UDP"
      }
      ports {
        port     = 53
        protocol = "TCP"
      }
    }

    # Вариант 2: только namespaceSelector (на случай иных меток CoreDNS)
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

############################
# Kyverno (Admission Policy)
############################

resource "helm_release" "kyverno" {
  count      = var.enable_kyverno ? 1 : 0
  name       = "kyverno"
  repository = "https://kyverno.github.io/kyverno/"
  chart      = "kyverno"
  version    = var.kyverno_version != "" ? var.kyverno_version : null
  namespace  = "kyverno"
  create_namespace = true
  timeout    = local.helm_timeout
  atomic     = true

  values = [
    yamlencode({
      replicaCount = 2
      image = {
        pullPolicy = "IfNotPresent"
      }
      resources = {
        requests = { cpu = "50m", memory = "64Mi" }
        limits   = { cpu = "200m", memory = "256Mi" }
      }
    })
  ]

  depends_on = [kubernetes_namespace.security_core]
}

##############
# Falco (eBPF)
##############

resource "helm_release" "falco" {
  count      = var.enable_falco ? 1 : 0
  name       = "falco"
  repository = "https://falcosecurity.github.io/charts"
  chart      = "falco"
  version    = var.falco_version != "" ? var.falco_version : null
  namespace  = "falco"
  create_namespace = true
  timeout    = local.helm_timeout
  atomic     = true

  values = [
    yamlencode({
      driver = {
        kind = "ebpf"
      }
      falco = {
        jsonOutput = true
        priority   = "warning"
      }
      resources = {
        requests = { cpu = "50m", memory = "64Mi" }
        limits   = { cpu = "200m", memory = "256Mi" }
      }
    })
  ]

  depends_on = [helm_release.kyverno]
}

##################################
# Trivy Operator (vuln/config/secret)
##################################

resource "helm_release" "trivy_operator" {
  count      = var.enable_trivy_operator ? 1 : 0
  name       = "trivy-operator"
  repository = "https://aquasecurity.github.io/helm-charts/"
  chart      = "trivy-operator"
  version    = var.trivy_operator_version != "" ? var.trivy_operator_version : null
  namespace  = "trivy-system"
  create_namespace = true
  timeout    = local.helm_timeout
  atomic     = true

  values = [
    yamlencode({
      trivy = {
        ignoreUnfixed = true
        severity      = var.trivy_severity
        securityChecks = "vuln,secret,config"
      }
      operator = {
        scanJobsConcurrentLimit = 2
      }
      resources = {
        requests = { cpu = "50m", memory = "64Mi" }
        limits   = { cpu = "200m", memory = "256Mi" }
      }
    })
  ]

  depends_on = [helm_release.kyverno]
}

##############################
# kube-bench как CronJob (CIS)
##############################

resource "kubernetes_service_account_v1" "kube_bench" {
  count = var.enable_kube_bench ? 1 : 0

  metadata {
    name      = "kube-bench"
    namespace = "kube-bench"
    labels    = var.labels_common
  }
}

resource "kubernetes_namespace" "kube_bench" {
  count = var.enable_kube_bench ? 1 : 0

  metadata {
    name   = "kube-bench"
    labels = var.labels_common
  }
}

resource "kubernetes_cron_job_v1" "kube_bench" {
  count = var.enable_kube_bench ? 1 : 0

  metadata {
    name      = "kube-bench"
    namespace = kubernetes_namespace.kube_bench[0].metadata[0].name
    labels    = var.labels_common
  }

  spec {
    schedule                  = var.kube_bench_schedule
    concurrency_policy        = "Forbid"
    successful_jobs_history_limit = 1
    failed_jobs_history_limit     = 3

    job_template {
      metadata {
        labels = var.labels_common
      }

      spec {
        backoff_limit = 0

        template {
          metadata {
            labels = var.labels_common
          }
          spec {
            service_account_name = kubernetes_service_account_v1.kube_bench[0].metadata[0].name
            restart_policy       = "Never"

            container {
              name  = "kube-bench"
              image = "aquasec/kube-bench:latest"
              args  = ["--benchmark", "cis-1.8", "--json"]
              security_context {
                allow_privilege_escalation = false
                read_only_root_filesystem  = true
                run_as_non_root            = true
                seccomp_profile {
                  type = "RuntimeDefault"
                }
                capabilities {
                  drop = ["ALL"]
                }
              }
              resources {
                requests = {
                  cpu    = "50m"
                  memory = "64Mi"
                }
                limits = {
                  cpu    = "200m"
                  memory = "256Mi"
                }
              }
            }
          }
        }
      }
    }
  }

  depends_on = [kubernetes_namespace.kube_bench]
}

##############################
# Технические задержки/ожидания
##############################

resource "time_sleep" "wait_after_ns" {
  depends_on = [kubernetes_namespace.security_core]
  create_duration = "5s"
}

##############################
# Выходные значения
##############################

output "security_core_namespace" {
  value = kubernetes_namespace.security_core.metadata[0].name
}

output "kyverno_installed" {
  value       = var.enable_kyverno
  description = "Флаг установки Kyverno."
}

output "falco_installed" {
  value       = var.enable_falco
  description = "Флаг установки Falco."
}

output "trivy_operator_installed" {
  value       = var.enable_trivy_operator
  description = "Флаг установки Trivy Operator."
}
