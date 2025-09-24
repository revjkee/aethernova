terraform {
  required_version = ">= 1.5.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.23.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.13.0"
    }
  }
}

provider "kubernetes" {}
provider "helm" {}

############################################################
# ВХОДНЫЕ ПАРАМЕТРЫ
############################################################

variable "namespace" {
  type        = string
  default     = "bridge-relayer"
  description = "Namespace для релизов bridge-relayer"
}

# Репозиторий/чарт bjw-s app-template
# https://github.com/bjw-s-labs/helm-charts ; repo URL: https://bjw-s-labs.github.io/helm-charts
variable "chart_repository" {
  type        = string
  default     = "https://bjw-s-labs.github.io/helm-charts"
  description = "Helm repo URL с app-template/common (bjw-s)"
}

variable "chart_name" {
  type        = string
  default     = "app-template"
  description = "Имя чарта"
}

variable "chart_version" {
  type        = string
  description = "Версия чарта bjw-s/app-template (указать явно)"
}

# Контейнер relayer
variable "image_repository" {
  type        = string
  description = "Образ контейнера bridge-relayer (repository)"
}

variable "image_tag" {
  type        = string
  description = "Тег образа bridge-relayer (tag)"
}

variable "container_port" {
  type        = number
  default     = 8080
  description = "Порт приложения внутри контейнера (для Service и TCP-probes)"
}

variable "replicas" {
  type        = number
  default     = 2
  description = "Количество реплик Deployment"
}

# Нефиксированные env переменные (без секрета)
variable "relayer_env" {
  type        = map(string)
  default     = {}
  description = "Обычные env переменные (не секретные)"
}

# Данные секрета как map(key->value). Значения чувствительны.
# В Secret попадут как:
#  - env через envFrom.secretRef
#  - файлы через persistence(type=secret)
variable "relayer_secret_name" {
  type        = string
  default     = "bridge-relayer-secrets"
  description = "Имя создаваемого Kubernetes Secret c конфигурацией/ключами релейтера"
}

variable "relayer_secret_data" {
  type        = map(string)
  sensitive   = true
  description = "Ключи/значения для Kubernetes Secret (например, PRIVATE_KEY, RPC_URL, и т.п.)"
}

# Ресурсы контейнера
variable "resources" {
  type = object({
    requests = optional(object({
      cpu    = string
      memory = string
    }))
    limits = optional(object({
      cpu    = string
      memory = string
    }))
  })
  default = {
    requests = { cpu = "100m", memory = "256Mi" }
    limits   = { cpu = "1",    memory = "1Gi"   }
  }
}

############################################################
# РЕСУРСЫ KUBERNETES
############################################################

resource "kubernetes_namespace" "ns" {
  metadata { name = var.namespace }
}

# Kubernetes Secret с данными релейтера.
# По K8s спецификации поле data хранит base64-значения.
resource "kubernetes_secret" "relayer" {
  metadata {
    name      = var.relayer_secret_name
    namespace = kubernetes_namespace.ns.metadata[0].name
    labels = {
      "app.kubernetes.io/name"       = "bridge-relayer"
      "app.kubernetes.io/component"  = "runtime"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }

  type = "Opaque"

  # Преобразуем значения в base64.
  data = {
    for k, v in var.relayer_secret_data : k => base64encode(v)
  }

  depends_on = [kubernetes_namespace.ns]
}

############################################################
# HELM RELEASE: bjw-s/app-template
############################################################

locals {
  app_values = {
    # Тип контроллера и масштабирование
    controller = {
      type     = "deployment"
      replicas = var.replicas
    }

    image = {
      repository = var.image_repository
      tag        = var.image_tag
      pullPolicy = "IfNotPresent"
    }

    # Service и порт (используем TCP-пробы по умолчанию)
    service = {
      main = {
        enabled = true
        primary = true
        ports = {
          http = {
            enabled    = true
            primary    = true
            protocol   = "TCP"
            port       = var.container_port
            targetPort = var.container_port
          }
        }
      }
    }

    # Пробы по умолчанию типа TCP (см. common values)
    probes = {
      liveness  = { enabled = true, custom = false, type = "TCP" }
      readiness = { enabled = true, custom = false, type = "TCP" }
      startup   = { enabled = true, custom = false, type = "TCP" }
    }

    # Безопасные контексты
    podSecurityContext = {
      fsGroup = 2000
    }
    securityContext = {
      runAsUser                = 1000
      runAsGroup               = 1000
      runAsNonRoot             = true
      allowPrivilegeEscalation = false
      readOnlyRootFilesystem   = true
      capabilities = {
        drop = ["ALL"]
      }
    }

    # Env + envFrom из секрета
    env = var.relayer_env
    envFrom = [
      { secretRef = { name = kubernetes_secret.relayer.metadata[0].name } }
    ]

    # Монтирование секрета как файлов
    # Подробности — persistence.type: secret
    persistence = {
      keys = {
        enabled   = true
        type      = "secret"
        name      = kubernetes_secret.relayer.metadata[0].name
        mountPath = "/opt/relayer/keys" # пример каталога для ключей
        readOnly  = true
      }
    }

    # ServiceAccount по необходимости
    serviceAccount = {
      create = true
      name   = "bridge-relayer"
    }

    # Ресурсы
    resources = var.resources
  }
}

resource "helm_release" "bridge_relayer" {
  name             = "bridge-relayer"
  namespace        = kubernetes_namespace.ns.metadata[0].name
  repository       = var.chart_repository
  chart            = var.chart_name
  version          = var.chart_version
  create_namespace = false

  values = [
    yamlencode(local.app_values)
  ]

  depends_on = [
    kubernetes_secret.relayer
  ]
}
