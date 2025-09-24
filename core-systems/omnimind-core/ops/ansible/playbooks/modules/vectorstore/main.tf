###############################################
# Vectorstore (Helm-on-Kubernetes) — main.tf
# Self-contained Terraform module
###############################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.29.0"
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

################################################
# Inputs
################################################

variable "name" {
  type        = string
  description = "Release name (Helm) и логические имена ресурсов."
}

variable "namespace" {
  type        = string
  description = "Namespace для развертывания."
  default     = "vectorstore"
}

variable "labels" {
  type        = map(string)
  description = "Общие labels для всех управляемых ресурсов."
  default     = {
    "app.kubernetes.io/part-of" = "omnimind-core"
  }
}

variable "annotations" {
  type        = map(string)
  description = "Дополнительные аннотации на Pod/Deployment (передаются в values)."
  default     = {}
}

# Параметры чарта
variable "chart_repo" {
  type        = string
  description = "Helm repo (URL), напр. https://charts.example.com/..."
}

variable "chart_name" {
  type        = string
  description = "Имя чарта, напр. qdrant|weaviate|milvus|opensearch|redis-stack."
}

variable "chart_version" {
  type        = string
  description = "Версия чарта."
}

# Базовые значения для большинства чартов (реплики/ресурсы/персистентность/сервис)
variable "replicas" {
  type        = number
  description = "Количество реплик (если чарт поддерживает)."
  default     = 1
}

variable "image_pull_secrets" {
  type        = list(string)
  description = "Секреты pull image (если приватный реестр)."
  default     = []
}

variable "pod_security_context" {
  type = object({
    fsGroup             = optional(number)
    runAsNonRoot        = optional(bool, true)
    seccompProfileType  = optional(string, "RuntimeDefault")
  })
  default = {}
}

variable "container_security_context" {
  type = object({
    runAsUser                = optional(number, 10001)
    runAsGroup               = optional(number, 10001)
    allowPrivilegeEscalation = optional(bool, false)
    readOnlyRootFilesystem   = optional(bool, true)
    capabilities_drop_all    = optional(bool, true)
  })
  default = {}
}

variable "resources" {
  type = object({
    requests = object({
      cpu    = string
      memory = string
    })
    limits = object({
      cpu    = string
      memory = string
    })
  })
  default = {
    requests = { cpu = "250m", memory = "512Mi" }
    limits   = { cpu = "1000m", memory = "2Gi" }
  }
}

variable "persistence" {
  type = object({
    enabled        = bool
    storage_class  = optional(string)
    size           = optional(string, "20Gi")
    access_modes   = optional(list(string), ["ReadWriteOnce"])
  })
  default = {
    enabled = true
  }
}

variable "service" {
  type = object({
    type        = optional(string, "ClusterIP") # ClusterIP/NodePort/LoadBalancer
    http_port   = optional(number, 8080)
    grpc_port   = optional(number, 50051)
    extra_ports = optional(list(object({
      name = string
      port = number
      protocol = optional(string, "TCP")
    })), [])
  })
  default = {}
}

# Node placement
variable "node_selector" {
  type        = map(string)
  default     = {}
}
variable "tolerations" {
  type        = list(map(string))
  default     = []
}
variable "affinity" {
  type        = map(any)
  default     = {}
}
variable "topology_spread_constraints" {
  type        = list(map(any))
  default     = []
}

# Секрет для встраиваемой базовой аутентификации (если поддерживается чартом)
variable "basic_auth" {
  type = object({
    enabled  = bool
    username = optional(string)
    password = optional(string)
    existing_secret_name = optional(string)
  })
  default = {
    enabled = false
  }
}

# Опциональная генерация пароля, если включен basic_auth и не задан password
resource "random_password" "basic" {
  length  = 24
  special = false
  upper   = true
  lower   = true
  number  = true
  keepers = {
    name      = var.name
    namespace = var.namespace
  }
  count = var.basic_auth.enabled && (try(var.basic_auth.password, "") == "" && try(var.basic_auth.existing_secret_name, "") == "") ? 1 : 0
}

# NetworkPolicy (white-list ingress). Если false — не создаем политику.
variable "network_policy" {
  type = object({
    enabled           = bool
    allowed_ns_labels = optional(map(string), {})   # from namespaceSelector
    allowed_pod_labels = optional(map(string), {})  # from podSelector
    allowed_cidrs     = optional(list(string), [])  # ipBlock
  })
  default = {
    enabled = true
  }
}

# Дополнительные значения чарта: произвольная карта
variable "extra_values" {
  type        = map(any)
  description = "Произвольные values, которые будут поверх базовых."
  default     = {}
}

################################################
# Namespace
################################################

resource "kubernetes_namespace" "this" {
  metadata {
    name   = var.namespace
    labels = var.labels
  }
}

################################################
# Secret (basic auth) — опционально
################################################

resource "kubernetes_secret" "basic_auth" {
  count = var.basic_auth.enabled && try(var.basic_auth.existing_secret_name, "") == "" ? 1 : 0

  metadata {
    name      = "${var.name}-basic-auth"
    namespace = kubernetes_namespace.this.metadata[0].name
    labels    = var.labels
  }

  data = {
    username = base64encode(try(var.basic_auth.username, "admin"))
    password = base64encode(coalesce(try(var.basic_auth.password, null), try(random_password.basic[0].result, null)))
  }

  type = "Opaque"
}

locals {
  # Базовые values, ожидаемые большинством вендорских чартов (некоторые ключи
  # могут игнорироваться конкретным чартом — это нормально).
  base_values = {
    replicaCount = var.replicas

    imagePullSecrets = [for s in var.image_pull_secrets : { name = s }]

    podLabels       = var.labels
    podAnnotations  = var.annotations

    resources = {
      requests = {
        cpu    = var.resources.requests.cpu
        memory = var.resources.requests.memory
      }
      limits = {
        cpu    = var.resources.limits.cpu
        memory = var.resources.limits.memory
      }
    }

    persistence = {
      enabled      = var.persistence.enabled
      storageClass = try(var.persistence.storage_class, null)
      size         = try(var.persistence.size, null)
      accessModes  = try(var.persistence.access_modes, null)
    }

    service = {
      type = try(var.service.type, "ClusterIP")
      ports = concat([
        {
          name     = "http"
          port     = try(var.service.http_port, 8080)
          protocol = "TCP"
        }
      ],
      try(var.service.grpc_port, null) != null ? [
        {
          name     = "grpc"
          port     = var.service.grpc_port
          protocol = "TCP"
        }
      ] : [],
      [for p in try(var.service.extra_ports, []) : {
        name     = p.name
        port     = p.port
        protocol = try(p.protocol, "TCP")
      }])
    }

    podSecurityContext = {
      runAsNonRoot = try(var.pod_security_context.runAsNonRoot, true)
      fsGroup      = try(var.pod_security_context.fsGroup, null)
      seccompProfile = {
        type = try(var.pod_security_context.seccompProfileType, "RuntimeDefault")
      }
    }

    securityContext = {
      runAsUser              = try(var.container_security_context.runAsUser, 10001)
      runAsGroup             = try(var.container_security_context.runAsGroup, 10001)
      allowPrivilegeEscalation = try(var.container_security_context.allowPrivilegeEscalation, false)
      readOnlyRootFilesystem = try(var.container_security_context.readOnlyRootFilesystem, true)
      capabilities = {
        drop = try(var.container_security_context.capabilities_drop_all, true) ? ["ALL"] : []
      }
    }

    nodeSelector                   = var.node_selector
    tolerations                    = var.tolerations
    affinity                       = var.affinity
    topologySpreadConstraints      = var.topology_spread_constraints

    auth = var.basic_auth.enabled ? {
      existingSecret = try(var.basic_auth.existing_secret_name, kubernetes_secret.basic_auth[0].metadata[0].name)
      enabled        = true
    } : {
      enabled = false
    }
  }

  merged_values_yaml = yamlencode(merge(local.base_values, var.extra_values))
}

################################################
# Helm release
################################################

resource "helm_release" "vectorstore" {
  name       = var.name
  namespace  = kubernetes_namespace.this.metadata[0].name
  repository = var.chart_repo
  chart      = var.chart_name
  version    = var.chart_version

  create_namespace = false
  atomic           = true
  wait             = true
  lint             = true
  timeout          = 900

  values = [local.merged_values_yaml]

  # Метаданные релиза (Helm v3 не поддерживает labels напрямую — добавляем через annotations values/podLabels)
  depends_on = [kubernetes_namespace.this]
}

################################################
# NetworkPolicy (опционально)
################################################

resource "kubernetes_network_policy" "ingress_allowlist" {
  count = var.network_policy.enabled ? 1 : 0

  metadata {
    name      = "${var.name}-ingress-allowlist"
    namespace = kubernetes_namespace.this.metadata[0].name
    labels    = var.labels
  }

  spec {
    pod_selector {
      match_labels = var.labels
    }

    policy_types = ["Ingress"]

    # Разрешаем из namespaceSelector
    dynamic "ingress" {
      for_each = length(var.network_policy.allowed_ns_labels) > 0 ? [1] : []
      content {
        from {
          namespace_selector {
            match_labels = var.network_policy.allowed_ns_labels
          }
        }
      }
    }

    # Разрешаем из podSelector
    dynamic "ingress" {
      for_each = length(var.network_policy.allowed_pod_labels) > 0 ? [1] : []
      content {
        from {
          pod_selector {
            match_labels = var.network_policy.allowed_pod_labels
          }
        }
      }
    }

    # Разрешаем из IP-blocks
    dynamic "ingress" {
      for_each = length(var.network_policy.allowed_cidrs) > 0 ? [1] : []
      content {
        from {
          dynamic "ip_block" {
            for_each = var.network_policy.allowed_cidrs
            content {
              cidr = ip_block.value
            }
          }
        }
      }
    }

    # Порты: HTTP/GRPC/extra
    dynamic "ingress" {
      for_each = [1]
      content {
        ports {
          port     = try(var.service.http_port, 8080)
          protocol = "TCP"
        }
        dynamic "ports" {
          for_each = try(var.service.grpc_port, null) != null ? [var.service.grpc_port] : []
          content {
            port     = ports.value
            protocol = "TCP"
          }
        }
        dynamic "ports" {
          for_each = try(var.service.extra_ports, [])
          content {
            port     = ports.value.port
            protocol = try(ports.value.protocol, "TCP")
          }
        }
      }
    }
  }
}

################################################
# Validations
################################################

locals {
  required_chart_set = length(trimspace(var.chart_repo)) > 0 && length(trimspace(var.chart_name)) > 0 && length(trimspace(var.chart_version)) > 0
}

# Явная проверка входных данных
resource "null_resource" "validate" {
  triggers = {
    ok = local.required_chart_set ? "true" : ""
  }
  lifecycle {
    precondition {
      condition     = local.required_chart_set
      error_message = "chart_repo/chart_name/chart_version должны быть заданы."
    }
  }
}

################################################
# Outputs
################################################

output "namespace" {
  value       = kubernetes_namespace.this.metadata[0].name
  description = "Namespace, куда установлен векторный стор."
}

output "helm_release_name" {
  value       = helm_release.vectorstore.name
  description = "Имя релиза Helm."
}

output "basic_auth_secret" {
  value       = try(kubernetes_secret.basic_auth[0].metadata[0].name, "")
  description = "Имя секрета с базовой аутентификацией (если создан)."
}

output "applied_values_yaml" {
  value       = local.merged_values_yaml
  description = "Итоговые values, переданные в чарт."
  sensitive   = false
}
