#############################################
# modules/policies/gatekeeper/main.tf
# Промышленный модуль установки OPA Gatekeeper via Helm
#############################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12.1"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.24.0"
    }
  }
}

########################
# ВХОДНЫЕ ПАРАМЕТРЫ
########################

variable "release_name" {
  description = "Имя Helm-релиза Gatekeeper"
  type        = string
  default     = "gatekeeper"
}

variable "namespace" {
  description = "Неймспейс для Gatekeeper"
  type        = string
  default     = "gatekeeper-system"
}

variable "create_namespace" {
  description = "Создавать ли namespace (рекомендуется true; c 3.4.0 чарт сам namespace не создает)"
  type        = bool
  default     = true
}

variable "repository" {
  description = "Helm-репозиторий Gatekeeper"
  type        = string
  default     = "https://open-policy-agent.github.io/gatekeeper/charts"
}

variable "chart" {
  description = "Имя чарта Gatekeeper"
  type        = string
  default     = "gatekeeper"
}

variable "chart_version" {
  description = "Версия чарта (зафиксируйте в проде, напр. 3.20.x)"
  type        = string
  default     = null
}

variable "enable_external_data" {
  description = "Включить поддержку External Data провайдеров"
  type        = bool
  default     = false
}

variable "enable_mutation" {
  description = "Включить возможности мутации (иначе будет отключено)"
  type        = bool
  default     = false
}

variable "constraint_violations_limit" {
  description = "Лимит записей нарушений на Constraint для аудита"
  type        = number
  default     = 20
}

variable "exempt_namespaces" {
  description = "Неймспейсы, исключаемые контроллером (дополнительно к namespace релиза)"
  type        = list(string)
  default     = ["kube-system", "gatekeeper-system"]
}

variable "controller_manager" {
  description = "Параметры gatekeeper-controller-manager"
  type = object({
    replicas            = number
    resources           = map(any)      # {requests={cpu,mem}, limits={cpu,mem}}
    node_selector       = map(string)
    tolerations         = list(map(string))
    priority_class_name = string
    pod_annotations     = map(string)
    security_context    = map(any)
    metrics_port        = number
  })
  default = {
    replicas            = 2
    resources           = {
      requests = { cpu = "100m", memory = "256Mi" }
      limits   = { cpu = "1",    memory = "1Gi"   }
    }
    node_selector       = {}
    tolerations         = []
    priority_class_name = "system-cluster-critical"
    pod_annotations     = {}
    security_context    = { runAsNonRoot = true }
    metrics_port        = 8888
  }
}

variable "audit" {
  description = "Параметры gatekeeper-audit"
  type = object({
    replicas        = number
    resources       = map(any)
    node_selector   = map(string)
    tolerations     = list(map(string))
    pod_annotations = map(string)
    security_context= map(any)
    metrics_port    = number
    from_cache      = bool
  })
  default = {
    replicas        = 1
    resources       = {
      requests = { cpu = "100m", memory = "256Mi" }
      limits   = { cpu = "1",    memory = "1Gi"   }
    }
    node_selector   = {}
    tolerations     = []
    pod_annotations = {}
    security_context= { runAsNonRoot = true }
    metrics_port    = 8888
    from_cache      = false
  }
}

variable "values_overrides" {
  description = "Произвольные перезаписи values Helm-чарта (map будет merge с базовыми)"
  type        = any
  default     = {}
}

variable "wait" {
  description = "Ждать ли готовности релиза (Helm)"
  type        = bool
  default     = true
}

variable "timeout" {
  description = "Таймаут ожидания релиза (сек)"
  type        = number
  default     = 600
}

########################
# ЛОКАЛЫ
########################

locals {
  # Аннотации для скрейпа Prometheus на обоих компонентах (порт 8888 по умолчанию)
  cm_prometheus_annotations = merge(
    {
      "prometheus.io/scrape" = "true"
      "prometheus.io/port"   = tostring(var.controller_manager.metrics_port)
    },
    var.controller_manager.pod_annotations
  )

  audit_prometheus_annotations = merge(
    {
      "prometheus.io/scrape" = "true"
      "prometheus.io/port"   = tostring(var.audit.metrics_port)
    },
    var.audit.pod_annotations
  )

  # Базовые values чарта (собираем в один объект и кодируем yamlencode)
  chart_values = merge({
    # Глобальные опции
    enableExternalData        = var.enable_external_data
    constraintViolationsLimit = var.constraint_violations_limit
    disableMutation           = var.enable_mutation ? false : true
    disableValidatingWebhook  = false

    # Контроллер-менеджер (validating webhook)
    controllerManager = {
      replicas          = var.controller_manager.replicas
      resources         = var.controller_manager.resources
      nodeSelector      = var.controller_manager.node_selector
      tolerations       = var.controller_manager.tolerations
      priorityClassName = var.controller_manager.priority_class_name
      metricsPort       = var.controller_manager.metrics_port
      exemptNamespaces  = var.exempt_namespaces
      podAnnotations    = local.cm_prometheus_annotations
      securityContext   = var.controller_manager.security_context
    }

    # Аудит
    audit = {
      replicas        = var.audit.replicas
      resources       = var.audit.resources
      nodeSelector    = var.audit.node_selector
      tolerations     = var.audit.tolerations
      metricsPort     = var.audit.metrics_port
      podAnnotations  = local.audit_prometheus_annotations
      securityContext = var.audit.security_context
      auditFromCache  = var.audit.from_cache
    }
  }, var.values_overrides)
}

########################
# РЕСУРСЫ
########################

# Namespace под Gatekeeper (чарт его не создает начиная с 3.4.0)
resource "kubernetes_namespace_v1" "this" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name = var.namespace

    # Лейбл самозащиты (чтобы политики не ломали собственный неймспейс)
    labels = {
      "admission.gatekeeper.sh/ignore" = "no-self-manage"
    }
  }
}

# Установка Gatekeeper через Helm
resource "helm_release" "gatekeeper" {
  name             = var.release_name
  repository       = var.repository
  chart            = var.chart
  version          = var.chart_version
  namespace        = var.namespace
  create_namespace = false

  atomic  = true
  wait    = var.wait
  timeout = var.timeout

  # Передаем values одним YAML-документом
  values = [
    yamlencode(local.chart_values)
  ]

  # Явно ждем неймспейс, если он создается этим модулем
  depends_on = [kubernetes_namespace_v1.this]
}
