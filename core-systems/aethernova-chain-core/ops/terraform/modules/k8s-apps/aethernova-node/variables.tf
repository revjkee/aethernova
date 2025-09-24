#############################################
# AETHERNOVA — Kubernetes App Module Inputs #
# Terraform >= 1.3, Helm provider >= 2.12  #
#############################################

########################
# Module meta & naming #
########################

variable "name" {
  description = "Логическое имя приложения/релиза (будет использовано как префикс для ресурсов, Helm release name)."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.name)) && length(var.name) <= 63
    error_message = "name должен соответствовать DNS-1123 label и быть ≤63 символов (см. K8s Namespaces/DNS-1123)."
  }
  # RFC1123 для имен объектов/namespace: Kubernetes требует DNS label. 
  # Источники: Namespaces/Names. 
  # https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
  # https://kubernetes.io/docs/concepts/overview/working-with-objects/names/
}

variable "namespace" {
  description = "Namespace для деплоя приложения."
  type        = string
  default     = "aethernova"
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace)) && length(var.namespace) <= 63
    error_message = "namespace должен соответствовать DNS-1123 label и быть ≤63 символов (см. K8s Namespaces/DNS-1123)."
  }
}

variable "labels" {
  description = "Глобальные labels, применяемые к объектам, где возможно."
  type        = map(string)
  default     = {}
  nullable    = false
  # Labels — концепция K8s. https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
}

variable "annotations" {
  description = "Глобальные аннотации, применяемые к объектам, где возможно."
  type        = map(string)
  default     = {}
  nullable    = false
}

################
# Helm release #
################
# Аргументы соответствует hashicorp/helm:helm_release.
# См. Terraform Registry (chart, repository, version, namespace, create_namespace, timeout, atomic, wait, max_history, values/set/set_sensitive и др.)
# https://registry.terraform.io/providers/hashicorp/helm/latest/docs/resources/release
# Провайдер: https://registry.terraform.io/providers/hashicorp/helm/latest/docs
variable "helm_chart" {
  description = "Имя Helm chart (или путь)."
  type        = string
  nullable    = false
}

variable "helm_repository" {
  description = "Helm chart repository URL (если chart не локальный)."
  type        = string
  default     = null
}

variable "helm_version" {
  description = "Версия chart (SemVer)."
  type        = string
  default     = null
}

variable "helm_create_namespace" {
  description = "Создавать namespace при релизе."
  type        = bool
  default     = true
}

variable "helm_atomic" {
  description = "Atomic install/upgrade (в случае ошибок откатывает релиз)."
  type        = bool
  default     = true
}

variable "helm_wait" {
  description = "Дождаться готовности ресурсов."
  type        = bool
  default     = true
}

variable "helm_timeout_seconds" {
  description = "Таймаут ожидания установки/обновления."
  type        = number
  default     = 600
  validation {
    condition     = var.helm_timeout_seconds >= 60 && var.helm_timeout_seconds <= 3600
    error_message = "helm_timeout_seconds должен быть в диапазоне 60..3600 сек."
  }
}

variable "helm_max_history" {
  description = "Max количество ревизий Helm."
  type        = number
  default     = 10
}

variable "helm_values" {
  description = "Произвольные values для chart (map(any))."
  type        = map(any)
  default     = {}
  nullable    = false
}

variable "helm_set_list" {
  description = "Список set-блоков Helm (эквивалент resource.set)."
  type = list(object({
    name  = string
    value = string
    type  = optional(string) # string, int, bool; соответствует блокам set/set_sensitive/set_list в helm_release
  }))
  default  = []
  nullable = false
}

variable "helm_set_sensitive_list" {
  description = "Список set_sensitive-блоков Helm (секретные значения)."
  type = list(object({
    name  = string
    value = string
  }))
  default   = []
  sensitive = true
}

###########################
# Workload (Deployment/…) #
###########################

variable "replicas" {
  description = "Начальное число реплик для workload (Deployment/StatefulSet)."
  type        = number
  default     = 2
  validation {
    condition     = var.replicas >= 0 && var.replicas <= 1000
    error_message = "replicas должен быть в диапазоне 0..1000."
  }
}

variable "image" {
  description = "Параметры контейнерного образа основного контейнера."
  type = object({
    repository  = string
    tag         = string
    pullPolicy  = string # Kubernetes: Always | IfNotPresent | Never
    pullSecrets = optional(list(string), [])
  })
  nullable = false

  validation {
    condition     = contains(["Always", "IfNotPresent", "Never"], var.image.pullPolicy)
    error_message = "image.pullPolicy должен быть одним из: Always, IfNotPresent, Never (см. Kubernetes Images)."
  }
  # Политики выгрузки образов: Always/IfNotPresent/Never. 
  # https://kubernetes.io/docs/concepts/containers/images/
}

variable "command" {
  description = "Переписать команду контейнера."
  type        = list(string)
  default     = []
}

variable "args" {
  description = "Аргументы контейнера."
  type        = list(string)
  default     = []
}

variable "env" {
  description = "Переменные окружения (простые пары key=value)."
  type        = map(string)
  default     = {}
}

variable "env_from_configmaps" {
  description = "Список ConfigMap имен для envFrom."
  type        = list(string)
  default     = []
}

variable "env_from_secrets" {
  description = "Список Secret имен для envFrom."
  type        = list(string)
  default     = []
}

variable "resources" {
  description = "Запросы/лимиты ресурсов контейнера (строки должны быть валидными Kubernetes quantities)."
  type = object({
    requests = optional(object({
      cpu    = optional(string)
      memory = optional(string)
    }), {})
    limits = optional(object({
      cpu    = optional(string)
      memory = optional(string)
    }), {})
  })
  default = {}
  # О форматах quantity см. Kubernetes format/CEL и ресурсы:
  # https://kubernetes.io/docs/reference/using-api/cel/
}

###################
# Probes (health) #
###################
# Конфигурация проб: поля и семантика — Kubernetes Probes.
# https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/
# https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/
variable "liveness_probe" {
  description = "LivenessProbe контейнера."
  type = object({
    http_get = optional(object({
      path = string
      port = number
    }))
    tcp_socket = optional(object({
      port = number
    }))
    exec = optional(object({
      command = list(string)
    }))
    initial_delay_seconds = optional(number, 10)
    period_seconds        = optional(number, 10)
    timeout_seconds       = optional(number, 1)
    success_threshold     = optional(number, 1)
    failure_threshold     = optional(number, 3)
  })
  default = null
}

variable "readiness_probe" {
  description = "ReadinessProbe контейнера."
  type = object({
    http_get = optional(object({
      path = string
      port = number
    }))
    tcp_socket = optional(object({
      port = number
    }))
    exec = optional(object({
      command = list(string)
    }))
    initial_delay_seconds = optional(number, 5)
    period_seconds        = optional(number, 10)
    timeout_seconds       = optional(number, 1)
    success_threshold     = optional(number, 1)
    failure_threshold     = optional(number, 3)
  })
  default = null
}

variable "startup_probe" {
  description = "StartupProbe контейнера."
  type = object({
    http_get = optional(object({
      path = string
      port = number
    }))
    tcp_socket = optional(object({
      port = number
    }))
    exec = optional(object({
      command = list(string)
    }))
    initial_delay_seconds = optional(number, 0)
    period_seconds        = optional(number, 10)
    timeout_seconds       = optional(number, 1)
    success_threshold     = optional(number, 1)
    failure_threshold     = optional(number, 30)
  })
  default = null
}

#####################
# Security settings #
#####################
# Практики securityContext (runAsNonRoot, allowPrivilegeEscalation и др.) — официальные K8s docs.
# https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
# Pod Security Standards (Restricted): https://kubernetes.io/docs/concepts/security/pod-security-standards/
variable "pod_security_context" {
  description = "Pod-level securityContext."
  type = object({
    run_as_user                = optional(number)
    run_as_group               = optional(number)
    fs_group                   = optional(number)
    run_as_non_root            = optional(bool, true)
    fs_group_change_policy     = optional(string)
    seccomp_profile_type       = optional(string) # e.g., "RuntimeDefault", "Localhost"
    supplemental_groups        = optional(list(number), [])
    se_linux_options           = optional(map(string))
    sysctls                    = optional(map(string), {})
  })
  default = {}
}

variable "container_security_context" {
  description = "Container-level securityContext."
  type = object({
    read_only_root_filesystem = optional(bool, true)
    allow_privilege_escalation = optional(bool, false)
    privileged                = optional(bool, false)
    capabilities_add          = optional(list(string), [])
    capabilities_drop         = optional(list(string), ["ALL"])
    run_as_user               = optional(number)
    run_as_group              = optional(number)
    run_as_non_root           = optional(bool, true)
  })
  default = {}
}

#################
# Service (L4)  #
#################
# Типы сервиса и порты — Kubernetes Service.
# https://kubernetes.io/docs/concepts/services-networking/service/
variable "service" {
  description = "Параметры Service."
  type = object({
    enabled     = optional(bool, true)
    type        = optional(string, "ClusterIP") # ClusterIP|NodePort|LoadBalancer
    port        = optional(number, 80)
    target_port = optional(number, 8080)
    node_port   = optional(number)              # если type=NodePort
    protocol    = optional(string, "TCP")
    annotations = optional(map(string), {})
    labels      = optional(map(string), {})
  })
  default  = {}
  nullable = false

  validation {
    condition     = contains(["ClusterIP", "NodePort", "LoadBalancer"], coalesce(var.service.type, "ClusterIP"))
    error_message = "service.type должен быть ClusterIP|NodePort|LoadBalancer."
  }
}

#############
# Ingress   #
#############
# Ingress: pathType = Exact|Prefix|ImplementationSpecific; host — DNS-1123.
# https://kubernetes.io/docs/concepts/services-networking/ingress/
# Подробности pathType: https://docs.redhat.com/.../ingress-networking-k8s-io-v1
variable "ingress" {
  description = "Настройки Ingress."
  type = object({
    enabled          = optional(bool, false)
    class_name       = optional(string)
    annotations      = optional(map(string), {})
    hosts = optional(list(object({
      host  = string
      paths = list(object({
        path      = string
        path_type = string # Exact | Prefix | ImplementationSpecific
        service_port = optional(number)
      }))
    })), [])
    tls = optional(list(object({
      secret_name = string
      hosts       = list(string)
    })), [])
  })
  default = {}

  validation {
    condition = alltrue([
      for h in coalesce(var.ingress.hosts, []) :
      can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$", h.host))
      && length(h.host) <= 253
      && alltrue([
        for p in h.paths : contains(["Exact", "Prefix", "ImplementationSpecific"], p.path_type)
      ])
    ])
    error_message = "Ingress: host должен быть валидным DNS-1123 subdomain (≤253), path_type — Exact|Prefix|ImplementationSpecific."
  }
}

#############################
# Node placement & spreading#
#############################
variable "node_selector" {
  description = "NodeSelector (key=value)."
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Список tolerations."
  type = list(object({
    key               = optional(string)
    operator          = optional(string, "Exists")
    value             = optional(string)
    effect            = optional(string)
    toleration_seconds = optional(number)
  }))
  default = []
}

variable "affinity" {
  description = "Произвольная affinity-структура (map(any)), если нужна полная гибкость."
  type        = map(any)
  default     = {}
}

# TopologySpreadConstraints — управление распределением Pod по доменам отказа.
# https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/
variable "topology_spread_constraints" {
  description = "Правила TopologySpread для равномерного распределения Pod."
  type = list(object({
    max_skew           = number
    topology_key       = string
    when_unsatisfiable = string # DoNotSchedule|ScheduleAnyway
    label_selector     = optional(map(string), {})
  }))
  default = []
}

#########################
# Service Account / PDB #
#########################

variable "service_account" {
  description = "Создание/использование ServiceAccount."
  type = object({
    create      = optional(bool, true)
    name        = optional(string)
    annotations = optional(map(string), {})
  })
  default = {}
}

# PodDisruptionBudget: только один из min_available или max_unavailable (официальная рекомендация/ограничение).
# https://kubernetes.io/docs/tasks/run-application/configure-pdb/
variable "pdb" {
  description = "Настройки PodDisruptionBudget для workload."
  type = object({
    enabled                  = optional(bool, true)
    min_available            = optional(string) # число или %; НЕ использовать совместно с max_unavailable
    max_unavailable          = optional(string) # число или %
    unhealthy_pod_eviction_policy = optional(string, "AlwaysAllow") # см. Disruptions/OKD docs
    labels                   = optional(map(string), {})
    annotations              = optional(map(string), {})
  })
  default = {}

  validation {
    condition = !(
      try(var.pdb.min_available != null && var.pdb.max_unavailable != null, false)
    )
    error_message = "pdb: допускается только одно из min_available или max_unavailable."
  }
}

###########################
# In-cluster persistence  #
###########################
variable "persistence" {
  description = "PVC-настройки (если применимо для чарта/шаблона)."
  type = object({
    enabled       = optional(bool, false)
    storage_class = optional(string)
    access_modes  = optional(list(string), ["ReadWriteOnce"])
    size          = optional(string, "10Gi")
    annotations   = optional(map(string), {})
  })
  default = {}
}

###############################
# Autoscaling (HPA v2 schema) #
###############################
# HPA: цели Utilization/AverageValue/Value, метрики CPU/Memory/иные; см. autoscaling/v2.
# https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/
# https://docs.redhat.com/.../horizontalpodautoscaler-autoscaling-v2
variable "hpa" {
  description = "Параметры Horizontal Pod Autoscaler."
  type = object({
    enabled     = optional(bool, false)
    min_replicas = optional(number, 2)
    max_replicas = optional(number, 10)
    metrics = optional(list(object({
      type = string # Resource|Pods|Object|External
      resource = optional(object({
        name   = string # cpu|memory
        target = object({
          type               = string # Utilization|AverageValue|Value
          average_utilization = optional(number)
          average_value       = optional(string)
          value               = optional(string)
        })
      }))
      # при необходимости можно добавить схемы для Pods/Object/External
    })), [{
      type = "Resource"
      resource = {
        name   = "cpu"
        target = { type = "Utilization", average_utilization = 70 }
      }
    }])
    behavior = optional(object({
      scale_up = optional(object({
        stabilization_window_seconds = optional(number)
        policies = optional(list(object({
          type          = string # Pods|Percent
          value         = number
          period_seconds = number
        })), [])
        select_policy = optional(string) # Max|Min|Disabled
      }), {})
      scale_down = optional(object({
        stabilization_window_seconds = optional(number)
        policies = optional(list(object({
          type          = string
          value         = number
          period_seconds = number
        })), [])
        select_policy = optional(string)
      }), {})
    }), {})
  })
  default = {}
  # HPA основы/формулы: docs (автоскейл по средней утилизации, averageUtilization).
  # https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale-walkthrough/
  # https://docs.redhat.com/en/documentation/openshift_container_platform/4.14/html/autoscale_apis/horizontalpodautoscaler-autoscaling-v2
}

#################
# Ingress TLS   #
#################
variable "tls_secrets" {
  description = "Секреты TLS (если нужно создавать отдельно)."
  type = list(object({
    name = string
    crt  = string
    key  = string
  }))
  default   = []
  sensitive = true
}

##################
# Misc/advanced  #
##################

variable "revision_history_limit" {
  description = "Число хранимых ReplicaSets в истории (Deployment)."
  type        = number
  default     = 10
}

variable "update_strategy" {
  description = "Стратегия обновления (Deployment/StatefulSet) как map(any) для гибкости."
  type        = map(any)
  default     = {}
}

variable "priority_class_name" {
  description = "PriorityClassName для Pod."
  type        = string
  default     = null
}

variable "extra_pod_labels" {
  description = "Доп. метки только на Pod."
  type        = map(string)
  default     = {}
}

variable "extra_pod_annotations" {
  description = "Доп. аннотации только на Pod."
  type        = map(string)
  default     = {}
}

#############################
# Input validation examples #
#############################
# Примеры ниже демонстрируют практики nullable/validation (Terraform).
# https://developer.hashicorp.com/terraform/language/values/variables
# https://developer.hashicorp.com/terraform/language/expressions/type-constraints
# https://developer.hashicorp.com/terraform/tutorials/configuration-language/sensitive-variables
