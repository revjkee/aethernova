#############################################
# AETHERNOVA — Terraform module VARS (K8s) #
# Terraform >= 1.3                          #
#############################################

########################
# Module meta & naming #
########################

variable "module_enabled" {
  description = "Глобальный флаг включения модуля (для условного создания ресурсов)."
  type        = bool
  default     = true
}

variable "name" {
  description = "Базовое имя приложения/ресурса (используется в именах и метках)."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.name)) && length(var.name) <= 63
    error_message = "name должен соответствовать RFC1123 DNS-Label (строчные a–z, 0–9, '-', длина ≤ 63)."
  }
  # K8s DNS-1123 label requirement
}

variable "namespace" {
  description = "Namespace для деплоя (RFC1123 DNS-Label)."
  type        = string
  default     = "aethernova"
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace)) && length(var.namespace) <= 63
    error_message = "namespace должен соответствовать RFC1123 DNS-Label (строчные a–z, 0–9, '-', длина ≤ 63)."
  }
}

variable "environment" {
  description = "Окружение (dev|test|stage|prod) для меток/селекторов/логики."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "test", "stage", "prod"], var.environment)
    error_message = "environment должен быть одним из: dev, test, stage, prod."
  }
}

variable "labels" {
  description = "Глобальные labels, применяемые к объектам."
  type        = map(string)
  default     = {}
}

variable "annotations" {
  description = "Глобальные аннотации."
  type        = map(string)
  default     = {}
}

variable "common_tags" {
  description = "Общие теги для облаков (AWS/GCP/Azure) или артефактов."
  type        = map(string)
  default     = {}
}

###########################
# Container & image setup #
###########################

variable "image" {
  description = "Образ основного контейнера."
  type = object({
    repository  = string
    tag         = string
    pull_policy = string # Kubernetes: Always | IfNotPresent | Never
    pull_secrets = optional(list(string), [])
  })
  nullable = false

  validation {
    condition     = contains(["Always", "IfNotPresent", "Never"], var.image.pull_policy)
    error_message = "image.pull_policy должен быть одним из: Always, IfNotPresent, Never."
  }
  # K8s imagePullPolicy semantics
}

variable "replicas" {
  description = "Желаемое число реплик (Deployment/StatefulSet)."
  type        = number
  default     = 2

  validation {
    condition     = var.replicas >= 0 && var.replicas <= 1000
    error_message = "replicas должен быть в диапазоне 0..1000."
  }
}

variable "resources" {
  description = "Запросы/лимиты ресурсов контейнера (валидные K8s quantities)."
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
}

###################
# Probes (health) #
###################
# См. официальную схему проб (liveness/readiness/startup).
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

variable "pod_security_context" {
  description = "Pod-level securityContext."
  type = object({
    run_as_user            = optional(number)
    run_as_group           = optional(number)
    fs_group               = optional(number)
    run_as_non_root        = optional(bool, true)
    seccomp_profile_type   = optional(string) # RuntimeDefault|Localhost
    supplemental_groups    = optional(list(number), [])
    se_linux_options       = optional(map(string))
    sysctls                = optional(map(string), {})
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

variable "service" {
  description = "Kubernetes Service."
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

variable "ingress" {
  description = "Ingress настройки."
  type = object({
    enabled     = optional(bool, false)
    class_name  = optional(string)
    annotations = optional(map(string), {})
    hosts = optional(list(object({
      host  = string
      paths = list(object({
        path        = string
        path_type   = string # Exact|Prefix|ImplementationSpecific
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
      && alltrue([ for p in h.paths : contains(["Exact","Prefix","ImplementationSpecific"], p.path_type) ])
    ])
    error_message = "Ingress: host — валидный DNS-1123 subdomain (≤253), path_type — Exact|Prefix|ImplementationSpecific."
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
    key                = optional(string)
    operator           = optional(string, "Exists")
    value              = optional(string)
    effect             = optional(string)
    toleration_seconds = optional(number)
  }))
  default = []
}

variable "affinity" {
  description = "Произвольная affinity-структура (map(any))."
  type        = map(any)
  default     = {}
}

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

variable "pdb" {
  description = "PodDisruptionBudget настройки."
  type = object({
    enabled                       = optional(bool, true)
    min_available                 = optional(string) # число или %, взаимоисключимо с max_unavailable
    max_unavailable               = optional(string) # число или %
    unhealthy_pod_eviction_policy = optional(string) # AlwaysAllow|IfHealthyBudget
    labels                        = optional(map(string), {})
    annotations                   = optional(map(string), {})
  })
  default = {}

  validation {
    condition = !(try(var.pdb.min_available != null && var.pdb.max_unavailable != null, false))
    error_message = "pdb: допускается только одно из min_available или max_unavailable."
  }
}

###############################
# Autoscaling (HPA v2 schema) #
###############################

variable "hpa" {
  description = "Параметры Horizontal Pod Autoscaler (autoscaling/v2)."
  type = object({
    enabled      = optional(bool, false)
    min_replicas = optional(number, 2)
    max_replicas = optional(number, 10)
    metrics = optional(list(object({
      type = string # Resource|Pods|Object|External
      resource = optional(object({
        name   = string # cpu|memory
        target = object({
          type                = string # Utilization|AverageValue|Value
          average_utilization = optional(number)
          average_value       = optional(string)
          value               = optional(string)
        })
      }))
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
          type           = string # Pods|Percent
          value          = number
          period_seconds = number
        })), [])
        select_policy = optional(string) # Max|Min|Disabled
      }), {})
      scale_down = optional(object({
        stabilization_window_seconds = optional(number)
        policies = optional(list(object({
          type           = string
          value          = number
          period_seconds = number
        })), [])
        select_policy = optional(string)
      }), {})
    }), {})
  })
  default = {}
}

#################
# TLS / Secrets #
#################

variable "tls_secrets" {
  description = "TLS-секреты (если требуется создание отдельно)."
  type = list(object({
    name = string
    crt  = string
    key  = string
  }))
  default   = []
  sensitive = true
}

variable "extra_secrets" {
  description = "Произвольные секреты (ключ-значение) для шаблонов/чартов."
  type        = map(string)
  default     = {}
  sensitive   = true
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
  description = "Стратегия обновления (как map(any) для гибкости)."
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
