# aethernova-chain-core/ops/terraform/modules/k8s-apps/bridge-relayer/variables.tf

############################################
# Базовые параметры приложения
############################################

variable "name" {
  type        = string
  description = "Имя приложения (используется в метаданных и именовании Kubernetes-ресурсов)."
  default     = "bridge-relayer"
}

variable "namespace" {
  type        = string
  description = "Namespace для развертывания приложения."
  default     = "bridge"
}

variable "labels" {
  type        = map(string)
  description = "Дополнительные метки, которые будут добавлены ко всем объектам."
  default     = {}
}

variable "annotations" {
  type        = map(string)
  description = "Дополнительные аннотации, которые будут добавлены ко всем объектам."
  default     = {}
}

############################################
# Контейнер: образ, команда, переменные окружения
############################################

variable "image" {
  type = object({
    repository  = string
    tag         = string
    pull_policy = optional(string, "IfNotPresent") # k8s pullPolicy
    pull_secrets = optional(list(string), [])
  })
  description = "Контейнерный образ bridge-relayer и настройки его получения."
  default = {
    repository  = "ghcr.io/aethernova/bridge-relayer"
    tag         = "1.0.0"
    pull_policy = "IfNotPresent"
    pull_secrets = []
  }
  validation {
    condition     = contains(["Always", "IfNotPresent", "Never"], var.image.pull_policy)
    error_message = "image.pull_policy должен быть одним из: Always, IfNotPresent, Never (Kubernetes ImagePullPolicy)."
  }
}

variable "command" {
  type        = list(string)
  description = "Переопределение команды контейнера (entrypoint)."
  default     = []
}

variable "args" {
  type        = list(string)
  description = "Аргументы для контейнера (CMD)."
  default     = []
}

variable "env" {
  type = map(object({
    value     = optional(string)
    valueFrom = optional(object({
      secretKeyRef = optional(object({
        name = string
        key  = string
      }))
      configMapKeyRef = optional(object({
        name = string
        key  = string
      }))
    }))
  }))
  description = "Переменные окружения контейнера (прямые значения или ссылки на Secret/ConfigMap)."
  default     = {}
}

variable "env_from" {
  type = object({
    config_maps = optional(list(string), [])
    secrets     = optional(list(string), [])
  })
  description = "Подключение окружения через envFrom (ConfigMapRef/SecretRef)."
  default = {
    config_maps = []
    secrets     = []
  }
}

############################################
# Реплики, стратегия развёртывания и ресурсы
############################################

variable "replicas" {
  type        = number
  description = "Количество реплик Deployment."
  default     = 2
  validation {
    condition     = var.replicas >= 1 && floor(var.replicas) == var.replicas
    error_message = "replicas должен быть целым числом ≥ 1."
  }
}

variable "strategy" {
  type = object({
    type          = optional(string, "RollingUpdate") # "RollingUpdate" | "Recreate"
    max_surge     = optional(string, "25%")           # k8s поддерживает проценты или абсолютные значения
    max_unavailable = optional(string, "25%")
  })
  description = "Стратегия обновления Deployment."
  default = {
    type            = "RollingUpdate"
    max_surge       = "25%"
    max_unavailable = "25%"
  }
  validation {
    condition     = contains(["RollingUpdate", "Recreate"], var.strategy.type)
    error_message = "strategy.type должен быть RollingUpdate или Recreate."
  }
}

variable "resources" {
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
  description = "Ресурсы контейнера (requests/limits) для QoS и планирования."
  default = {
    requests = { cpu = "100m", memory = "128Mi" }
    limits   = { cpu = "500m", memory = "512Mi" }
  }
}

############################################
# Probes (liveness/readiness/startup)
############################################

variable "probes" {
  type = object({
    readiness = optional(object({
      enabled             = optional(bool, true)
      http_path           = optional(string, "/ready")
      port                = optional(number, 8080)
      initial_delay_seconds = optional(number, 5)
      period_seconds        = optional(number, 10)
      timeout_seconds       = optional(number, 1)
      failure_threshold     = optional(number, 3)
      success_threshold     = optional(number, 1)
    }), {})
    liveness = optional(object({
      enabled             = optional(bool, true)
      http_path           = optional(string, "/live")
      port                = optional(number, 8080)
      initial_delay_seconds = optional(number, 10)
      period_seconds        = optional(number, 10)
      timeout_seconds       = optional(number, 1)
      failure_threshold     = optional(number, 3)
      success_threshold     = optional(number, 1)
    }), {})
    startup = optional(object({
      enabled             = optional(bool, false)
      http_path           = optional(string, "/startup")
      port                = optional(number, 8080)
      initial_delay_seconds = optional(number, 0)
      period_seconds        = optional(number, 10)
      timeout_seconds       = optional(number, 1)
      failure_threshold     = optional(number, 30)
      success_threshold     = optional(number, 1)
    }), {})
  })
  description = "Настройка readiness/liveness/startup проб контейнера."
  default = {}
}

############################################
# SecurityContext (Pod/Container)
############################################

variable "pod_security_context" {
  type = object({
    fs_group        = optional(number)
    run_as_non_root = optional(bool, true)
    run_as_user     = optional(number)
    seccomp_profile = optional(object({
      type = string # "RuntimeDefault" | "Localhost" | "Unconfined"
      localhost_profile = optional(string)
    }))
  })
  description = "Pod-level SecurityContext (например, fsGroup, seccompProfile, runAsNonRoot/runAsUser)."
  default = {
    run_as_non_root = true
    seccomp_profile = { type = "RuntimeDefault" }
  }
}

variable "container_security_context" {
  type = object({
    read_only_root_filesystem = optional(bool, true)
    allow_privilege_escalation = optional(bool, false)
    capabilities = optional(object({
      drop = optional(list(string), ["ALL"])
      add  = optional(list(string), [])
    }), {})
  })
  description = "Container-level SecurityContext (capabilities, readOnlyRootFilesystem, allowPrivilegeEscalation)."
  default = {}
}

############################################
# Service / Ingress
############################################

variable "service" {
  type = object({
    enabled     = optional(bool, true)
    type        = optional(string, "ClusterIP") # ClusterIP|NodePort|LoadBalancer
    port        = optional(number, 80)
    target_port = optional(number, 8080)
    annotations = optional(map(string), {})
  })
  description = "Параметры Kubernetes Service."
  default     = {}
  validation {
    condition     = contains(["ClusterIP", "NodePort", "LoadBalancer"], try(var.service.type, "ClusterIP"))
    error_message = "service.type должен быть ClusterIP, NodePort или LoadBalancer."
  }
}

variable "ingress" {
  type = object({
    enabled      = optional(bool, false)
    class_name   = optional(string)
    annotations  = optional(map(string), {})
    hosts        = optional(list(object({
      host  = string
      paths = optional(list(object({
        path     = string
        path_type = optional(string, "Prefix")
      })), [{ path = "/", path_type = "Prefix" }])
    })), [])
    tls = optional(list(object({
      secret_name = string
      hosts       = list(string)
    })), [])
  })
  description = "Ingress-правила (без использования wildcard-хостов по умолчанию)."
  default     = {}
}

############################################
# HPA (autoscaling/v2)
############################################

variable "hpa" {
  type = object({
    enabled     = optional(bool, false)
    min_replicas = optional(number, 2)
    max_replicas = optional(number, 5)
    metrics = optional(list(object({
      type = string                         # "Resource" | "Pods" | "Object" | "External" (autoscaling/v2)
      resource = optional(object({
        name = string                       # "cpu" | "memory" и т.п.
        target = object({
          type               = string       # "Utilization" | "AverageValue" | "Value"
          average_utilization = optional(number)
          average_value       = optional(string)
          value               = optional(string)
        })
      }))
      # при необходимости можно расширить для Pods/Object/External
    })), [{
      type = "Resource"
      resource = {
        name = "cpu"
        target = { type = "Utilization", average_utilization = 70 }
      }
    }])
  })
  description = "HorizontalPodAutoscaler (autoscaling/v2)."
  default     = {}
  validation {
    condition     = try(var.hpa.max_replicas, 5) >= try(var.hpa.min_replicas, 2)
    error_message = "hpa.max_replicas должен быть ≥ hpa.min_replicas."
  }
}

############################################
# Scheduling: nodeSelector, tolerations, affinity, topology spread
############################################

variable "node_selector" {
  type        = map(string)
  description = "nodeSelector для Pod."
  default     = {}
}

variable "tolerations" {
  type = list(object({
    key      = optional(string)
    operator = optional(string, "Exists") # "Exists" | "Equal"
    value    = optional(string)
    effect   = optional(string)           # "NoSchedule" | "PreferNoSchedule" | "NoExecute"
  }))
  description = "Tolerations для Pod."
  default     = []
}

variable "affinity" {
  type        = any
  description = "Политики affinity/anti-affinity (сырое представление spec.affinity)."
  default     = null
}

variable "topology_spread_constraints" {
  type = list(object({
    max_skew           = number
    topology_key       = string
    when_unsatisfiable = string           # "DoNotSchedule" | "ScheduleAnyway"
    label_selector     = optional(object({
      match_labels = optional(map(string), {})
    }), {})
  }))
  description = "Правила распределения Pod по топологии (topologySpreadConstraints)."
  default     = []
}

############################################
# PDB, PriorityClass, NetworkPolicy
############################################

variable "pdb" {
  type = object({
    enabled         = optional(bool, true)
    min_available   = optional(string)
    max_unavailable = optional(string)
  })
  description = "PodDisruptionBudget для повышения устойчивости при эвакуациях."
  default = {
    enabled       = true
    min_available = "50%"
  }
}

variable "priority_class_name" {
  type        = string
  description = "PriorityClass для Pod (если используется)."
  default     = null
}

variable "network_policy" {
  type = object({
    enabled          = optional(bool, false)
    ingress_allow_ns = optional(list(string), [])   # список namespace, откуда разрешён трафик
    egress_allow_cidrs = optional(list(string), []) # список CIDR, куда разрешён исходящий трафик
  })
  description = "Базовая NetworkPolicy (whitelist-подход по ingress/egress)."
  default     = {}
}

############################################
# Мониторинг: ServiceMonitor (Prometheus Operator)
############################################

variable "servicemonitor" {
  type = object({
    enabled     = optional(bool, false)
    interval    = optional(string, "30s")
    scrape_timeout = optional(string, "10s")
    labels      = optional(map(string), {})
    relabelings = optional(list(map(string)), [])
    metric_relabelings = optional(list(map(string)), [])
    target_port = optional(number, 8080)
    scheme      = optional(string, "http")
    path        = optional(string, "/metrics")
  })
  description = "Создание ServiceMonitor для Prometheus Operator."
  default     = {}
  validation {
    condition     = contains(["http", "https"], try(var.servicemonitor.scheme, "http"))
    error_message = "servicemonitor.scheme должен быть http или https."
  }
}

############################################
# Volume(s) и монтирования
############################################

variable "volumes" {
  type = list(object({
    name = string
    config_map = optional(object({
      name = string
      items = optional(list(object({
        key  = string
        path = string
      })), [])
    }))
    secret = optional(object({
      secret_name = string
      items = optional(list(object({
        key  = string
        path = string
      })), [])
    }))
    persistent_volume_claim = optional(object({
      claim_name = string
      read_only  = optional(bool, false)
    }))
    empty_dir = optional(object({
      medium    = optional(string) # "" | "Memory"
      size_limit = optional(string)
    }))
  }))
  description = "Дополнительные Volumes (ConfigMap/Secret/PVC/EmptyDir)."
  default     = []
}

variable "volume_mounts" {
  type = list(object({
    name       = string
    mount_path = string
    read_only  = optional(bool, false)
    sub_path   = optional(string)
  }))
  description = "Монтирования Volumes в контейнер."
  default     = []
}

############################################
# ServiceAccount / RBAC
############################################

variable "service_account" {
  type = object({
    create = optional(bool, true)
    name   = optional(string)
    annotations = optional(map(string), {})
  })
  description = "ServiceAccount для Pod; при create=false используется существующий SA."
  default     = {}
}

variable "rbac" {
  type = object({
    create = optional(bool, true)
    # можно расширить ролями/правами при необходимости
  })
  description = "Создание базовых RBAC (Role/RoleBinding или ClusterRole/ClusterRoleBinding)."
  default     = { create = true }
}

############################################
# Прочее
############################################

variable "termination_grace_period_seconds" {
  type        = number
  description = "Время на корректное завершение контейнера (Pod.spec.terminationGracePeriodSeconds)."
  default     = 30
}

variable "pod_annotations" {
  type        = map(string)
  description = "Аннотации уровня Pod (например, для sidecar-инжекторов/политик)."
  default     = {}
}

variable "pod_labels" {
  type        = map(string)
  description = "Дополнительные метки уровня Pod."
  default     = {}
}
