##############################################
# k8s-apps/explorer — variables.tf (industrial)
# Terraform >= 1.3 (optional() в object-типах)
##############################################

variable "enabled" {
  description = "Включить развёртывание приложения explorer."
  type        = bool
  default     = true
}

variable "name" {
  description = "Имя релиза/приложения (DNS-1123 label)."
  type        = string
  default     = "explorer"
  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.name)) && length(var.name) <= 63
    error_message = "name должен соответствовать RFC1123 DNS label и иметь длину <= 63."
  }
}

variable "namespace" {
  description = "Namespace для приложения (DNS-1123 label)."
  type        = string
  default     = "explorer"
  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace)) && length(var.namespace) <= 63
    error_message = "namespace должен соответствовать RFC1123 DNS label и иметь длину <= 63."
  }
}

variable "labels" {
  description = "Глобальные лейблы для всех создаваемых ресурсов."
  type        = map(string)
  default     = {}
}

variable "annotations" {
  description = "Глобальные аннотации для всех создаваемых ресурсов."
  type        = map(string)
  default     = {}
}

# -------------------------------------------
# Образ и деплой
# -------------------------------------------
variable "image" {
  description = "Настройки контейнерного образа."
  type = object({
    repository      = string
    tag             = optional(string, "latest")
    pull_policy     = optional(string, "IfNotPresent") # Always|IfNotPresent|Never
    pull_secrets    = optional(list(string), [])
  })
}

variable "replicas" {
  description = "Число реплик (если HPA.disabled)."
  type        = number
  default     = 2
  validation {
    condition     = var.replicas >= 1 && var.replicas <= 100
    error_message = "replicas должен быть в диапазоне 1..100."
  }
}

variable "resources" {
  description = "Ресурсы контейнера (requests/limits). Ключи обычно cpu/memory."
  type = object({
    requests = optional(map(string), {})
    limits   = optional(map(string), {})
  })
  default = {
    requests = { cpu = "100m", memory = "256Mi" }
    limits   = { cpu = "500m", memory = "512Mi" }
  }
}

# -------------------------------------------
# Security Context
# -------------------------------------------
variable "pod_security_context" {
  description = "Pod-level securityContext."
  type = object({
    fs_group             = optional(number)
    run_as_user          = optional(number)
    run_as_group         = optional(number)
    run_as_non_root      = optional(bool, true)
    seccomp_profile_type = optional(string) # e.g. "RuntimeDefault"
  })
  default = {
    run_as_non_root = true
  }
}

variable "container_security_context" {
  description = "Container-level securityContext."
  type = object({
    allow_privilege_escalation = optional(bool, false)
    read_only_root_filesystem  = optional(bool, true)
    privileged                 = optional(bool, false)
    capabilities = optional(object({
      drop  = optional(list(string), ["ALL"])
      add   = optional(list(string), [])
    }), {
      drop = ["ALL"]
      add  = []
    })
  })
}

# -------------------------------------------
# Probes
# -------------------------------------------
variable "probes" {
  description = "Настройки liveness/readiness/startup probes."
  type = object({
    port                     = number
    path                     = optional(string, "/healthz")
    scheme                   = optional(string, "HTTP")
    initial_delay_seconds    = optional(number, 10)
    period_seconds           = optional(number, 10)
    timeout_seconds          = optional(number, 2)
    failure_threshold        = optional(number, 3)
    success_threshold        = optional(number, 1)
    enable_startup_probe     = optional(bool, false)
    startup_initial_delay_s  = optional(number, 20)
    startup_period_seconds   = optional(number, 10)
    startup_failure_threshold= optional(number, 30)
  })
}

# -------------------------------------------
# Service
# -------------------------------------------
variable "service" {
  description = "Сервис для приложения."
  type = object({
    type        = optional(string, "ClusterIP") # ClusterIP|NodePort|LoadBalancer|ExternalName
    port        = optional(number, 80)
    target_port = optional(number, 0) # 0 => использовать containerPort
    node_port   = optional(number)    # только для NodePort
    annotations = optional(map(string), {})
    labels      = optional(map(string), {})
    session_affinity = optional(string, "None")
  })
  default = {}
  validation {
    condition = contains(["ClusterIP","NodePort","LoadBalancer","ExternalName"], lookup(var.service, "type", "ClusterIP"))
    error_message = "service.type должен быть одним из: ClusterIP|NodePort|LoadBalancer|ExternalName."
  }
}

# -------------------------------------------
# Ingress
# -------------------------------------------
variable "ingress" {
  description = "Ingress (networking.k8s.io/v1)."
  type = object({
    enabled     = bool
    class_name  = optional(string)
    annotations = optional(map(string), {})
    hosts = optional(list(object({
      host  = string
      paths = optional(list(object({
        path      = optional(string, "/")
        path_type = optional(string, "Prefix") # Prefix|Exact|ImplementationSpecific
      })), [{ path = "/", path_type = "Prefix" }])
    })), [])
    tls = optional(list(object({
      secret_name = string
      hosts       = list(string)
    })), [])
  })
  default = {
    enabled = false
    hosts   = []
    tls     = []
  }
  validation {
    condition = alltrue([
      for h in var.ingress.hosts : can(regex(
        # RFC1123 subdomain
        "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
        h.host))
    ])
    error_message = "ingress.hosts[*].host должен соответствовать RFC1123 DNS subdomain."
  }
}

# -------------------------------------------
# Persistence (PVC)
# -------------------------------------------
variable "persistence" {
  description = "Персистентность (PVC) для explorer."
  type = object({
    enabled         = bool
    existing_claim  = optional(string)
    storage_class   = optional(string)
    access_modes    = optional(list(string), ["ReadWriteOnce"])
    size            = optional(string, "10Gi")
    annotations     = optional(map(string), {})
    mount_path      = optional(string, "/data")
    sub_path        = optional(string)
  })
  default = {
    enabled = false
  }
}

# -------------------------------------------
# ServiceAccount
# -------------------------------------------
variable "service_account" {
  description = "ServiceAccount настройки."
  type = object({
    create                         = optional(bool, true)
    name                           = optional(string)
    annotations                    = optional(map(string), {})
    automount_service_account_token= optional(bool, true)
  })
  default = {}
  validation {
    condition     = var.service_account.name == null || (can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.service_account.name)) && length(var.service_account.name) <= 253)
    error_message = "service_account.name должен соответствовать RFC1123 DNS subdomain (длина <= 253)."
  }
}

# -------------------------------------------
# HPA (autoscaling/v2)
# -------------------------------------------
variable "hpa" {
  description = "Горизонтальное авто-масштабирование."
  type = object({
    enabled       = bool
    min_replicas  = optional(number, 2)
    max_replicas  = optional(number, 5)
    # Простая форма метрик: target CPU/Memory utilization %
    cpu_average_utilization    = optional(number) # %
    memory_average_utilization = optional(number) # %
    labels      = optional(map(string), {})
    annotations = optional(map(string), {})
  })
  default = {
    enabled      = false
    min_replicas = 2
    max_replicas = 5
  }
  validation {
    condition     = !var.hpa.enabled || (var.hpa.min_replicas <= var.hpa.max_replicas)
    error_message = "hpa.min_replicas должен быть <= hpa.max_replicas."
  }
}

# -------------------------------------------
# PDB (policy/v1)
# -------------------------------------------
variable "pdb" {
  description = "PodDisruptionBudget для поддержания доступности."
  type = object({
    enabled         = bool
    min_available   = optional(string)   # число или процент, например '1' или '50%'
    max_unavailable = optional(string)
    labels          = optional(map(string), {})
    annotations     = optional(map(string), {})
  })
  default = {
    enabled = false
  }
  validation {
    condition     = !var.pdb.enabled || !((try(var.pdb.min_available, null) != null) && (try(var.pdb.max_unavailable, null) != null))
    error_message = "Укажите только один из полей: pdb.min_available ИЛИ pdb.max_unavailable."
  }
}

# -------------------------------------------
# ServiceMonitor (Prometheus Operator)
# -------------------------------------------
variable "service_monitor" {
  description = "ServiceMonitor для сбора метрик Prometheus."
  type = object({
    enabled          = bool
    labels           = optional(map(string), {})
    annotations      = optional(map(string), {})
    namespace        = optional(string)
    interval         = optional(string, "30s")
    scrape_timeout   = optional(string, "10s")
    scheme           = optional(string, "http") # http|https
    relabelings      = optional(list(map(any)), [])
    metric_relabelings = optional(list(map(any)), [])
    # выбор целевого порта
    target = optional(object({
      port_name   = optional(string)
      port_number = optional(number)
      path        = optional(string, "/metrics")
      tls_config  = optional(map(any))
      bearer_token_secret = optional(object({
        name = string
        key  = string
      }))
    }), {})
  })
  default = {
    enabled = false
  }
  validation {
    condition = !var.service_monitor.enabled || (
      try(var.service_monitor.target.port_name, null) != null
      || try(var.service_monitor.target.port_number, null) != null
    )
    error_message = "service_monitor.target: задайте port_name или port_number."
  }
}

# -------------------------------------------
# NetworkPolicy (базовая)
# -------------------------------------------
variable "network_policy" {
  description = "NetworkPolicy для ограничения трафика."
  type = object({
    enabled = bool
    ingress = optional(object({
      allowed_namespace_selectors = optional(list(map(string)), [])
      allowed_pod_selectors       = optional(list(map(string)), [])
      allowed_cidrs               = optional(list(string), [])
      ports                       = optional(list(number), [80])
    }), {})
    egress = optional(object({
      allowed_cidrs = optional(list(string), ["0.0.0.0/0"])
      ports         = optional(list(number), [])
    }), {})
  })
  default = {
    enabled = false
  }
}

# -------------------------------------------
# Операционные настройки Pod
# -------------------------------------------
variable "pod" {
  description = "Операционные параметры Pod."
  type = object({
    container_port                 = optional(number, 8080)
    node_selector                  = optional(map(string), {})
    tolerations                    = optional(list(map(any)), [])
    affinity                       = optional(map(any), {})
    topology_spread_constraints    = optional(list(map(any)), [])
    priority_class_name            = optional(string)
    termination_grace_period_secs  = optional(number, 30)
    pod_labels                     = optional(map(string), {})
    pod_annotations                = optional(map(string), {})
    extra_volumes                  = optional(list(map(any)), [])
    extra_volume_mounts            = optional(list(map(any)), [])
    extra_init_containers          = optional(list(map(any)), [])
    extra_containers               = optional(list(map(any)), [])
    rollout_strategy               = optional(string, "RollingUpdate")
  })
  default = {}
}

# -------------------------------------------
# Конфигурация приложения
# -------------------------------------------
variable "env" {
  description = "Плоские переменные окружения (name=value)."
  type        = map(string)
  default     = {}
}

variable "extra_env" {
  description = "Сложные env с valueFrom (Secret/ConfigMap)."
  type = list(object({
    name  = string
    value = optional(string)
    value_from = optional(object({
      secret_key_ref = optional(object({
        name     = string
        key      = string
        optional = optional(bool, false)
      }))
      config_map_key_ref = optional(object({
        name     = string
        key      = string
        optional = optional(bool, false)
      }))
    }))
  }))
  default = []
}

variable "env_from" {
  description = "Подключение целиком ConfigMap/Secret."
  type = list(object({
    config_map_ref = optional(object({
      name     = string
      optional = optional(bool, false)
    }))
    secret_ref = optional(object({
      name     = string
      optional = optional(bool, false)
    }))
  }))
  default = []
}

variable "configmap" {
  description = "Данные для ConfigMap (если требуется)."
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Секреты (именованные пары key=value). Передавать осторожно."
  type        = map(string)
  default     = {}
  sensitive   = true
}
