#############################################
# Module: k8s-apps/rpc-gateway
# File  : variables.tf
# Note  : Industrial-grade inputs with validations
#############################################

variable "name" {
  description = "Application name (used in resource names/labels)."
  type        = string
  default     = "rpc-gateway"
  validation {
    condition     = length(var.name) > 0 && length(var.name) <= 63
    error_message = "name must be 1..63 characters."
  }
}

variable "namespace" {
  description = "Kubernetes namespace for deploying rpc-gateway."
  type        = string
  default     = "default"
  validation {
    condition     = length(var.namespace) > 0 && length(var.namespace) <= 63
    error_message = "namespace must be 1..63 characters."
  }
}

variable "labels" {
  description = "Common labels for all resources."
  type        = map(string)
  default = {
    "app.kubernetes.io/part-of"  = "aethernova-chain-core"
    "app.kubernetes.io/name"     = "rpc-gateway"
    "app.kubernetes.io/component"= "gateway"
  }
}

variable "annotations" {
  description = "Common annotations for all resources."
  type        = map(string)
  default     = {}
}

variable "replicas" {
  description = "Number of pod replicas."
  type        = number
  default     = 2
  validation {
    condition     = var.replicas >= 1 && var.replicas <= 100
    error_message = "replicas must be between 1 and 100."
  }
}

variable "revision_history_limit" {
  description = "How many old ReplicaSets/Deployments to retain."
  type        = number
  default     = 5
  validation {
    condition     = var.revision_history_limit >= 0 && var.revision_history_limit <= 50
    error_message = "revision_history_limit must be 0..50."
  }
}

variable "image_repository" {
  description = "Container image repository for rpc-gateway."
  type        = string
  default     = "ghcr.io/aethernova/rpc-gateway"
}

variable "image_tag" {
  description = "Container image tag."
  type        = string
  default     = "v1.0.0"
}

variable "image_pull_policy" {
  description = "Image pull policy."
  type        = string
  default     = "IfNotPresent"
  validation {
    condition     = contains(["Always", "IfNotPresent", "Never"], var.image_pull_policy)
    error_message = "image_pull_policy must be one of: Always, IfNotPresent, Never."
  }
}

variable "image_pull_secrets" {
  description = "List of imagePullSecrets (Secret names)."
  type        = list(string)
  default     = []
}

variable "service_account" {
  description = "ServiceAccount settings."
  type = object({
    create                          = bool
    name                            = string
    annotations                     = map(string)
    automount_service_account_token = bool
  })
  default = {
    create                          = true
    name                            = ""
    annotations                     = {}
    automount_service_account_token = false
  }
}

variable "service_type" {
  description = "Kubernetes Service type."
  type        = string
  default     = "ClusterIP"
  validation {
    condition     = contains(["ClusterIP", "NodePort", "LoadBalancer", "ExternalName"], var.service_type)
    error_message = "service_type must be one of: ClusterIP, NodePort, LoadBalancer, ExternalName."
  }
}

variable "service_annotations" {
  description = "Annotations for Service (e.g. external-dns)."
  type        = map(string)
  default     = {}
}

variable "service_labels" {
  description = "Additional Service labels."
  type        = map(string)
  default     = {}
}

variable "service_ports" {
  description = "Service ports for rpc-gateway."
  type = object({
    http = object({
      enabled     = bool
      port        = number
      target_port = number
      protocol    = string
    })
    metrics = object({
      enabled     = bool
      port        = number
      target_port = number
      protocol    = string
    })
  })
  default = {
    http = {
      enabled     = true
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
    }
    metrics = {
      enabled     = true
      port        = 9100
      target_port = 9100
      protocol    = "TCP"
    }
  }
  validation {
    condition     = var.service_ports.http.port > 0 && var.service_ports.http.port < 65536 && var.service_ports.metrics.port > 0 && var.service_ports.metrics.port < 65536
    error_message = "service_ports.*.port must be valid TCP ports (1..65535)."
  }
}

variable "container_ports" {
  description = "Container ports exposed by rpc-gateway."
  type = object({
    http    = number
    metrics = number
  })
  default = {
    http    = 8080
    metrics = 9100
  }
  validation {
    condition     = var.container_ports.http > 0 && var.container_ports.http < 65536 && var.container_ports.metrics > 0 && var.container_ports.metrics < 65536
    error_message = "container_ports must be valid TCP ports (1..65535)."
  }
}

variable "ingress" {
  description = "Ingress configuration."
  type = object({
    enabled          = bool
    class_name       = string
    annotations      = map(string)
    hosts            = list(object({
      host  = string
      paths = list(object({
        path      = string
        path_type = string
        port      = number
      }))
    }))
    tls = list(object({
      hosts       = list(string)
      secret_name = string
    }))
  })
  default = {
    enabled     = false
    class_name  = ""
    annotations = {}
    hosts       = []
    tls         = []
  }
  validation {
    condition     = var.ingress.enabled == false || length(var.ingress.hosts) > 0
    error_message = "ingress.hosts must be provided when ingress.enabled is true."
  }
}

variable "resources" {
  description = "Resource requests/limits for the main container."
  type = object({
    requests = map(string)
    limits   = map(string)
  })
  default = {
    requests = { cpu = "250m", memory = "256Mi" }
    limits   = { cpu = "1",    memory = "1Gi"   }
  }
  validation {
    condition = alltrue([
      contains(keys(var.resources.requests), "cpu"),
      contains(keys(var.resources.requests), "memory"),
      contains(keys(var.resources.limits), "cpu"),
      contains(keys(var.resources.limits), "memory"),
    ])
    error_message = "resources.requests and resources.limits must include keys: cpu, memory."
  }
}

variable "ephemeral_storage" {
  description = "Ephemeral storage requests/limits for the main container (optional)."
  type = object({
    requests = string
    limits   = string
  })
  default = {
    requests = "256Mi"
    limits   = "1Gi"
  }
}

variable "env" {
  description = "Environment variables for the main container."
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

variable "env_from" {
  description = "Environment sources (ConfigMap/Secret names)."
  type = list(object({
    config_map_ref = string
    secret_ref     = string
  }))
  default = []
}

variable "config_map" {
  description = "Key-value data for ConfigMap mounted into the container."
  type        = map(string)
  default     = {}
}

variable "secret_data" {
  description = "Key-value secret data (string values; encoding outside of this module)."
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "volume_claim" {
  description = "PersistentVolumeClaim for data (if enabled)."
  type = object({
    enabled       = bool
    storage_class = string
    size          = string
    access_modes  = list(string)
    annotations   = map(string)
    labels        = map(string)
    mount_path    = string
  })
  default = {
    enabled       = false
    storage_class = ""
    size          = "10Gi"
    access_modes  = ["ReadWriteOnce"]
    annotations   = {}
    labels        = {}
    mount_path    = "/data"
  }
  validation {
    condition     = var.volume_claim.enabled == false || (length(var.volume_claim.size) > 0 && length(var.volume_claim.mount_path) > 0)
    error_message = "When volume_claim.enabled is true, size and mount_path must be set."
  }
}

variable "extra_volumes" {
  description = "Additional Volume specs (raw K8s objects)."
  type        = list(any)
  default     = []
}

variable "extra_volume_mounts" {
  description = "Additional VolumeMounts for main container."
  type = list(object({
    name       = string
    mount_path = string
    read_only  = bool
    sub_path   = string
  }))
  default = []
}

variable "pod_security_context" {
  description = "Pod-level security context."
  type = object({
    run_as_non_root           = bool
    fs_group                  = number
    fs_group_change_policy    = string
    seccomp_profile_type      = string
  })
  default = {
    run_as_non_root        = true
    fs_group               = 10001
    fs_group_change_policy = "OnRootMismatch"
    seccomp_profile_type   = "RuntimeDefault"
  }
}

variable "security_context" {
  description = "Container-level security context."
  type = object({
    run_as_user                = number
    run_as_group               = number
    allow_privilege_escalation = bool
    read_only_root_filesystem  = bool
    capabilities_drop          = list(string)
  })
  default = {
    run_as_user                = 10001
    run_as_group               = 10001
    allow_privilege_escalation = false
    read_only_root_filesystem  = true
    capabilities_drop          = ["ALL"]
  }
}

variable "node_selector" {
  description = "Node selector for scheduling."
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Tolerations for scheduling."
  type = list(object({
    key                = string
    operator           = string
    value              = string
    effect             = string
    toleration_seconds = number
  }))
  default = []
}

variable "affinity" {
  description = "Pod affinity/anti-affinity (raw object)."
  type        = any
  default     = null
}

variable "topology_spread_constraints" {
  description = "List of topology spread constraints."
  type        = list(any)
  default     = []
}

variable "priority_class_name" {
  description = "PriorityClass name for pods."
  type        = string
  default     = ""
}

variable "dns_policy" {
  description = "Pod DNS policy."
  type        = string
  default     = "ClusterFirst"
  validation {
    condition     = contains(["ClusterFirst", "Default", "None", "ClusterFirstWithHostNet"], var.dns_policy)
    error_message = "dns_policy must be one of: ClusterFirst, Default, None, ClusterFirstWithHostNet."
  }
}

variable "command" {
  description = "Container command override."
  type        = list(string)
  default     = []
}

variable "args" {
  description = "Container args override."
  type        = list(string)
  default     = []
}

variable "cors" {
  description = "CORS configuration for the gateway."
  type = object({
    enabled         = bool
    allowed_origins = list(string)
    allowed_methods = list(string)
    allowed_headers = list(string)
    max_age_seconds = number
  })
  default = {
    enabled         = false
    allowed_origins = []
    allowed_methods = ["GET", "POST", "OPTIONS"]
    allowed_headers = ["Content-Type", "Authorization"]
    max_age_seconds = 600
  }
}

variable "probes" {
  description = "Liveness/Readiness/Startup probe settings."
  type = object({
    liveness = object({
      enabled                = bool
      path                   = string
      port                   = number
      initial_delay_seconds  = number
      period_seconds         = number
      timeout_seconds        = number
      failure_threshold      = number
      success_threshold      = number
    })
    readiness = object({
      enabled                = bool
      path                   = string
      port                   = number
      initial_delay_seconds  = number
      period_seconds         = number
      timeout_seconds        = number
      failure_threshold      = number
      success_threshold      = number
    })
    startup = object({
      enabled                = bool
      path                   = string
      port                   = number
      initial_delay_seconds  = number
      period_seconds         = number
      timeout_seconds        = number
      failure_threshold      = number
      success_threshold      = number
    })
  })
  default = {
    liveness = {
      enabled               = true
      path                  = "/healthz"
      port                  = 8080
      initial_delay_seconds = 30
      period_seconds        = 15
      timeout_seconds       = 5
      failure_threshold     = 5
      success_threshold     = 1
    }
    readiness = {
      enabled               = true
      path                  = "/readyz"
      port                  = 8080
      initial_delay_seconds = 10
      period_seconds        = 10
      timeout_seconds       = 3
      failure_threshold     = 6
      success_threshold     = 1
    }
    startup = {
      enabled               = true
      path                  = "/startupz"
      port                  = 8080
      initial_delay_seconds = 5
      period_seconds        = 10
      timeout_seconds       = 3
      failure_threshold     = 30
      success_threshold     = 1
    }
  }
}

variable "pdb" {
  description = "PodDisruptionBudget configuration (one-of min_available, max_unavailable)."
  type = object({
    enabled         = bool
    min_available   = string
    max_unavailable = string
    labels          = map(string)
    annotations     = map(string)
  })
  default = {
    enabled         = true
    min_available   = null
    max_unavailable = "1"
    labels          = {}
    annotations     = {}
  }
  validation {
    condition = var.pdb.enabled == false || (
      ((var.pdb.min_available == null) != (var.pdb.max_unavailable == null))
    )
    error_message = "Exactly one of pdb.min_available or pdb.max_unavailable must be set when pdb.enabled is true."
  }
}

variable "hpa" {
  description = "HorizontalPodAutoscaler configuration."
  type = object({
    enabled                           = bool
    min_replicas                      = number
    max_replicas                      = number
    target_cpu_utilization_percentage = number
    target_memory_utilization_percent = number
  })
  default = {
    enabled                           = false
    min_replicas                      = 2
    max_replicas                      = 5
    target_cpu_utilization_percentage = 70
    target_memory_utilization_percent = 80
  }
  validation {
    condition     = var.hpa.enabled == false || (var.hpa.max_replicas >= var.hpa.min_replicas && var.hpa.min_replicas >= 1)
    error_message = "When hpa.enabled is true, max_replicas must be >= min_replicas and min_replicas >= 1."
  }
}

variable "service_monitor" {
  description = "ServiceMonitor for Prometheus Operator."
  type = object({
    enabled       = bool
    namespace     = string
    interval      = string
    scrape_timeout= string
    labels        = map(string)
    annotations   = map(string)
    scheme        = string
    relabelings   = list(any)
    port_name     = string
    path          = string
  })
  default = {
    enabled        = true
    namespace      = ""
    interval       = "30s"
    scrape_timeout = "10s"
    labels         = {}
    annotations    = {}
    scheme         = "http"
    relabelings    = []
    port_name      = "metrics"
    path           = "/metrics"
  }
}

variable "prometheus_rule" {
  description = "PrometheusRule groups/rules."
  type = object({
    enabled = bool
    labels  = map(string)
    annotations = map(string)
    groups  = list(any)
  })
  default = {
    enabled     = true
    labels      = {}
    annotations = {}
    groups      = []
  }
}

variable "network_policy" {
  description = "NetworkPolicy configuration."
  type = object({
    enabled     = bool
    labels      = map(string)
    annotations = map(string)
    policy_types= list(string)
    ingress     = list(any)
    egress      = list(any)
  })
  default = {
    enabled      = true
    labels       = {}
    annotations  = {}
    policy_types = ["Ingress", "Egress"]
    ingress      = []
    egress       = []
  }
  validation {
    condition     = alltrue([for t in var.network_policy.policy_types : contains(["Ingress", "Egress"], t)])
    error_message = "network_policy.policy_types must contain only Ingress and/or Egress."
  }
}

variable "external_service" {
  description = "Expose as LoadBalancer with optional allocated static LB IP."
  type = object({
    enabled          = bool
    allocate_lb_ip   = bool
    load_balancer_ip = string
    annotations      = map(string)
  })
  default = {
    enabled          = false
    allocate_lb_ip   = false
    load_balancer_ip = ""
    annotations      = {}
  }
  validation {
    condition     = var.external_service.enabled == false || var.service_type == "LoadBalancer"
    error_message = "external_service requires service_type = LoadBalancer."
  }
}

variable "log_level" {
  description = "Gateway log level."
  type        = string
  default     = "info"
  validation {
    condition     = contains(["trace","debug","info","warn","error"], var.log_level)
    error_message = "log_level must be one of: trace, debug, info, warn, error."
  }
}

variable "timeouts" {
  description = "Resource operation timeouts (used by calling resources)."
  type = object({
    create = string
    update = string
    delete = string
  })
  default = {
    create = "10m"
    update = "10m"
    delete = "10m"
  }
}
