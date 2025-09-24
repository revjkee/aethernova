/**
 * Aethernova — k8s-observability/grafana
 * File: variables.tf
 *
 * Declarative, industrial-grade variable schema for deploying Grafana via Helm in Kubernetes.
 * Requires Terraform >= 1.3 for optional() in object types.
 */

############################################
# Identity & Helm release
############################################

variable "name" {
  description = "Logical release name (Helm) and base name for K8s objects."
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace to install Grafana."
  type        = string
  default     = "observability"
}

variable "helm" {
  description = <<EOT
Helm release settings.
repo: chart repository URL (e.g., 'https://grafana.github.io/helm-charts')
chart: chart name (e.g., 'grafana' or 'kube-prometheus-stack' subchart override)
version: semantic version constraint for the chart (e.g., '~> 8.0')
atomic/wait/timeout/max_history: release controls
create_namespace: create namespace if not exists
values_overrides: raw values map merged into chart
EOT
  type = object({
    repo             = string
    chart            = string
    version          = string
    atomic           = optional(bool, true)
    wait             = optional(bool, true)
    timeout_seconds  = optional(number, 600)
    max_history      = optional(number, 10)
    create_namespace = optional(bool, true)
    values_overrides = optional(any, {})
  })
}

############################################
# Image & Pod settings
############################################

variable "image" {
  description = "Grafana container image settings."
  type = object({
    repository  = optional(string, "grafana/grafana")
    tag         = optional(string)            # e.g. "11.1.0"
    pull_policy = optional(string, "IfNotPresent")
  })
  default = {}
}

variable "replica_count" {
  description = "Desired Grafana replicas (ignored if HPA enabled)."
  type        = number
  default     = 1
  validation {
    condition     = var.replica_count >= 1
    error_message = "replica_count must be >= 1."
  }
}

variable "resources" {
  description = "Pod resource requests/limits."
  type = object({
    requests = optional(object({
      cpu    = optional(string, "200m")
      memory = optional(string, "256Mi")
    }), {})
    limits = optional(object({
      cpu    = optional(string)
      memory = optional(string)
    }), {})
  })
  default = {}
}

variable "node_selector" {
  description = "Node selector for scheduling."
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Pod tolerations."
  type = list(object({
    key               = optional(string)
    operator          = optional(string, "Exists")
    value             = optional(string)
    effect            = optional(string)
    toleration_seconds= optional(number)
  }))
  default = []
}

variable "affinity" {
  description = "Pod affinity/anti-affinity rules (raw)."
  type        = any
  default     = null
}

variable "security_context" {
  description = "Pod/container security contexts."
  type = object({
    pod = optional(object({
      runAsUser               = optional(number)
      runAsGroup              = optional(number)
      fsGroup                 = optional(number)
      fsGroupChangePolicy     = optional(string)
      seccompProfile          = optional(object({
        type = string
      }))
    }), {})
    container = optional(object({
      runAsUser                = optional(number)
      allowPrivilegeEscalation = optional(bool, false)
      readOnlyRootFilesystem   = optional(bool, true)
      capabilities             = optional(object({
        add  = optional(list(string), [])
        drop = optional(list(string), ["ALL"])
      }), {})
    }), {})
  })
  default = {}
}

variable "service_account" {
  description = "ServiceAccount management."
  type = object({
    create      = optional(bool, true)
    name        = optional(string)
    annotations = optional(map(string), {})
  })
  default = {}
}

############################################
# Service & Ingress
############################################

variable "service" {
  description = "Service configuration for Grafana."
  type = object({
    type                     = optional(string, "ClusterIP") # ClusterIP|NodePort|LoadBalancer
    port                     = optional(number, 80)
    target_port              = optional(number, 3000)
    node_port                = optional(number)
    annotations              = optional(map(string), {})
    labels                   = optional(map(string), {})
    external_traffic_policy  = optional(string)              # Local|Cluster
    load_balancer_ip         = optional(string)
    load_balancer_source_ranges = optional(list(string), [])
  })
  default = {}
  validation {
    condition     = contains(["ClusterIP","NodePort","LoadBalancer"], coalesce(var.service.type, "ClusterIP"))
    error_message = "service.type must be one of ClusterIP|NodePort|LoadBalancer."
  }
}

variable "ingress" {
  description = "Ingress configuration."
  type = object({
    enabled     = optional(bool, false)
    class_name  = optional(string)
    annotations = optional(map(string), {})
    hosts = optional(list(object({
      host  = string
      paths = optional(list(object({
        path     = string
        pathType = optional(string, "Prefix")
      })), [{ path = "/", pathType = "Prefix" }])
    })), [])
    tls = optional(list(object({
      secretName = string
      hosts      = list(string)
    })), [])
  })
  default = {}
}

variable "root_url" {
  description = "GF_SERVER_ROOT_URL (public URL) e.g. https://grafana.example.com"
  type        = string
  default     = ""
}

############################################
# Persistence (PVC)
############################################

variable "persistence" {
  description = "Persistent storage for Grafana."
  type = object({
    enabled       = optional(bool, false)
    size          = optional(string, "10Gi")
    storage_class = optional(string)
    access_modes  = optional(list(string), ["ReadWriteOnce"])
    existing_claim= optional(string)
    annotations   = optional(map(string), {})
  })
  default = {}
  validation {
    condition     = var.persistence.enabled ? can(regex("^[0-9]+(Mi|Gi|Ti)$", coalesce(var.persistence.size, "10Gi"))) : true
    error_message = "persistence.size must match ^[0-9]+(Mi|Gi|Ti)$ when persistence.enabled = true."
  }
}

############################################
# Admin credentials & auth
############################################

variable "admin" {
  description = "Grafana admin credentials (never output)."
  type = object({
    user                      = optional(string, "admin")
    password                  = optional(string)          # sensitive, set via tfvars
    existing_secret_name      = optional(string)
    existing_secret_key       = optional(string, "admin-password")
    disable_initial_user      = optional(bool, false)
  })
  default = {}
}

############################################
# SSO: OIDC / OAuth
############################################

variable "oidc" {
  description = "OIDC/OAuth settings for Grafana."
  type = object({
    enabled                   = optional(bool, false)
    name                      = optional(string, "OIDC")
    client_id                 = optional(string)
    client_secret_secret_name = optional(string)
    client_secret_key         = optional(string, "client-secret")
    issuer_url                = optional(string)
    auth_url                  = optional(string)  # for generic OAuth
    token_url                 = optional(string)  # for generic OAuth
    api_url                   = optional(string)
    scopes                    = optional(list(string), ["openid","profile","email"])
    allowed_domains           = optional(list(string), [])
    allow_sign_up             = optional(bool, true)
    use_pkce                  = optional(bool, true)
    role_attribute_path       = optional(string)
    login_attribute_path      = optional(string)
    email_attribute_path      = optional(string)
    name_attribute_path       = optional(string)
    callback_url_override     = optional(string)
    signout_redirect_url      = optional(string)
  })
  default = {}
}

############################################
# SMTP & LDAP (optional)
############################################

variable "smtp" {
  description = "SMTP settings for alerting/invites."
  type = object({
    enabled                 = optional(bool, false)
    host                    = optional(string)    # host:port or separate port
    port                    = optional(number, 587)
    user                    = optional(string)
    password_secret_name    = optional(string)
    password_secret_key     = optional(string, "password")
    from_address            = optional(string)
    from_name               = optional(string, "Grafana")
    starttls_policy         = optional(string, "OpportunisticStartTLS") # Disabled|OpportunisticStartTLS|MandatoryStartTLS
    skip_verify             = optional(bool, false)
  })
  default = {}
}

variable "ldap" {
  description = "LDAP integration (if enabled, provide config as string or secret)."
  type = object({
    enabled              = optional(bool, false)
    config               = optional(string)      # full ldap.toml content
    config_secret_name   = optional(string)
    config_secret_key    = optional(string, "ldap-toml")
  })
  default = {}
}

############################################
# Datasources & Dashboards
############################################

variable "datasources" {
  description = <<EOT
Grafana datasources. Each item becomes a provisioned datasource via configmap/secret.
Fields:
  name, type, url, access (proxy/direct), is_default, uid
  basic_auth (bool), basic_auth_user, basic_auth_password_secret{name,key}
  json_data (map), secure_json_data (map)
  editable (bool)
EOT
  type = list(object({
    name        = string
    type        = string
    url         = string
    access      = optional(string, "proxy")
    uid         = optional(string)
    is_default  = optional(bool, false)
    basic_auth  = optional(bool, false)
    basic_auth_user = optional(string)
    basic_auth_password_secret = optional(object({
      name = string
      key  = optional(string, "password")
    }))
    json_data        = optional(map(any), {})
    secure_json_data = optional(map(any), {})
    editable         = optional(bool, true)
  }))
  default = []
}

variable "dashboards_json_by_folder" {
  description = "Dashboards grouped by folder: { 'FolderName' = { 'slug' = '<JSON string>' } }."
  type        = map(map(string))
  default     = {}
}

variable "dashboard_files" {
  description = "Optional local file paths to dashboard JSONs (evaluated in parent module)."
  type        = list(string)
  default     = []
}

variable "plugins" {
  description = "Additional Grafana plugins to install (IDs, e.g., 'grafana-clock-panel')."
  type        = list(string)
  default     = []
}

############################################
# Sidecars (dashboards/datasources discovery)
############################################

variable "sidecar" {
  description = "Sidecar discovery configuration for dashboards and datasources."
  type = object({
    dashboards = optional(object({
      enabled         = optional(bool, false)
      label           = optional(string, "grafana_dashboard")
      label_value     = optional(string, "1")
      search_namespace= optional(string, "")
      folder_annotation = optional(string, "grafana_folder")
    }), {})
    datasources = optional(object({
      enabled         = optional(bool, false)
      label           = optional(string, "grafana_datasource")
      label_value     = optional(string, "1")
      search_namespace= optional(string, "")
    }), {})
  })
  default = {}
}

############################################
# grafana.ini overrides & env
############################################

variable "grafana_ini" {
  description = "Arbitrary grafana.ini structure (map-of-sections -> map-of-key-values)."
  type        = map(map(string))
  default     = {}
}

variable "env" {
  description = "Extra environment variables for Grafana container."
  type        = map(string)
  default     = {}
}

############################################
# Monitoring & HPA
############################################

variable "service_monitor" {
  description = "ServiceMonitor for Prometheus Operator."
  type = object({
    enabled        = optional(bool, true)
    labels         = optional(map(string), {})
    interval       = optional(string, "30s")
    scrape_timeout = optional(string, "10s")
    namespace      = optional(string)   # override
  })
  default = {}
}

variable "hpa" {
  description = "Horizontal Pod Autoscaler."
  type = object({
    enabled                        = optional(bool, false)
    min_replicas                   = optional(number, 1)
    max_replicas                   = optional(number, 3)
    target_cpu_utilization         = optional(number)   # %
    target_memory_utilization      = optional(number)   # %
    behavior                       = optional(any)      # raw HPA behavior
  })
  default = {}
  validation {
    condition     = !coalesce(var.hpa.enabled, false) ? true : (var.hpa.max_replicas >= var.hpa.min_replicas)
    error_message = "hpa.max_replicas must be >= hpa.min_replicas when HPA is enabled."
  }
}

############################################
# NetworkPolicy (optional)
############################################

variable "network_policy" {
  description = "K8s NetworkPolicy to restrict ingress/egress."
  type = object({
    enabled = optional(bool, false)
    ingress = optional(list(object({
      from = optional(list(any)), [])   # raw peers
      ports= optional(list(object({
        port     = number
        protocol = optional(string, "TCP")
      })), [])
    })), [])
    egress = optional(list(object({
      to   = optional(list(any)), [])
      ports= optional(list(object({
        port     = number
        protocol = optional(string, "TCP")
      })), [])
    })), [])
    pod_selector = optional(map(string), {})
    policy_types = optional(list(string), ["Ingress","Egress"])
  })
  default = {}
}

############################################
# Probes
############################################

variable "probes" {
  description = "Liveness/Readiness/Startup probe tuning."
  type = object({
    liveness = optional(object({
      path                = optional(string, "/api/health")
      initial_delay_seconds = optional(number, 30)
      period_seconds        = optional(number, 10)
      timeout_seconds       = optional(number, 2)
      failure_threshold     = optional(number, 6)
      success_threshold     = optional(number, 1)
    }), {})
    readiness = optional(object({
      path                = optional(string, "/api/health")
      initial_delay_seconds = optional(number, 10)
      period_seconds        = optional(number, 10)
      timeout_seconds       = optional(number, 2)
      failure_threshold     = optional(number, 6)
      success_threshold     = optional(number, 1)
    }), {})
    startup = optional(object({
      path                = optional(string, "/api/health")
      initial_delay_seconds = optional(number, 10)
      period_seconds        = optional(number, 10)
      timeout_seconds       = optional(number, 2)
      failure_threshold     = optional(number, 30)
      success_threshold     = optional(number, 1)
    }), {})
  })
  default = {}
}

############################################
# Volumes (advanced)
############################################

variable "extra_volumes" {
  description = "Extra Pod volumes (raw)."
  type        = list(any)
  default     = []
}

variable "extra_volume_mounts" {
  description = "Extra container volume mounts (raw)."
  type        = list(any)
  default     = []
}

############################################
# Outputs and debug
############################################

variable "expose_debug_outputs" {
  description = "Expose additional internal/debug outputs."
  type        = bool
  default     = false
}
