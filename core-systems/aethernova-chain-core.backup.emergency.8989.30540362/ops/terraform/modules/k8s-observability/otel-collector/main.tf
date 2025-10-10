#############################################
# Module: k8s-observability/otel-collector/main.tf
# Purpose: Industrial-grade Helm release for OpenTelemetry Collector
# Notes:
# - Works with both Deployment and DaemonSet modes
# - Enables PDB, HPA, ServiceMonitor, NetworkPolicy (opt-in)
# - Secure-by-default: runAsNonRoot, fsGroup, readOnlyRootFilesystem
# - Pipelines: traces, metrics, logs (customizable)
# - Values assembled via yamlencode for safety
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
      version = ">= 2.29.0"
    }
  }
}

#############################################
# Inputs
#############################################

variable "namespace" {
  type        = string
  description = "Kubernetes namespace for the otel-collector release"
  default     = "observability"
}

variable "create_namespace" {
  type        = bool
  description = "Create namespace if it doesn't exist"
  default     = true
}

variable "release_name" {
  type        = string
  description = "Helm release name"
  default     = "opentelemetry-collector"
}

variable "chart_repository" {
  type        = string
  description = "Helm repository URL for OpenTelemetry Collector chart"
  # Public helm repo for Opentelemetry charts
  default     = "https://open-telemetry.github.io/opentelemetry-helm-charts"
}

variable "chart_name" {
  type        = string
  description = "Chart name"
  default     = "opentelemetry-collector"
}

variable "chart_version" {
  type        = string
  description = "Chart version (pin for reproducibility)"
  # Pin explicitly in your environment; leave empty for latest
  default     = ""
}

variable "mode" {
  type        = string
  description = "Workload mode: deployment or daemonset or statefulset"
  default     = "deployment"
  validation {
    condition     = contains(["deployment", "daemonset", "statefulset"], var.mode)
    error_message = "mode must be one of: deployment, daemonset, statefulset."
  }
}

variable "replica_count" {
  type        = number
  description = "Replicas for deployment mode"
  default     = 2
}

variable "service_account_name" {
  type        = string
  description = "ServiceAccount name (empty => chart manages)"
  default     = "otel-collector"
}

variable "create_service_account" {
  type        = bool
  description = "Create ServiceAccount"
  default     = true
}

variable "image" {
  description = "Collector container image settings"
  type = object({
    repository = optional(string, "otel/opentelemetry-collector")
    tag        = optional(string,   null) # e.g. "0.103.0"
    pullPolicy = optional(string,   "IfNotPresent")
  })
  default = {}
}

variable "resources" {
  description = "Pod resources"
  type = object({
    limits = optional(object({
      cpu    = optional(string)
      memory = optional(string)
    }), {})
    requests = optional(object({
      cpu    = optional(string, "100m")
      memory = optional(string, "256Mi")
    }), {})
  })
  default = {}
}

variable "node_selector" {
  type        = map(string)
  description = "Node selector"
  default     = {}
}

variable "tolerations" {
  description = "Pod tolerations"
  type = list(object({
    key               = optional(string)
    operator          = optional(string)
    value             = optional(string)
    effect            = optional(string)
    tolerationSeconds = optional(number)
  }))
  default = []
}

variable "affinity" {
  description = "Pod affinity"
  type        = any
  default     = {}
}

variable "extra_env" {
  description = "Extra environment variables"
  type        = map(string)
  default     = {}
}

variable "secret_refs" {
  description = <<EOT
List of secret references to mount as environment variables via valuesFrom.
Each item: { name = "k8s-secret-name", optional = true/false }
EOT
  type = list(object({
    name     = string
    optional = optional(bool, false)
  }))
  default = []
}

variable "service_monitor_enabled" {
  type        = bool
  description = "Enable ServiceMonitor (Prometheus Operator)"
  default     = true
}

variable "network_policy_enabled" {
  type        = bool
  description = "Enable NetworkPolicy to restrict traffic"
  default     = true
}

variable "hpa" {
  description = "HorizontalPodAutoscaler config (only for deployment)"
  type = object({
    enabled          = optional(bool, true)
    min_replicas     = optional(number, 2)
    max_replicas     = optional(number, 8)
    target_cpu_util  = optional(number, 70)
    target_mem_util  = optional(number, null)
  })
  default = {}
}

variable "pdb" {
  description = "PodDisruptionBudget"
  type = object({
    enabled          = optional(bool, true)
    min_available    = optional(string, null) # e.g. "1"
    max_unavailable  = optional(string, null) # e.g. "25%"
  })
  default = {}
}

variable "ingest_endpoints" {
  description = <<EOT
Exporter destinations. Any field may be null/empty to disable.
- otlp: { endpoint = "tempo-distributor.observability.svc:4317", tls_insecure = true }
- prometheus_remote_write: { endpoint = "http://prometheus-server.monitoring:9090/api/v1/write", headers = { "X-Scope-OrgID" = "tenant" } }
- loki: { endpoint = "http://loki-gateway.observability:3100", labels = { cluster="prod" } }
EOT
  type = object({
    otlp = optional(object({
      endpoint     = string
      tls_insecure = optional(bool, false)
      headers      = optional(map(string), {})
    }), null)
    prometheus_remote_write = optional(object({
      endpoint = string
      headers  = optional(map(string), {})
      tls_insecure = optional(bool, false)
    }), null)
    loki = optional(object({
      endpoint = string
      labels   = optional(map(string), {})
      tls_insecure = optional(bool, false)
    }), null)
  })
  default = {
    otlp = null
    prometheus_remote_write = null
    loki = null
  }
}

variable "receivers" {
  description = "Custom receivers override (advanced)"
  type        = any
  default     = null
}

variable "processors" {
  description = "Custom processors override (advanced)"
  type        = any
  default     = null
}

variable "exporters" {
  description = "Custom exporters override (advanced)"
  type        = any
  default     = null
}

variable "extensions" {
  description = "Custom extensions override (advanced)"
  type        = any
  default     = null
}

variable "service_pipelines" {
  description = "Custom service pipelines override (advanced)"
  type        = any
  default     = null
}

variable "pod_security_context" {
  description = "Pod-level security context overrides"
  type = object({
    runAsNonRoot           = optional(bool,  true)
    runAsUser              = optional(number, 10001)
    runAsGroup             = optional(number, 10001)
    fsGroup                = optional(number, 10001)
    seccompProfile         = optional(object({ type = string }), { type = "RuntimeDefault" })
  })
  default = {}
}

variable "container_security_context" {
  description = "Container-level security context overrides"
  type = object({
    readOnlyRootFilesystem = optional(bool, true)
    allowPrivilegeEscalation = optional(bool, false)
    capabilities = optional(object({
      drop = optional(list(string), ["ALL"])
      add  = optional(list(string), [])
    }), {})
  })
  default = {}
}

variable "extra_values" {
  description = "Raw values to merge into chart values last"
  type        = any
  default     = {}
}

#############################################
# Namespace (optional create)
#############################################

resource "kubernetes_namespace" "this" {
  count = var.create_namespace ? 1 : 0
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/part-of" = "observability"
      "opentelemetry.io/component" = "collector"
    }
  }
}

#############################################
# Values assembly
#############################################

locals {
  # Default receivers/processors/exporters/extensions
  default_receivers = {
    otlp = {
      protocols = {
        grpc = { endpoint = "0.0.0.0:4317" }
        http = { endpoint = "0.0.0.0:4318" }
      }
    }
    prometheus = {
      config = {
        scrape_configs = [
          {
            job_name = "kubernetes-pods"
            kubernetes_sd_configs = [{ role = "pod" }]
            relabel_configs = [
              { action = "keep", regex = "true", source_labels = ["__meta_kubernetes_pod_annotation_prometheus_io_scrape"] },
              { action = "replace", source_labels = ["__meta_kubernetes_pod_annotation_prometheus_io_path"], target_label = "__metrics_path__", regex = "(.+)", replacement = "$1" },
              { action = "replace", source_labels = ["__address__", "__meta_kubernetes_pod_annotation_prometheus_io_port"], regex = "(.+):\\d+;(\\d+)", replacement = "$1:$2", target_label = "__address__" },
              { action = "labelmap", regex = "__meta_kubernetes_pod_label_(.+)" }
            ]
          }
        ]
      }
    }
    filelog = {
      include         = ["/var/log/containers/*.log"]
      start_at        = "end"
      include_file_path = true
      include_file_name = true
      operators = [
        { type = "container" },
        { type = "batch", flush_interval = "5s", send_batch_size = 8192 }
      ]
    }
  }

  default_processors = {
    batch = { send_batch_max_size = 8192, send_batch_size = 2048, timeout = "2s" }
    memory_limiter = {
      check_interval = "5s"
      limit_mib      = 512
      spike_limit_mib = 256
    }
    resource = {
      attributes = [
        { key = "k8s.namespace.name", action = "upsert", from_attribute = "k8s.namespace.name" },
        { key = "service.namespace",  action = "upsert", value = var.namespace }
      ]
    }
    attributes = {
      actions = [
        { key = "deployment.environment", action = "insert", value = "prod" }
      ]
    }
  }

  default_exporters = merge(
    {},

    # OTLP exporter (traces/metrics/logs)
    (var.ingest_endpoints.otlp == null ? {} : {
      otlp = {
        endpoint = var.ingest_endpoints.otlp.endpoint
        headers  = try(var.ingest_endpoints.otlp.headers, {})
        tls = {
          insecure = try(var.ingest_endpoints.otlp.tls_insecure, false)
        }
      }
    }),

    # Prometheus Remote Write exporter (metrics)
    (var.ingest_endpoints.prometheus_remote_write == null ? {} : {
      prometheusremotewrite = {
        endpoint = var.ingest_endpoints.prometheus_remote_write.endpoint
        headers  = try(var.ingest_endpoints.prometheus_remote_write.headers, {})
        tls = {
          insecure = try(var.ingest_endpoints.prometheus_remote_write.tls_insecure, false)
        }
      }
    }),

    # Loki exporter (logs)
    (var.ingest_endpoints.loki == null ? {} : {
      loki = {
        endpoint = var.ingest_endpoints.loki.endpoint
        labels   = try(var.ingest_endpoints.loki.labels, {})
        tls = {
          insecure = try(var.ingest_endpoints.loki.tls_insecure, false)
        }
      }
    })
  )

  default_extensions = {
    health_check = { endpoint = "0.0.0.0:13133" }
    pprof        = { endpoint = "0.0.0.0:1777" }
    zpages       = { endpoint = "0.0.0.0:55679" }
  }

  default_service_pipelines = {
    traces = {
      receivers  = compact(["otlp"])
      processors = ["memory_limiter", "batch", "resource", "attributes"]
      exporters  = compact([
        (var.ingest_endpoints.otlp == null ? "" : "otlp")
      ])
    }
    metrics = {
      receivers  = compact(["otlp", "prometheus"])
      processors = ["memory_limiter", "batch", "resource"]
      exporters  = compact([
        (var.ingest_endpoints.prometheus_remote_write == null ? "" : "prometheusremotewrite"),
        (var.ingest_endpoints.otlp == null ? "" : "otlp")
      ])
    }
    logs = {
      receivers  = compact(["otlp", "filelog"])
      processors = ["memory_limiter", "batch", "resource"]
      exporters  = compact([
        (var.ingest_endpoints.loki == null ? "" : "loki"),
        (var.ingest_endpoints.otlp == null ? "" : "otlp")
      ])
    }
  }

  # Final OTel Collector config (can be fully overridden via *override variables)
  otel_config = {
    receivers  = coalesce(var.receivers,  local.default_receivers)
    processors = coalesce(var.processors, local.default_processors)
    exporters  = coalesce(var.exporters,  local.default_exporters)
    extensions = coalesce(var.extensions, local.default_extensions)
    service = coalesce(var.service_pipelines, {
      telemetry = {
        logs = { level = "info" }
      }
      pipelines = local.default_service_pipelines
    })
  }

  # Helm values (chart schema compliant)
  values = {
    mode = var.mode

    # Image
    image = {
      repository = try(var.image.repository, "otel/opentelemetry-collector")
      tag        = try(var.image.tag, null)
      pullPolicy = try(var.image.pullPolicy, "IfNotPresent")
    }

    replicaCount = var.mode == "deployment" ? var.replica_count : null

    serviceAccount = {
      create = var.create_service_account
      name   = var.service_account_name
      annotations = {}
    }

    podAnnotations = {
      "prometheus.io/scrape" = "true"
      "prometheus.io/port"   = "8888"
      "prometheus.io/path"   = "/metrics"
    }

    # Security
    securityContext = merge({
      runAsNonRoot = true
      runAsUser    = 10001
      runAsGroup   = 10001
      fsGroup      = 10001
      seccompProfile = { type = "RuntimeDefault" }
    }, var.pod_security_context)

    containerSecurityContext = merge({
      readOnlyRootFilesystem   = true
      allowPrivilegeEscalation = false
      capabilities = {
        drop = ["ALL"]
      }
    }, var.container_security_context)

    resources = var.resources

    nodeSelector = var.node_selector
    tolerations  = var.tolerations
    affinity     = var.affinity

    # Networking
    service = {
      type = "ClusterIP"
      ports = [
        { name = "otlp-grpc", port = 4317, targetPort = 4317 },
        { name = "otlp-http", port = 4318, targetPort = 4318 },
        { name = "metrics",   port = 8888, targetPort = 8888 },
      ]
    }

    # Observability endpoints
    ports = {
      otlp = {
        enabled = true
        containerPort = 4317
        servicePort   = 4317
        protocol      = "TCP"
      }
      otlp-http = {
        enabled = true
        containerPort = 4318
        servicePort   = 4318
        protocol      = "TCP"
      }
      metrics = {
        enabled = true
        containerPort = 8888
        servicePort   = 8888
        protocol      = "TCP"
      }
    }

    # Prometheus ServiceMonitor
    serviceMonitor = {
      enabled = var.service_monitor_enabled
      additionalLabels = {
        release = "kube-prometheus-stack"
      }
      interval = "30s"
      scrapeTimeout = "10s"
      path = "/metrics"
      port = "metrics"
    }

    # NetworkPolicy
    networkPolicy = {
      enabled = var.network_policy_enabled
      egress = [
        {
          to = [{ ipBlock = { cidr = "0.0.0.0/0" } }]
          ports = [
            { protocol = "TCP", port = 4317 },
            { protocol = "TCP", port = 4318 },
            { protocol = "TCP", port = 80    },
            { protocol = "TCP", port = 443   },
            { protocol = "TCP", port = 3100  } # Loki (if used)
          ]
        }
      ]
      ingress = [
        {
          from = [{ podSelector = {} }]
          ports = [
            { protocol = "TCP", port = 4317 },
            { protocol = "TCP", port = 4318 },
            { protocol = "TCP", port = 8888 }
          ]
        }
      ]
    }

    # PDB
    podDisruptionBudget = {
      enabled        = try(var.pdb.enabled, true)
      minAvailable   = try(var.pdb.min_available, null)
      maxUnavailable = try(var.pdb.max_unavailable, null)
    }

    # HPA (only relevant to Deployment)
    autoscaling = {
      enabled = var.mode == "deployment" ? try(var.hpa.enabled, true) : false
      minReplicas = try(var.hpa.min_replicas, 2)
      maxReplicas = try(var.hpa.max_replicas, 8)
      targetCPUUtilizationPercentage = try(var.hpa.target_cpu_util, 70)
      targetMemoryUtilizationPercentage = try(var.hpa.target_mem_util, null)
    }

    # Volumes for logs collection (filelog)
    extraVolumes = [
      { name = "varlog", hostPath = { path = "/var/log", type = "" } }
    ]
    extraVolumeMounts = [
      { name = "varlog", mountPath = "/var/log", readOnly = true }
    ]

    # Env
    env = merge({
      "OTEL_RESOURCE_ATTRIBUTES" = "service.name=otel-collector,service.namespace=${var.namespace}"
      "GOMEMLIMIT"               = "700MiB"
    }, var.extra_env)

    # Secrets via valuesFrom (envFrom)
    envFrom = length(var.secret_refs) == 0 ? null : [
      for s in var.secret_refs : {
        secretRef = {
          name     = s.name
          optional = try(s.optional, false)
        }
      }
    ]

    # Raw OpenTelemetry Collector config
    config = local.otel_config
  }

  merged_values = merge(local.values, var.extra_values)
}

#############################################
# Helm release
#############################################

resource "helm_release" "otel_collector" {
  name       = var.release_name
  namespace  = var.namespace
  repository = var.chart_repository
  chart      = var.chart_name
  version    = length(var.chart_version) > 0 ? var.chart_version : null

  create_namespace = false # handled by kubernetes_namespace resource (if enabled)

  values = [
    yamlencode(local.merged_values)
  ]

  # Wait for resources to become Ready
  wait          = true
  timeout       = 600
  atomic        = true
  cleanup_on_fail = true

  # Reconcile on changes in this module (helm provider 2.11+)
  disable_crd_hooks = false

  depends_on = [
    kubernetes_namespace.this
  ]
}

#############################################
# Helpful outputs
#############################################

output "release_name" {
  description = "Helm release name"
  value       = helm_release.otel_collector.name
}

output "namespace" {
  description = "Namespace where the release is installed"
  value       = var.namespace
}

output "service_monitor_enabled" {
  description = "Whether ServiceMonitor is enabled"
  value       = var.service_monitor_enabled
}

output "network_policy_enabled" {
  description = "Whether NetworkPolicy is enabled"
  value       = var.network_policy_enabled
}

output "mode" {
  description = "Workload mode"
  value       = var.mode
}
