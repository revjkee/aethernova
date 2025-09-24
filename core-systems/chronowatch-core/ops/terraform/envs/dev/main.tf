#############################################
# chronowatch-core/ops/terraform/envs/dev/main.tf
# Industrial-grade Terraform for dev Kubernetes environment
#############################################

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.33.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13.2"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6.2"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0.5"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11.2"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5.2"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2.2"
    }
  }

  # For dev we keep state on local filesystem.
  # For shared environments replace with remote backend (S3/GCS/AzureRM) — not configured here.
  backend "local" {
    path = "tfstate/chronowatch-core-dev.tfstate"
  }
}

##################################################
# Variables
##################################################

variable "env" {
  description = "Deployment environment name"
  type        = string
  default     = "dev"
}

variable "kubeconfig_path" {
  description = "Path to kubeconfig for dev cluster"
  type        = string
  default     = "~/.kube/config"
}

variable "kube_context" {
  description = "Optional kubeconfig context to use"
  type        = string
  default     = ""
}

variable "namespace_core" {
  description = "Namespace for chronowatch-core"
  type        = string
  default     = "chronowatch-core"
}

variable "namespace_observability" {
  description = "Namespace for observability addons (optional)"
  type        = string
  default     = "observability"
}

variable "enable_network_policies" {
  description = "Whether to apply baseline NetworkPolicies"
  type        = bool
  default     = true
}

variable "enable_pdb" {
  description = "Whether to allow PodDisruptionBudget templates from Helm"
  type        = bool
  default     = true
}

variable "chart_version" {
  description = "Helm chart version for chronowatch-core (when using packaged chart). For local path it is ignored."
  type        = string
  default     = "1.0.0"
}

variable "chart_source" {
  description = <<-EOT
    Helm chart source:
    - local path: ../../helm/chronowatch-core
    - or OCI/URL repo when confirmed (not set here). I cannot verify this.
  EOT
  type    = string
  default = "../../helm/chronowatch-core"
}

variable "image_repository" {
  description = "Container image repo (to be confirmed)"
  type        = string
  default     = "ghcr.io/ORG/chronowatch-core" # I cannot verify this.
}

variable "image_tag" {
  description = "Container image tag (align with appVersion)"
  type        = string
  default     = "1.0.0"
}

variable "replicas" {
  description = "Number of pod replicas for core deployment"
  type        = number
  default     = 2
}

variable "resources_core" {
  description = "K8s resource requests/limits for the core workload"
  type = object({
    requests = object({ cpu = string, memory = string })
    limits   = object({ cpu = string, memory = string })
  })
  default = {
    requests = { cpu = "100m", memory = "256Mi" }
    limits   = { cpu = "500m", memory = "512Mi" }
  }
}

variable "service_port" {
  description = "Service port for chronowatch-core"
  type        = number
  default     = 8080
}

variable "grpc_port" {
  description = "Optional gRPC port if enabled in chart values"
  type        = number
  default     = 9090
}

##################################################
# Locals
##################################################

locals {
  name_prefix = "chronowatch"
  app_name    = "chronowatch-core"

  labels_common = {
    "app.kubernetes.io/name"       = local.app_name
    "app.kubernetes.io/instance"   = "${local.app_name}-${var.env}"
    "app.kubernetes.io/managed-by" = "terraform"
    "app.kubernetes.io/part-of"    = "chronowatch"
    "app.kubernetes.io/component"  = "core"
    "app.kubernetes.io/version"    = var.chart_version
    "env"                          = var.env
  }

  annotations_common = {
    "security.chronowatch.io/sbom"            = "false" # switch to true when SBOM is shipped. I cannot verify this.
    "security.chronowatch.io/slsa-provenance" = "false" # I cannot verify this.
  }
}

##################################################
# Providers
##################################################

provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = var.kube_context != "" ? var.kube_context : null
}

provider "helm" {
  kubernetes {
    config_path    = var.kubeconfig_path
    config_context = var.kube_context != "" ? var.kube_context : null
  }
}

##################################################
# Namespaces
##################################################

resource "kubernetes_namespace" "core" {
  metadata {
    name        = var.namespace_core
    labels      = local.labels_common
    annotations = local.annotations_common
  }
}

resource "kubernetes_namespace" "observability" {
  metadata {
    name        = var.namespace_observability
    labels = merge(local.labels_common, {
      "app.kubernetes.io/component" = "observability"
    })
    annotations = local.annotations_common
  }
}

##################################################
# Service Accounts / RBAC (minimal, dev)
##################################################

resource "kubernetes_service_account" "core" {
  metadata {
    name      = "${local.app_name}-sa"
    namespace = kubernetes_namespace.core.metadata[0].name
    labels    = local.labels_common
  }
  automount_service_account_token = true
}

resource "kubernetes_cluster_role" "core_readonly" {
  metadata {
    name   = "${local.app_name}-readonly"
    labels = local.labels_common
  }

  rule {
    api_groups = [""]
    resources  = ["pods", "services", "endpoints", "configmaps", "secrets", "namespaces"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = ["apps"]
    resources  = ["deployments", "statefulsets", "daemonsets", "replicasets"]
    verbs      = ["get", "list", "watch"]
  }
}

resource "kubernetes_cluster_role_binding" "core_readonly" {
  metadata {
    name   = "${local.app_name}-readonly"
    labels = local.labels_common
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.core_readonly.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.core.metadata[0].name
    namespace = kubernetes_namespace.core.metadata[0].name
  }
}

##################################################
# Network Policies (baseline zero-trust)
##################################################

resource "kubernetes_network_policy_v1" "core_default_deny_ingress" {
  count = var.enable_network_policies ? 1 : 0

  metadata {
    name      = "deny-all-ingress"
    namespace = kubernetes_namespace.core.metadata[0].name
    labels    = local.labels_common
  }

  spec {
    pod_selector {} # select all pods
    policy_types = ["Ingress"]
    # no ingress rules -> deny all
  }
}

resource "kubernetes_network_policy_v1" "core_default_allow_dns_egress" {
  count = var.enable_network_policies ? 1 : 0

  metadata {
    name      = "allow-dns-egress"
    namespace = kubernetes_namespace.core.metadata[0].name
    labels    = local.labels_common
  }

  spec {
    pod_selector {}
    policy_types = ["Egress"]

    egress {
      to {
        namespace_selector {}
      }
      ports {
        port     = 53
        protocol = "UDP"
      }
      ports {
        port     = 53
        protocol = "TCP"
      }
    }
  }
}

# Example allow from same namespace (optional open baseline)
resource "kubernetes_network_policy_v1" "core_allow_same_ns_ingress" {
  count = var.enable_network_policies ? 1 : 0

  metadata {
    name      = "allow-same-ns-ingress"
    namespace = kubernetes_namespace.core.metadata[0].name
    labels    = local.labels_common
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress"]

    ingress {
      from {
        pod_selector {} # same namespace pods
      }
    }
  }
}

##################################################
# Helm Release: chronowatch-core
##################################################

# Uses a local chart path by default.
# If switching to OCI/remote repo, add 'repository' and remove 'chart' path accordingly (not configured here). I cannot verify this.
resource "helm_release" "chronowatch_core" {
  name       = "${local.app_name}"
  namespace  = kubernetes_namespace.core.metadata[0].name
  chart      = var.chart_source
  # repository = "oci://REGISTRY/ORG" # I cannot verify this.
  # version    = var.chart_version     # when using packaged chart

  create_namespace = false
  atomic           = true
  cleanup_on_fail  = true
  wait             = true
  timeout          = 600

  values = [
    yamlencode({
      image = {
        repository = var.image_repository
        tag        = var.image_tag
        pullPolicy = "IfNotPresent"
      }

      replicaCount = var.replicas

      service = {
        type = "ClusterIP"
        port = var.service_port
      }

      grpc = {
        enabled = true
        port    = var.grpc_port
      }

      resources = {
        requests = {
          cpu    = var.resources_core.requests.cpu
          memory = var.resources_core.requests.memory
        }
        limits = {
          cpu    = var.resources_core.limits.cpu
          memory = var.resources_core.limits.memory
        }
      }

      podDisruptionBudget = {
        enabled        = var.enable_pdb
        minAvailable   = 1
        # maxUnavailable = null
      }

      podLabels      = local.labels_common
      podAnnotations = local.annotations_common

      serviceAccount = {
        create = false
        name   = kubernetes_service_account.core.metadata[0].name
      }

      # NetworkPolicy templates expected in chart; enforced separately above as baseline
      networkPolicy = {
        enabled = true
      }

      # Standard labels for k8s objects created by the chart
      labels = local.labels_common
    })
  ]

  depends_on = [
    kubernetes_service_account.core,
    kubernetes_network_policy_v1.core_default_deny_ingress,
    kubernetes_network_policy_v1.core_default_allow_dns_egress,
    kubernetes_network_policy_v1.core_allow_same_ns_ingress,
  ]
}

##################################################
# Observability namespace placeholder (no installs here)
##################################################

resource "time_static" "deployment_timestamp" {}

resource "local_file" "deployment_meta" {
  content = jsonencode({
    app          = local.app_name
    env          = var.env
    kube_context = var.kube_context
    namespace    = var.namespace_core
    image        = "${var.image_repository}:${var.image_tag}"
    deployed_at  = time_static.deployment_timestamp.rfc3339
  })
  filename = "tfout/chronowatch-core-dev-deploy.json"
}

##################################################
# Outputs
##################################################

output "namespace_core" {
  description = "Kubernetes namespace for chronowatch-core"
  value       = kubernetes_namespace.core.metadata[0].name
}

output "helm_release_name" {
  description = "Helm release name"
  value       = helm_release.chronowatch_core.name
}

output "service_hint" {
  description = "Service endpoints hint (ClusterIP)"
  value       = {
    http_port = var.service_port
    grpc_port = var.grpc_port
  }
}

output "deployment_metadata_file" {
  description = "Path to deployment metadata file"
  value       = local_file.deployment_meta.filename
}
