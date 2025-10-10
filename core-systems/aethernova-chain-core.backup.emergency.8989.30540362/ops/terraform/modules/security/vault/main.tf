###############################################################################
# File: ops/terraform/modules/security/vault/main.tf
# Purpose: Production-grade Vault on Kubernetes via official Helm chart.
# Features:
#   - HA mode with Integrated Storage (Raft)
#   - Optional Auto-Unseal via AWS KMS / GCP Cloud KMS / Azure Key Vault
#   - Optional Injector, PDB, Prometheus Operator integration flags
# Notes:
#   - Providers (helm, kubernetes) должны быть сконфигурированы в вызывающем слое.
#   - Версию чарта можно пиновать вне этого файла (helm_release.version) при необходимости.
###############################################################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.14"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.32"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

###############################################################################
# Inputs
###############################################################################

variable "enabled" {
  description = "Install Vault when true."
  type        = bool
  default     = true
}

variable "namespace" {
  description = "Kubernetes namespace for Vault release."
  type        = string
  default     = "vault"
}

variable "create_namespace" {
  description = "Create namespace if it does not exist."
  type        = bool
  default     = true
}

variable "release_name" {
  description = "Helm release name."
  type        = string
  default     = "vault"
}

variable "helm_repository" {
  description = "Official HashiCorp Helm repo for Vault."
  type        = string
  default     = "https://helm.releases.hashicorp.com"
}

variable "helm_chart" {
  description = "Helm chart name."
  type        = string
  default     = "vault"
}

# Optionally pin a specific chart version (string). Leave null to use repo default.
variable "helm_chart_version" {
  description = "Helm chart version (optional)."
  type        = string
  default     = null
}

variable "replicas" {
  description = "Number of Vault server replicas in HA."
  type        = number
  default     = 3
}

variable "tls_disable" {
  description = "Set global.tlsDisable for chart (for TLS termination by ingress/mesh)."
  type        = bool
  default     = true
}

variable "enable_injector" {
  description = "Enable Vault Agent Injector."
  type        = bool
  default     = true
}

variable "enable_pdb" {
  description = "Enable PodDisruptionBudget for the server."
  type        = bool
  default     = true
}

variable "enable_prometheus_operator" {
  description = "Integrate with Prometheus Operator via chart options."
  type        = bool
  default     = false
}

# Auto-Unseal selection and parameters
variable "auto_unseal" {
  description = "Auto-Unseal backend: none | aws_kms | gcp_kms | azure_key_vault."
  type        = string
  default     = "none"
  validation {
    condition     = contains(["none", "aws_kms", "gcp_kms", "azure_key_vault"], var.auto_unseal)
    error_message = "auto_unseal must be one of: none, aws_kms, gcp_kms, azure_key_vault."
  }
}

# AWS KMS (awskms) params
variable "aws_kms_region" {
  description = "AWS region for KMS (awskms seal)."
  type        = string
  default     = null
}
variable "aws_kms_key_id" {
  description = "AWS KMS key id/arn for Vault seal."
  type        = string
  default     = null
}

# GCP Cloud KMS (gcpckms) params
variable "gcp_kms_project"   { type = string, default = null }
variable "gcp_kms_region"    { type = string, default = null } # e.g., global
variable "gcp_kms_key_ring"  { type = string, default = null }
variable "gcp_kms_crypto_key"{ type = string, default = null }
# Optional path to SA json inside the container (mounted via Secret/CSI by platform team)
variable "gcp_kms_credentials_path" {
  type        = string
  default     = null
  description = "Path to GCP credentials JSON inside pod for gcpckms (optional)."
}

# Azure Key Vault (azurekeyvault) params
variable "az_tenant_id"     { type = string, default = null }
variable "az_client_id"     { type = string, default = null }
variable "az_client_secret" { type = string, default = null }
variable "az_vault_name"    { type = string, default = null }
variable "az_key_name"      { type = string, default = null }

###############################################################################
# Namespace (optional creation)
###############################################################################

resource "kubernetes_namespace" "this" {
  count = var.enabled && var.create_namespace ? 1 : 0
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name" = "vault"
    }
  }
}

###############################################################################
# Guardrails: validate Auto-Unseal parameters when enabled
###############################################################################

resource "null_resource" "auto_unseal_guard" {
  triggers = {
    auto_unseal = var.auto_unseal
  }

  lifecycle {
    precondition {
      condition     = (var.auto_unseal != "aws_kms") || (var.aws_kms_region != null && var.aws_kms_key_id != null)
      error_message = "For auto_unseal=aws_kms, aws_kms_region and aws_kms_key_id must be set."
    }
    precondition {
      condition     = (var.auto_unseal != "gcp_kms") || (var.gcp_kms_project != null && var.gcp_kms_region != null && var.gcp_kms_key_ring != null && var.gcp_kms_crypto_key != null)
      error_message = "For auto_unseal=gcp_kms, gcp_kms_project/region/key_ring/crypto_key must be set."
    }
    precondition {
      condition     = (var.auto_unseal != "azure_key_vault") || (var.az_tenant_id != null && var.az_client_id != null && var.az_client_secret != null && var.az_vault_name != null && var.az_key_name != null)
      error_message = "For auto_unseal=azure_key_vault, az_tenant_id/client_id/client_secret/vault_name/key_name must be set."
    }
  }
}

###############################################################################
# Build Vault configuration fragments for Auto-Unseal (seal stanza)
###############################################################################

locals {
  seal_awskms = var.auto_unseal != "aws_kms" ? "" : <<-HCL
    seal "awskms" {
      region     = "${var.aws_kms_region}"
      kms_key_id = "${var.aws_kms_key_id}"
    }
  HCL

  seal_gcpckms = var.auto_unseal != "gcp_kms" ? "" : <<-HCL
    seal "gcpckms" {
      project     = "${var.gcp_kms_project}"
      region      = "${var.gcp_kms_region}"
      key_ring    = "${var.gcp_kms_key_ring}"
      crypto_key  = "${var.gcp_kms_crypto_key}"
%{ if var.gcp_kms_credentials_path != null }
      credentials = "${var.gcp_kms_credentials_path}"
%{ endif }
    }
  HCL

  seal_azure = var.auto_unseal != "azure_key_vault" ? "" : <<-HCL
    seal "azurekeyvault" {
      tenant_id     = "${var.az_tenant_id}"
      client_id     = "${var.az_client_id}"
      client_secret = "${var.az_client_secret}"
      vault_name    = "${var.az_vault_name}"
      key_name      = "${var.az_key_name}"
    }
  HCL

  # Only seal stanza; base listener/storage config управляет сам Helm-чарт для HA+Raft
  extra_server_config = trimspace(join("\n\n", compact([
    local.seal_awskms,
    local.seal_gcpckms,
    local.seal_azure
  ])))

  # Helm values rendered via yamlencode for determinism
  values_map = {
    global = {
      tlsDisable = var.tls_disable
    }

    injector = {
      enabled = var.enable_injector
    }

    # Server section per official chart
    server = {
      ha = {
        enabled = true
        replicas = var.replicas
        raft = {
          enabled = true
        }
        # Add raw Vault config (HCL) if present, e.g., seal stanza(s)
        config = length(local.extra_server_config) > 0 ? local.extra_server_config : null
      }

      disruptionBudget = {
        enabled = var.enable_pdb
      }
    }

    # Prometheus Operator integration toggle
    serverTelemetry = {
      prometheusOperator = var.enable_prometheus_operator
    }
  }

  values_yaml = yamlencode(local.values_map)
}

###############################################################################
# Helm release: Vault
###############################################################################

resource "helm_release" "vault" {
  count            = var.enabled ? 1 : 0
  name             = var.release_name
  repository       = var.helm_repository
  chart            = var.helm_chart
  namespace        = var.namespace
  create_namespace = false # управляем отдельным ресурсом

  # Optional: pin version when provided
  dynamic "set" {
    for_each = var.helm_chart_version == null ? [] : [1]
    content {
      name  = "dummy" # no-op to satisfy dynamic block when pinning via dedicated argument below
      value = "dummy"
    }
  }

  # Если вы хотите закрепить версию чарта — раскомментируйте строку ниже
  # version = var.helm_chart_version

  values = [
    local.values_yaml
  ]

  depends_on = [
    null_resource.auto_unseal_guard,
    kubernetes_namespace.this
  ]
}
