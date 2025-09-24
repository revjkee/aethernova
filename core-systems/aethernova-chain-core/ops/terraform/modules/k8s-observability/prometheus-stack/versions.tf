// SPDX-License-Identifier: Apache-2.0
// Module: aethernova-chain-core/ops/terraform/modules/k8s-observability/prometheus-stack
// File:   versions.tf
// Purpose:
//   Pin Terraform & provider versions for Helm-based kube-prometheus-stack deployments.
//   Provider configurations (credentials, kubeconfig, contexts, aliases) MUST be set in the ROOT module.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.14"
      // Expect aliased configs from root module for multi-cluster rollouts
      configuration_aliases = [
        helm.eks,
        helm.gke,
        helm.aks
      ]
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.33"
      configuration_aliases = [
        kubernetes.eks,
        kubernetes.gke,
        kubernetes.aks
      ]
    }

    // Utility providers occasionally used by this module or submodules
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

// NOTE:
// - Do NOT configure providers in this module.
// - In root, define aliased providers and pass them into the module, e.g.:
//
//   provider "kubernetes" {
//     alias       = "gke"
//     config_path = var.kubeconfig
//     config_context = var.kube_context_gke
//   }
//
//   provider "helm" {
//     alias = "gke"
//     kubernetes {
//       config_path    = var.kubeconfig
//       config_context = var.kube_context_gke
//     }
//   }
//
//   module "prometheus_stack" {
//     source = "aethernova-chain-core/ops/terraform/modules/k8s-observability/prometheus-stack"
//     providers = {
//       kubernetes = kubernetes.gke
//       helm       = helm.gke
//     }
//   }
