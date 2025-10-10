terraform {
  required_version = ">= 1.6.0"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 3.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.38"
    }
    argocd = {
      source  = "argoproj-labs/argocd"
      version = "~> 7.11"
    }
    kubectl = {
      source  = "cynkra/kubectl"
      version = "~> 1.15"
    }
  }
}
