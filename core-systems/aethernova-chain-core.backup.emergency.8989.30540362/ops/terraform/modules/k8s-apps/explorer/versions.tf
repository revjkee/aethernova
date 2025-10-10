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
    kubectl = {
      source  = "cynkra/kubectl"
      version = "~> 1.15"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.5"
    }
  }
}
