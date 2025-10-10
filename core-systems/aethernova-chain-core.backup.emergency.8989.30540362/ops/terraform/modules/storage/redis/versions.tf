#############################################
# File: ops/terraform/modules/storage/redis/versions.tf
# Purpose: Pin Terraform & providers with explicit registry sources
# Notes:
# - Only version constraints here; provider config lives in providers.tf
# - Ranges follow SemVer and official Terraform guidance
#############################################

terraform {
  # Pin Terraform Core to a stable major (1.x)
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    #############################
    # Cloud providers (optional)
    #############################

    aws = {
      source  = "hashicorp/aws"
      # AWS provider major 5.x; stay below next major
      version = ">= 5.0.0, < 6.0.0"
    }

    azurerm = {
      source  = "hashicorp/azurerm"
      # AzureRM provider major 3.x
      version = ">= 3.0.0, < 4.0.0"
    }

    google = {
      source  = "hashicorp/google"
      # Google provider 5–6 majors are common in prod; allow either, cap before next major
      version = ">= 5.0.0, < 7.0.0"
    }

    #############################
    # K8s toolchain (optional)
    #############################

    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.26.0, < 3.0.0"
    }

    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12.0, < 3.0.0"
    }

    #############################
    # Utilities commonly used with Redis
    #############################

    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0, < 4.0.0"
    }

    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.0, < 5.0.0"
    }

    time = {
      source  = "hashicorp/time"
      version = ">= 0.11.0, < 1.0.0"
    }

    http = {
      source  = "hashicorp/http"
      version = ">= 3.4.0, < 4.0.0"
    }

    local = {
      source  = "hashicorp/local"
      version = ">= 2.4.0, < 3.0.0"
    }

    #############################
    # Managed Redis (Redis Enterprise Cloud) — optional
    #############################

    rediscloud = {
      source  = "RedisLabs/rediscloud"
      # Current major is 2.x; cap before next major to avoid breaking changes
      version = ">= 2.0.0, < 3.0.0"
    }
  }
}
