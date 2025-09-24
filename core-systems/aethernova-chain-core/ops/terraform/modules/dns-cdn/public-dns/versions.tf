###############################################################################
# File: ops/terraform/modules/dns-cdn/public-dns/versions.tf
# Purpose: Version pinning for multi-cloud Public DNS/CDN module.
# Notes: Provider configuration (auth, accounts, regions) is defined elsewhere.
###############################################################################

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    # DNS in major clouds
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }

    # Public DNS / CDN vendors
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
    fastly = {
      source  = "fastly/fastly"
      version = "~> 5.0"
    }
    akamai = {
      source  = "akamai/akamai"
      version = "~> 6.0"
    }

    # Utilities
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}
