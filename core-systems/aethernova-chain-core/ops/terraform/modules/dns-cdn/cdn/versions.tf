// SPDX-License-Identifier: Apache-2.0
// Module: aethernova-chain-core/ops/terraform/modules/dns-cdn/cdn
// File:   versions.tf
// Purpose:
//   Pin Terraform & provider versions for multi-cloud CDN/DNS stacks:
//   - AWS (CloudFront, Route53)
//   - Cloudflare (Zones, DNS, CDN)
//   - Fastly (Services/Backends)
//   - Azure (Front Door / CDN via azurerm)
//   - Google Cloud CDN (via google)
// Notes:
//   - Provider configurations (credentials, regions, accounts, aliases) MUST be set in the ROOT module.
//   - This module only declares provider requirements and expected configuration aliases.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
      // Example aliases expected by the module (configure in root):
      // - aws.default      : regional ops (e.g., origin S3/ALB region)
      // - aws.us_east_1    : CloudFront/ACM global region
      // - aws.alt          : optional secondary region for failover
      configuration_aliases = [
        aws.default,
        aws.us_east_1,
        aws.alt
      ]
    }

    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
      // Example aliases for multiple Cloudflare accounts or scopes
      configuration_aliases = [
        cloudflare.primary,
        cloudflare.secondary
      ]
    }

    fastly = {
      source  = "fastly/fastly"
      version = "~> 3.0"
      configuration_aliases = [
        fastly.primary
      ]
    }

    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
      configuration_aliases = [
        azurerm.cdn
      ]
    }

    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
      configuration_aliases = [
        google.cdn
      ]
    }

    // Utility providers (for asset packaging, timestamps, local files, probes, etc.)
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3"
    }
  }
}

/*
ROOT module examples (do NOT place provider configs in this module):

provider "aws" {
  alias  = "default"
  region = var.aws_region
}
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}
provider "aws" {
  alias  = "alt"
  region = var.aws_alt_region
}

provider "cloudflare" {
  alias   = "primary"
  api_token = var.cloudflare_api_token
}
provider "cloudflare" {
  alias   = "secondary"
  api_token = var.cloudflare_secondary_api_token
}

provider "fastly" {
  alias   = "primary"
  api_key = var.fastly_api_key
}

provider "azurerm" {
  alias    = "cdn"
  features {}
}

provider "google" {
  alias   = "cdn"
  project = var.gcp_project
  region  = var.gcp_region
}

module "cdn" {
  source = "aethernova-chain-core/ops/terraform/modules/dns-cdn/cdn"
  providers = {
    aws.default      = aws.default
    aws.us_east_1    = aws.us_east_1
    aws.alt          = aws.alt
    cloudflare       = cloudflare.primary
    fastly           = fastly.primary
    azurerm          = azurerm.cdn
    google           = google.cdn
  }
}
*/
