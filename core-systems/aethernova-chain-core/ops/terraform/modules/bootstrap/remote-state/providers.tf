###############################################################################
# File: ops/terraform/modules/bootstrap/remote-state/providers.tf
# Purpose: Provider definitions for multi-cloud remote-state bootstrap module.
# Notes:
#  - Supports AWS (S3 + DynamoDB), GCP (GCS + optional locking via Firestore),
#    and Azure (Storage Account + blob container + optional table for locking).
#  - Provider configuration reads from variables with sane defaults that can be
#    overridden via tfvars or environment (e.g., AWS_PROFILE, GOOGLE_*).
#  - Keep all providers present; only the ones referenced by resources will be
#    initialized by Terraform during planning/apply.
#  - Tested with Terraform >= 1.6.
###############################################################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 6.11"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.9"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
  }
}

###############################################################################
# Input variables (scoped to this module for provider configuration)
###############################################################################

# Target cloud to bootstrap. Controls which resources are created by this module.
# Valid values: "aws", "gcp", "azure".
variable "cloud" {
  description = "Target cloud to bootstrap remote state in."
  type        = string
  default     = "aws"
  validation {
    condition     = contains(["aws", "gcp", "azure"], var.cloud)
    error_message = "cloud must be one of: aws, gcp, azure."
  }
}

# --------------------------------------------------------------------------------
# AWS
# --------------------------------------------------------------------------------
variable "aws_region" {
  description = "AWS region for remote state resources (e.g., eu-north-1)."
  type        = string
  default     = null
}

variable "aws_profile" {
  description = "Optional AWS CLI profile to use (falls back to env/role if null)."
  type        = string
  default     = null
}

variable "aws_default_tags" {
  description = "Default AWS resource tags applied via provider default_tags."
  type        = map(string)
  default     = {
    project     = "aethernova-chain-core"
    module      = "bootstrap/remote-state"
    managed_by  = "terraform"
    environment = "prod"
  }
}

# --------------------------------------------------------------------------------
# GCP
# --------------------------------------------------------------------------------
variable "gcp_project" {
  description = "GCP project ID hosting the state bucket."
  type        = string
  default     = null
}

variable "gcp_region" {
  description = "GCP region for state bucket (e.g., europe-north1)."
  type        = string
  default     = null
}

variable "gcp_user_project_override" {
  description = "Bill requests to the user project (recommended for org policies)."
  type        = bool
  default     = true
}

# --------------------------------------------------------------------------------
# Azure
# --------------------------------------------------------------------------------
variable "azure_subscription_id" {
  description = "Azure Subscription ID for remote state resources."
  type        = string
  default     = null
}

variable "azure_tenant_id" {
  description = "Azure Tenant ID (Directory)."
  type        = string
  default     = null
}

variable "azure_environment" {
  description = "Azure cloud environment (e.g., public, usgovernment, china)."
  type        = string
  default     = "public"
  validation {
    condition = contains(
      ["public", "usgovernment", "china", "german", "stack"],
      var.azure_environment
    )
    error_message = "azure_environment must be one of: public, usgovernment, china, german, stack."
  }
}

###############################################################################
# Locals for uniform metadata across providers
###############################################################################
locals {
  # RFC-3339 timestamp useful for tagging and diagnostics
  bootstrap_timestamp = time_static.bootstrap.rfc3339
}

# Static time value captured on first apply for reproducible tags/ids
resource "time_static" "bootstrap" {}

###############################################################################
# Provider: AWS
###############################################################################
# Auth order (provider follows standard AWS resolution):
# - Explicit profile (var.aws_profile)
# - Environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN)
# - Shared config/credentials files (~/.aws/config, ~/.aws/credentials)
# - EC2/ECS/SSO/role-based metadata providers
provider "aws" {
  region  = coalesce(var.aws_region, try(data.aws_region.current.name, null))
  profile = var.aws_profile

  # Apply uniform tags to all AWS resources managed by this module.
  default_tags {
    tags = merge(
      var.aws_default_tags,
      {
        bootstrap_timestamp = local.bootstrap_timestamp
      }
    )
  }
}

# Helper data source to resolve region if not explicitly provided
data "aws_region" "current" {}

###############################################################################
# Provider: Google (GCP)
###############################################################################
# Auth order:
# - Application Default Credentials (ADC), e.g., GOOGLE_APPLICATION_CREDENTIALS
# - gcloud user credentials
# - Instance metadata (GCE)
provider "google" {
  project                 = var.gcp_project
  region                  = var.gcp_region
  user_project_override   = var.gcp_user_project_override
  request_timeout         = "60s"
  # Enable a slightly higher number of retries for robustness in orgs with policies.
  # (Provider has sensible defaults; exposed here for explicitness.)
  # batching = true  # available in newer provider versions; uncomment if needed
}

###############################################################################
# Provider: AzureRM
###############################################################################
# Auth order:
# - Environment variables (ARM_CLIENT_ID/SECRET, ARM_TENANT_ID, ARM_SUBSCRIPTION_ID)
# - Azure CLI
# - Managed Identity
provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id
  tenant_id       = var.azure_tenant_id
  environment     = var.azure_environment

  # Reduce timeouts on account ops that may be blocked by org policy, but keep
  # generous defaults for storage operations in the resource files.
}

###############################################################################
# Aliases (optional): If consumers want to pass in aliased providers explicitly
###############################################################################
provider "aws" {
  alias   = "mgmt"
  region  = coalesce(var.aws_region, try(data.aws_region.current.name, null))
  profile = var.aws_profile

  default_tags {
    tags = merge(
      var.aws_default_tags,
      {
        scope               = "mgmt"
        bootstrap_timestamp = local.bootstrap_timestamp
      }
    )
  }
}

provider "google" {
  alias                 = "mgmt"
  project               = var.gcp_project
  region                = var.gcp_region
  user_project_override = var.gcp_user_project_override
  request_timeout       = "60s"
}

provider "azurerm" {
  alias           = "mgmt"
  features        {}
  subscription_id = var.azure_subscription_id
  tenant_id       = var.azure_tenant_id
  environment     = var.azure_environment
}

###############################################################################
# Provider-sensitive validations (fail fast if required inputs are missing)
###############################################################################

# Validate required inputs when a specific cloud is selected.
# These locals compute boolean guards; separate resources (in other *.tf files)
# should additionally gate creation with `count`/`for_each` on var.cloud.
locals {
  _aws_required_ok = var.cloud != "aws" || (
    coalesce(var.aws_region, "") != ""
  )

  _gcp_required_ok = var.cloud != "gcp" || (
    coalesce(var.gcp_project, "") != "" &&
    coalesce(var.gcp_region, "")  != ""
  )

  _azure_required_ok = var.cloud != "azure" || (
    coalesce(var.azure_subscription_id, "") != "" &&
    coalesce(var.azure_tenant_id, "")       != ""
  )
}

# Terraform doesn't have a native "assert", but we can use preconditions on
# a no-op resource to fail early with a clear message per cloud.
resource "null_resource" "provider_guard" {
  triggers = {
    ts = local.bootstrap_timestamp
  }

  lifecycle {
    precondition {
      condition     = local._aws_required_ok
      error_message = "For cloud=aws, aws_region must be provided (or resolvable)."
    }
    precondition {
      condition     = local._gcp_required_ok
      error_message = "For cloud=gcp, gcp_project and gcp_region must be provided."
    }
    precondition {
      condition     = local._azure_required_ok
      error_message = "For cloud=azure, azure_subscription_id and azure_tenant_id must be provided."
    }
  }
}
