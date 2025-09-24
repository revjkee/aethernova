#############################################
# versions.tf — security/kms-keys (industrial)
# Purpose: Pin Terraform & providers for KMS/Key Vault usage
# Terraform >= 1.5 recommended
#############################################

terraform {
  # Require Terraform CLI version
  required_version = ">= 1.5.0, < 2.0.0"

  # Pin and source providers used by multi-cloud KMS modules
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.0.0"
    }

    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0.0, < 5.0.0"
    }

    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0, < 6.0.0"
    }

    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.0.0, < 6.0.0"
    }

    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.0, < 5.0.0"
    }

    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0, < 4.0.0"
    }

    time = {
      source  = "hashicorp/time"
      version = ">= 0.9.0, < 2.0.0"
    }
  }
}

#############################################
# Notes:
# - aws:     AWS KMS (aws_kms_key, grants, aliases)
# - azurerm: Azure Key Vault & Keys (azurerm_key_vault, azurerm_key_vault_key)
# - google:  Cloud KMS (google_kms_key_ring, crypto_keys, IAM)
# - tls:     Local key material (when needed for bootstrap or tests)
# - random:  Random suffixes/bytes where appropriate (aliases, names)
# - time:    Time-based resources for rotation/testing scenarios
#############################################
