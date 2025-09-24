#############################################
# examples/aethernova-node-sa/main.tf
# Industrial-grade, multi-cloud example
# Terraform >= 1.5
#############################################

terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.0.0"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0, < 6.0.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0.0, < 5.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0, < 4.0.0"
    }
  }
}

#############################################
# Provider configuration (example/defaults)
#############################################

provider "aws" {
  region = var.aws_region
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
}

provider "azurerm" {
  features {}
}

#############################################
# Variables (example-scope)
#############################################

variable "environment" {
  description = "Окружение: dev/stage/prod."
  type        = string
}

variable "name_prefix" {
  description = "Префикс имён (орг/команда/проект)."
  type        = string
  default     = "aethernova"
}

# ---------- AWS ----------
variable "aws_region" {
  description = "AWS регион."
  type        = string
  default     = "eu-north-1"
}

variable "aws_ssm_param_prefix" {
  description = "Префикс параметров в AWS SSM Parameter Store для ноды (например, /aethernova/node/)."
  type        = string
  default     = "/aethernova/node/"
}

variable "aws_snapshot_bucket_arn" {
  description = "ARN S3 бакета со снапшотами (например, arn:aws:s3:::aethernova-node-snapshots)."
  type        = string
}

variable "aws_kms_key_arn" {
  description = "ARN KMS ключа для расшифровки данных снапшотов/секретов."
  type        = string
}

# ---------- GCP ----------
variable "gcp_project" {
  description = "GCP Project ID."
  type        = string
}

variable "gcp_region" {
  description = "GCP регион."
  type        = string
  default     = "europe-north1"
}

variable "gcs_bucket_name" {
  description = "Имя GCS бакета со снапшотами."
  type        = string
}

variable "gcp_kms_crypto_key_id" {
  description = "Полный ID KMS-ключа (google_kms_crypto_key) для расшифровки, формат: projects/.../locations/.../keyRings/.../cryptoKeys/..."
  type        = string
}

# ---------- Azure ----------
variable "azure_location" {
  description = "Azure регион (например, northeurope)."
  type        = string
  default     = "northeurope"
}

variable "azure_resource_group_name" {
  description = "Имя существующей Resource Group для размещения идентичности."
  type        = string
}

variable "azure_storage_account_id" {
  description = "Resource ID Storage Account со снапшотами (для RBAC назначения)."
  type        = string
}

variable "azure_key_vault_id" {
  description = "Resource ID Key Vault (для назначения ролей Crypto User/Reader)."
  type        = string
}

variable "tags" {
  description = "Единые теги/метки."
  type        = map(string)
  default     = {}
}

#############################################
# Locals (consistent naming)
#############################################

locals {
  workload_id        = "node"
  base_name          = "${var.name_prefix}-${var.environment}-${local.workload_id}"

  # AWS naming
  aws_role_name      = "${local.base_name}-role"
  aws_instance_prof  = "${local.base_name}-instance-profile"
  aws_policy_name    = "${local.base_name}-policy"

  # GCP naming
  gcp_sa_account_id  = replace("${local.base_name}-sa", "/[^a-z0-9-]/", "-")
  gcp_sa_display     = "Aethernova ${upper(var.environment)} Node Service Account"

  # Azure naming
  azure_uami_name    = "${local.base_name}-uami"
}

#############################################
# ---------------- AWS IAM ------------------
#############################################

# Trust policy: EC2 instances (можно расширить под EKS via IRSA при необходимости)
data "aws_iam_policy_document" "aws_trust" {
  statement {
    sid     = "EC2AssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# Least-privilege policy for node workload
data "aws_iam_policy_document" "aws_inline" {
  # Read SSM parameters under specific prefix
  statement {
    sid     = "ReadNodeParameters"
    effect  = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath"
    ]
    resources = [
      "arn:aws:ssm:${var.aws_region}:*:parameter${var.aws_ssm_param_prefix}*"
    ]
  }

  # Read snapshots from S3
  statement {
    sid     = "ReadSnapshotsS3"
    effect  = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = [
      var.aws_snapshot_bucket_arn,
      "${var.aws_snapshot_bucket_arn}/*"
    ]
  }

  # Decrypt via KMS
  statement {
    sid     = "DecryptKMS"
    effect  = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = [var.aws_kms_key_arn]
  }

  # Write logs to CloudWatch
  statement {
    sid     = "WriteLogs"
    effect  = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "node" {
  name               = local.aws_role_name
  assume_role_policy = data.aws_iam_policy_document.aws_trust.json
  tags               = merge(var.tags, { "Name" = local.aws_role_name, "Workload" = local.workload_id })
}

resource "aws_iam_role_policy" "node_inline" {
  name   = local.aws_policy_name
  role   = aws_iam_role.node.id
  policy = data.aws_iam_policy_document.aws_inline.json
}

resource "aws_iam_instance_profile" "node" {
  name = local.aws_instance_prof
  role = aws_iam_role.node.name
  tags = merge(var.tags, { "Name" = local.aws_instance_prof })
}

#############################################
# ----------------- GCP IAM -----------------
#############################################

resource "google_service_account" "node" {
  account_id   = substr(local.gcp_sa_account_id, 0, 30) # лимит GCP SA id
  display_name = local.gcp_sa_display
}

# Logs writer at project scope
resource "google_project_iam_member" "sa_logging" {
  project = var.gcp_project
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.node.email}"
}

# Optional metrics writer (часто полезно для агента)
resource "google_project_iam_member" "sa_metrics" {
  project = var.gcp_project
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.node.email}"
}

# Read snapshots from GCS bucket
resource "google_storage_bucket_iam_member" "sa_bucket_reader" {
  bucket = var.gcs_bucket_name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.node.email}"
}

# Decrypt with Cloud KMS
resource "google_kms_crypto_key_iam_member" "sa_kms_decrypter" {
  crypto_key_id = var.gcp_kms_crypto_key_id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "serviceAccount:${google_service_account.node.email}"
}

#############################################
# ---------------- Azure IAM ----------------
#############################################

# User Assigned Managed Identity
resource "azurerm_user_assigned_identity" "node" {
  name                = local.azure_uami_name
  resource_group_name = var.azure_resource_group_name
  location            = var.azure_location
  tags                = merge(var.tags, { "Name" = local.azure_uami_name, "Workload" = local.workload_id })
}

# Role: Storage Blob Data Reader (чтение снапшотов)
resource "azurerm_role_assignment" "uami_storage_reader" {
  scope              = var.azure_storage_account_id
  role_definition_name = "Storage Blob Data Reader"
  principal_id       = azurerm_user_assigned_identity.node.principal_id

  # предотвратить дрожание ID
  depends_on = [azurerm_user_assigned_identity.node]
}

# Role: Key Vault Crypto User (использование ключей для расшифровки)
resource "azurerm_role_assignment" "uami_kv_crypto_user" {
  scope                = var.azure_key_vault_id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_user_assigned_identity.node.principal_id

  depends_on = [azurerm_user_assigned_identity.node]
}

# Optional: Log Analytics Contributor / Monitoring Reader — добавить по необходимости
# resource "azurerm_role_assignment" "uami_monitoring" { ... }

#############################################
# Outputs
#############################################

output "aws_iam_role_arn" {
  description = "AWS IAM Role ARN для ноды."
  value       = aws_iam_role.node.arn
}

output "aws_instance_profile_name" {
  description = "AWS Instance Profile для привязки к EC2."
  value       = aws_iam_instance_profile.node.name
}

output "gcp_service_account_email" {
  description = "GCP Service Account email."
  value       = google_service_account.node.email
}

output "azure_uami_client_id" {
  description = "Azure User Assigned Managed Identity client_id."
  value       = azurerm_user_assigned_identity.node.client_id
}

output "azure_uami_principal_id" {
  description = "Azure User Assigned Managed Identity principal_id."
  value       = azurerm_user_assigned_identity.node.principal_id
}
