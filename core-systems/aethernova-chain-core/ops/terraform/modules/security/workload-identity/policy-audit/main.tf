// SPDX-License-Identifier: Apache-2.0
// Module: aethernova-chain-core/ops/terraform/modules/security/policy-audit
// File:   main.tf
// Purpose:
//   Cross-cloud audit & security posture bootstrap:
//     - AWS: CloudTrail (+ S3/KMS, CloudWatch Logs), data events selectors.
//     - GCP: Audit Logs (ADMIN_READ/DATA_READ/DATA_WRITE) at project/folder/org scope.
//     - Azure: Microsoft Defender for Cloud plans (Security Center), auto-provisioning, contact.
// Notes:
//   - Provider configuration (aws/google/azurerm) must be in the ROOT module.
//   - Each cloud is enabled via a flag; safe defaults prevent accidental costs.

//-----------------------------
// Terraform requirements
//-----------------------------
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50.0"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 5.37.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.117.0"
    }
  }
}

//-----------------------------
// Global toggles
//-----------------------------
variable "enable_aws"   { type = bool, default = false, description = "Включить аудит в AWS (CloudTrail/S3/KMS/CloudWatch)." }
variable "enable_gcp"   { type = bool, default = false, description = "Включить Audit Logs в GCP (project/folder/org)." }
variable "enable_azure" { type = bool, default = false, description = "Включить Defender for Cloud (Security Center) в Azure." }

//-----------------------------
// AWS — CloudTrail + S3/KMS + CloudWatch
//-----------------------------
variable "aws" {
  description = <<-EOT
    Настройки AWS-аудита:
      - trail_name: имя CloudTrail.
      - s3_bucket_name: имя S3 для логов (если null — создаётся с именем на основе аккаунта/регионa).
      - s3_force_destroy: позволять удаление с версиями.
      - kms_create: создать KMS-ключ для шифрования (или использовать kms_key_arn).
      - kms_key_arn: ARN существующего KMS-ключа (если kms_create=false).
      - cw_logs_enabled: включить доставку в CloudWatch Logs.
      - is_organization_trail: организационный трейл (требует AWS Organizations).
      - include_management_events: логировать management events.
      - data_events:
          s3_buckets: список ARN бакетов (логируются объекты).
          lambda_functions: список ARN функций.
          dynamodb_tables: список ARN таблиц.
  EOT
  type = object({
    trail_name               = optional(string, "aethernova-org-trail")
    s3_bucket_name           = optional(string)
    s3_force_destroy         = optional(bool, false)
    kms_create               = optional(bool, true)
    kms_key_arn              = optional(string)
    cw_logs_enabled          = optional(bool, true)
    is_organization_trail    = optional(bool, false)
    include_management_events= optional(bool, true)
    data_events = optional(object({
      s3_buckets       = optional(list(string), [])
      lambda_functions = optional(list(string), [])
      dynamodb_tables  = optional(list(string), [])
    }), {})
    tags = optional(map(string), {})
  })
  default = {}
}

# Identity/partition to build ARNs and bucket name defaults
data "aws_caller_identity" "current" {
  count = var.enable_aws ? 1 : 0
}
data "aws_region" "current" {
  count = var.enable_aws ? 1 : 0
}
data "aws_partition" "current" {
  count = var.enable_aws ? 1 : 0
}

locals {
  aws_account_id = var.enable_aws ? data.aws_caller_identity.current[0].account_id : null
  aws_region     = var.enable_aws ? data.aws_region.current[0].name : null
  aws_bucket_name_effective = var.enable_aws ? coalesce(try(var.aws.s3_bucket_name, null), "cloudtrail-${local.aws_account_id}-${local.aws_region}") : null
  aws_tags = try(var.aws.tags, {})
}

# S3 bucket for CloudTrail logs (versioned, encrypted, blocked public)
resource "aws_s3_bucket" "cloudtrail" {
  count  = var.enable_aws ? 1 : 0
  bucket = local.aws_bucket_name_effective
  force_destroy = try(var.aws.s3_force_destroy, false)

  tags = merge(local.aws_tags, {
    "Name" = local.aws_bucket_name_effective
  })
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count  = var.enable_aws ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  count  = var.enable_aws ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  versioning_configuration { status = "Enabled" }
}

# KMS key for S3 SSE-KMS and CloudTrail encryption (optional create)
resource "aws_kms_key" "cloudtrail" {
  count               = var.enable_aws && try(var.aws.kms_create, true) ? 1 : 0
  description         = "KMS key for CloudTrail log encryption"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowRootAccount"
        Effect   = "Allow"
        Principal= { AWS = "arn:${data.aws_partition.current[0].partition}:iam::${local.aws_account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid = "AllowCloudTrailUseOfTheKey"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action = [
          "kms:Encrypt","kms:Decrypt","kms:ReEncrypt*","kms:GenerateDataKey*","kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
  tags = local.aws_tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count  = var.enable_aws ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = try(var.aws.kms_create, true) ? aws_kms_key.cloudtrail[0].arn : try(var.aws.kms_key_arn, null)
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# S3 policy allowing CloudTrail to write logs to the bucket (per AWS docs)
data "aws_iam_policy_document" "cloudtrail_bucket" {
  count = var.enable_aws ? 1 : 0

  statement {
    sid = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail[0].arn]
    principals { type = "Service" identifiers = ["cloudtrail.amazonaws.com"] }
  }

  statement {
    sid = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail[0].arn}/AWSLogs/${local.aws_account_id}/*"]
    principals { type = "Service" identifiers = ["cloudtrail.amazonaws.com"] }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count  = var.enable_aws ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  policy = data.aws_iam_policy_document.cloudtrail_bucket[0].json
}

# CloudWatch Logs (optional)
resource "aws_cloudwatch_log_group" "cloudtrail" {
  count             = var.enable_aws && try(var.aws.cw_logs_enabled, true) ? 1 : 0
  name              = "/aws/cloudtrail/${try(var.aws.trail_name, "aethernova-org-trail")}"
  retention_in_days = 90
  tags              = local.aws_tags
}

resource "aws_iam_role" "cloudtrail_cw" {
  count = var.enable_aws && try(var.aws.cw_logs_enabled, true) ? 1 : 0
  name  = "CloudTrail_LogsRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
  tags = local.aws_tags
}

resource "aws_iam_role_policy" "cloudtrail_cw" {
  count = var.enable_aws && try(var.aws.cw_logs_enabled, true) ? 1 : 0
  name  = "CloudTrail_LogsPolicy"
  role  = aws_iam_role.cloudtrail_cw[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogStream","logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
    }]
  })
}

# CloudTrail itself
resource "aws_cloudtrail" "this" {
  count = var.enable_aws ? 1 : 0

  name                          = try(var.aws.trail_name, "aethernova-org-trail")
  s3_bucket_name                = aws_s3_bucket.cloudtrail[0].bucket
  kms_key_id                    = try(var.aws.kms_create, true) ? aws_kms_key.cloudtrail[0].arn : try(var.aws.kms_key_arn, null)
  include_global_service_events = try(var.aws.include_management_events, true)
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  is_organization_trail         = try(var.aws.is_organization_trail, false)

  dynamic "cloud_watch_logs_group_arn" {
    for_each = try(var.aws.cw_logs_enabled, true) ? [1] : []
    content  = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
  }
  dynamic "cloud_watch_logs_role_arn" {
    for_each = try(var.aws.cw_logs_enabled, true) ? [1] : []
    content  = aws_iam_role.cloudtrail_cw[0].arn
  }

  event_selector {
    read_write_type           = "All"
    include_management_events = try(var.aws.include_management_events, true)

    dynamic "data_resource" {
      for_each = toset(try(var.aws.data_events.s3_buckets, []))
      content {
        type   = "AWS::S3::Object"
        values = ["${data_resource.value}/"]
      }
    }

    dynamic "data_resource" {
      for_each = toset(try(var.aws.data_events.lambda_functions, []))
      content {
        type   = "AWS::Lambda::Function"
        values = [data_resource.value]
      }
    }

    dynamic "data_resource" {
      for_each = toset(try(var.aws.data_events.dynamodb_tables, []))
      content {
        type   = "AWS::DynamoDB::Table"
        values = [data_resource.value]
      }
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
  tags       = local.aws_tags
}

//-----------------------------
// GCP — Audit Logs (project/folder/org)
//-----------------------------
variable "gcp" {
  description = <<-EOT
    Настройки GCP Audit Logs:
      - scope: "project" | "folder" | "organization"
      - project_id / folder_id / organization_id: идентификатор уровня.
      - enable_admin_read/data_read/data_write: включаемые типы логов.
      - exempted_members: список членов, исключаемых из аудита (опционально).
      - labels: ярлыки.
  EOT
  type = object({
    scope           = optional(string, "project")
    project_id      = optional(string)
    folder_id       = optional(string)
    organization_id = optional(string)
    enable_admin_read = optional(bool, true)
    enable_data_read  = optional(bool, true)
    enable_data_write = optional(bool, true)
    exempted_members  = optional(list(string), [])
    labels            = optional(map(string), {})
  })
  default = {}
}

# Project-level
resource "google_project_iam_audit_config" "project_all" {
  count   = var.enable_gcp && try(var.gcp.scope, "project") == "project" ? 1 : 0
  project = var.gcp.project_id
  service = "allServices"

  dynamic "audit_log_config" {
    for_each = try(var.gcp.enable_admin_read, true) ? [1] : []
    content {
      log_type         = "ADMIN_READ"
      exempted_members = try(var.gcp.exempted_members, [])
    }
  }
  dynamic "audit_log_config" {
    for_each = try(var.gcp.enable_data_read, true) ? [1] : []
    content {
      log_type         = "DATA_READ"
      exempted_members = try(var.gcp.exempted_members, [])
    }
  }
  dynamic "audit_log_config" {
    for_each = try(var.gcp.enable_data_write, true) ? [1] : []
    content {
      log_type         = "DATA_WRITE"
      exempted_members = try(var.gcp.exempted_members, [])
    }
  }
}

# Folder-level
resource "google_folder_iam_audit_config" "folder_all" {
  count  = var.enable_gcp && try(var.gcp.scope, "project") == "folder" ? 1 : 0
  folder = var.gcp.folder_id
  service = "allServices"

  dynamic "audit_log_config" {
    for_each = try(var.gcp.enable_admin_read, true) ? [1] : []
    content {
      log_type         = "ADMIN_READ"
      exempted_members = try(var.gcp.exempted_members, [])
    }
  }
  dynamic "audit_log_config" {
    for_each = try(var.gcp.enable_data_read, true) ? [1] : []
    content {
      log_type         = "DATA_READ"
      exempted_members = try(var.gcp.exempted_members, [])
    }
  }
  dynamic "audit_log_config" {
    for_each = try(var.gcp.enable_data_write, true) ? [1] : []
    content {
      log_type         = "DATA_WRITE"
      exempted_members = try(var.gcp.exempted_members, [])
    }
  }
}

# Organization-level
resource "google_organization_iam_audit_config" "org_all" {
  count        = var.enable_gcp && try(var.gcp.scope, "project") == "organization" ? 1 : 0
  org_id       = var.gcp.organization_id
  service      = "allServices"

  dynamic "audit_log_config" {
    for_each = try(var.gcp.enable_admin_read, true) ? [1] : []
    content {
      log_type         = "ADMIN_READ"
      exempted_members = try(var.gcp.exempted_members, [])
    }
  }
  dynamic "audit_log_config" {
    for_each = try(var.gcp.enable_data_read, true) ? [1] : []
    content {
      log_type         = "DATA_READ"
      exempted_members = try(var.gcp.exempted_members, [])
    }
  }
  dynamic "audit_log_config" {
    for_each = try(var.gcp.enable_data_write, true) ? [1] : []
    content {
      log_type         = "DATA_WRITE"
      exempted_members = try(var.gcp.exempted_members, [])
    }
  }
}

//-----------------------------
// Azure — Microsoft Defender for Cloud (Security Center)
//-----------------------------
variable "azure" {
  description = <<-EOT
    Настройки Azure Defender for Cloud:
      - auto_provisioning: "On"|"Off" для автопровижининга.
      - contact_email/phone: контакт для алертов.
      - alert_notifications/alerts_to_admins: флаги уведомлений.
      - defender_plans: map(resource_type => object({ tier, subplan, extensions }))
        resource_type примеры: "VirtualMachines","AppServices","StorageAccounts","KubernetesService","SqlServers","SqlManagedInstances","KeyVaults","ContainerRegistry","Dns","Arm","OpenSourceRelationalDatabases".
        tier: "Standard" | "Free"
        subplan: строка (например "DefenderForStorageV2")
        extensions: map для extension.name и additional_extension_properties.
  EOT
  type = object({
    auto_provisioning = optional(string, "Off")
    contact_email     = optional(string)
    phone             = optional(string, null)
    alert_notifications = optional(bool, true)
    alerts_to_admins    = optional(bool, true)
    defender_plans = optional(map(object({
      tier       = optional(string, "Standard")
      resource_type = string
      subplan    = optional(string)
      extensions = optional(map(string), {})
    })), {})
  })
  default = {}
}

# Auto-provisioning (Security Center)
resource "azurerm_security_center_auto_provisioning" "this" {
  count          = var.enable_azure ? 1 : 0
  auto_provision = try(var.azure.auto_provisioning, "Off")
}

# Subscription pricing (Defender plans)
resource "azurerm_security_center_subscription_pricing" "plan" {
  for_each     = var.enable_azure ? try(var.azure.defender_plans, {}) : {}
  tier         = coalesce(try(each.value.tier, null), "Standard")
  resource_type= each.value.resource_type
  subplan      = try(each.value.subplan, null)

  dynamic "extension" {
    for_each = length(try(each.value.extensions, {})) > 0 ? [1] : []
    content {
      name = keys(each.value.extensions)[0]
      additional_extension_properties = each.value.extensions
    }
  }
}

# Security contact
resource "azurerm_security_center_contact" "this" {
  count                 = var.enable_azure && try(var.azure.contact_email, null) != null ? 1 : 0
  email                 = var.azure.contact_email
  phone                 = try(var.azure.phone, null)
  alert_notifications   = try(var.azure.alert_notifications, true)
  alerts_to_admins      = try(var.azure.alerts_to_admins, true)
}

//-----------------------------
// Outputs (minimal essentials)
//-----------------------------
output "aws_cloudtrail_arn" {
  description = "ARN CloudTrail (если включен)."
  value       = try(aws_cloudtrail.this[0].arn, null)
}

output "aws_cloudtrail_s3_bucket" {
  description = "Имя S3-бакета для логов CloudTrail."
  value       = try(aws_s3_bucket.cloudtrail[0].bucket, null)
}

output "gcp_audit_scope" {
  description = "Уровень GCP audit-config (project/folder/organization)."
  value       = try(var.gcp.scope, null)
}

output "azure_defender_plans" {
  description = "Итоговая карта подключенных Defender-планов по ресурсам."
  value       = { for k, v in azurerm_security_center_subscription_pricing.plan : k => { id = v.id, resource_type = v.resource_type, tier = v.tier, subplan = try(v.subplan, null) } }
}
