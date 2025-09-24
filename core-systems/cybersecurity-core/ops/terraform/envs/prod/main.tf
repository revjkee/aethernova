###############################################################################
# cybersecurity-core/ops/terraform/envs/prod/main.tf
# Industrial-grade prod baseline: audit S3, CloudTrail, AWS Config, GuardDuty,
# Security Hub, ECR scanning. Backend configured via -backend-config at init.
###############################################################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Intentionally empty; pass backend settings at init:
  # terraform init \
  #   -backend-config="bucket=<tfstate-bucket>" \
  #   -backend-config="key=cybersecurity-core/prod/terraform.tfstate" \
  #   -backend-config="region=<region>" \
  #   -backend-config="dynamodb_table=<lock-table>" \
  #   -backend-config="encrypt=true"
  backend "s3" {}
}

###############################################################################
# Locals & Inputs
###############################################################################

locals {
  project      = "cybersecurity-core"
  environment  = "prod"
  name_prefix  = "${local.project}-${local.environment}"

  # Unified tags for cost/accountability/compliance
  tags = merge({
    "Project"      = local.project
    "Environment"  = local.environment
    "Owner"        = "Aethernova"
    "ManagedBy"    = "Terraform"
    "SecurityTier" = "High"
  }, var.additional_tags)
}

variable "region" {
  description = "AWS region for prod"
  type        = string
  default     = "eu-north-1"
}

variable "audit_bucket_name" {
  description = "Central S3 bucket for audit logs (CloudTrail/AWS Config). Must be globally unique."
  type        = string
  default     = null
}

variable "ecr_repository_name" {
  description = "ECR repository for container images (scanning on push)."
  type        = string
  default     = "cybersecurity-core"
}

variable "additional_tags" {
  description = "Additional resource tags"
  type        = map(string)
  default     = {}
}

###############################################################################
# Providers & Data
###############################################################################

provider "aws" {
  region = var.region

  default_tags {
    tags = local.tags
  }
}

data "aws_caller_identity" "this" {}
data "aws_region" "this" {}
data "aws_partition" "this" {}

###############################################################################
# S3: Central audit bucket (versioned, encrypted, no public, TLS-only)
###############################################################################

# If audit_bucket_name not provided, derive deterministic name skeleton
locals {
  audit_bucket_name = coalesce(
    var.audit_bucket_name,
    "${local.name_prefix}-${data.aws_region.this.name}-audit-logs"
  )
}

resource "aws_s3_bucket" "audit" {
  bucket = local.audit_bucket_name

  tags = merge(local.tags, {
    "Name" = "${local.name_prefix}-audit"
  })
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Deny non-TLS and allow CloudTrail to put logs with proper ACL
resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:${data.aws_partition.this.partition}:s3:::${aws_s3_bucket.audit.id}",
          "arn:${data.aws_partition.this.partition}:s3:::${aws_s3_bucket.audit.id}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid = "AllowCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.${data.aws_partition.this.dns_suffix}"
        }
        Action = "s3:GetBucketAcl"
        Resource = "arn:${data.aws_partition.this.partition}:s3:::${aws_s3_bucket.audit.id}"
      },
      {
        Sid = "AllowCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.${data.aws_partition.this.dns_suffix}"
        }
        Action = "s3:PutObject"
        Resource = "arn:${data.aws_partition.this.partition}:s3:::${aws_s3_bucket.audit.id}/AWSLogs/${data.aws_caller_identity.this.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# Optional lifecycle (retain noncurrent versions for 180 days)
resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    id     = "retain-noncurrent"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 180
    }
  }
}

###############################################################################
# CloudTrail: multi-region, global services, validation -> S3 audit bucket
###############################################################################

resource "aws_cloudtrail" "main" {
  name                          = "${local.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.audit.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  # By default CloudTrail writes under s3://<bucket>/AWSLogs/<account-id>/CloudTrail/<region>/
  # (no s3_key_prefix to keep policy simple)

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    # Data events can be significant in size; enable selectively if needed
    # data_resource {
    #   type   = "AWS::S3::Object"
    #   values = ["arn:${data.aws_partition.this.partition}:s3:::"]
    # }
  }

  tags = merge(local.tags, {
    "Name" = "${local.name_prefix}-trail"
  })
}

###############################################################################
# AWS Config: recorder + delivery channel to the audit bucket
###############################################################################

resource "aws_iam_role" "config" {
  name = "${local.name_prefix}-aws-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.${data.aws_partition.this.dns_suffix}" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.tags
}

# Attach AWS managed policy for AWS Config service role
resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:${data.aws_partition.this.partition}:iam::aws:policy/service-role/AWSConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${local.name_prefix}-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
    # resource_types              = [] # optional fine-grain
  }

  depends_on = [aws_iam_role_policy_attachment.config_managed]
}

resource "aws_config_delivery_channel" "main" {
  name           = "${local.name_prefix}-config-channel"
  s3_bucket_name = aws_s3_bucket.audit.bucket
  s3_key_prefix  = "awsconfig"

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

###############################################################################
# GuardDuty & Security Hub: enable detectors and account
###############################################################################

resource "aws_guardduty_detector" "main" {
  enable = true
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes = true
      }
    }
  }

  tags = merge(local.tags, {
    "Name" = "${local.name_prefix}-guardduty"
  })
}

resource "aws_securityhub_account" "main" {
  enable_default_standards = false # стандарты можно включить отдельными ресурсами в нужной версии
  control_finding_generator = "SECURITY_CONTROL"
  tags = merge(local.tags, {
    "Name" = "${local.name_prefix}-securityhub"
  })
}

###############################################################################
# ECR: repository with scanning on push
###############################################################################

resource "aws_ecr_repository" "app" {
  name                 = var.ecr_repository_name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = merge(local.tags, {
    "Name" = "${local.name_prefix}-ecr"
  })
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy     = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 50 images, expire older"
        action       = { type = "expire" }
        selection    = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 50
        }
      }
    ]
  })
}

###############################################################################
# Outputs (optional)
###############################################################################

output "audit_bucket_name" {
  description = "Audit S3 bucket"
  value       = aws_s3_bucket.audit.bucket
}

output "cloudtrail_trail_arn" {
  description = "CloudTrail trail ARN"
  value       = aws_cloudtrail.main.arn
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "securityhub_account_id" {
  description = "Security Hub account ID"
  value       = aws_securityhub_account.main.id
}

output "ecr_repository_url" {
  description = "ECR repository URL"
  value       = aws_ecr_repository.app.repository_url
}
