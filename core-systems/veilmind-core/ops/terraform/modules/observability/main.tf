// File: veilmind-core/ops/terraform/modules/observability/main.tf
// Industrial-grade Observability module for AWS (AMP/AMG/CloudWatch + IRSA)

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
  }
}

########################################
# Inputs
########################################

variable "name" {
  description = "Logical name/prefix for resources (e.g. 'veilmind-core')"
  type        = string
}

variable "environment" {
  description = "Environment label (e.g. 'prod'|'staging'|'dev')"
  type        = string
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "kms_key_id" {
  description = "Optional KMS key id/arn for logs encryption (CloudWatch)"
  type        = string
  default     = null
}

# Feature toggles
variable "enable_amp" {
  description = "Create Amazon Managed Prometheus workspace"
  type        = bool
  default     = true
}

variable "enable_amg" {
  description = "Create Amazon Managed Grafana workspace"
  type        = bool
  default     = true
}

variable "enable_cloudwatch_logs" {
  description = "Create CloudWatch Log Groups"
  type        = bool
  default     = true
}

# CloudWatch logs
variable "log_groups" {
  description = "List of CloudWatch Log Groups to create (names)"
  type        = list(string)
  default     = [
    "/aws/veilmind/api",
    "/aws/veilmind/worker",
    "/aws/veilmind/otel"
  ]
}

variable "log_retention_days" {
  description = "Retention in days for log groups"
  type        = number
  default     = 30
}

# IRSA (OTel/агенты) — требуются данные OIDC и имя ServiceAccount
variable "cluster_oidc_provider_arn" {
  description = "ARN of EKS cluster OIDC provider (for IRSA). Example: arn:aws:iam::<acc>:oidc-provider/oidc.eks.<region>.amazonaws.com/id/<id>"
  type        = string
}

variable "cluster_oidc_provider_url" {
  description = "Issuer URL of OIDC provider (without https://). Example: oidc.eks.<region>.amazonaws.com/id/<id>"
  type        = string
}

variable "irsa_serviceaccount_namespace" {
  description = "Namespace of ServiceAccount used by OTel collector/agents"
  type        = string
  default     = "observability"
}

variable "irsa_serviceaccount_name" {
  description = "ServiceAccount name used by OTel collector/agents"
  type        = string
  default     = "otel-collector"
}

# AMG settings
variable "amg_authentication_providers" {
  description = "Grafana auth providers. Allowed: ['SSO','SAML']"
  type        = list(string)
  default     = ["SSO"]
}

variable "amg_account_access_type" {
  description = "AMG account access type: CURRENT_ACCOUNT or ORGANIZATION"
  type        = string
  default     = "CURRENT_ACCOUNT"
  validation {
    condition     = contains(["CURRENT_ACCOUNT", "ORGANIZATION"], var.amg_account_access_type)
    error_message = "amg_account_access_type must be CURRENT_ACCOUNT or ORGANIZATION."
  }
}

variable "amg_permission_type" {
  description = "AMG permission type: SERVICE_MANAGED or CUSTOMER_MANAGED"
  type        = string
  default     = "SERVICE_MANAGED"
}

variable "amg_workspace_name" {
  description = "AMG workspace description/name"
  type        = string
  default     = "veilmind-core"
}

# Optional AMG API key (sensitive)
variable "amg_api_key_name" {
  description = "If non-empty, create Grafana API key with this name"
  type        = string
  default     = ""
}

variable "amg_api_key_ttl_seconds" {
  description = "TTL in seconds for AMG API key"
  type        = number
  default     = 86400
}

variable "amg_api_key_role" {
  description = "Role for AMG API key: VIEWER | EDITOR | ADMIN"
  type        = string
  default     = "ADMIN"
}

# AMP rule groups (optional). Map: <namespace_name> => YAML content string
variable "amp_rule_groups_yaml" {
  description = "Map of AMP rule group namespaces to YAML content for recording/alerting rules"
  type        = map(string)
  default     = {}
}

########################################
# Data
########################################

data "aws_caller_identity" "this" {}
data "aws_region" "this" {}

locals {
  name_prefix = "${var.name}-${var.environment}"
  common_tags = merge(
    {
      "Project"     = var.name
      "Environment" = var.environment
      "ManagedBy"   = "Terraform"
      "Module"      = "veilmind-core/observability"
    },
    var.tags
  )
}

########################################
# CloudWatch Log Groups
########################################

resource "aws_cloudwatch_log_group" "this" {
  for_each          = var.enable_cloudwatch_logs ? toset(var.log_groups) : []
  name              = each.key
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_id
  tags              = local.common_tags
}

########################################
# Amazon Managed Prometheus (AMP)
########################################

resource "aws_prometheus_workspace" "this" {
  count       = var.enable_amp ? 1 : 0
  alias       = local.name_prefix
  tags        = local.common_tags
  logging_configuration {
    log_group_arn = var.enable_cloudwatch_logs && contains(var.log_groups, "/aws/veilmind/otel") ?
      aws_cloudwatch_log_group.this["/aws/veilmind/otel"].arn : null
  }
}

# Optional: rule group namespaces for AMP
resource "aws_prometheus_rule_group_namespace" "this" {
  for_each     = var.enable_amp ? var.amp_rule_groups_yaml : {}
  name         = each.key
  workspace_id = aws_prometheus_workspace.this[0].id
  data         = each.value
  depends_on   = [aws_prometheus_workspace.this]
}

########################################
# IAM for IRSA (OTel/agents) - Least Privilege
########################################

data "aws_iam_policy_document" "irsa_assume" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.cluster_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.cluster_oidc_provider_url}:sub"
      values   = ["system:serviceaccount:${var.irsa_serviceaccount_namespace}:${var.irsa_serviceaccount_name}"]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.cluster_oidc_provider_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "irsa_otel" {
  name               = "${local.name_prefix}-irsa-otel"
  assume_role_policy = data.aws_iam_policy_document.irsa_assume.json
  tags               = local.common_tags
}

# AMP RemoteWrite + read/query minimal
data "aws_iam_policy_document" "amp" {
  statement {
    effect = "Allow"
    actions = [
      "aps:RemoteWrite",
      "aps:GetSeries",
      "aps:GetLabels",
      "aps:GetMetricMetadata",
      "aps:QueryMetrics"
    ]
    resources = var.enable_amp ? [aws_prometheus_workspace.this[0].arn] : ["*"]
  }
}

# CloudWatch Logs (create stream + put events)
data "aws_iam_policy_document" "logs" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams"
    ]
    resources = [
      for lg in (var.enable_cloudwatch_logs ? aws_cloudwatch_log_group.this : {}) :
      "${lg.arn}:*"
    ]
  }
}

# X-Ray (optional, safe to include)
data "aws_iam_policy_document" "xray" {
  statement {
    effect = "Allow"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
      "xray:GetSamplingRules",
      "xray:GetSamplingTargets",
      "xray:GetSamplingStatisticSummaries"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "irsa_amp" {
  name   = "${local.name_prefix}-amp"
  policy = data.aws_iam_policy_document.amp.json
  tags   = local.common_tags
}

resource "aws_iam_policy" "irsa_logs" {
  name   = "${local.name_prefix}-logs"
  policy = data.aws_iam_policy_document.logs.json
  tags   = local.common_tags
}

resource "aws_iam_policy" "irsa_xray" {
  name   = "${local.name_prefix}-xray"
  policy = data.aws_iam_policy_document.xray.json
  tags   = local.common_tags
}

resource "aws_iam_role_policy_attachment" "irsa_amp_attach" {
  role       = aws_iam_role.irsa_otel.name
  policy_arn = aws_iam_policy.irsa_amp.arn
}

resource "aws_iam_role_policy_attachment" "irsa_logs_attach" {
  role       = aws_iam_role.irsa_otel.name
  policy_arn = aws_iam_policy.irsa_logs.arn
}

resource "aws_iam_role_policy_attachment" "irsa_xray_attach" {
  role       = aws_iam_role.irsa_otel.name
  policy_arn = aws_iam_policy.irsa_xray.arn
}

########################################
# Amazon Managed Grafana (AMG)
########################################

resource "aws_grafana_workspace" "this" {
  count                     = var.enable_amg ? 1 : 0
  name                      = var.amg_workspace_name
  account_access_type       = var.amg_account_access_type
  authentication_providers  = var.amg_authentication_providers
  permission_type           = var.amg_permission_type
  # workspace_data_sources  = ["PROMETHEUS", "CLOUDWATCH", "XRAY"] // optional if supported
  tags                      = local.common_tags
}

# Optional API key (sensitive)
resource "aws_grafana_workspace_api_key" "this" {
  count            = var.enable_amg && length(var.amg_api_key_name) > 0 ? 1 : 0
  key_name         = var.amg_api_key_name
  key_role         = var.amg_api_key_role
  seconds_to_live  = var.amg_api_key_ttl_seconds
  workspace_id     = aws_grafana_workspace.this[0].id
}

########################################
# Outputs
########################################

output "amp_workspace_id" {
  description = "AMP workspace ID"
  value       = try(aws_prometheus_workspace.this[0].id, null)
}

output "amp_workspace_arn" {
  description = "AMP workspace ARN"
  value       = try(aws_prometheus_workspace.this[0].arn, null)
}

output "amp_remote_write_endpoint" {
  description = "AMP remote write URL"
  value       = try(aws_prometheus_workspace.this[0].prometheus_endpoint, null)
}

output "amg_workspace_id" {
  description = "AMG workspace ID"
  value       = try(aws_grafana_workspace.this[0].id, null)
}

output "amg_workspace_endpoint" {
  description = "AMG workspace endpoint URL"
  value       = try(aws_grafana_workspace.this[0].endpoint, null)
}

output "irsa_role_arn" {
  description = "IAM role ARN for IRSA (attach to ServiceAccount via eks.amazonaws.com/role-arn)"
  value       = aws_iam_role.irsa_otel.arn
}

output "cloudwatch_log_group_arns" {
  description = "List of created CloudWatch Log Group ARNs"
  value       = var.enable_cloudwatch_logs ? [for lg in aws_cloudwatch_log_group.this : lg.arn] : []
}

output "amg_api_key_value" {
  description = "Sensitive AMG API key (if created)"
  value       = try(aws_grafana_workspace_api_key.this[0].key, null)
  sensitive   = true
}
