# path: omnimind-core/ops/ansible/playbooks/modules/queue/main.tf
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

############################################################
# Locals
############################################################
locals {
  base_name   = coalesce(var.name, format("%s-%s-queue", var.project, var.environment))
  queue_name  = var.fifo ? (endswith(local.base_name, ".fifo") ? local.base_name : "${local.base_name}.fifo") : local.base_name
  dlq_name    = var.fifo ? "${local.queue_name}-dlq.fifo" : "${local.queue_name}-dlq"

  common_tags = merge(
    {
      Name        = local.queue_name
      Project     = var.project
      Environment = var.environment
      ManagedBy   = "Terraform"
      Module      = "omnimind-core/queue"
    },
    var.tags
  )

  use_kms         = var.create_kms_key || try(length(var.kms_key_id) > 0, false)
  kms_key_arn     = var.create_kms_key ? aws_kms_key.this[0].arn : (try(var.kms_key_id, null))
  enable_sse_sqs  = !local.use_kms && var.sse_sqs_enabled

  # Build queue policy if any restriction configured
  policy_statements = compact([
    (length(var.allowed_principals) > 0 || length(var.source_vpce_ids) > 0) ? jsonencode({
      Sid       = "QueueAccessControl"
      Effect    = "Allow"
      Principal = length(var.allowed_principals) > 0 ? { AWS = var.allowed_principals } : "*"
      Action    = var.allowed_actions
      Resource  = "*"
      Condition = length(var.source_vpce_ids) > 0 ? {
        StringEquals = { "aws:SourceVpce" = var.source_vpce_ids }
      } : null
    }) : null
  ])

  queue_policy = length(local.policy_statements) > 0 ? jsonencode({
    Version   = "2012-10-17"
    Statement = [for s in local.policy_statements : jsondecode(s)]
  }) : null
}

############################################################
# KMS (optional, if create_kms_key=true)
############################################################
resource "aws_kms_key" "this" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "KMS key for ${local.queue_name} SQS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = var.kms_key_policy
  tags                    = local.common_tags
}

resource "aws_kms_alias" "this" {
  count         = var.create_kms_key ? 1 : 0
  name          = "alias/${replace(local.queue_name, ".", "-")}"
  target_key_id = aws_kms_key.this[0].id
}

############################################################
# DLQ (optional)
############################################################
resource "aws_sqs_queue" "dlq" {
  count = var.redrive.enabled ? 1 : 0

  name                              = local.dlq_name
  fifo_queue                        = var.fifo
  content_based_deduplication       = var.fifo ? var.content_based_deduplication : null
  deduplication_scope               = var.fifo ? var.deduplication_scope : null
  fifo_throughput_limit             = var.fifo ? var.fifo_throughput_limit : null

  message_retention_seconds         = var.redrive.dlq_message_retention_seconds
  visibility_timeout_seconds        = var.visibility_timeout_seconds
  max_message_size                  = var.max_message_size
  delay_seconds                     = var.delay_seconds
  receive_wait_time_seconds         = var.receive_wait_time_seconds

  kms_master_key_id                 = local.kms_key_arn
  kms_data_key_reuse_period_seconds = local.use_kms ? var.kms_data_key_reuse_period_seconds : null
  sqs_managed_sse_enabled           = local.enable_sse_sqs

  tags = merge(local.common_tags, { Purpose = "DLQ" })
}

# Allow redrive into DLQ from main queue
resource "aws_sqs_queue_redrive_allow_policy" "dlq_allow" {
  count = var.redrive.enabled ? 1 : 0

  queue_url = aws_sqs_queue.dlq[0].id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = ["${aws_sqs_queue.main.arn}"]
  })
}

############################################################
# Main Queue
############################################################
resource "aws_sqs_queue" "main" {
  name                              = local.queue_name
  fifo_queue                        = var.fifo
  content_based_deduplication       = var.fifo ? var.content_based_deduplication : null
  deduplication_scope               = var.fifo ? var.deduplication_scope : null
  fifo_throughput_limit             = var.fifo ? var.fifo_throughput_limit : null

  # Core timings
  delay_seconds                     = var.delay_seconds
  max_message_size                  = var.max_message_size
  message_retention_seconds         = var.message_retention_seconds
  receive_wait_time_seconds         = var.receive_wait_time_seconds
  visibility_timeout_seconds        = var.visibility_timeout_seconds

  # Encryption
  kms_master_key_id                 = local.kms_key_arn
  kms_data_key_reuse_period_seconds = local.use_kms ? var.kms_data_key_reuse_period_seconds : null
  sqs_managed_sse_enabled           = local.enable_sse_sqs

  # Redrive to DLQ
  redrive_policy = var.redrive.enabled ? jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq[0].arn
    maxReceiveCount     = var.redrive.max_receive_count
  }) : null

  # Access policy (optional)
  policy = local.queue_policy

  tags = local.common_tags
}

############################################################
# CloudWatch Alarms (optional)
############################################################
resource "aws_cloudwatch_metric_alarm" "depth" {
  count               = var.alarms.enabled ? 1 : 0
  alarm_name          = "${local.queue_name}-DepthHigh"
  alarm_description   = "SQS visible messages exceed threshold"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = var.alarms.period
  evaluation_periods  = var.alarms.evaluation_periods
  threshold           = var.alarms.depth_threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  dimensions          = { QueueName = aws_sqs_queue.main.name }
  treat_missing_data  = var.alarms.treat_missing_data
  alarm_actions       = var.alarms.alarm_actions
  ok_actions          = var.alarms.ok_actions
  tags                = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "age" {
  count               = var.alarms.enabled ? 1 : 0
  alarm_name          = "${local.queue_name}-OldestAgeHigh"
  alarm_description   = "SQS oldest message age exceeds threshold"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  statistic           = "Maximum"
  period              = var.alarms.period
  evaluation_periods  = var.alarms.evaluation_periods
  threshold           = var.alarms.age_threshold_seconds
  comparison_operator = "GreaterThanOrEqualToThreshold"
  dimensions          = { QueueName = aws_sqs_queue.main.name }
  treat_missing_data  = var.alarms.treat_missing_data
  alarm_actions       = var.alarms.alarm_actions
  ok_actions          = var.alarms.ok_actions
  tags                = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  count               = var.alarms.enabled && var.redrive.enabled ? 1 : 0
  alarm_name          = "${local.dlq_name}-DLQDepthNonZero"
  alarm_description   = "DLQ visible messages exceed threshold"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = var.alarms.period
  evaluation_periods  = var.alarms.evaluation_periods
  threshold           = var.alarms.dlq_depth_threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  dimensions          = { QueueName = aws_sqs_queue.dlq[0].name }
  treat_missing_data  = var.alarms.treat_missing_data
  alarm_actions       = var.alarms.alarm_actions
  ok_actions          = var.alarms.ok_actions
  tags                = local.common_tags
}

############################################################
# Variables
############################################################
variable "project" {
  description = "Project identifier for tagging and naming."
  type        = string
}

variable "environment" {
  description = "Environment name (e.g., prod, stage)."
  type        = string
}

variable "name" {
  description = "Explicit queue name. If null, computed from project/environment. For FIFO queues .fifo suffix is auto-appended."
  type        = string
  default     = null
  validation {
    condition     = var.name == null || length(var.name) >= 3
    error_message = "If provided, name must be at least 3 characters."
  }
}

variable "tags" {
  description = "Additional resource tags."
  type        = map(string)
  default     = {}
}

# Queue mode
variable "fifo" {
  description = "Create FIFO queue."
  type        = bool
  default     = false
}

variable "content_based_deduplication" {
  description = "Enable content-based deduplication (FIFO only)."
  type        = bool
  default     = true
}

variable "fifo_throughput_limit" {
  description = "FIFO throughput limit (perQueue or perMessageGroupId). FIFO only."
  type        = string
  default     = "perMessageGroupId"
  validation {
    condition     = contains(["perQueue", "perMessageGroupId"], var.fifo_throughput_limit)
    error_message = "fifo_throughput_limit must be perQueue or perMessageGroupId."
  }
}

variable "deduplication_scope" {
  description = "FIFO deduplication scope (queue or messageGroup)."
  type        = string
  default     = "messageGroup"
  validation {
    condition     = contains(["queue", "messageGroup"], var.deduplication_scope)
    error_message = "deduplication_scope must be queue or messageGroup."
  }
}

# Timings and sizing
variable "delay_seconds" {
  description = "Default delay (seconds) for messages."
  type        = number
  default     = 0
}

variable "receive_wait_time_seconds" {
  description = "Long polling wait time (seconds)."
  type        = number
  default     = 10
}

variable "visibility_timeout_seconds" {
  description = "Visibility timeout (seconds)."
  type        = number
  default     = 30
}

variable "message_retention_seconds" {
  description = "Retention of messages (seconds)."
  type        = number
  default     = 345600 # 4 days
}

variable "max_message_size" {
  description = "Max message size in bytes."
  type        = number
  default     = 262144
}

# Encryption
variable "create_kms_key" {
  description = "Create a dedicated KMS key for SQS encryption."
  type        = bool
  default     = false
}

variable "kms_key_id" {
  description = "Existing KMS key ARN or ID to use."
  type        = string
  default     = null
}

variable "kms_data_key_reuse_period_seconds" {
  description = "Data key reuse period (seconds) when using KMS."
  type        = number
  default     = 300
}

variable "kms_key_policy" {
  description = "Optional KMS key resource policy (when create_kms_key=true)."
  type        = string
  default     = null
}

variable "sse_sqs_enabled" {
  description = "Enable SQS-managed SSE when no KMS key is used."
  type        = bool
  default     = true
}

# Redrive / DLQ
variable "redrive" {
  description = "Dead-letter queue settings."
  type = object({
    enabled                         = bool
    max_receive_count               = number
    dlq_message_retention_seconds   = number
  })
  default = {
    enabled                       = true
    max_receive_count             = 5
    dlq_message_retention_seconds = 1209600 # 14 days
  }
}

# Access control
variable "allowed_principals" {
  description = "List of AWS principal ARNs allowed by queue policy. Empty means no explicit principal restriction."
  type        = list(string)
  default     = []
}

variable "allowed_actions" {
  description = "Actions allowed for allowed_principals."
  type        = list(string)
  default = [
    "sqs:SendMessage",
    "sqs:ReceiveMessage",
    "sqs:ChangeMessageVisibility",
    "sqs:ChangeMessageVisibilityBatch",
    "sqs:DeleteMessage",
    "sqs:DeleteMessageBatch",
    "sqs:GetQueueAttributes",
    "sqs:GetQueueUrl",
    "sqs:ListQueueTags",
    "sqs:TagQueue",
    "sqs:UntagQueue"
  ]
}

variable "source_vpce_ids" {
  description = "Restrict access via Interface VPC Endpoint IDs (aws:SourceVpce condition)."
  type        = list(string)
  default     = []
}

# Alarms
variable "alarms" {
  description = "CloudWatch alarm configuration."
  type = object({
    enabled               = bool
    period                = number
    evaluation_periods    = number
    depth_threshold       = number
    age_threshold_seconds = number
    dlq_depth_threshold   = number
    alarm_actions         = list(string)
    ok_actions            = list(string)
    treat_missing_data    = string
  })
  default = {
    enabled               = true
    period                = 60
    evaluation_periods    = 3
    depth_threshold       = 1000
    age_threshold_seconds = 300
    dlq_depth_threshold   = 1
    alarm_actions         = []
    ok_actions            = []
    treat_missing_data    = "notBreaching"
  }
}

############################################################
# Outputs
############################################################
output "queue_name" {
  value       = aws_sqs_queue.main.name
  description = "SQS queue name."
}

output "queue_arn" {
  value       = aws_sqs_queue.main.arn
  description = "SQS queue ARN."
}

output "queue_url" {
  value       = aws_sqs_queue.main.id
  description = "SQS queue URL."
}

output "dlq_arn" {
  value       = try(aws_sqs_queue.dlq[0].arn, null)
  description = "DLQ ARN if created."
}

output "kms_key_arn" {
  value       = local.kms_key_arn
  description = "KMS key ARN if used."
}

output "alarm_arns" {
  value = compact([
    try(aws_cloudwatch_metric_alarm.depth[0].arn, null),
    try(aws_cloudwatch_metric_alarm.age[0].arn, null),
    try(aws_cloudwatch_metric_alarm.dlq_depth[0].arn, null),
  ])
  description = "CloudWatch alarm ARNs."
}
