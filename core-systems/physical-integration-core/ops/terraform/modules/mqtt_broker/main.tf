terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
  }
}

# -------------------------------
# Locals & defaults
# -------------------------------
locals {
  name_prefix = var.name_prefix != "" ? var.name_prefix : "mqtt"
  tags        = merge(var.tags, { "module" = "physical-integration-core/mqtt_broker" })

  # Безопасные действия MQTT по умолчанию — только publish/subscribe для заданных топиков
  default_actions = coalesce(var.allowed_actions, [
    "iot:Connect",
    "iot:Publish",
    "iot:Receive",
    "iot:Subscribe"
  ])

  # Набор ARNs топиков (resource-level permissions) из заданных шаблонов
  topic_arns = [
    for t in var.topic_filters : "arn:${data.aws_partition.current.partition}:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:topic/${t}"
  ]

  topicfilter_arns = [
    for t in var.topic_filters : "arn:${data.aws_partition.current.partition}:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:topicfilter/${t}"
  ]

  # Включение конкретных выходов для правил маршрутизации
  rule_targets_enabled = {
    s3        = var.rule_s3 != null && var.rule_s3.enable
    kinesis   = var.rule_kinesis != null && var.rule_kinesis.enable
    dynamodb  = var.rule_dynamodb != null && var.rule_dynamodb.enable
    sns       = var.rule_sns != null && var.rule_sns.enable
    http      = var.rule_http != null && var.rule_http.enable
    firehose  = var.rule_firehose != null && var.rule_firehose.enable
    sqs       = var.rule_sqs != null && var.rule_sqs.enable
    lambda    = var.rule_lambda != null && var.rule_lambda.enable
  }
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_iot_endpoint" "iot" {
  endpoint_type = "iot:Data-ATS"
}

# -------------------------------
# CloudWatch Logs for AWS IoT
# -------------------------------
resource "aws_cloudwatch_log_group" "iot" {
  name              = "/aws/iot/${local.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_id
  tags              = local.tags
}

resource "aws_iot_logging_options" "this" {
  default_log_level = var.iot_log_level
  role_arn          = aws_iam_role.iot_logging.arn
}

resource "aws_iam_role" "iot_logging" {
  name               = "${local.name_prefix}-iot-logs-role"
  assume_role_policy = data.aws_iam_policy_document.iot_logs_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "iot_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["iot.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "iot_logging" {
  name = "${local.name_prefix}-iot-logs-policy"
  role = aws_iam_role.iot_logging.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
        Resource = "${aws_cloudwatch_log_group.iot.arn}:*"
      }
    ]
  })
}

# -------------------------------
# Thing Type & Thing Group (опционально)
# -------------------------------
resource "aws_iot_thing_type" "this" {
  count = var.create_thing_type ? 1 : 0
  name  = "${local.name_prefix}-type"
  tags  = local.tags
}

resource "aws_iot_thing_group" "this" {
  count = var.create_thing_group ? 1 : 0
  name  = "${local.name_prefix}-group"
  tags  = local.tags
}

# -------------------------------
# IoT Policy (least-privilege, параметризуемый топиками)
# -------------------------------
data "aws_iam_policy_document" "iot_policy" {
  statement {
    sid     = "Connect"
    effect  = "Allow"
    actions = ["iot:Connect"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "iot:ClientId"
      values   = [var.client_id_condition]
    }
  }

  statement {
    sid     = "Publish"
    effect  = "Allow"
    actions = ["iot:Publish", "iot:Receive"]
    resources = local.topic_arns
  }

  statement {
    sid     = "Subscribe"
    effect  = "Allow"
    actions = ["iot:Subscribe"]
    resources = local.topicfilter_arns
  }
}

resource "aws_iot_policy" "this" {
  name   = "${local.name_prefix}-policy"
  policy = data.aws_iam_policy_document.iot_policy.json
}

# Привязка политики к уже созданным сертификатам (их ARNs передаются через var.certificate_arns)
resource "aws_iot_policy_attachment" "certs" {
  for_each  = toset(var.certificate_arns)
  policy    = aws_iot_policy.this.name
  target    = each.value
  depends_on = [aws_iot_policy.this]
}

# -------------------------------
# Role Alias для устройств (опционально)
# Позволяет устройствам получать временные креденшелы на конкретную IAM роль.
# -------------------------------
resource "aws_iam_role" "device_role" {
  count              = var.enable_role_alias ? 1 : 0
  name               = "${local.name_prefix}-device-role"
  assume_role_policy = data.aws_iam_policy_document.device_trust[count.index].json
  tags               = local.tags
}

data "aws_iam_policy_document" "device_trust" {
  count = var.enable_role_alias ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["credentials.iot.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "device_inline" {
  count = var.enable_role_alias ? 1 : 0
  name  = "${local.name_prefix}-device-access"
  role  = aws_iam_role.device_role[0].id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = var.device_role_statements
  })
}

resource "aws_iot_role_alias" "this" {
  count                 = var.enable_role_alias ? 1 : 0
  alias                 = "${local.name_prefix}-role-alias"
  role_arn              = aws_iam_role.device_role[0].arn
  credential_duration   = var.role_alias_credential_duration_seconds
}

# -------------------------------
# Topic Rules (опционально, любые комбинации)
# -------------------------------
resource "aws_iot_topic_rule" "this" {
  count         = var.enable_topic_rule ? 1 : 0
  name          = "${local.name_prefix}-rule"
  enabled       = true
  sql           = var.rule_sql                                # например: "SELECT * FROM 'sensors/+/data'"
  sql_version   = "2016-03-23"
  description   = "MQTT rule for ${local.name_prefix}"
  error_action {
    cloudwatch_logs {
      log_group_name  = aws_cloudwatch_log_group.iot.name
      role_arn        = aws_iam_role.iot_rule[0].arn
    }
  }

  dynamic "s3" {
    for_each = local.rule_targets_enabled.s3 ? [1] : []
    content {
      bucket_name = var.rule_s3.bucket_name
      key         = var.rule_s3.key
      role_arn    = aws_iam_role.iot_rule[0].arn
    }
  }

  dynamic "kinesis" {
    for_each = local.rule_targets_enabled.kinesis ? [1] : []
    content {
      role_arn     = aws_iam_role.iot_rule[0].arn
      stream_name  = var.rule_kinesis.stream_name
      partition_key = try(var.rule_kinesis.partition_key, null)
    }
  }

  dynamic "dynamodb" {
    for_each = local.rule_targets_enabled.dynamodb ? [1] : []
    content {
      role_arn    = aws_iam_role.iot_rule[0].arn
      table_name  = var.rule_dynamodb.table_name
      hash_key_field  = var.rule_dynamodb.hash_key_field
      hash_key_value  = var.rule_dynamodb.hash_key_value
      range_key_field = try(var.rule_dynamodb.range_key_field, null)
      range_key_value = try(var.rule_dynamodb.range_key_value, null)
      operation       = try(var.rule_dynamodb.operation, null)
      payload_field   = try(var.rule_dynamodb.payload_field, null)
    }
  }

  dynamic "sns" {
    for_each = local.rule_targets_enabled.sns ? [1] : []
    content {
      role_arn   = aws_iam_role.iot_rule[0].arn
      target_arn = var.rule_sns.topic_arn
      message_format = try(var.rule_sns.message_format, null)
    }
  }

  dynamic "http" {
    for_each = local.rule_targets_enabled.http ? [1] : []
    content {
      url         = var.rule_http.url
      confirmation_url = try(var.rule_http.confirmation_url, null)
      http_header {
        key   = "Content-Type"
        value = "application/json"
      }
      auth {
        sigv4 {
          service_name = try(var.rule_http.sigv4_service_name, "execute-api")
          role_arn     = aws_iam_role.iot_rule[0].arn
          region       = data.aws_region.current.name
        }
      }
    }
  }

  dynamic "firehose" {
    for_each = local.rule_targets_enabled.firehose ? [1] : []
    content {
      role_arn        = aws_iam_role.iot_rule[0].arn
      delivery_stream_name = var.rule_firehose.delivery_stream_name
      separator       = try(var.rule_firehose.separator, null)
    }
  }

  dynamic "sqs" {
    for_each = local.rule_targets_enabled.sqs ? [1] : []
    content {
      role_arn   = aws_iam_role.iot_rule[0].arn
      queue_url  = var.rule_sqs.queue_url
      use_base64 = try(var.rule_sqs.use_base64, false)
    }
  }

  dynamic "lambda" {
    for_each = local.rule_targets_enabled.lambda ? [1] : []
    content {
      function_arn = var.rule_lambda.function_arn
    }
  }

  tags = local.tags
}

# Роль для Topic Rule действий
resource "aws_iam_role" "iot_rule" {
  count              = var.enable_topic_rule ? 1 : 0
  name               = "${local.name_prefix}-rule-role"
  assume_role_policy = data.aws_iam_policy_document.iot_rule_assume[0].json
  tags               = local.tags
}

data "aws_iam_policy_document" "iot_rule_assume" {
  count = var.enable_topic_rule ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["iot.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "iot_rule" {
  count = var.enable_topic_rule ? 1 : 0
  name  = "${local.name_prefix}-rule-inline"
  role  = aws_iam_role.iot_rule[0].id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = concat(
      local.rule_targets_enabled.s3 ? [{
        Effect: "Allow",
        Action: ["s3:PutObject"],
        Resource: "arn:${data.aws_partition.current.partition}:s3:::${var.rule_s3.bucket_name}/${var.rule_s3.key}"
      }] : [],
      local.rule_targets_enabled.kinesis ? [{
        Effect: "Allow",
        Action: ["kinesis:PutRecord", "kinesis:PutRecords"],
        Resource: "arn:${data.aws_partition.current.partition}:kinesis:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:stream/${var.rule_kinesis.stream_name}"
      }] : [],
      local.rule_targets_enabled.dynamodb ? [{
        Effect: "Allow",
        Action: ["dynamodb:PutItem", "dynamodb:UpdateItem"],
        Resource: "arn:${data.aws_partition.current.partition}:dynamodb:${data.aws_region.current.name}:*:table/${var.rule_dynamodb.table_name}"
      }] : [],
      local.rule_targets_enabled.sns ? [{
        Effect: "Allow",
        Action: ["sns:Publish"],
        Resource: var.rule_sns.topic_arn
      }] : [],
      local.rule_targets_enabled.http ? [{
        Effect: "Allow",
        Action: ["execute-api:Invoke", "execute-api:ManageConnections"],
        Resource: "*"
      }] : [],
      local.rule_targets_enabled.firehose ? [{
        Effect: "Allow",
        Action: ["firehose:PutRecord", "firehose:PutRecordBatch"],
        Resource: "arn:${data.aws_partition.current.partition}:firehose:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:deliverystream/${var.rule_firehose.delivery_stream_name}"
      }] : [],
      local.rule_targets_enabled.sqs ? [{
        Effect: "Allow",
        Action: ["sqs:SendMessage"],
        Resource: var.rule_sqs.queue_arn
      }] : [],
      local.rule_targets_enabled.lambda ? [{
        Effect: "Allow",
        Action: ["lambda:InvokeFunction"],
        Resource: var.rule_lambda.function_arn
      }] : []
    )
  })
}

# -------------------------------
# Outputs
# -------------------------------
output "iot_endpoint" {
  value       = data.aws_iot_endpoint.iot.endpoint_address
  description = "ATS data endpoint for MQTT/TLS."
}

output "iot_policy_name" {
  value       = aws_iot_policy.this.name
  description = "Name of the AWS IoT policy applied to device certificates."
}

output "thing_group_name" {
  value       = try(aws_iot_thing_group.this[0].name, null)
  description = "Thing group name (if created)."
}

output "role_alias" {
  value       = try(aws_iot_role_alias.this[0].alias, null)
  description = "IoT role alias for device credentials (if enabled)."
}

# -------------------------------
# Variables (inline для самодостаточности файла модуля)
# Рекомендуется вынести в variables.tf, но оставлено здесь по требованию одного файла.
# -------------------------------
variable "name_prefix" {
  type        = string
  default     = "mqtt"
  description = "Префикс для имен ресурсов."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Теги для всех создаваемых ресурсов."
}

variable "log_retention_days" {
  type        = number
  default     = 30
  description = "Срок хранения логов CloudWatch."
}

variable "logs_kms_key_id" {
  type        = string
  default     = null
  description = "KMS Key для шифрования логов (опционально)."
}

variable "iot_log_level" {
  type        = string
  default     = "INFO"
  description = "Уровень логирования AWS IoT: DEBUG|INFO|ERROR|WARN|DISABLED."
}

variable "create_thing_type" {
  type        = bool
  default     = false
  description = "Создавать ли Thing Type."
}

variable "create_thing_group" {
  type        = bool
  default     = false
  description = "Создавать ли Thing Group."
}

variable "client_id_condition" {
  type        = string
  default     = "${iot:Connection.Thing.ThingName}"
  description = "Ограничение на подключение по iot:ClientId (по умолчанию — имя Thing)."
}

variable "topic_filters" {
  type        = list(string)
  description = "Список топиков/шаблонов topic и topicfilter (например, sensors/+/data)."
  default     = ["${iot:Connection.Thing.ThingName}/#", "broadcast/#"]
}

variable "allowed_actions" {
  type        = list(string)
  default     = null
  description = "Необязательный кастомный список действий IoT в политике."
}

variable "certificate_arns" {
  type        = list(string)
  default     = []
  description = "ARN сертификатов, к которым будет присоединена политика."
}

variable "enable_role_alias" {
  type        = bool
  default     = false
  description = "Создавать ли Role Alias для выдачи временных креденшел."
}

variable "device_role_statements" {
  type = list(object({
    Effect   = string
    Action   = list(string)
    Resource = any
  }))
  default     = []
  description = "IAM‑права, которые получают устройства через Role Alias."
}

variable "role_alias_credential_duration_seconds" {
  type        = number
  default     = 3600
  description = "TTL временных креденшелов, выдаваемых через Role Alias."
}

variable "enable_topic_rule" {
  type        = bool
  default     = false
  description = "Создавать ли Topic Rule."
}

variable "rule_sql" {
  type        = string
  default     = "SELECT * FROM 'devices/+/events'"
  description = "SQL выражение AWS IoT Rule."
}

# --- Targets: S3
variable "rule_s3" {
  type = object({
    enable     = bool
    bucket_name = string
    key         = string
  })
  default = null
}

# --- Targets: Kinesis
variable "rule_kinesis" {
  type = object({
    enable        = bool
    stream_name   = string
    partition_key = optional(string)
  })
  default = null
}

# --- Targets: DynamoDB
variable "rule_dynamodb" {
  type = object({
    enable          = bool
    table_name      = string
    hash_key_field  = string
    hash_key_value  = string
    range_key_field = optional(string)
    range_key_value = optional(string)
    operation       = optional(string)
    payload_field   = optional(string)
  })
  default = null
}

# --- Targets: SNS
variable "rule_sns" {
  type = object({
    enable         = bool
    topic_arn      = string
    message_format = optional(string)
  })
  default = null
}

# --- Targets: HTTP
variable "rule_http" {
  type = object({
    enable               = bool
    url                  = string
    confirmation_url     = optional(string)
    sigv4_service_name   = optional(string)
  })
  default = null
}

# --- Targets: Firehose
variable "rule_firehose" {
  type = object({
    enable               = bool
    delivery_stream_name = string
    separator            = optional(string)
  })
  default = null
}

# --- Targets: SQS
variable "rule_sqs" {
  type = object({
    enable    = bool
    queue_url = string
    queue_arn = string
    use_base64 = optional(bool)
  })
  default = null
}

# --- Targets: Lambda
variable "rule_lambda" {
  type = object({
    enable       = bool
    function_arn = string
  })
  default = null
}
