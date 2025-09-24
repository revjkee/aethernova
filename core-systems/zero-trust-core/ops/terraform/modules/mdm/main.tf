terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# ------------------------------- INPUTS ---------------------------------------

variable "name_prefix" {
  description = "Префикс имён ресурсов (например, zero-trust-core-prod)."
  type        = string
}

variable "tags" {
  description = "Общие тэги."
  type        = map(string)
  default     = {}
}

variable "region" {
  description = "AWS регион (если null — берется текущий)."
  type        = string
  default     = null
}

# KMS
variable "create_kms_key" {
  description = "Создавать собственный KMS-ключ для шифрования S3/CloudWatch."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Существующий KMS-ключ (если create_kms_key=false)."
  type        = string
  default     = null
}

# S3
variable "create_buckets" {
  description = "Создавать S3 бакеты для SSM (Session logs, Inventory sync)."
  type        = bool
  default     = true
}

variable "session_logs_bucket_name" {
  description = "Имя S3 бакета для логов Session Manager (если null — сгенерируется)."
  type        = string
  default     = null
}

variable "inventory_bucket_name" {
  description = "Имя S3 бакета для SSM Resource Data Sync (если null — сгенерируется)."
  type        = string
  default     = null
}

variable "force_destroy" {
  description = "Разрешить удаление бакетов с объектами (использовать осознанно)."
  type        = bool
  default     = false
}

variable "session_logs_cw_retention_days" {
  description = "Retention дней для CloudWatch Log Group сессий."
  type        = number
  default     = 90
}

# VPC Endpoints (для приватного доступа к SSM без Интернета)
variable "enable_vpc_endpoints" {
  description = "Создавать интерфейсные VPC endpoints для SSM/SSMMessages/EC2Messages."
  type        = bool
  default     = false
}

variable "vpc_id" {
  description = "VPC ID (обязательно, если enable_vpc_endpoints=true)."
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "Список приватных subnet IDs для интерфейсных endpoints."
  type        = list(string)
  default     = []
}

variable "endpoint_security_group_id" {
  description = "ID существующей SG для endpoints (если пусто — создадим свою)."
  type        = string
  default     = ""
}

# Patch/Inventory
variable "enable_patch_management" {
  description = "Включить Patch Baseline + Maintenance Window."
  type        = bool
  default     = true
}

variable "patch_window_cron" {
  description = "Расписание MW в формате CRON (UTC). Пример: cron(0 3 ? * SUN *) — каждое воскресенье 03:00."
  type        = string
  default     = "cron(0 3 ? * SUN *)"
}

variable "patch_target_tag_key" {
  description = "Ключ тега для таргетинга инстансов на патчинг/инвентарь."
  type        = string
  default     = "mdm:managed"
}

variable "patch_target_tag_value" {
  description = "Значение тега для таргетинга."
  type        = string
  default     = "true"
}

variable "max_concurrency" {
  description = "Максимальная конкуррентность задачи патчинга."
  type        = string
  default     = "10%"
}

variable "max_errors" {
  description = "Максимально допустимые ошибки для MW задачи."
  type        = string
  default     = "5%"
}

# Hybrid Activation (опционально для он‑прем/вирт. машин вне EC2)
variable "enable_hybrid_activation" {
  description = "Создать SSM Activation для регистрации внешних узлов."
  type        = bool
  default     = false
}

variable "hybrid_activation_description" {
  description = "Описание активации."
  type        = string
  default     = "zero-trust-core hybrid activation"
}

variable "hybrid_default_instance_name" {
  description = "Шаблон имени управляемого инстанса."
  type        = string
  default     = "ztc-managed"
}

variable "hybrid_registration_limit" {
  description = "Сколько узлов можно зарегистрировать."
  type        = number
  default     = 50
}

variable "hybrid_expiration_days" {
  description = "Срок действия активации в днях."
  type        = number
  default     = 30
}

# ------------------------------- LOCALS ---------------------------------------

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  region     = coalesce(var.region, data.aws_region.current.name)
  name_norm  = lower(replace(var.name_prefix, "/[^a-zA-Z0-9-]/", "-"))
  common_tags = merge({
    "Project"     = "zero-trust-core"
    "Component"   = "mdm"
    "ManagedBy"   = "terraform"
  }, var.tags)

  kms_arn_effective = var.create_kms_key ? aws_kms_key.this[0].arn : var.kms_key_arn

  session_logs_bucket_auto = "${local.name_norm}-ssm-session-logs-${local.region}-${data.aws_caller_identity.current.account_id}"
  inventory_bucket_auto    = "${local.name_norm}-ssm-inventory-${local.region}-${data.aws_caller_identity.current.account_id}"
}

# ------------------------------- KMS ------------------------------------------

resource "aws_kms_key" "this" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "KMS for ${var.name_prefix} MDM (SSM logs/inventory)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.common_tags
}

resource "aws_kms_alias" "this" {
  count         = var.create_kms_key ? 1 : 0
  name          = "alias/${local.name_norm}-mdm"
  target_key_id = aws_kms_key.this[0].key_id
}

# ------------------------------- S3 POLICIES ----------------------------------

# Общая политика: только TLS, только зашифрованные объекты KMS
data "aws_iam_policy_document" "s3_secure_base" {
  statement {
    sid     = "DenyInsecureTransport"
    actions = ["s3:*"]
    effect  = "Deny"
    principals { type = "*", identifiers = ["*"] }
    resources = ["*"]
    condition { test = "Bool", variable = "aws:SecureTransport", values = ["false"] }
  }

  statement {
    sid     = "DenyUnEncryptedObjectUploads"
    actions = ["s3:PutObject"]
    effect  = "Deny"
    principals { type = "*", identifiers = ["*"] }
    resources = ["*"]
    condition { test = "Null", variable = "s3:x-amz-server-side-encryption", values = ["true"] }
  }

  statement {
    sid     = "DenyIncorrectEncryptionHeader"
    actions = ["s3:PutObject"]
    effect  = "Deny"
    principals { type = "*", identifiers = ["*"] }
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

# ------------------------------- S3 BUCKETS -----------------------------------

resource "aws_s3_bucket" "session_logs" {
  count         = var.create_buckets ? 1 : 0
  bucket        = coalesce(var.session_logs_bucket_name, local.session_logs_bucket_auto)
  force_destroy = var.force_destroy
  tags          = merge(local.common_tags, { "Name" = "ssm-session-logs" })
}

resource "aws_s3_bucket_versioning" "session_logs" {
  count  = length(aws_s3_bucket.session_logs) > 0 ? 1 : 0
  bucket = aws_s3_bucket.session_logs[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "session_logs" {
  count  = length(aws_s3_bucket.session_logs) > 0 ? 1 : 0
  bucket = aws_s3_bucket.session_logs[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_arn_effective
    }
    bucket_key_enabled = true
  }
}

# Разрешить SSM сервису писать логи с префиксом "sessions/"
data "aws_iam_policy_document" "session_logs" {
  count = length(aws_s3_bucket.session_logs) > 0 ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.s3_secure_base.json]

  statement {
    sid     = "AllowSSMServiceWrite"
    actions = ["s3:PutObject", "s3:PutObjectAcl"]
    effect  = "Allow"
    principals { type = "Service", identifiers = ["ssm.amazonaws.com"] }
    resources = ["${aws_s3_bucket.session_logs[0].arn}/sessions/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid     = "DenyWrongKmsKey"
    actions = ["s3:PutObject"]
    effect  = "Deny"
    principals { type = "*", identifiers = ["*"] }
    resources = ["${aws_s3_bucket.session_logs[0].arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [local.kms_arn_effective]
    }
  }
}

resource "aws_s3_bucket_policy" "session_logs" {
  count  = length(aws_s3_bucket.session_logs) > 0 ? 1 : 0
  bucket = aws_s3_bucket.session_logs[0].id
  policy = data.aws_iam_policy_document.session_logs[0].json
}

# Inventory bucket + Resource Data Sync
resource "aws_s3_bucket" "inventory" {
  count         = var.create_buckets ? 1 : 0
  bucket        = coalesce(var.inventory_bucket_name, local.inventory_bucket_auto)
  force_destroy = var.force_destroy
  tags          = merge(local.common_tags, { "Name" = "ssm-inventory" })
}

resource "aws_s3_bucket_versioning" "inventory" {
  count  = length(aws_s3_bucket.inventory) > 0 ? 1 : 0
  bucket = aws_s3_bucket.inventory[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "inventory" {
  count  = length(aws_s3_bucket.inventory) > 0 ? 1 : 0
  bucket = aws_s3_bucket.inventory[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_arn_effective
    }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "inventory" {
  count = length(aws_s3_bucket.inventory) > 0 ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.s3_secure_base.json]

  statement {
    sid     = "AllowSSMResourceDataSync"
    actions = ["s3:PutObject", "s3:PutObjectAcl", "s3:GetBucketLocation"]
    effect  = "Allow"
    principals { type = "Service", identifiers = ["ssm.amazonaws.com"] }
    resources = [
      aws_s3_bucket.inventory[0].arn,
      "${aws_s3_bucket.inventory[0].arn}/inventory/*"
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid     = "DenyWrongKmsKey"
    actions = ["s3:PutObject"]
    effect  = "Deny"
    principals { type = "*", identifiers = ["*"] }
    resources = ["${aws_s3_bucket.inventory[0].arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [local.kms_arn_effective]
    }
  }
}

resource "aws_s3_bucket_policy" "inventory" {
  count  = length(aws_s3_bucket.inventory) > 0 ? 1 : 0
  bucket = aws_s3_bucket.inventory[0].id
  policy = data.aws_iam_policy_document.inventory[0].json
}

# ------------------------------- CLOUDWATCH LOGS -------------------------------

resource "aws_cloudwatch_log_group" "session" {
  name              = "/aws/ssm/SessionManager"
  retention_in_days = var.session_logs_cw_retention_days
  kms_key_id        = local.kms_arn_effective
  tags              = local.common_tags
}

# Разрешаем сервису SSM писать в лог‑группу (resource policy Log Groups)
data "aws_iam_policy_document" "cw_ssm" {
  statement {
    sid     = "AllowSSMServiceLogging"
    effect  = "Allow"
    principals { type = "Service", identifiers = ["ssm.amazonaws.com"] }
    actions = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.session.arn}:*"]
  }
}

resource "aws_cloudwatch_log_resource_policy" "ssm" {
  policy_name     = "SSM-SessionManager"
  policy_document = data.aws_iam_policy_document.cw_ssm.json
}

# ------------------------------- SESSION PREFS --------------------------------

# Глобальные преференсы Session Manager: отправка логов в CloudWatch/S3
resource "aws_ssm_parameter" "session_prefs" {
  name  = "/amazon/ssm/session-manager/preferences"
  type  = "String"
  tier  = "Standard"
  tags  = local.common_tags
  value = jsonencode({
    CloudWatchLoggingEnabled = true
    CloudWatchLogGroupName   = aws_cloudwatch_log_group.session.name
    CloudWatchEncryptionEnabled = true
    S3LoggingEnabled         = length(aws_s3_bucket.session_logs) > 0
    S3BucketName             = length(aws_s3_bucket.session_logs) > 0 ? aws_s3_bucket.session_logs[0].bucket : null
    S3KeyPrefix              = "sessions"
    KmsKeyId                 = local.kms_arn_effective
    ShellProfile = {
      linux  = "export HISTCONTROL=ignoredups"
      windows= ""
    }
  })
}

# ------------------------------- IAM FOR EC2 ----------------------------------

# Роль для EC2, минимальный набор + CloudWatchAgent
data "aws_iam_policy_document" "ec2_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals { type = "Service", identifiers = ["ec2.${data.aws_partition.current.dns_suffix}"] }
  }
}

resource "aws_iam_role" "ec2_ssm" {
  name               = "${local.name_norm}-ec2-ssm"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
  tags               = local.common_tags
}

# Подключаем управляемые политики
resource "aws_iam_role_policy_attachment" "ec2_ssm_core" {
  role       = aws_iam_role.ec2_ssm.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ec2_cw_agent" {
  role       = aws_iam_role.ec2_ssm.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Inline-политика: доступ к KMS для шифрования/дешифрования CloudWatch/S3 (минимально)
data "aws_iam_policy_document" "ec2_inline" {
  statement {
    sid     = "KmsUse"
    effect  = "Allow"
    actions = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = [local.kms_arn_effective]
  }
}

resource "aws_iam_role_policy" "ec2_inline" {
  name   = "${local.name_norm}-ec2-ssm-inline"
  role   = aws_iam_role.ec2_ssm.id
  policy = data.aws_iam_policy_document.ec2_inline.json
}

resource "aws_iam_instance_profile" "ec2_ssm" {
  name = "${local.name_norm}-ec2-ssm"
  role = aws_iam_role.ec2_ssm.name
  tags = local.common_tags
}

# ------------------------------- PATCH MGMT -----------------------------------

# Linux baseline (Amazon Linux 2/Ubuntu/Debian/RHEL) — одобряем Security/Critical через 7 дней
resource "aws_ssm_patch_baseline" "linux" {
  count        = var.enable_patch_management ? 1 : 0
  name         = "${var.name_prefix}-linux-baseline"
  description  = "Baseline for Linux - security/critical after 7 days"
  operating_system = "AMAZON_LINUX_2"
  approval_rule {
    approve_after_days = 7
    enable_non_security = false
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security"]
    }
    patch_filter {
      key    = "SEVERITY"
      values = ["Critical", "Important"]
    }
  }
  tags = local.common_tags
}

resource "aws_ssm_default_patch_baseline" "linux" {
  count             = var.enable_patch_management ? 1 : 0
  operating_system  = "AMAZON_LINUX_2"
  baseline_id       = aws_ssm_patch_baseline.linux[0].id
}

# Windows baseline
resource "aws_ssm_patch_baseline" "windows" {
  count        = var.enable_patch_management ? 1 : 0
  name         = "${var.name_prefix}-windows-baseline"
  description  = "Baseline for Windows - security/critical after 7 days"
  operating_system = "WINDOWS"
  approval_rule {
    approve_after_days = 7
    enable_non_security = false
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["SecurityUpdates", "CriticalUpdates"]
    }
  }
  tags = local.common_tags
}

resource "aws_ssm_default_patch_baseline" "windows" {
  count            = var.enable_patch_management ? 1 : 0
  operating_system = "WINDOWS"
  baseline_id      = aws_ssm_patch_baseline.windows[0].id
}

# Maintenance Window + Task AWS-RunPatchBaseline
resource "aws_ssm_maintenance_window" "patch" {
  count                     = var.enable_patch_management ? 1 : 0
  name                      = "${var.name_prefix}-patch-window"
  description               = "Weekly patch window"
  schedule                  = var.patch_window_cron
  duration                  = 3
  cutoff                    = 1
  allow_unassociated_targets= false
  tags                      = local.common_tags
}

resource "aws_ssm_maintenance_window_target" "patch_targets" {
  count          = var.enable_patch_management ? 1 : 0
  window_id      = aws_ssm_maintenance_window.patch[0].id
  name           = "tagged-targets"
  resource_type  = "INSTANCE"
  description    = "Instances tagged for managed patching"
  targets {
    key    = "tag:${var.patch_target_tag_key}"
    values = [var.patch_target_tag_value]
  }
}

resource "aws_ssm_maintenance_window_task" "patch_task" {
  count                 = var.enable_patch_management ? 1 : 0
  window_id             = aws_ssm_maintenance_window.patch[0].id
  name                  = "RunPatchBaseline"
  description           = "Install security updates"
  task_type             = "RUN_COMMAND"
  task_arn              = "AWS-RunPatchBaseline"
  priority              = 1
  max_concurrency       = var.max_concurrency
  max_errors            = var.max_errors
  targets {
    key    = "WindowTargetIds"
    values = [aws_ssm_maintenance_window_target.patch_targets[0].id]
  }
  task_invocation_parameters {
    run_command {
      parameters = {
        Operation = ["Install"]
      }
      output_s3_bucket     = try(aws_s3_bucket.session_logs[0].bucket, null)
      output_s3_key_prefix = "patching"
      cloudwatch_config {
        cloudwatch_log_group_name = aws_cloudwatch_log_group.session.name
        cloudwatch_output_enabled = true
      }
    }
  }
  service_role_arn = null
  tags             = local.common_tags
}

# Inventory (Software/Hardware inventory) — AWS-GatherSoftwareInventory
resource "aws_ssm_association" "inventory" {
  name = "AWS-GatherSoftwareInventory"
  targets {
    key    = "tag:${var.patch_target_tag_key}"
    values = [var.patch_target_tag_value]
  }
  output_location {
    s3_bucket_name = try(aws_s3_bucket.session_logs[0].bucket, null)
    s3_key_prefix  = "inventory/associations"
  }
  depends_on = [aws_ssm_parameter.session_prefs]
}

# Resource Data Sync -> S3 (для Inventory/Compliance)
resource "aws_ssm_resource_data_sync" "inventory" {
  count = length(aws_s3_bucket.inventory) > 0 ? 1 : 0
  name  = "${local.name_norm}-inventory-sync"
  s3_destination {
    bucket_name = aws_s3_bucket.inventory[0].bucket
    prefix      = "inventory"
    region      = local.region
    kms_key_arn = local.kms_arn_effective
    sync_format = "JsonSerDe"
  }
}

# ------------------------------- VPC ENDPOINTS --------------------------------

# Optionally create SG for interface endpoints
resource "aws_security_group" "endpoints" {
  count       = var.enable_vpc_endpoints && var.endpoint_security_group_id == "" ? 1 : 0
  name        = "${local.name_norm}-ssm-endpoints"
  description = "Allow HTTPS to SSM endpoints"
  vpc_id      = var.vpc_id
  tags        = local.common_tags

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # при необходимости сузьте до внутренних подсетей
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

locals {
  ep_sg_id = var.endpoint_security_group_id != "" ? var.endpoint_security_group_id : (
    length(aws_security_group.endpoints) > 0 ? aws_security_group.endpoints[0].id : ""
  )
}

resource "aws_vpc_endpoint" "ssm" {
  count              = var.enable_vpc_endpoints ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${local.region}.ssm"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnet_ids
  security_group_ids = [local.ep_sg_id]
  private_dns_enabled= true
  tags               = local.common_tags
}

resource "aws_vpc_endpoint" "ssmmessages" {
  count              = var.enable_vpc_endpoints ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${local.region}.ssmmessages"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnet_ids
  security_group_ids = [local.ep_sg_id]
  private_dns_enabled= true
  tags               = local.common_tags
}

resource "aws_vpc_endpoint" "ec2messages" {
  count              = var.enable_vpc_endpoints ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${local.region}.ec2messages"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnet_ids
  security_group_ids = [local.ep_sg_id]
  private_dns_enabled= true
  tags               = local.common_tags
}

# ------------------------------- HYBRID ACTIVATION ----------------------------

resource "aws_ssm_activation" "hybrid" {
  count                = var.enable_hybrid_activation ? 1 : 0
  description          = var.hybrid_activation_description
  default_instance_name= var.hybrid_default_instance_name
  iam_role             = "AmazonSSMManagedInstanceCore" # использует менеджед‑роль для on-prem
  registration_limit   = var.hybrid_registration_limit
  expiration_date      = timeadd(timestamp(), "${var.hybrid_expiration_days}h")
  tags                 = local.common_tags
}

# ------------------------------- OUTPUTS --------------------------------------

output "kms_key_arn" {
  value       = local.kms_arn_effective
  description = "KMS ключ, используемый для шифрования."
}

output "session_logs_bucket" {
  value       = try(aws_s3_bucket.session_logs[0].bucket, null)
  description = "S3 бакет для логов Session Manager (если создан)."
}

output "inventory_bucket" {
  value       = try(aws_s3_bucket.inventory[0].bucket, null)
  description = "S3 бакет для Resource Data Sync (если создан)."
}

output "cloudwatch_log_group_name" {
  value       = aws_cloudwatch_log_group.session.name
  description = "Имя CloudWatch Log Group для Session Manager."
}

output "ec2_instance_profile_name" {
  value       = aws_iam_instance_profile.ec2_ssm.name
  description = "Instance profile для EC2, чтобы узлы управлялись SSM."
}

output "vpc_endpoint_ids" {
  value = {
    ssm         = try(aws_vpc_endpoint.ssm[0].id, null)
    ssmmessages = try(aws_vpc_endpoint.ssmmessages[0].id, null)
    ec2messages = try(aws_vpc_endpoint.ec2messages[0].id, null)
  }
  description = "ID интерфейсных VPC endpoints (если включены)."
}

output "hybrid_activation" {
  value = var.enable_hybrid_activation ? {
    id   = aws_ssm_activation.hybrid[0].id
    code = aws_ssm_activation.hybrid[0].activation_code
  } : null
  sensitive   = true
  description = "Данные для регистрации on‑prem узлов (если включено)."
}
