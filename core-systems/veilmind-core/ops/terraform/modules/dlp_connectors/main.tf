// veilmind-core/ops/terraform/modules/dlp_connectors/main.tf
// Industrial Zero-Trust DLP Connector Module (AWS)

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6"
    }
  }
}

############################
# Inputs (module variables)
############################

variable "name_prefix" {
  description = "Префикс имени для всех ресурсов (a-z0-9-)"
  type        = string
}

variable "tags" {
  description = "Общие теги"
  type        = map(string)
  default     = {}
}

variable "vpc_id" {
  description = "ID VPC для ECS/Fargate и (опционально) VPC Endpoints"
  type        = string
}

variable "private_subnet_ids" {
  description = "Список приватных подсетей для ECS/Fargate"
  type        = list(string)
}

variable "security_group_ids_extra" {
  description = "Дополнительные security groups для задач (опционально)"
  type        = list(string)
  default     = []
}

variable "create_vpc_endpoints" {
  description = "Создавать ли приватные VPC Endpoints для S3/SQS/Logs/ECR/Secrets/STS"
  type        = bool
  default     = true
}

variable "create_kms_key" {
  description = "Создавать собственный KMS ключ для шифрования или использовать существующий"
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "ARN существующего KMS-ключа (если create_kms_key=false)"
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "Срок хранения логов CloudWatch"
  type        = number
  default     = 90
}

variable "desired_count" {
  description = "Количество задач ECS (реплик) коннектора"
  type        = number
  default     = 2
}

variable "task_cpu" {
  description = "CPU (Fargate), например 256/512/1024/2048/4096"
  type        = number
  default     = 512
}

variable "task_memory" {
  description = "Память (MiB) для Fargate, например 1024/2048/4096/8192"
  type        = number
  default     = 1024
}

variable "connector_image" {
  description = "Полный образ контейнера коннектора (ECR/регистри), например 123456789012.dkr.ecr.eu-west-1.amazonaws.com/dlp-connector:1.0.0"
  type        = string
}

variable "connector_command" {
  description = "Переопределение команды контейнера (опционально)"
  type        = list(string)
  default     = null
}

variable "vendor_api_url" {
  description = "Базовый URL внешнего DLP API (коннектор отправляет туда результаты)"
  type        = string
}

variable "vendor_token_secret_arn" {
  description = "ARN существующего секрета с токеном провайдера DLP; если null — секрет будет создан пустым (без версии)"
  type        = string
  default     = null
}

variable "create_s3_notifications" {
  description = "Настраивать ли S3 Bucket Notifications на нашу SQS (может конфликтовать с уже существующими настройками)"
  type        = bool
  default     = false
}

variable "source_s3_arns" {
  description = "Список ARN S3 бакетов-источников событий (для нотификаций и/или IAM-политик)"
  type        = list(string)
  default     = []
}

variable "sqs_visibility_timeout" {
  description = "Visibility timeout для рабочей очереди, сек"
  type        = number
  default     = 120
}

variable "sqs_message_retention_seconds" {
  description = "Срок хранения сообщений в рабочей очереди, сек"
  type        = number
  default     = 86400
}

variable "dlq_message_retention_seconds" {
  description = "Срок хранения сообщений в DLQ, сек"
  type        = number
  default     = 1209600
}

variable "restrict_egress_https_only" {
  description = "Разрешить только исходящий трафик TCP 443 из задач ECS"
  type        = bool
  default     = true
}

############################
# Locals / Helpers
############################

locals {
  name           = replace(lower(var.name_prefix), "/[^a-z0-9-]/", "-")
  common_tags    = merge({ "app.kubernetes.io/name" = "veilmind-core", "component" = "dlp-connector" }, var.tags)
  s3_bucket_names = [
    for arn in var.source_s3_arns :
    replace(arn, "arn:aws:s3:::", "")
  ]

  // KMS resolve
  kms_arn = coalesce(var.kms_key_arn, try(aws_kms_key.this[0].arn, null))

  // Secrets resolve
  vendor_secret_arn = coalesce(var.vendor_token_secret_arn, try(aws_secretsmanager_secret.vendor[0].arn, null))
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

############################
# KMS (optional create)
############################

resource "aws_kms_key" "this" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "${local.name} dlp connector key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EnableRoot"
        Effect   = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

############################
# CloudWatch Logs
############################

resource "aws_cloudwatch_log_group" "connector" {
  name              = "/${local.name}/dlp-connector"
  retention_in_days = var.log_retention_days
  kms_key_id        = local.kms_arn
  tags              = local.common_tags
}

############################
# Secrets Manager (token)
############################

resource "random_id" "suffix" {
  byte_length = 3
}

resource "aws_secretsmanager_secret" "vendor" {
  count       = var.vendor_token_secret_arn == null ? 1 : 0
  name        = "${local.name}/vendor-token-${random_id.suffix.hex}"
  description = "DLP vendor API token (value not managed by Terraform)"
  kms_key_id  = local.kms_arn
  tags        = local.common_tags

  // ВНИМАНИЕ: не создаём версию секрета, чтобы токен не попал в Terraform state.
  // Загрузите значение вручную или через CI/CD вне Terraform.
}

############################
# SQS Queues (main + DLQ)
############################

resource "aws_sqs_queue" "dlq" {
  name                              = "${local.name}-dlq"
  kms_master_key_id                 = local.kms_arn
  message_retention_seconds         = var.dlq_message_retention_seconds
  sqs_managed_sse_enabled           = false
  visibility_timeout_seconds        = 30
  receive_wait_time_seconds         = 10
  redrive_allow_policy              = jsonencode({ redrivePermission = "byQueue", sourceQueueArns = [] })
  tags                              = local.common_tags
}

resource "aws_sqs_queue" "main" {
  name                              = "${local.name}-events"
  kms_master_key_id                 = local.kms_arn
  message_retention_seconds         = var.sqs_message_retention_seconds
  visibility_timeout_seconds        = var.sqs_visibility_timeout
  receive_wait_time_seconds         = 10
  redrive_policy                    = jsonencode({ deadLetterTargetArn = aws_sqs_queue.dlq.arn, maxReceiveCount = 5 })
  sqs_managed_sse_enabled           = false
  tags                              = local.common_tags
}

# Разрешаем S3 публиковать сообщения, если указаны бакеты
data "aws_iam_policy_document" "sqs_allow_s3" {
  statement {
    sid     = "AllowS3SendMessage"
    effect  = "Allow"
    actions = ["sqs:SendMessage", "sqs:SendMessageBatch"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    resources = [aws_sqs_queue.main.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [for b in local.s3_bucket_names : "arn:${data.aws_partition.current.partition}:s3:::${b}"]
    }
  }
}

resource "aws_sqs_queue_policy" "main" {
  queue_url = aws_sqs_queue.main.id
  policy    = data.aws_iam_policy_document.sqs_allow_s3.json
}

############################
# Optional S3 -> SQS Notifications
############################

resource "aws_s3_bucket_notification" "sources" {
  for_each = var.create_s3_notifications ? toset(local.s3_bucket_names) : []

  bucket = each.key

  queue {
    queue_arn     = aws_sqs_queue.main.arn
    events        = ["s3:ObjectCreated:*"]
    filter_suffix = ""   # при необходимости можно настраивать через форк модуля
  }

  depends_on = [aws_sqs_queue_policy.main]
}

############################
# ECS Cluster + Networking
############################

resource "aws_ecs_cluster" "this" {
  name = "${local.name}-ecs"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = local.common_tags
}

resource "aws_security_group" "task" {
  name        = "${local.name}-sg"
  description = "ECS task SG (egress restrictions)"
  vpc_id      = var.vpc_id
  tags        = local.common_tags

  egress {
    description      = "HTTPS only"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = var.restrict_egress_https_only ? ["0.0.0.0/0"] : []
    ipv6_cidr_blocks = var.restrict_egress_https_only ? ["::/0"] : []
  }

  dynamic "egress" {
    for_each = var.restrict_egress_https_only ? [] : [1]
    content {
      description      = "Full egress (disabled in strict mode)"
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }
  }
}

############################
# IAM (Execution + Task Roles)
############################

data "aws_iam_policy_document" "execution_assume" {
  statement {
    effect = "Allow"
    principals { type = "Service", identifiers = ["ecs-tasks.amazonaws.com"] }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "execution" {
  name               = "${local.name}-exec"
  assume_role_policy = data.aws_iam_policy_document.execution_assume.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid     = "ECRPull"
    effect  = "Allow"
    actions = ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
    resources = ["*"]
  }
  statement {
    sid     = "CWLogs"
    effect  = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.connector.arn}:*"]
  }
}

resource "aws_iam_policy" "execution" {
  name   = "${local.name}-exec"
  policy = data.aws_iam_policy_document.execution.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = aws_iam_policy.execution.arn
}

# Task Role (least privilege)
resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.execution_assume.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "task" {
  statement {
    sid     = "ReadQueue"
    effect  = "Allow"
    actions = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:ChangeMessageVisibility"]
    resources = [aws_sqs_queue.main.arn]
  }
  statement {
    sid     = "DeadLetterSend"
    effect  = "Allow"
    actions = ["sqs:SendMessage", "sqs:SendMessageBatch"]
    resources = [aws_sqs_queue.dlq.arn]
  }
  statement {
    sid     = "ReadSecretValue"
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [local.vendor_secret_arn]
  }
  statement {
    sid     = "UseKMS"
    effect  = "Allow"
    actions = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [local.kms_arn]
  }
  dynamic "statement" {
    for_each = length(local.s3_bucket_names) > 0 ? [1] : []
    content {
      sid     = "ReadS3IfNeeded"
      effect  = "Allow"
      actions = ["s3:GetObject", "s3:ListBucket"]
      resources = concat(
        [for b in local.s3_bucket_names : "arn:${data.aws_partition.current.partition}:s3:::${b}"],
        [for b in local.s3_bucket_names : "arn:${data.aws_partition.current.partition}:s3:::${b}/*"]
      )
    }
  }
}

resource "aws_iam_policy" "task" {
  name   = "${local.name}-task"
  policy = data.aws_iam_policy_document.task.json
}

resource "aws_iam_role_policy_attachment" "task" {
  role       = aws_iam_role.task.name
  policy_arn = aws_iam_policy.task.arn
}

############################
# ECS Task Definition
############################

locals {
  container_env = [
    { name = "SQS_QUEUE_URL",    value = aws_sqs_queue.main.id },
    { name = "VENDOR_API_URL",   value = var.vendor_api_url },
    { name = "AWS_REGION",       value = data.aws_region.current.name },
    { name = "LOG_LEVEL",        value = "INFO" }
  ]

  container_secrets = [
    { name = "VENDOR_TOKEN", valueFrom = local.vendor_secret_arn }
  ]
}

resource "aws_ecs_task_definition" "connector" {
  family                   = "${local.name}-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.task_cpu)
  memory                   = tostring(var.task_memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "dlp-connector"
      image     = var.connector_image
      essential = true
      command   = var.connector_command
      linuxParameters = {
        capabilities = {}
      }
      environment = local.container_env
      secrets     = local.container_secrets
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.connector.name
          awslogs-region        = data.aws_region.current.name
          awslogs-stream-prefix = "dlp"
          mode                  = "non-blocking"
        }
      }
      ulimits = [
        { name = "nofile", softLimit = 262144, hardLimit = 262144 }
      ]
      readonlyRootFilesystem = true
      portMappings = []
      healthCheck = {
        command     = ["CMD-SHELL", "test -f /tmp/healthy || exit 1"]
        interval    = 30
        retries     = 3
        timeout     = 5
        startPeriod = 60
      }
    }
  ])

  tags = local.common_tags
}

############################
# ECS Service (Fargate)
############################

resource "aws_ecs_service" "connector" {
  name            = "${local.name}-svc"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.connector.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = concat([aws_security_group.task.id], var.security_group_ids_extra)
    assign_public_ip = false
  }

  deployment_controller { type = "ECS" }

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200
  enable_execute_command             = false
  propagate_tags                     = "SERVICE"

  tags = local.common_tags

  lifecycle {
    ignore_changes = [desired_count] // позволяет аутоскейлеру управлять числом задач
  }
}

############################
# Optional: VPC Endpoints
############################

resource "aws_vpc_endpoint" "s3" {
  count             = var.create_vpc_endpoints ? 1 : 0
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [] // предполагается, что маршрутизация управляется извне; задайте в корневом модуле при необходимости
  tags              = local.common_tags
}

locals {
  interface_endpoints = var.create_vpc_endpoints ? toset([
    "logs", "ecr.api", "ecr.dkr", "secretsmanager", "sqs", "sts"
  ]) : toset([])
}

resource "aws_vpc_endpoint" "interface" {
  for_each          = local.interface_endpoints
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.${each.key}"
  vpc_endpoint_type = "Interface"
  subnet_ids        = var.private_subnet_ids
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.task.id]
  tags                = merge(local.common_tags, { "endpoint" = each.key })
}

############################
# Outputs
############################

output "sqs_queue_url" {
  value       = aws_sqs_queue.main.id
  description = "URL рабочей очереди событий"
}

output "sqs_queue_arn" {
  value       = aws_sqs_queue.main.arn
  description = "ARN рабочей очереди событий"
}

output "dlq_arn" {
  value       = aws_sqs_queue.dlq.arn
  description = "ARN очереди DLQ"
}

output "ecs_cluster_id" {
  value       = aws_ecs_cluster.this.id
  description = "ID ECS кластера"
}

output "ecs_service_name" {
  value       = aws_ecs_service.connector.name
  description = "Имя ECS сервиса"
}

output "task_role_arn" {
  value       = aws_iam_role.task.arn
  description = "ARN роли задач (IAM)"
}

output "execution_role_arn" {
  value       = aws_iam_role.execution.arn
  description = "ARN роли исполнения (IAM)"
}

output "kms_key_arn" {
  value       = local.kms_arn
  description = "ARN используемого KMS ключа"
}

output "vendor_secret_arn" {
  value       = local.vendor_secret_arn
  description = "ARN секрета с DLP токеном (значение не управляется Terraform)"
}
