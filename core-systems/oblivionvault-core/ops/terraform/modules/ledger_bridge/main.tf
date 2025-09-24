terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.55"
    }
  }
}

############################
# VARIABLES (module inputs) #
############################

variable "name" {
  description = "Базовое имя модуля (например, 'ledger-bridge')."
  type        = string
}

variable "tags" {
  description = "Общие теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

variable "region" {
  description = "AWS Region для провайдера."
  type        = string
}

variable "vpc_id" {
  description = "ID существующего VPC."
  type        = string
}

variable "private_subnet_ids" {
  description = "Список приватных сабнетов для ECS Service."
  type        = list(string)
}

variable "create_security_group" {
  description = "Создавать Security Group для сервиса (иначе использовать существующую)?"
  type        = bool
  default     = true
}

variable "security_group_id" {
  description = "Существующий Security Group ID (используется, если create_security_group=false)."
  type        = string
  default     = null
}

variable "image" {
  description = "Контейнерный образ (ECR/публичный) для мост‑сервиса."
  type        = string
}

variable "container_port" {
  description = "Порт контейнера."
  type        = number
  default     = 8080
}

variable "healthcheck_path" {
  description = "HTTP путь для healthcheck (если null — используется TCP)."
  type        = string
  default     = "/health"
}

variable "cpu" {
  description = "Ресурсы CPU для таска (Fargate), например 256/512/1024/2048."
  type        = number
  default     = 512
}

variable "memory" {
  description = "Память (MiB) для таска (Fargate), например 1024/2048/4096."
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Желаемое число реплик ECS сервиса."
  type        = number
  default     = 2
}

variable "assign_public_ip" {
  description = "Назначать ли публичный IP задачам (обычно false для приватных сабнетов)."
  type        = bool
  default     = false
}

variable "create_cluster" {
  description = "Создавать ли отдельный ECS кластер."
  type        = bool
  default     = true
}

variable "cluster_name" {
  description = "Имя существующего кластера ECS (если create_cluster=false)."
  type        = string
  default     = null
}

variable "environment" {
  description = "Ключ-значение переменных окружения контейнера (несекретные)."
  type        = map(string)
  default     = {}
}

variable "secrets_json" {
  description = "JSON строка конфигурации (секрет), будет помещена в Secrets Manager."
  type        = string
  default     = null
  sensitive   = true
}

variable "extra_secret_arns" {
  description = "Доп. ARNs секретов (RPC ключи, приватные ключи и т.д.), которые будут примаплены в контейнер."
  type        = list(string)
  default     = []
}

variable "enable_autoscaling" {
  description = "Включить авто‑масштабирование ECS сервиса по длине очереди."
  type        = bool
  default     = true
}

variable "min_task_count" {
  description = "Минимум задач для авто‑масштабирования."
  type        = number
  default     = 2
}

variable "max_task_count" {
  description = "Максимум задач для авто‑масштабирования."
  type        = number
  default     = 10
}

variable "scale_target_max_msg_per_task" {
  description = "Целевая метрика: сообщений SQS на одну задачу."
  type        = number
  default     = 50
}

variable "sqs_message_retention_seconds" {
  description = "Retention сообщений SQS."
  type        = number
  default     = 345600 # 4 days
}

variable "sqs_visibility_timeout_seconds" {
  description = "Visibility timeout для SQS."
  type        = number
  default     = 300
}

variable "sqs_dlq_max_receive" {
  description = "Сколько раз сообщение может быть прочитано до перемещения в DLQ."
  type        = number
  default     = 5
}

variable "dynamodb_billing_mode" {
  description = "Billing mode для DynamoDB ('PAY_PER_REQUEST' или 'PROVISIONED')."
  type        = string
  default     = "PAY_PER_REQUEST"
}

variable "dynamodb_table_name_override" {
  description = "Переопределить имя таблицы DynamoDB (по умолчанию формируется автоматически)."
  type        = string
  default     = null
}

variable "permissions_boundary_arn" {
  description = "Опциональная граница прав IAM (Permissions Boundary) для ролей."
  type        = string
  default     = null
}

provider "aws" {
  region = var.region
}

##########
# LOCALS #
##########

locals {
  base_name     = var.name
  workspace     = terraform.workspace
  suffix        = replace(lower(local.workspace), "/[^a-z0-9-]/", "-")
  resource_name = "${local.base_name}-${local.suffix}"

  common_tags = merge(
    {
      "Project"     = "oblivionvault-core"
      "Module"      = "ledger_bridge"
      "Environment" = local.workspace
      "ManagedBy"   = "Terraform"
    },
    var.tags
  )
}

##########################
# SECURITY & ENCRYPTION  #
##########################

resource "aws_kms_key" "this" {
  description             = "KMS key for ${local.resource_name} secrets and data at rest"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = local.common_tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/${local.resource_name}"
  target_key_id = aws_kms_key.this.id
}

####################
# SECRETS MANAGER  #
####################

resource "aws_secretsmanager_secret" "bridge_config" {
  name       = "${local.resource_name}-config"
  kms_key_id = aws_kms_key.this.id
  tags       = local.common_tags
}

resource "aws_secretsmanager_secret_version" "bridge_config" {
  count         = var.secrets_json == null ? 0 : 1
  secret_id     = aws_secretsmanager_secret.bridge_config.id
  secret_string = var.secrets_json
}

#####################
# DYNAMODB CHECKPOINT
#####################

resource "aws_dynamodb_table" "checkpoints" {
  name         = coalesce(var.dynamodb_table_name_override, "${local.resource_name}-checkpoints")
  billing_mode = var.dynamodb_billing_mode

  hash_key = "pk"
  range_key = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.this.arn
  }

  tags = local.common_tags
}

########
# SQS  #
########

resource "aws_sqs_queue" "dlq" {
  name                              = "${local.resource_name}-dlq"
  message_retention_seconds         = max(var.sqs_message_retention_seconds, 1209600) # keep DLQ up to 14d
  kms_master_key_id                 = aws_kms_key.this.arn
  kms_data_key_reuse_period_seconds = 300
  tags                              = local.common_tags
}

resource "aws_sqs_queue" "main" {
  name                              = "${local.resource_name}-queue"
  visibility_timeout_seconds        = var.sqs_visibility_timeout_seconds
  message_retention_seconds         = var.sqs_message_retention_seconds
  redrive_policy                    = jsonencode({ deadLetterTargetArn = aws_sqs_queue.dlq.arn, maxReceiveCount = var.sqs_dlq_max_receive })
  kms_master_key_id                 = aws_kms_key.this.arn
  kms_data_key_reuse_period_seconds = 300
  tags                              = local.common_tags
}

#####################
# CLOUDWATCH LOGS   #
#####################

resource "aws_cloudwatch_log_group" "this" {
  name              = "/oblivionvault/${local.resource_name}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.this.arn
  tags              = local.common_tags
}

#####################
# SECURITY GROUP    #
#####################

resource "aws_security_group" "svc" {
  count       = var.create_security_group ? 1 : 0
  name        = "${local.resource_name}-sg"
  description = "Security group for ${local.resource_name} ECS service"
  vpc_id      = var.vpc_id
  tags        = local.common_tags

  egress {
    description = "Allow all egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

locals {
  effective_sg_id = var.create_security_group ? aws_security_group.svc[0].id : var.security_group_id
}

############
# ECS PART #
############

resource "aws_ecs_cluster" "this" {
  count = var.create_cluster ? 1 : 0
  name  = "${local.resource_name}-ecs"
  tags  = local.common_tags

  configuration {
    execute_command_configuration {
      logging = "DEFAULT"
      kms_key_id = aws_kms_key.this.arn
    }
  }
}

locals {
  ecs_cluster_name = var.create_cluster ? aws_ecs_cluster.this[0].name : var.cluster_name
}

resource "aws_iam_role" "task_exec" {
  name                 = "${local.resource_name}-exec-role"
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_assume.json
  permissions_boundary = var.permissions_boundary_arn
  tags                 = local.common_tags
}

resource "aws_iam_role" "task_role" {
  name                 = "${local.resource_name}-task-role"
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_assume.json
  permissions_boundary = var.permissions_boundary_arn
  tags                 = local.common_tags
}

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# Execution role policy: pull from ECR, write logs, read secrets (by ARNs)
data "aws_iam_policy_document" "exec_policy" {
  statement {
    sid     = "Logs"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams", "logs:CreateLogGroup"]
    resources = ["*"]
  }

  statement {
    sid = "ECRPull"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchCheckLayerAvailability",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories"
    ]
    resources = ["*"]
  }

  statement {
    sid      = "DecryptSecrets"
    actions  = ["kms:Decrypt"]
    resources = [aws_kms_key.this.arn]
  }

  statement {
    sid = "ReadSecrets"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]
    resources = concat(
      [aws_secretsmanager_secret.bridge_config.arn],
      var.extra_secret_arns
    )
  }
}

resource "aws_iam_policy" "exec_policy" {
  name        = "${local.resource_name}-exec-policy"
  description = "Execution policy for ECS tasks of ${local.resource_name}"
  policy      = data.aws_iam_policy_document.exec_policy.json
  tags        = local.common_tags
}

resource "aws_iam_role_policy_attachment" "exec_attach" {
  role       = aws_iam_role.task_exec.name
  policy_arn = aws_iam_policy.exec_policy.arn
}

# Task role policy: SQS, DynamoDB, KMS (decrypt), CloudWatch metrics (optional)
data "aws_iam_policy_document" "task_policy" {
  statement {
    sid = "SQSAccess"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ChangeMessageVisibility",
      "sqs:SendMessage",
      "sqs:ListQueues"
    ]
    resources = [aws_sqs_queue.main.arn, aws_sqs_queue.dlq.arn]
  }

  statement {
    sid = "DynamoDBCheckpoints"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:UpdateItem",
      "dynamodb:DescribeTable",
      "dynamodb:Query"
    ]
    resources = [aws_dynamodb_table.checkpoints.arn]
  }

  statement {
    sid      = "KMSDecrypt"
    actions  = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*"]
    resources = [aws_kms_key.this.arn]
  }
}

resource "aws_iam_policy" "task_policy" {
  name        = "${local.resource_name}-task-policy"
  description = "Task policy for ${local.resource_name}"
  policy      = data.aws_iam_policy_document.task_policy.json
  tags        = local.common_tags
}

resource "aws_iam_role_policy_attachment" "task_attach" {
  role       = aws_iam_role.task_role.name
  policy_arn = aws_iam_policy.task_policy.arn
}

resource "aws_ecs_task_definition" "this" {
  family                   = "${local.resource_name}-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.task_exec.arn
  task_role_arn            = aws_iam_role.task_role.arn

  container_definitions = jsonencode([
    {
      name      = "bridge"
      image     = var.image
      essential = true
      portMappings = [{
        containerPort = var.container_port
        hostPort      = var.container_port
        protocol      = "tcp"
      }]
      environment = [
        for k, v in var.environment : {
          name  = k
          value = v
        }
      ]
      secrets = concat(
        [
          {
            name      = "BRIDGE_CONFIG_JSON"
            valueFrom = aws_secretsmanager_secret.bridge_config.arn
          }
        ],
        [
          for arn in var.extra_secret_arns : {
            name      = replace(split(":", arn)[length(split(":", arn)) - 1], "/", "_")
            valueFrom = arn
          }
        ]
      )
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = var.region
          awslogs-stream-prefix = "ecs"
        }
      }
      healthCheck = (
        var.healthcheck_path != null ?
        {
          command     = ["CMD-SHELL", "curl -sf http://localhost:${var.container_port}${var.healthcheck_path} || exit 1"]
          interval    = 30
          timeout     = 5
          retries     = 3
          startPeriod = 30
        } :
        {
          command     = ["CMD-SHELL", "nc -z localhost ${var.container_port} || exit 1"]
          interval    = 30
          timeout     = 5
          retries     = 3
          startPeriod = 30
        }
      )
    }
  ])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  ephemeral_storage {
    size_in_gib = 21
  }

  tags = local.common_tags
}

resource "aws_ecs_service" "this" {
  name            = "${local.resource_name}-svc"
  cluster         = local.ecs_cluster_name
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [local.effective_sg_id]
    assign_public_ip = var.assign_public_ip ? "ENABLED" : "DISABLED"
  }

  deployment_controller {
    type = "ECS"
  }

  enable_execute_command = true

  tags = local.common_tags

  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [
    aws_cloudwatch_log_group.this
  ]
}

#########################################
# APPLICATION AUTO SCALING (optional)   #
#########################################

resource "aws_appautoscaling_target" "ecs" {
  count              = var.enable_autoscaling ? 1 : 0
  max_capacity       = var.max_task_count
  min_capacity       = var.min_task_count
  resource_id        = "service/${local.ecs_cluster_name}/${aws_ecs_service.this.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

# Политика по длине очереди: целимся в X сообщений на одну задачу
resource "aws_cloudwatch_metric_alarm" "queue_depth" {
  count               = var.enable_autoscaling ? 1 : 0
  alarm_name          = "${local.resource_name}-queue-depth"
  alarm_description   = "Scale ECS service based on SQS ApproximateNumberOfMessagesVisible"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Average"
  threshold           = var.scale_target_max_msg_per_task * max(var.min_task_count, 1)
  dimensions = {
    QueueName = aws_sqs_queue.main.name
  }
  treat_missing_data = "notBreaching"
  tags               = local.common_tags
}

resource "aws_appautoscaling_policy" "scale_out" {
  count              = var.enable_autoscaling ? 1 : 0
  name               = "${local.resource_name}-scale-out"
  policy_type        = "StepScaling"
  resource_id        = aws_appautoscaling_target.ecs[0].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs[0].service_namespace

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 60
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_lower_bound = 0
      scaling_adjustment          = 1
    }
    step_adjustment {
      metric_interval_lower_bound = 20
      scaling_adjustment          = 2
    }
  }
}

resource "aws_appautoscaling_policy" "scale_in" {
  count              = var.enable_autoscaling ? 1 : 0
  name               = "${local.resource_name}-scale-in"
  policy_type        = "StepScaling"
  resource_id        = aws_appautoscaling_target.ecs[0].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs[0].service_namespace

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 120
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_upper_bound = 0
      scaling_adjustment          = -1
    }
  }
}

################
# OUTPUTS (in file for self-containment)
################

output "kms_key_arn" {
  description = "ARN KMS ключа."
  value       = aws_kms_key.this.arn
}

output "secrets_config_arn" {
  description = "ARN секрета конфигурации bridge."
  value       = aws_secretsmanager_secret.bridge_config.arn
}

output "sqs_queue_url" {
  description = "URL основной очереди."
  value       = aws_sqs_queue.main.url
}

output "sqs_dlq_url" {
  description = "URL DLQ."
  value       = aws_sqs_queue.dlq.url
}

output "dynamodb_table_name" {
  description = "Имя таблицы чекпойнтов."
  value       = aws_dynamodb_table.checkpoints.name
}

output "ecs_cluster_name" {
  description = "Имя ECS кластера."
  value       = local.ecs_cluster_name
}

output "ecs_service_name" {
  description = "Имя ECS сервиса."
  value       = aws_ecs_service.this.name
}

output "log_group_name" {
  description = "Имя CloudWatch Log Group."
  value       = aws_cloudwatch_log_group.this.name
}
