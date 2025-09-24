terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
  }
}

########################################
# Data / Locals
########################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_vpc" "this" {
  id = var.vpc_id
}

locals {
  name        = var.name
  labels      = merge(var.tags, { "app" = var.name, "component" = "ztna-broker" })
  env         = var.env
  container   = var.name
  ecs_log_grp = "/aws/ecs/${var.name}"

  # Поддержка env/secret для контейнера
  container_env = [
    for k, v in var.environment :
    {
      name  = k
      value = v
    }
  ]

  container_secrets = [
    for k, arn in var.secrets :
    {
      name      = k
      valueFrom = arn
    }
  ]

  # Источник ingress для сервиса (NLB не имеет SG): по умолчанию — весь VPC CIDR.
  ingress_cidrs = length(var.allowed_ingress_cidrs) > 0 ? var.allowed_ingress_cidrs : [data.aws_vpc.this.cidr_block]

  # Выбор протокола листенера NLB
  nlb_listener_protocol = var.tls_certificate_arn != null && var.tls_certificate_arn != "" ? "TLS" : "TCP"

  # Healthcheck на Target Group (NLB поддерживает TCP/HTTP/HTTPS)
  tg_hc_protocol = var.healthcheck.protocol
  tg_hc_path     = try(var.healthcheck.path, null)
  tg_hc_port     = try(var.healthcheck.port, var.container_port)
}

########################################
# IAM (task execution / task role)
########################################

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "task_execution" {
  name               = "${local.name}-task-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
  tags               = local.labels
}

# Базовая политика выполнения ECS (pull образов, логи и т.д.)
resource "aws_iam_role_policy_attachment" "task_execution_managed" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Доступ к секретам (минимально — только перечисленные)
data "aws_iam_policy_document" "secrets_access" {
  count = length(var.secrets) > 0 ? 1 : 0

  statement {
    sid     = "SecretsAccess"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      for _, arn in var.secrets : arn
    ]
  }
}

resource "aws_iam_policy" "secrets_access" {
  count       = length(var.secrets) > 0 ? 1 : 0
  name        = "${local.name}-secrets-access"
  description = "Allow ECS task execution to read declared secrets"
  policy      = data.aws_iam_policy_document.secrets_access[0].json
  tags        = local.labels
}

resource "aws_iam_role_policy_attachment" "secrets_access" {
  count      = length(var.secrets) > 0 ? 1 : 0
  role       = aws_iam_role.task_execution.name
  policy_arn = aws_iam_policy.secrets_access[0].arn
}

resource "aws_iam_role" "task_role" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
  tags               = local.labels
}

########################################
# CloudWatch Logs
########################################

resource "aws_cloudwatch_log_group" "ecs" {
  name              = local.ecs_log_grp
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
  tags              = local.labels
}

########################################
# Networking / Security
########################################

resource "aws_security_group" "service" {
  name        = "${local.name}-svc"
  description = "Security group for ZTNA broker tasks"
  vpc_id      = var.vpc_id
  tags        = local.labels
}

# Ingress от NLB (источники — CIDR VPC/подсетей)
resource "aws_vpc_security_group_ingress_rule" "service_tls" {
  security_group_id = aws_security_group.service.id
  cidr_ipv4         = local.ingress_cidrs[0]
  from_port         = var.container_port
  to_port           = var.container_port
  ip_protocol       = "tcp"
  description       = "Ingress from NLB to broker"
}

# Дополнительные CIDR при необходимости
resource "aws_vpc_security_group_ingress_rule" "service_tls_extra" {
  for_each          = toset(slice(local.ingress_cidrs, 1, length(local.ingress_cidrs)))
  security_group_id = aws_security_group.service.id
  cidr_ipv4         = each.value
  from_port         = var.container_port
  to_port           = var.container_port
  ip_protocol       = "tcp"
  description       = "Ingress (extra CIDR) from NLB to broker"
}

# Egress в Интернет/внутри VPC (для обновлений, внешних API, IdP и т.п.)
resource "aws_vpc_security_group_egress_rule" "service_all" {
  security_group_id = aws_security_group.service.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Allow all egress"
}

########################################
# ECS Cluster / Task / Service (Fargate)
########################################

resource "aws_ecs_cluster" "this" {
  name = "${local.name}-cluster"
  setting {
    name  = "containerInsights"
    value = var.enable_container_insights ? "enabled" : "disabled"
  }
  tags = local.labels
}

resource "aws_ecs_task_definition" "this" {
  family                   = local.name
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.task_role.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }
  ephemeral_storage {
    size_in_gib = var.ephemeral_storage_gib
  }

  container_definitions = jsonencode([
    {
      name      = local.container
      image     = var.container_image
      essential = true

      portMappings = [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ]

      # Логи в CloudWatch
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.ecs.name
          awslogs-region        = data.aws_region.current.name
          awslogs-stream-prefix = "ecs"
        }
      }

      # Переменные окружения и секреты
      environment = local.container_env
      secrets     = local.container_secrets

      # Ограничения по ресурсам единичного контейнера
      readonlyRootFilesystem = var.readonly_root_fs
      linuxParameters = {
        initProcessEnabled = true
        maxSwap            = 0
        sharedMemorySize   = 0
      }

      # Healthcheck контейнера (опционально) — чаще хватает TG healthcheck.
      # healthCheck = {
      #   command     = ["CMD-SHELL", "curl -sf http://127.0.0.1:${var.healthcheck.port}${var.healthcheck.path} || exit 1"]
      #   interval    = 15
      #   timeout     = 5
      #   retries     = 3
      #   startPeriod = 15
      # }
    }
  ])

  tags = local.labels
}

resource "aws_lb" "nlb" {
  name                             = "${local.name}-nlb"
  load_balancer_type               = "network"
  internal                         = var.internal
  subnets                          = var.nlb_subnet_ids
  enable_cross_zone_load_balancing = true
  idle_timeout                     = 350
  dynamic "access_logs" {
    for_each = var.enable_nlb_access_logs && var.access_logs_bucket != null ? [1] : []
    content {
      bucket  = var.access_logs_bucket
      prefix  = var.access_logs_prefix
      enabled = true
    }
  }
  tags = local.labels
}

resource "aws_lb_target_group" "tg" {
  name        = "${local.name}-tg"
  port        = var.container_port
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 15
    timeout             = 6
    protocol            = upper(local.tg_hc_protocol)
    port                = local.tg_hc_port
    path                = local.tg_hc_protocol == "HTTP" || local.tg_hc_protocol == "HTTPS" ? local.tg_hc_path : null
  }

  tags = local.labels
}

# NLB Listener: TCP или TLS при наличии сертификата
resource "aws_lb_listener" "tls" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = var.listener_port
  protocol          = local.nlb_listener_protocol
  alpn_policy       = var.alpn_policy

  dynamic "ssl_policy" {
    for_each = local.nlb_listener_protocol == "TLS" ? [1] : []
    content {
      # атрибут ssl_policy доступен напрямую, но dynamic для наглядности
    }
  }

  certificate_arn = local.nlb_listener_protocol == "TLS" ? var.tls_certificate_arn : null

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }

  lifecycle {
    ignore_changes = [ssl_policy] # чтобы не дрожать от несущественных апдейтов
  }

  tags = local.labels
}

# ECS Service
resource "aws_ecs_service" "this" {
  name                               = local.name
  cluster                            = aws_ecs_cluster.this.id
  task_definition                    = aws_ecs_task_definition.this.arn
  desired_count                      = var.desired_count
  launch_type                        = "FARGATE"
  platform_version                   = "1.4.0"
  enable_execute_command             = var.enable_exec
  health_check_grace_period_seconds  = 60
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  propagate_tags                     = "SERVICE"

  network_configuration {
    subnets         = var.service_subnet_ids
    security_groups = [aws_security_group.service.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.tg.arn
    container_name   = local.container
    container_port   = var.container_port
  }

  depends_on = [aws_lb_listener.tls]

  tags = local.labels

  lifecycle {
    ignore_changes = [desired_count] # HPA/AppAutoscaling управляет количеством
  }
}

########################################
# Application Auto Scaling (по CPU/Memory)
########################################

resource "aws_appautoscaling_target" "ecs" {
  max_capacity       = var.as_max_capacity
  min_capacity       = var.as_min_capacity
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.this.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${local.name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value       = var.as_target_cpu
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    scale_in_cooldown  = 60
    scale_out_cooldown = 60
  }
}

resource "aws_appautoscaling_policy" "memory" {
  name               = "${local.name}-mem"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value       = var.as_target_memory
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    scale_in_cooldown  = 60
    scale_out_cooldown = 60
  }
}

########################################
# PrivateLink (VPC Endpoint Service)
########################################

resource "aws_vpc_endpoint_service" "this" {
  count = var.enable_vpce_service ? 1 : 0

  acceptance_required        = var.vpce_acceptance_required
  network_load_balancer_arns = [aws_lb.nlb.arn]
  private_dns_name           = var.vpce_private_dns_name # опционально (для потребителей в вашем домене)

  tags = local.labels
}

# Allow‑list принципалов (клиентские аккаунты/организации)
resource "aws_vpc_endpoint_service_allowed_principal" "allow" {
  for_each               = var.enable_vpce_service ? toset(var.vpce_allowed_principals) : toset([])
  vpc_endpoint_service_id = aws_vpc_endpoint_service.this[0].id
  principal_arn           = each.value
}

########################################
# Variables
########################################

variable "name" {
  description = "Базовое имя ресурсов (cluster, service, NLB, TG и т.д.)"
  type        = string
  default     = "ztna-broker"
}

variable "env" {
  description = "Окружение (prod/stage/dev...)"
  type        = string
  default     = "prod"
}

variable "vpc_id" {
  description = "ID целевого VPC"
  type        = string
}

variable "service_subnet_ids" {
  description = "Список приватных подсетей для ECS сервисов (awsvpc)"
  type        = list(string)
}

variable "nlb_subnet_ids" {
  description = "Список подсетей для NLB (обычно приватные при internal=true)"
  type        = list(string)
}

variable "internal" {
  description = "Внутренний NLB (true) или внешним (false)"
  type        = bool
  default     = true
}

variable "container_image" {
  description = "Образ контейнера брокера (например, ECR URI с digest)"
  type        = string
}

variable "container_port" {
  description = "Порт контейнера, на который форвардит NLB/TG"
  type        = number
  default     = 8443
}

variable "listener_port" {
  description = "Порт NLB listener (обычно 443)"
  type        = number
  default     = 443
}

variable "tls_certificate_arn" {
  description = "ARN ACM‑сертификата для TLS listener (если пусто — TCP pass‑through)"
  type        = string
  default     = null
}

variable "alpn_policy" {
  description = "ALPN policy для TLS (например, HTTP2Preferred, None)"
  type        = string
  default     = "None"
}

variable "healthcheck" {
  description = "Параметры healthcheck target‑группы"
  type = object({
    protocol = optional(string, "TCP")  # TCP|HTTP|HTTPS
    path     = optional(string)         # для HTTP/HTTPS
    port     = optional(number)         # по умолчанию = container_port
  })
  default = {
    protocol = "TCP"
  }
}

variable "desired_count" {
  description = "Начальное число задач ECS"
  type        = number
  default     = 2
}

variable "task_cpu" {
  description = "CPU Fargate задачи (1024 = 1 vCPU)"
  type        = number
  default     = 512
}

variable "task_memory" {
  description = "Память Fargate задачи (MiB)"
  type        = number
  default     = 1024
}

variable "cpu_architecture" {
  description = "Архитектура CPU для Fargate (X86_64 или ARM64)"
  type        = string
  default     = "X86_64"
}

variable "ephemeral_storage_gib" {
  description = "Ephemeral storage для задачи (GiB)"
  type        = number
  default     = 21
}

variable "readonly_root_fs" {
  description = "Только чтение для root FS контейнера"
  type        = bool
  default     = true
}

variable "environment" {
  description = "ENV переменные для контейнера"
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Секреты для контейнера: имя переменной -> ARN секрета"
  type        = map(string)
  default     = {}
}

variable "enable_container_insights" {
  description = "Включить ECS Container Insights"
  type        = bool
  default     = true
}

variable "enable_exec" {
  description = "Разрешить ecs execute‑command (SSM) для отладки"
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Срок хранения CloudWatch логов"
  type        = number
  default     = 30
}

variable "log_kms_key_arn" {
  description = "KMS‑ключ для шифрования лог‑группы (опционально)"
  type        = string
  default     = null
}

variable "allowed_ingress_cidrs" {
  description = "CIDR‑источники для ingress на сервис (по умолчанию VPC CIDR)"
  type        = list(string)
  default     = []
}

variable "enable_nlb_access_logs" {
  description = "Включить access logs на NLB (нужен предварительно сконфигурированный S3 бакет)"
  type        = bool
  default     = false
}

variable "access_logs_bucket" {
  description = "Имя S3 бакета для NLB access logs (если enable_nlb_access_logs=true)"
  type        = string
  default     = null
}

variable "access_logs_prefix" {
  description = "Префикс в бакете для NLB access logs"
  type        = string
  default     = "nlb/${var.name}"
}

variable "enable_vpce_service" {
  description = "Публиковать сервис как PrivateLink Endpoint Service"
  type        = bool
  default     = true
}

variable "vpce_allowed_principals" {
  description = "Список ARN принципалов (аккаунт/орг) с доступом к Endpoint Service"
  type        = list(string)
  default     = []
}

variable "vpce_acceptance_required" {
  description = "Требовать ручного подтверждения соединений PrivateLink"
  type        = bool
  default     = true
}

variable "vpce_private_dns_name" {
  description = "Private DNS name для Endpoint Service (опционально)"
  type        = string
  default     = null
}

variable "tags" {
  description = "Общие теги"
  type        = map(string)
  default     = {}
}

########################################
# Outputs
########################################

output "ecs_cluster_arn" {
  value       = aws_ecs_cluster.this.arn
  description = "ARN ECS кластера"
}

output "ecs_service_arn" {
  value       = aws_ecs_service.this.arn
  description = "ARN ECS сервиса"
}

output "task_execution_role_arn" {
  value       = aws_iam_role.task_execution.arn
  description = "ARN роли исполнения задачи"
}

output "task_role_arn" {
  value       = aws_iam_role.task_role.arn
  description = "ARN роли задачи"
}

output "service_security_group_id" {
  value       = aws_security_group.service.id
  description = "ID SG сервиса"
}

output "nlb_arn" {
  value       = aws_lb.nlb.arn
  description = "ARN NLB"
}

output "nlb_dns_name" {
  value       = aws_lb.nlb.dns_name
  description = "DNS имя NLB"
}

output "target_group_arn" {
  value       = aws_lb_target_group.tg.arn
  description = "ARN target group"
}

output "vpc_endpoint_service_service_name" {
  value       = var.enable_vpce_service ? aws_vpc_endpoint_service.this[0].service_name : null
  description = "Имя PrivateLink сервиса (для потребителей VPC)"
}

output "vpc_endpoint_service_id" {
  value       = var.enable_vpce_service ? aws_vpc_endpoint_service.this[0].id : null
  description = "ID PrivateLink сервиса"
}
