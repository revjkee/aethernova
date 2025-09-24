/************************************************************
* datafabric-core / ops/terraform/modules/observability/main.tf
* Назначение: Managed Prometheus (AMP) + Managed Grafana (AMG) + CloudWatch Logs + SNS + IRSA
* Требования: Terraform >= 1.4, AWS provider >= 5.0
*************************************************************/

terraform {
  required_version = ">= 1.4"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

provider "aws" {
  region = var.region
}

########################
# ВХОДНЫЕ ПАРАМЕТРЫ
########################

variable "region" {
  description = "AWS регион"
  type        = string
}

variable "tags" {
  description = "Общие теги"
  type        = map(string)
  default     = {}
}

# -------- CloudWatch Logs --------
variable "log_group_name" {
  description = "Имя CloudWatch Log Group для прилож. логов"
  type        = string
  default     = "/datafabric/core"
}

variable "log_retention_days" {
  description = "Время хранения логов (сутки)"
  type        = number
  default     = 30
}

# -------- KMS --------
variable "create_kms" {
  description = "Создать customer‑managed KMS ключ для SNS/Logs/Grafana"
  type        = bool
  default     = true
}

variable "kms_alias" {
  description = "Алиас KMS (если create_kms=true)"
  type        = string
  default     = "alias/datafabric-observability"
}

# -------- AMP (Managed Prometheus) --------
variable "amp_workspace_name" {
  description = "Имя AMP Workspace"
  type        = string
  default     = "datafabric-core"
}

variable "amp_logging_enabled" {
  description = "Включить логирование AMP в CloudWatch Logs"
  type        = bool
  default     = true
}

variable "amp_rule_groups_yaml" {
  description = "Путь к YAML файлу (или содержимому) Rule Groups для AMP. Если пусто — ресурс не создается."
  type        = string
  default     = ""
}

variable "amp_rule_groups_name" {
  description = "Имя namespace для Rule Groups"
  type        = string
  default     = "datafabric-rules"
}

variable "amp_alertmanager_yaml" {
  description = "Путь к YAML файлу (или содержимому) Alertmanager для AMP. Если пусто — ресурс не создается."
  type        = string
  default     = ""
}

# -------- IRSA для remote-write из EKS --------
variable "enable_irsa" {
  description = "Создать IAM роль для EKS ServiceAccount (IRSA) для remote‑write в AMP"
  type        = bool
  default     = true
}

variable "oidc_provider_arn" {
  description = "ARN OIDC провайдера кластера EKS (aws_iam_openid_connect_provider)"
  type        = string
  default     = ""
}

variable "eks_namespace" {
  description = "Namespace в EKS, где работает Prometheus/agent"
  type        = string
  default     = "monitoring"
}

variable "eks_service_account" {
  description = "ServiceAccount name, которому выдаем роль"
  type        = string
  default     = "prometheus-agent"
}

# -------- AMG (Managed Grafana) --------
variable "enable_grafana" {
  description = "Создать Managed Grafana Workspace"
  type        = bool
  default     = true
}

variable "grafana_workspace_name" {
  description = "Имя Grafana Workspace"
  type        = string
  default     = "datafabric-core"
}

variable "grafana_auth_providers" {
  description = "Список auth провайдеров Grafana: AWS_SSO, SAML, IAM Identity Center и т.д."
  type        = list(string)
  default     = ["AWS_SSO"]
}

variable "grafana_organizational_units" {
  description = "Список OU/рамок доступа для AMG (при необходимости)"
  type        = list(string)
  default     = []
}

variable "grafana_account_access_type" {
  description = "Тип доступа к аккаунтам: CURRENT_ACCOUNT или ORGANIZATION"
  type        = string
  default     = "CURRENT_ACCOUNT"
}

variable "grafana_data_sources" {
  description = <<EOT
Список data‑sources для AMG. Пока поддерживаем AMP:
  [
    {
      type = "AMP",
      name = "amp-default"
      workspace_arn = "<arn>"
      default = true
    }
  ]
EOT
  type = list(object({
    type          = string
    name          = string
    workspace_arn = optional(string)
    default       = optional(bool, false)
  }))
  default = []
}

variable "grafana_role_associations" {
  description = "Связки ролей AMG (ADMIN/EDITOR/VIEWER) с IAM/SSO пользователями/группами"
  type = list(object({
    role        = string
    user_ids    = optional(list(string), [])
    group_ids   = optional(list(string), [])
  }))
  default = []
}

# -------- SNS --------
variable "create_sns" {
  description = "Создать SNS Topic для оповещений (можно использовать в Alertmanager)"
  type        = bool
  default     = true
}

variable "sns_topic_name" {
  description = "Имя SNS топика"
  type        = string
  default     = "datafabric-observability"
}

variable "sns_email_subscriptions" {
  description = "E-mail подписчики SNS"
  type        = list(string)
  default     = []
}

########################
# ЛОКАЛЫ
########################

locals {
  tags = merge(var.tags, {
    "managed-by" = "terraform",
    "module"     = "datafabric-core/observability"
  })
}

########################
# KMS (опционально)
########################

resource "aws_kms_key" "this" {
  count                   = var.create_kms ? 1 : 0
  description             = "KMS для Observability (SNS/Logs/Grafana)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.tags
}

resource "aws_kms_alias" "this" {
  count         = var.create_kms ? 1 : 0
  name          = var.kms_alias
  target_key_id = aws_kms_key.this[0].id
}

########################
# CloudWatch Logs
########################

resource "aws_cloudwatch_log_group" "app" {
  name              = var.log_group_name
  retention_in_days = var.log_retention_days
  kms_key_id        = var.create_kms ? aws_kms_key.this[0].arn : null
  tags              = local.tags
}

########################
# AMP Workspace + Logging
########################

resource "aws_prometheus_workspace" "this" {
  alias       = var.amp_workspace_name
  tags        = local.tags
  logging_configuration {
    # по состоянию провайдера 5.x — optional; включаем только если нужно
    log_group_arn = var.amp_logging_enabled ? aws_cloudwatch_log_group.app.arn : null
  }
}

# Rule Groups (если yaml предоставлен)
# Принимаем либо путь к файлу (fileexists) либо инлайн YAML.
locals {
  amp_rules_source = var.amp_rule_groups_yaml != "" && fileexists(var.amp_rule_groups_yaml) ? file(var.amp_rule_groups_yaml) : var.amp_rule_groups_yaml
}

resource "aws_prometheus_rule_group_namespace" "this" {
  count            = local.amp_rules_source != "" ? 1 : 0
  name             = var.amp_rule_groups_name
  workspace_id     = aws_prometheus_workspace.this.id
  data             = local.amp_rules_source
}

# Alertmanager definition (если yaml предоставлен)
locals {
  amp_am_source = var.amp_alertmanager_yaml != "" && fileexists(var.amp_alertmanager_yaml) ? file(var.amp_alertmanager_yaml) : var.amp_alertmanager_yaml
}

resource "aws_prometheus_alert_manager_definition" "this" {
  count        = local.amp_am_source != "" ? 1 : 0
  workspace_id = aws_prometheus_workspace.this.id
  data         = local.amp_am_source
}

########################
# IRSA для remote-write в AMP (EKS)
########################

# Trust policy для SA: system:serviceaccount:<namespace>:<sa>
data "aws_iam_policy_document" "irsa_trust" {
  count = var.enable_irsa && var.oidc_provider_arn != "" ? 1 : 0

  statement {
    effect = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = replace(var.oidc_provider_arn, "arn:aws:iam::", "") # заглушка, не используется прямо
      values   = []
    }
  }
}

# В провайдере AWS нет прямой подстановки условия без конкретного issuer. Сделаем вручную:
# Упростим: получим OIDC issuer через data (если доступен) — или просим подставлять в overlay. 
# В модуле оставляем безопасный trust через stringLike по субьекту.
data "aws_iam_openid_connect_provider" "eks" {
  count = var.enable_irsa && var.oidc_provider_arn != "" ? 1 : 0
  arn   = var.oidc_provider_arn
}

data "aws_iam_policy_document" "irsa_trust_fix" {
  count = var.enable_irsa && var.oidc_provider_arn != "" ? 1 : 0

  statement {
    effect = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.eks[0].arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(data.aws_iam_openid_connect_provider.eks[0].url, "https://", "")}:sub"
      values   = ["system:serviceaccount:${var.eks_namespace}:${var.eks_service_account}"]
    }
  }
}

resource "aws_iam_role" "amp_remote_write" {
  count              = var.enable_irsa && var.oidc_provider_arn != "" ? 1 : 0
  name               = "datafabric-amp-remote-write"
  assume_role_policy = data.aws_iam_policy_document.irsa_trust_fix[0].json
  tags               = local.tags
}

# Политика для AMP RemoteWrite/Query
data "aws_iam_policy_document" "amp_policy" {
  statement {
    effect = "Allow"
    actions = [
      "aps:RemoteWrite",
      "aps:QueryMetrics",
      "aps:GetSeries",
      "aps:GetLabels",
      "aps:GetMetricMetadata"
    ]
    resources = [aws_prometheus_workspace.this.arn]
  }
}

resource "aws_iam_policy" "amp" {
  count  = var.enable_irsa && var.oidc_provider_arn != "" ? 1 : 0
  name   = "datafabric-amp-access"
  policy = data.aws_iam_policy_document.amp_policy.json
}

resource "aws_iam_role_policy_attachment" "amp_attach" {
  count      = var.enable_irsa && var.oidc_provider_arn != "" ? 1 : 0
  role       = aws_iam_role.amp_remote_write[0].name
  policy_arn = aws_iam_policy.amp[0].arn
}

########################
# SNS Topic (оповещения)
########################

resource "aws_sns_topic" "alerts" {
  count = var.create_sns ? 1 : 0
  name  = var.sns_topic_name
  kms_master_key_id = var.create_kms ? aws_kms_key.this[0].arn : null
  tags  = local.tags
}

resource "aws_sns_topic_subscription" "emails" {
  count     = var.create_sns ? length(var.sns_email_subscriptions) : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.sns_email_subscriptions[count.index]
}

########################
# Managed Grafana (AMG)
########################

resource "aws_grafana_workspace" "this" {
  count                 = var.enable_grafana ? 1 : 0
  name                  = var.grafana_workspace_name
  account_access_type   = var.grafana_account_access_type
  authentication_providers = var.grafana_auth_providers
  permission_type       = "SERVICE_MANAGED"
  data_sources          = ["PROMETHEUS"]   # минимально, реальные data sources добавим ниже
  organizational_units  = length(var.grafana_organizational_units) > 0 ? var.grafana_organizational_units : null
  kms_key_id            = var.create_kms ? aws_kms_key.this[0].arn : null
  tags                  = local.tags
}

# Привязка AMP как data-source в AMG (через API Keys обычно; в Terraform ограниченная поддержка).
# В AWS provider отсутствует нативный ресурс data‑source для AMG — используйте инфраструктурные пайплайны/скрипты.
# Тем не менее, полезно отдать ARN AMP и Workspace ID для внешней автоматизации.
# Также добавим role associations (администраторы/редакторы/читатели), если заданы.

resource "aws_grafana_role_association" "assoc_user" {
  for_each = var.enable_grafana ? {
    for idx, assoc in var.grafana_role_associations :
    "assoc-${idx}" => assoc
  } : {}

  workspace_id = aws_grafana_workspace.this[0].id
  role         = each.value.role
  # Одновременно users и groups Terraform не поддерживает в одном ресурсе — создадим по users:
  # Для групп рекомендуется отдельный цикл (ниже).
  # Здесь добавим только пользователей, если заданы.
  user_ids = try(each.value.user_ids, [])
}

resource "aws_grafana_role_association" "assoc_group" {
  for_each = var.enable_grafana ? {
    for idx, assoc in var.grafana_role_associations :
    "assocg-${idx}" => assoc if length(try(assoc.group_ids, [])) > 0
  } : {}

  workspace_id = aws_grafana_workspace.this[0].id
  role         = each.value.role
  group_ids    = try(each.value.group_ids, [])
}

########################
# ВЫХОДЫ
########################

output "log_group_name" {
  description = "CloudWatch LogGroup name"
  value       = aws_cloudwatch_log_group.app.name
}

output "kms_key_arn" {
  description = "KMS ключ ARN (если создан)"
  value       = var.create_kms ? aws_kms_key.this[0].arn : null
}

output "amp_workspace_id" {
  description = "ID AMP Workspace"
  value       = aws_prometheus_workspace.this.id
}

output "amp_workspace_arn" {
  description = "ARN AMP Workspace"
  value       = aws_prometheus_workspace.this.arn
}

output "amp_endpoint" {
  description = "AMP endpoint для remote-write/query"
  value       = aws_prometheus_workspace.this.prometheus_endpoint
}

output "irsa_role_arn" {
  description = "IAM Role ARN для IRSA (remote-write)"
  value       = var.enable_irsa && var.oidc_provider_arn != "" ? aws_iam_role.amp_remote_write[0].arn : null
}

output "sns_topic_arn" {
  description = "SNS Topic ARN (если создан)"
  value       = var.create_sns ? aws_sns_topic.alerts[0].arn : null
}

output "grafana_workspace_id" {
  description = "Grafana Workspace ID (если создан)"
  value       = var.enable_grafana ? aws_grafana_workspace.this[0].id : null
}

output "grafana_endpoint" {
  description = "Grafana URL (если создан)"
  value       = var.enable_grafana ? aws_grafana_workspace.this[0].endpoint : null
}

output "grafana_aws_console_url" {
  description = "AWS Console ссылка на Grafana workspace"
  value       = var.enable_grafana ? "https://${var.region}.console.aws.amazon.com/grafana/home?region=${var.region}#/${aws_grafana_workspace.this[0].id}" : null
}
