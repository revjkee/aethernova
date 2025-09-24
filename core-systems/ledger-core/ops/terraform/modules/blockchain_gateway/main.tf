###############################################################################
# Blockchain Gateway (AWS) — HTTP API Gateway v2 + VPC Link → NLB
# - Приватная интеграция на NLB (например, EKS/NLB, ECS/NLB, On-Prem via TGW)
# - JWT авторизация (OIDC), настраиваемые пути/маршруты
# - Кастомный домен + Route53 Alias
# - WAFv2 (опционально)
# - Логи и метрики (CloudWatch), троттлинг, алармы в SNS (опционально)
# Требования: Terraform >= 1.3, AWS provider >= 5.x
###############################################################################

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.30"
    }
  }
}

#########################
# ВХОДНЫЕ ПЕРЕМЕННЫЕ
#########################

variable "name" {
  description = "Базовое имя (используется в ресурсах и тегах)"
  type        = string
  default     = "ledger-core-gw"
  validation {
    condition     = length(var.name) <= 30
    error_message = "name должен быть до 30 символов."
  }
}

variable "tags" {
  description = "Теги для всех ресурсов"
  type        = map(string)
  default     = {}
}

variable "environment" {
  description = "Окружение (dev|staging|prod)"
  type        = string
  default     = "staging"
  validation {
    condition     = can(regex("^(dev|staging|prod)$", var.environment))
    error_message = "environment должен быть одним из: dev|staging|prod."
  }
}

variable "nlb_listener_arn" {
  description = "ARN листенера NLB для интеграции API Gateway (HTTP API v2 VPC Link)"
  type        = string
}

variable "vpc_link_subnet_ids" {
  description = "Список приватных subnet IDs для VPC Link"
  type        = list(string)
  validation {
    condition     = length(var.vpc_link_subnet_ids) >= 2
    error_message = "Нужно минимум 2 приватные подсети для отказоустойчивого VPC Link."
  }
}

variable "vpc_link_security_group_ids" {
  description = "Security Group IDs для VPC Link (eNIs, которые создаст API GW)"
  type        = list(string)
  default     = []
}

variable "enable_waf" {
  description = "Присоединить WebACL (WAFv2) к API"
  type        = bool
  default     = false
}

variable "wafv2_web_acl_arn" {
  description = "ARN WebACL (WAFv2). Обязателен, если enable_waf = true"
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "FQDN публичного домена API (например, api.ledger.example.com). Пусто — без домена."
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = "ARN ACM сертификата для domain_name (в том же регионе). Обязателен при наличии domain_name."
  type        = string
  default     = ""
}

variable "route53_hosted_zone_id" {
  description = "ID Hosted Zone для записи A/AAAA. Обязателен при наличии domain_name."
  type        = string
  default     = ""
}

variable "jwt_issuer" {
  description = "Issuer для JWT‑авторизатора (OIDC Discovery URL)"
  type        = string
  default     = ""
}

variable "jwt_audience" {
  description = "Список JWT Audience значений (client_id и т.п.)"
  type        = list(string)
  default     = []
}

variable "routes" {
  description = <<EOT
Маршруты HTTP API:
Список объектов { route_key = "ANY /path/{proxy+}" | "GET /health", authorization = "JWT"|"NONE" }
EOT
  type = list(object({
    route_key     = string
    authorization = optional(string, "JWT")
  }))
  default = [
    { route_key = "ANY /{proxy+}", authorization = "JWT" },
    { route_key = "GET /health",  authorization = "NONE" }
  ]
}

variable "stage_name" {
  description = "Имя stage (например, v1)"
  type        = string
  default     = "v1"
}

variable "throttle_burst_limit" {
  description = "Пиковый лимит запросов на stage (burst)"
  type        = number
  default     = 200
}

variable "throttle_rate_limit" {
  description = "Средний RPS лимит на stage (rate)"
  type        = number
  default     = 100
}

variable "enable_access_logs" {
  description = "Включить access‑логи HTTP API в CloudWatch"
  type        = bool
  default     = true
}

variable "alarm_sns_topic_arn" {
  description = "SNS Topic ARN для уведомлений об алармах (если пусто — алармы создаются без действия)"
  type        = string
  default     = ""
}

variable "latency_p99_threshold_ms" {
  description = "Порог P99 латентности в мс для аларма"
  type        = number
  default     = 1500
}

#########################
# ЛОКАЛЫ И ТЕГИ
#########################

locals {
  common_tags = merge(
    {
      "Project"     = "ledger-core"
      "Component"   = "blockchain-gateway"
      "Environment" = var.environment
      "Name"        = var.name
      "ManagedBy"   = "terraform"
    },
    var.tags
  )

  use_domain = length(var.domain_name) > 0
  use_waf    = var.enable_waf

  # Валидации связок
  domain_requirements_ok = local.use_domain ? (
    length(var.certificate_arn) > 0 && length(var.route53_hosted_zone_id) > 0
  ) : true
  waf_requirements_ok = local.use_waf ? length(var.wafv2_web_acl_arn) > 0 : true
}

#########################
# ВАЛИДАЦИИ
#########################

# Встроенные preconditions для читаемых ошибок
resource "null_resource" "validate_domain" {
  count = local.use_domain && !local.domain_requirements_ok ? 1 : 0
  provisioner "local-exec" {
    command = "echo 'ERROR: domain_name задан, но не указан certificate_arn/route53_hosted_zone_id' && exit 1"
  }
}

resource "null_resource" "validate_waf" {
  count = local.use_waf && !local.waf_requirements_ok ? 1 : 0
  provisioner "local-exec" {
    command = "echo 'ERROR: enable_waf=true, но не указан wafv2_web_acl_arn' && exit 1"
  }
}

#########################
# CLOUDWATCH LOGS
#########################

resource "aws_cloudwatch_log_group" "api_gw_access" {
  count             = var.enable_access_logs ? 1 : 0
  name              = "/aws/apigw/${var.name}/access"
  retention_in_days = 30
  tags              = local.common_tags
}

#########################
# VPC LINK (для приватной интеграции)
#########################

resource "aws_apigatewayv2_vpc_link" "this" {
  name               = "${var.name}-vpclink"
  security_group_ids = var.vpc_link_security_group_ids
  subnet_ids         = var.vpc_link_subnet_ids
  tags               = local.common_tags
}

#########################
# HTTP API + JWT авторизатор
#########################

resource "aws_apigatewayv2_api" "this" {
  name          = var.name
  protocol_type = "HTTP"
  description   = "Ledger Core blockchain gateway (HTTP API v2 via VPC Link → NLB)"
  tags          = local.common_tags
}

# JWT Authorizer (опционально — если указаны issuer и audience)
resource "aws_apigatewayv2_authorizer" "jwt" {
  count                       = length(var.jwt_issuer) > 0 && length(var.jwt_audience) > 0 ? 1 : 0
  api_id                      = aws_apigatewayv2_api.this.id
  authorizer_type             = "JWT"
  identity_sources            = ["$request.header.Authorization"]
  name                        = "${var.name}-jwt"
  jwt_configuration {
    issuer   = var.jwt_issuer
    audience = var.jwt_audience
  }
}

# Интеграция на NLB Listener через VPC Link (HTTP proxy)
resource "aws_apigatewayv2_integration" "nlb" {
  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "HTTP_PROXY"
  connection_type        = "VPC_LINK"
  connection_id          = aws_apigatewayv2_vpc_link.this.id
  integration_method     = "ANY"
  integration_uri        = var.nlb_listener_arn
  payload_format_version = "1.0"
  timeout_milliseconds   = 29000
  description            = "Proxy to NLB via VPC Link"
}

# Маршруты
resource "aws_apigatewayv2_route" "routes" {
  for_each  = { for r in var.routes : r.route_key => r }
  api_id    = aws_apigatewayv2_api.this.id
  route_key = each.key
  target    = "integrations/${aws_apigatewayv2_integration.nlb.id}"

  # Авторизация
  authorization_type = (
    try(each.value.authorization, "JWT") == "NONE" || length(aws_apigatewayv2_authorizer.jwt) == 0
  ) ? "NONE" : "JWT"

  authorizer_id = (
    try(each.value.authorization, "JWT") == "JWT" && length(aws_apigatewayv2_authorizer.jwt) > 0
  ) ? aws_apigatewayv2_authorizer.jwt[0].id : null
}

# Stage (логирование и троттлинг)
resource "aws_apigatewayv2_stage" "stage" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = var.stage_name
  auto_deploy = true
  tags        = local.common_tags

  default_route_settings {
    throttling_burst_limit = var.throttle_burst_limit
    throttling_rate_limit  = var.throttle_rate_limit
    detailed_metrics_enabled = true
  }

  access_log_settings {
    count         = var.enable_access_logs ? 1 : 0
    destination_arn = var.enable_access_logs ? aws_cloudwatch_log_group.api_gw_access[0].arn : null
    format = var.enable_access_logs ? jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      path           = "$context.path"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      integration    = "$context.integration.status"
      jwtSub         = "$context.authorizer.claims.sub"
      errorMessage   = "$context.error.message"
    }) : null
  }
  lifecycle {
    ignore_changes = [
      access_log_settings[0].destination_arn,
      access_log_settings[0].format
    ]
  }
}

#########################
# КАСТОМНЫЙ ДОМЕН (опционально)
#########################

resource "aws_apigatewayv2_domain_name" "this" {
  count       = local.use_domain ? 1 : 0
  domain_name = var.domain_name
  domain_name_configuration {
    certificate_arn = var.certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
  tags = local.common_tags
}

resource "aws_apigatewayv2_api_mapping" "this" {
  count       = local.use_domain ? 1 : 0
  api_id      = aws_apigatewayv2_api.this.id
  domain_name = aws_apigatewayv2_domain_name.this[0].domain_name
  stage       = aws_apigatewayv2_stage.stage.name
}

# Route53 Alias -> API GW domain
data "aws_apigatewayv2_domain_name" "lookup" {
  count       = local.use_domain ? 1 : 0
  domain_name = aws_apigatewayv2_domain_name.this[0].domain_name
}

resource "aws_route53_record" "api_alias_v4" {
  count   = local.use_domain ? 1 : 0
  zone_id = var.route53_hosted_zone_id
  name    = var.domain_name
  type    = "A"
  alias {
    name                   = data.aws_apigatewayv2_domain_name.lookup[0].domain_name_configuration[0].target_domain_name
    zone_id                = data.aws_apigatewayv2_domain_name.lookup[0].domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "api_alias_v6" {
  count   = local.use_domain ? 1 : 0
  zone_id = var.route53_hosted_zone_id
  name    = var.domain_name
  type    = "AAAA"
  alias {
    name                   = data.aws_apigatewayv2_domain_name.lookup[0].domain_name_configuration[0].target_domain_name
    zone_id                = data.aws_apigatewayv2_domain_name.lookup[0].domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}

#########################
# WAFv2 (опционально)
#########################

resource "aws_wafv2_web_acl_association" "this" {
  count        = local.use_waf ? 1 : 0
  resource_arn = aws_apigatewayv2_stage.stage.arn
  web_acl_arn  = var.wafv2_web_acl_arn
}

#########################
# АЛАРМЫ (CloudWatch)
#########################

# 5XX
resource "aws_cloudwatch_metric_alarm" "api_5xx" {
  alarm_name          = "${var.name}-5xx"
  alarm_description   = "High 5XX errors on HTTP API"
  namespace           = "AWS/ApiGateway"
  metric_name         = "5xx"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 5
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  dimensions = {
    ApiId = aws_apigatewayv2_api.this.id
    Stage = aws_apigatewayv2_stage.stage.name
  }
  treat_missing_data = "notBreaching"
  alarm_actions      = length(var.alarm_sns_topic_arn) > 0 ? [var.alarm_sns_topic_arn] : []
  ok_actions         = length(var.alarm_sns_topic_arn) > 0 ? [var.alarm_sns_topic_arn] : []
  tags               = local.common_tags
}

# 4XX (подозрение на клиентские/аутентификационные проблемы)
resource "aws_cloudwatch_metric_alarm" "api_4xx" {
  alarm_name          = "${var.name}-4xx"
  alarm_description   = "High 4XX errors on HTTP API"
  namespace           = "AWS/ApiGateway"
  metric_name         = "4xx"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 5
  threshold           = 50
  comparison_operator = "GreaterThanOrEqualToThreshold"
  dimensions = {
    ApiId = aws_apigatewayv2_api.this.id
    Stage = aws_apigatewayv2_stage.stage.name
  }
  treat_missing_data = "notBreaching"
  alarm_actions      = length(var.alarm_sns_topic_arn) > 0 ? [var.alarm_sns_topic_arn] : []
  ok_actions         = length(var.alarm_sns_topic_arn) > 0 ? [var.alarm_sns_topic_arn] : []
  tags               = local.common_tags
}

# P99 Latency
resource "aws_cloudwatch_metric_alarm" "api_latency_p99" {
  alarm_name          = "${var.name}-latency-p99"
  alarm_description   = "P99 latency too high"
  namespace           = "AWS/ApiGateway"
  metric_name         = "Latency"
  extended_statistic  = "p99"
  period              = 60
  evaluation_periods  = 5
  threshold           = var.latency_p99_threshold_ms
  comparison_operator = "GreaterThanThreshold"
  dimensions = {
    ApiId = aws_apigatewayv2_api.this.id
    Stage = aws_apigatewayv2_stage.stage.name
  }
  treat_missing_data = "notBreaching"
  alarm_actions      = length(var.alarm_sns_topic_arn) > 0 ? [var.alarm_sns_topic_arn] : []
  ok_actions         = length(var.alarm_sns_topic_arn) > 0 ? [var.alarm_sns_topic_arn] : []
  tags               = local.common_tags
}

#########################
# ВЫХОДНЫЕ ДАННЫЕ
#########################

output "api_id" {
  description = "ID созданного HTTP API"
  value       = aws_apigatewayv2_api.this.id
}

output "api_invoke_url" {
  description = "Invoke URL для API (без домена)"
  value       = aws_apigatewayv2_stage.stage.invoke_url
}

output "domain_url" {
  description = "Публичный URL через кастомный домен (если включено)"
  value       = local.use_domain ? "https://${var.domain_name}" : ""
}

output "vpc_link_id" {
  description = "ID созданного VPC Link"
  value       = aws_apigatewayv2_vpc_link.this.id
}

output "waf_attached" {
  description = "Признак присоединения WAF к stage"
  value       = local.use_waf
}
