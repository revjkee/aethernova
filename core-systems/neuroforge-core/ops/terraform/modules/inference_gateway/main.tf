terraform {
  required_version = ">= 1.5.0"
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

# ----------------------------
# ВХОДНЫЕ ПЕРЕМЕННЫЕ
# ----------------------------
variable "name" {
  description = "Базовое имя ресурсов (используется в тегах/именах)."
  type        = string
}

variable "environment" {
  description = "Окружение (prod|staging|dev...)."
  type        = string
  default     = "prod"
}

variable "tags" {
  description = "Дополнительные теги."
  type        = map(string)
  default     = {}
}

variable "vpc_id" {
  description = "ID VPC, где создаются ресурсы."
  type        = string
}

variable "public_subnet_ids" {
  description = "Список публичных подсетей для ALB (как минимум две в разных AZ)."
  type        = list(string)
}

variable "internal" {
  description = "Внутренний (true) или внешнедоступный (false) ALB."
  type        = bool
  default     = false
}

variable "allowed_cidrs" {
  description = "Сетевые диапазоны, которым разрешён доступ к ALB (443/80)."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "egress_all" {
  description = "Разрешить исходящий трафик из SG ALB ко всем адресам."
  type        = bool
  default     = true
}

variable "acm_certificate_arn" {
  description = "ARN TLS-сертификата ACM для HTTPS-листенера (обязателен при enable_https=true)."
  type        = string
  default     = ""
}

variable "enable_https" {
  description = "Создавать HTTPS-листенер на 443."
  type        = bool
  default     = true
}

variable "enable_http_redirect" {
  description = "Создавать HTTP 80 с редиректом на HTTPS."
  type        = bool
  default     = true
}

variable "listener_additional_headers" {
  description = "Доп. заголовки, добавляемые ALB (например, X-Forwarded-*). Только описание — управление обычно вне ALB."
  type        = map(string)
  default     = {}
}

# Target Group / backend
variable "target_protocol" {
  description = "Протокол бэкенда TG (HTTP | HTTPS | TCP | TLS | GENEVE | UDP | TCP_UDP | HTTP2 | GRPC)."
  type        = string
  default     = "HTTP"
}

variable "target_protocol_version" {
  description = "Версия протокола (HTTP1 | HTTP2 | GRPC)."
  type        = string
  default     = "HTTP1"
}

variable "target_port" {
  description = "Порт бэкенда в TG."
  type        = number
  default     = 8080
}

variable "target_group_type" {
  description = "Тип TG: instance | ip | alb | lambda."
  type        = string
  default     = "ip"
}

variable "target_deregistration_delay_seconds" {
  description = "Задержка дерегистрации целей при drain."
  type        = number
  default     = 15
}

variable "health_check" {
  description = "Параметры health check."
  type = object({
    enabled             = optional(bool, true)
    path                = optional(string, "/health/ready")
    matcher             = optional(string, "200-399")
    interval            = optional(number, 15)
    timeout             = optional(number, 5)
    healthy_threshold   = optional(number, 2)
    unhealthy_threshold = optional(number, 3)
    port                = optional(string, "traffic-port")
    protocol            = optional(string, "HTTP")
  })
  default = {}
}

# ALB настройки
variable "alb_idle_timeout" {
  description = "Idle timeout ALB (сек)."
  type        = number
  default     = 60
}

variable "alb_enable_http2" {
  description = "Включить HTTP/2 на ALB."
  type        = bool
  default     = true
}

variable "alb_drop_invalid_headers" {
  description = "Отклонять некорректные заголовки."
  type        = bool
  default     = true
}

variable "alb_deletion_protection" {
  description = "Защита от удаления ALB."
  type        = bool
  default     = true
}

# WAF настройки
variable "enable_waf" {
  description = "Подключить AWS WAFv2 к ALB."
  type        = bool
  default     = true
}

variable "waf_scope" {
  description = "Область WAF (для ALB используйте REGIONAL)."
  type        = string
  default     = "REGIONAL"
}

variable "waf_managed_rules" {
  description = "Набор управляемых правил WAFv2 (список rule group ARNs или преднастроенных)."
  type = list(object({
    name        = string
    vendor_name = string
    version     = optional(string)
    priority    = number
    override_action_none = optional(bool, true)
  }))
  default = [
    { name = "AWS-AWSManagedRulesCommonRuleSet",     vendor_name = "AWS", priority = 10 },
    { name = "AWS-AWSManagedRulesKnownBadInputsRuleSet", vendor_name = "AWS", priority = 20 },
    { name = "AWS-AWSManagedRulesSQLiRuleSet",       vendor_name = "AWS", priority = 30 },
    { name = "AWS-AWSManagedRulesLinuxRuleSet",      vendor_name = "AWS", priority = 40 }
  ]
}

# ДНС
variable "create_dns_record" {
  description = "Создавать A-Alias запись в Route53."
  type        = bool
  default     = false
}

variable "hosted_zone_id" {
  description = "Hosted Zone ID для Route53 (требуется если create_dns_record=true)."
  type        = string
  default     = ""
}

variable "record_name" {
  description = "DNS-имя (FQDN) для ALB (например, inference.example.com)."
  type        = string
  default     = ""
}

# Логи ALB
variable "enable_access_logs" {
  description = "Включить логи ALB в S3."
  type        = bool
  default     = false
}

variable "access_logs_bucket" {
  description = "Имя S3-бакета для логов (должны быть нужные политики)."
  type        = string
  default     = ""
}

variable "access_logs_prefix" {
  description = "Префикс в бакете для логов."
  type        = string
  default     = "alb"
}

# ----------------------------
# ДАННЫЕ И ЛОКАЛЫ
# ----------------------------
data "aws_caller_identity" "this" {}
data "aws_region" "this" {}

locals {
  name = var.name

  common_tags = merge(
    {
      "Name"                     = "${var.name}-inference-gw"
      "nf:environment"           = var.environment
      "nf:component"             = "inference-gateway"
      "nf:owner"                 = "platform"
      "nf:provisioner"           = "terraform"
      "nf:region"                = data.aws_region.this.name
      "nf:account_id"            = data.aws_caller_identity.this.account_id
    },
    var.tags
  )

  hc = merge({
    enabled             = true
    path                = "/health/ready"
    matcher             = "200-399"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
    port                = "traffic-port"
    protocol            = "HTTP"
  }, var.health_check)
}

# ----------------------------
# SECURITY GROUP
# ----------------------------
resource "aws_security_group" "alb" {
  name        = "${var.name}-alb-sg"
  description = "ALB SG for inference gateway"
  vpc_id      = var.vpc_id
  tags        = local.common_tags

  dynamic "ingress" {
    for_each = var.enable_https ? toset(["443"]) : toset(["80"])
    content {
      description = var.enable_https ? "HTTPS from allowed ranges" : "HTTP from allowed ranges"
      from_port   = tonumber(ingress.value)
      to_port     = tonumber(ingress.value)
      protocol    = "tcp"
      cidr_blocks = var.allowed_cidrs
    }
  }

  # Дополнительно открываем 80 для редиректа, если включён
  dynamic "ingress" {
    for_each = var.enable_http_redirect ? toset(["80"]) : toset([])
    content {
      description = "HTTP redirect to HTTPS"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = var.allowed_cidrs
    }
  }

  egress {
    description = var.egress_all ? "Allow all egress" : "Deny all egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.egress_all ? ["0.0.0.0/0"] : []
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ----------------------------
# LOAD BALANCER (ALB)
# ----------------------------
resource "aws_lb" "this" {
  name               = substr("${var.name}-alb", 0, 32) # лимит 32
  internal           = var.internal
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  idle_timeout               = var.alb_idle_timeout
  enable_http2               = var.alb_enable_http2
  drop_invalid_header_fields = var.alb_drop_invalid_headers
  desync_mitigation_mode     = "defensive"
  xff_header_processing_mode = "preserve"

  dynamic "access_logs" {
    for_each = var.enable_access_logs ? [1] : []
    content {
      bucket  = var.access_logs_bucket
      prefix  = var.access_logs_prefix
      enabled = true
    }
  }

  enable_deletion_protection = var.alb_deletion_protection

  tags = local.common_tags
}

# ----------------------------
# TARGET GROUP
# ----------------------------
resource "aws_lb_target_group" "this" {
  name        = substr("${var.name}-tg", 0, 32)
  vpc_id      = var.vpc_id
  port        = var.target_port
  protocol    = var.target_protocol
  target_type = var.target_group_type

  protocol_version = var.target_protocol_version

  deregistration_delay = var.target_deregistration_delay_seconds
  slow_start           = 0
  stickiness {
    enabled = false
    type    = "lb_cookie"
  }

  dynamic "health_check" {
    for_each = local.hc.enabled ? [1] : []
    content {
      enabled             = true
      path                = local.hc.path
      matcher             = local.hc.matcher
      interval            = local.hc.interval
      timeout             = local.hc.timeout
      healthy_threshold   = local.hc.healthy_threshold
      unhealthy_threshold = local.hc.unhealthy_threshold
      port                = local.hc.port
      protocol            = local.hc.protocol
    }
  }

  tags = local.common_tags
}

# ----------------------------
# LISTENERS
# ----------------------------
# HTTP :80 → редирект на HTTPS
resource "aws_lb_listener" "http" {
  count             = var.enable_http_redirect ? 1 : 0
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  tags = local.common_tags
}

# HTTPS :443 → TG
resource "aws_lb_listener" "https" {
  count             = var.enable_https ? 1 : 0
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  certificate_arn = var.acm_certificate_arn != "" ? var.acm_certificate_arn : null

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }

  tags = local.common_tags

  lifecycle {
    precondition {
      condition     = var.acm_certificate_arn != ""
      error_message = "acm_certificate_arn must be provided when enable_https=true"
    }
  }
}

# ----------------------------
# WAFv2 (REGIONAL) + association
# ----------------------------
resource "aws_wafv2_web_acl" "this" {
  count       = var.enable_waf ? 1 : 0
  name        = "${var.name}-waf"
  description = "WAF for inference gateway ALB"
  scope       = var.waf_scope # REGIONAL для ALB

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-waf"
    sampled_requests_enabled   = true
  }

  dynamic "rule" {
    for_each = var.waf_managed_rules
    content {
      name     = rule.value.name
      priority = rule.value.priority
      override_action {
        dynamic "none" {
          for_each = rule.value.override_action_none ? [1] : []
          content {}
        }
      }
      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = rule.value.vendor_name
          dynamic "version" {
            for_each = try([rule.value.version], [])
            content {
              # пустой блок не допускается; используем переменную, если задана
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-${rule.value.name}"
        sampled_requests_enabled   = true
      }
    }
  }

  tags = local.common_tags
}

resource "aws_wafv2_web_acl_association" "alb" {
  count        = var.enable_waf ? 1 : 0
  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.this[0].arn
}

# ----------------------------
# DNS (Route53 alias)
# ----------------------------
data "aws_lb" "dns" {
  arn = aws_lb.this.arn
}

resource "aws_route53_record" "alias" {
  count   = var.create_dns_record ? 1 : 0
  zone_id = var.hosted_zone_id
  name    = var.record_name
  type    = "A"
  alias {
    name                   = data.aws_lb.dns.dns_name
    zone_id                = data.aws_lb.dns.zone_id
    evaluate_target_health = true
  }

  lifecycle {
    precondition {
      condition     = var.hosted_zone_id != "" && var.record_name != ""
      error_message = "hosted_zone_id and record_name must be provided when create_dns_record=true"
    }
  }
}

# ----------------------------
# ВЫХОДЫ
# ----------------------------
output "alb_arn" {
  description = "ARN созданного ALB."
  value       = aws_lb.this.arn
}

output "alb_dns_name" {
  description = "DNS-имя ALB."
  value       = aws_lb.this.dns_name
}

output "alb_zone_id" {
  description = "Hosted zone ID ALB (для alias-записей)."
  value       = aws_lb.this.zone_id
}

output "security_group_id" {
  description = "ID Security Group для ALB."
  value       = aws_security_group.alb.id
}

output "target_group_arn" {
  description = "ARN Target Group (зарегистрируйте цели вне модуля)."
  value       = aws_lb_target_group.this.arn
}

output "https_listener_arn" {
  description = "ARN HTTPS-листенера (если включён)."
  value       = try(aws_lb_listener.https[0].arn, null)
}

output "waf_web_acl_arn" {
  description = "ARN WAFv2 Web ACL (если включён)."
  value       = try(aws_wafv2_web_acl.this[0].arn, null)
}

output "route53_record_fqdn" {
  description = "FQDN Route53 (если создан)."
  value       = try(aws_route53_record.alias[0].fqdn, null)
}
