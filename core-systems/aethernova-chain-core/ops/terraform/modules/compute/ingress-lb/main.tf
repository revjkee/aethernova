# aethernova-chain-core/ops/terraform/modules/compute/ingress-lb/main.tf
#
# Промышленный модуль L4/NLB и L7/ALB для Kubernetes ingress в AWS.
# Особенности:
# - Поддержка ALB (HTTP/HTTPS, redirect 80->443) и NLB (TCP/TLS).
# - Регистрация IP/instance targets (для ingress/NodePort/DaemonSet).
# - Опциональные: WAFv2, S3 access logs, cross-zone, deletion protection.
# - Жёсткие валидации входных данных, теги и вывод ключевых артефактов.
#
# Предполагается, что провайдеры и версии зафиксированы во внешнем versions.tf.
# Внешние зависимости (VPC/Subnets/ACM/IAM) должны быть переданы через переменные.

###############################################################################
# VARIABLES
###############################################################################

variable "name" {
  description = "Логическое имя LB (префикс для ресурсов)."
  type        = string
}

variable "lb_type" {
  description = "Тип балансировщика: alb|nlb."
  type        = string
  default     = "alb"
  validation {
    condition     = contains(["alb", "nlb"], var.lb_type)
    error_message = "lb_type должен быть 'alb' или 'nlb'."
  }
}

variable "vpc_id" {
  description = "ID VPC, в которой создаётся LB."
  type        = string
}

variable "subnet_ids" {
  description = "Список Subnet IDs для LB (как минимум 2 AZ)."
  type        = list(string)
  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "Нужно минимум 2 подсети в разных AZ."
  }
}

variable "scheme" {
  description = "Схема LB: internet-facing|internal."
  type        = string
  default     = "internet-facing"
  validation {
    condition     = contains(["internet-facing", "internal"], var.scheme)
    error_message = "scheme должен быть 'internet-facing' или 'internal'."
  }
}

variable "enable_http" {
  description = "Открывать HTTP-листенер 80."
  type        = bool
  default     = true
}

variable "enable_https" {
  description = "Открывать HTTPS-листенер 443 (ALB) или TLS (NLB)."
  type        = bool
  default     = false
}

variable "certificate_arn" {
  description = "ARN ACM-сертификата для HTTPS (ALB) или TLS (NLB)."
  type        = string
  default     = null
}

variable "allowed_ingress_cidrs" {
  description = "Список CIDR для входа (ALB Security Group). Для internet-facing по умолчанию 0.0.0.0/0."
  type        = list(string)
  default     = null
}

variable "target_type" {
  description = "Тип таргетов: ip|instance."
  type        = string
  default     = "ip"
  validation {
    condition     = contains(["ip", "instance"], var.target_type)
    error_message = "target_type должен быть 'ip' или 'instance'."
  }
}

variable "target_port_http" {
  description = "Порт таргетов для HTTP (ALB) / TCP (NLB)."
  type        = number
  default     = 30080
}

variable "target_port_https" {
  description = "Порт таргетов для HTTPS (ALB) / TLS (NLB)."
  type        = number
  default     = 30443
}

variable "health_check_path" {
  description = "Путь health-check для ALB (HTTP/HTTPS)."
  type        = string
  default     = "/healthz"
}

variable "health_check_protocol" {
  description = "Протокол health-check (ALB: HTTP/HTTPS; NLB: TCP)."
  type        = string
  default     = "HTTP"
}

variable "health_check_port" {
  description = "Порт health-check (число или 'traffic-port' для ALB)."
  type        = string
  default     = "traffic-port"
}

variable "health_check_interval" {
  description = "Интервал health-check, сек."
  type        = number
  default     = 30
}

variable "health_check_timeout" {
  description = "Таймаут health-check, сек."
  type        = number
  default     = 5
}

variable "health_check_healthy_threshold" {
  description = "Порог здоровых проверок."
  type        = number
  default     = 3
}

variable "health_check_unhealthy_threshold" {
  description = "Порог нездоровых проверок."
  type        = number
  default     = 3
}

variable "cross_zone" {
  description = "Включить cross-zone load balancing."
  type        = bool
  default     = true
}

variable "deletion_protection" {
  description = "Защита от удаления для LB."
  type        = bool
  default     = true
}

variable "idle_timeout" {
  description = "Idle timeout ALB (сек)."
  type        = number
  default     = 60
}

variable "enable_access_logs" {
  description = "Включить S3 access logs."
  type        = bool
  default     = false
}

variable "access_logs_s3_bucket" {
  description = "Имя S3 бакета для access logs."
  type        = string
  default     = null
}

variable "access_logs_s3_prefix" {
  description = "Префикс в бакете для access logs."
  type        = string
  default     = null
}

variable "wafv2_web_acl_arn" {
  description = "ARN WAFv2 Web ACL для ассоциации (только для ALB)."
  type        = string
  default     = null
}

variable "register_targets" {
  description = <<-EOT
    Явная регистрация таргетов. Список объектов:
    [
      { id = "10.0.1.10", port = 30080 }, # для target_type=ip
      { id = "i-0123456789abcdef0", port = 30080 }, # для target_type=instance
      ...
    ]
  EOT
  type = list(object({
    id   = string
    port = number
  }))
  default = []
}

variable "tags" {
  description = "Теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

###############################################################################
# LOCALS
###############################################################################

locals {
  is_alb                   = var.lb_type == "alb"
  is_nlb                   = var.lb_type == "nlb"
  use_default_ingress_cidr = var.allowed_ingress_cidrs == null && var.scheme == "internet-facing"
  ingress_cidrs            = local.use_default_ingress_cidr ? ["0.0.0.0/0"] : coalesce(var.allowed_ingress_cidrs, [])
  name_prefix              = replace(var.name, "/[^a-zA-Z0-9-]/", "-")

  # Протоколы listener/target по типу LB
  alb_http_protocol  = "HTTP"
  alb_https_protocol = "HTTPS"
  nlb_tcp_protocol   = "TCP"
  nlb_tls_protocol   = "TLS"

  common_tags = merge({
    "Name"       = local.name_prefix
    "ManagedBy"  = "Terraform"
    "Module"     = "aethernova.ingress-lb"
    "LbType"     = var.lb_type
    "Scheme"     = var.scheme
  }, var.tags)
}

###############################################################################
# SECURITY GROUP (ALB ONLY)
###############################################################################

resource "aws_security_group" "alb_sg" {
  count       = local.is_alb ? 1 : 0
  name        = "${local.name_prefix}-alb-sg"
  description = "Security Group for ALB ${local.name_prefix}"
  vpc_id      = var.vpc_id
  tags        = local.common_tags
}

resource "aws_security_group_rule" "alb_ingress_http" {
  count             = local.is_alb && var.enable_http ? 1 : 0
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = local.ingress_cidrs
  security_group_id = aws_security_group.alb_sg[0].id
  description       = "Allow HTTP"
}

resource "aws_security_group_rule" "alb_ingress_https" {
  count             = local.is_alb && var.enable_https ? 1 : 0
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = local.ingress_cidrs
  security_group_id = aws_security_group.alb_sg[0].id
  description       = "Allow HTTPS"
}

resource "aws_security_group_rule" "alb_egress_all" {
  count             = local.is_alb ? 1 : 0
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.alb_sg[0].id
  description       = "Allow all egress"
}

###############################################################################
# LOAD BALANCER
###############################################################################

resource "aws_lb" "this" {
  name               = substr("${local.name_prefix}-${var.lb_type}", 0, 32)
  load_balancer_type = local.is_alb ? "application" : "network"
  internal           = var.scheme == "internal"
  security_groups    = local.is_alb ? [aws_security_group.alb_sg[0].id] : null
  subnets            = var.subnet_ids

  enable_deletion_protection = var.deletion_protection

  dynamic "access_logs" {
    for_each = var.enable_access_logs && var.access_logs_s3_bucket != null ? [1] : []
    content {
      bucket  = var.access_logs_s3_bucket
      prefix  = coalesce(var.access_logs_s3_prefix, local.name_prefix)
      enabled = true
    }
  }

  tags = local.common_tags
}

# Cross-zone и иные атрибуты
resource "aws_lb_attribute" "attrs" {
  for_each = {
    cross_zone                  = var.cross_zone
    idle_timeout_timeout_seconds = local.is_alb ? var.idle_timeout : null
    access_logs_s3_enabled       = var.enable_access_logs
  }

  load_balancer_arn = aws_lb.this.arn
  key               = each.key == "cross_zone" ? (local.is_alb ? "routing.http2.enabled" : "load_balancing.cross_zone.enabled") : (
                      each.key == "idle_timeout_timeout_seconds" ? "idle_timeout.timeout_seconds" :
                      each.key == "access_logs_s3_enabled" ? "access_logs.s3.enabled" : each.key)
  value             = each.value == null ? null : tostring(each.value)

  lifecycle {
    ignore_changes = [value] # некоторые ключи не применимы для ALB/NLB; игнорим no-op для платформенной идемпотентности
  }
}

###############################################################################
# TARGET GROUPS
###############################################################################

# Основной TG под HTTP/TCP
resource "aws_lb_target_group" "primary" {
  name        = substr("${local.name_prefix}-${local.is_alb ? "http" : "tcp"}", 0, 32)
  port        = var.target_port_http
  protocol    = local.is_alb ? local.alb_http_protocol : local.nlb_tcp_protocol
  target_type = var.target_type
  vpc_id      = var.vpc_id

  health_check {
    enabled             = true
    protocol            = local.is_alb ? var.health_check_protocol : "TCP"
    path                = local.is_alb ? var.health_check_path : null
    port                = local.is_alb ? var.health_check_port : "traffic-port"
    interval            = var.health_check_interval
    timeout             = var.health_check_timeout
    healthy_threshold   = var.health_check_healthy_threshold
    unhealthy_threshold = var.health_check_unhealthy_threshold
    matcher             = local.is_alb && var.health_check_protocol == "HTTP" ? "200-399" : null
  }

  tags = local.common_tags
}

# Дополнительный TG под HTTPS/TLS (если требуется)
resource "aws_lb_target_group" "secondary" {
  count       = var.enable_https ? 1 : 0
  name        = substr("${local.name_prefix}-${local.is_alb ? "https" : "tls"}", 0, 32)
  port        = var.target_port_https
  protocol    = local.is_alb ? local.alb_https_protocol : local.nlb_tls_protocol
  target_type = var.target_type
  vpc_id      = var.vpc_id

  health_check {
    enabled             = true
    protocol            = local.is_alb ? var.health_check_protocol : "TCP"
    path                = local.is_alb ? var.health_check_path : null
    port                = local.is_alb ? var.health_check_port : "traffic-port"
    interval            = var.health_check_interval
    timeout             = var.health_check_timeout
    healthy_threshold   = var.health_check_healthy_threshold
    unhealthy_threshold = var.health_check_unhealthy_threshold
    matcher             = local.is_alb && var.health_check_protocol == "HTTP" ? "200-399" : null
  }

  tags = local.common_tags
}

###############################################################################
# LISTENERS
###############################################################################

# HTTP 80 (ALB) или TCP 80 (NLB)
resource "aws_lb_listener" "http" {
  count             = var.enable_http ? 1 : 0
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = local.is_alb ? local.alb_http_protocol : local.nlb_tcp_protocol

  dynamic "default_action" {
    for_each = local.is_alb && var.enable_https && var.certificate_arn != null ? [1] : []
    content {
      type = "redirect"
      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }

  dynamic "default_action" {
    for_each = !(local.is_alb && var.enable_https && var.certificate_arn != null) ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.primary.arn
    }
  }

  tags = local.common_tags
}

# HTTPS 443 (ALB) или TLS 443 (NLB)
resource "aws_lb_listener" "https" {
  count             = var.enable_https ? 1 : 0
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = local.is_alb ? local.alb_https_protocol : local.nlb_tls_protocol
  ssl_policy        = local.is_alb ? "ELBSecurityPolicy-TLS13-1-2-2021-06" : null
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = coalesce(try(aws_lb_target_group.secondary[0].arn, null), aws_lb_target_group.primary.arn)
  }

  tags = local.common_tags
}

###############################################################################
# TARGET ATTACHMENTS (если требуется явная регистрация)
###############################################################################

resource "aws_lb_target_group_attachment" "primary" {
  for_each         = { for i, tgt in var.register_targets : i => tgt }
  target_group_arn = aws_lb_target_group.primary.arn
  target_id        = each.value.id
  port             = each.value.port
}

resource "aws_lb_target_group_attachment" "secondary" {
  for_each = var.enable_https ? { for i, tgt in var.register_targets : i => tgt } : {}
  target_group_arn = try(aws_lb_target_group.secondary[0].arn, null)
  target_id        = each.value.id
  port             = each.value.port
}

###############################################################################
# WAFv2 (только для ALB)
###############################################################################

resource "aws_wafv2_web_acl_association" "this" {
  count        = local.is_alb && var.wafv2_web_acl_arn != null ? 1 : 0
  resource_arn = aws_lb.this.arn
  web_acl_arn  = var.wafv2_web_acl_arn
}

###############################################################################
# OUTPUTS
###############################################################################

output "lb_arn" {
  description = "ARN балансировщика."
  value       = aws_lb.this.arn
}

output "lb_name" {
  description = "Имя балансировщика."
  value       = aws_lb.this.name
}

output "lb_dns_name" {
  description = "DNS-имя балансировщика."
  value       = aws_lb.this.dns_name
}

output "lb_zone_id" {
  description = "Hosted zone ID балансировщика."
  value       = aws_lb.this.zone_id
}

output "security_group_id" {
  description = "Security Group ALB (пусто для NLB)."
  value       = local.is_alb ? aws_security_group.alb_sg[0].id : null
}

output "http_listener_arn" {
  description = "ARN HTTP/TCP листенера (если включён)."
  value       = try(aws_lb_listener.http[0].arn, null)
}

output "https_listener_arn" {
  description = "ARN HTTPS/TLS листенера (если включён)."
  value       = try(aws_lb_listener.https[0].arn, null)
}

output "primary_target_group_arn" {
  description = "ARN основного target group."
  value       = aws_lb_target_group.primary.arn
}

output "secondary_target_group_arn" {
  description = "ARN дополнительного target group (если есть)."
  value       = try(aws_lb_target_group.secondary[0].arn, null)
}
