terraform {
  required_version = ">= 1.6.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60.0, < 6.0.0"
    }
  }
}

############################################
# Core networking
############################################

variable "vpc_id" {
  description = "ID VPC, в которой создаётся Load Balancer."
  type        = string

  validation {
    condition     = length(var.vpc_id) > 0
    error_message = "vpc_id must be a non-empty string."
  }
}

variable "subnet_ids" {
  description = "Список Subnet IDs для размещения Load Balancer (2+ для prod)."
  type        = list(string)

  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "Provide at least two subnet IDs for production-grade high availability."
  }
}

variable "security_group_ids" {
  description = "Список Security Group IDs для ALB/NLB (для NLB обычно пусто, если используете SG для NLB — передайте явно)."
  type        = list(string)
  default     = []
}

############################################
# LB type & scheme
############################################

variable "lb_type" {
  description = "Тип балансировщика: application (ALB) или network (NLB)."
  type        = string
  default     = "application"

  validation {
    condition     = contains(["application", "network"], var.lb_type)
    error_message = "lb_type must be either 'application' or 'network'."
  }
}

variable "scheme" {
  description = "Схема доступности: 'internet-facing' или 'internal'."
  type        = string
  default     = "internet-facing"

  validation {
    condition     = contains(["internet-facing", "internal"], var.scheme)
    error_message = "scheme must be 'internet-facing' or 'internal'."
  }
}

variable "ip_address_type" {
  description = "Тип адреса: ipv4 или dualstack (ALB/NLB поддержка)."
  type        = string
  default     = "ipv4"

  validation {
    condition     = contains(["ipv4", "dualstack"], var.ip_address_type)
    error_message = "ip_address_type must be 'ipv4' or 'dualstack'."
  }
}

variable "enable_cross_zone_load_balancing" {
  description = "Включить cross-zone балансировку (для NLB = true рекомендуется)."
  type        = bool
  default     = true
}

variable "deletion_protection" {
  description = "Защита от удаления LB."
  type        = bool
  default     = true
}

############################################
# Access logs
############################################

variable "enable_access_logs" {
  description = "Включить журналы доступа ALB/NLB в S3."
  type        = bool
  default     = true
}

variable "access_logs_s3_bucket" {
  description = "Имя S3 бакета для логов доступа LB."
  type        = string
  default     = ""
}

variable "access_logs_s3_prefix" {
  description = "Префикс для логов доступа в S3."
  type        = string
  default     = "elb-access-logs/"
}

############################################
# Attributes / tuning
############################################

variable "idle_timeout" {
  description = "Idle timeout для ALB (сек). Для NLB игнорируется."
  type        = number
  default     = 60

  validation {
    condition     = var.idle_timeout >= 1 && var.idle_timeout <= 4000
    error_message = "idle_timeout must be between 1 and 4000 seconds."
  }
}

variable "drop_invalid_header_fields" {
  description = "ALB: удалять некорректные заголовки (security hardening)."
  type        = bool
  default     = true
}

variable "routing_http2_enabled" {
  description = "ALB: включить HTTP/2."
  type        = bool
  default     = true
}

variable "routing_http_drop_invalid_header_fields" {
  description = "ALB: дропать некорректные заголовки на уровне маршрутизации."
  type        = bool
  default     = true
}

variable "enable_waf" {
  description = "Подключить AWS WAFv2 WebACL к ALB."
  type        = bool
  default     = false
}

variable "waf_web_acl_arn" {
  description = "ARN AWS WAFv2 WebACL (региональный) для привязки к ALB."
  type        = string
  default     = ""
}

############################################
# TLS / certificates
############################################

variable "listener_https_enabled" {
  description = "Создавать HTTPS листенер для ALB."
  type        = bool
  default     = true
}

variable "listener_http_enabled" {
  description = "Создавать HTTP листенер (обычно 80) и редиректить на HTTPS."
  type        = bool
  default     = true
}

variable "listener_http_port" {
  description = "Порт HTTP листенера."
  type        = number
  default     = 80
}

variable "listener_https_port" {
  description = "Порт HTTPS листенера."
  type        = number
  default     = 443
}

variable "ssl_policy" {
  description = "Политика шифров для HTTPS листенера ALB (пример: ELBSecurityPolicy-TLS13-1-2-2021-06)."
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

variable "certificate_arn" {
  description = "ARN ACM сертификата для HTTPS."
  type        = string
  default     = ""

  validation {
    condition     = var.listener_https_enabled == false || length(var.certificate_arn) > 0
    error_message = "certificate_arn must be provided when listener_https_enabled = true."
  }
}

############################################
# Listeners (advanced)
############################################

variable "additional_listeners" {
  description = <<-EOT
Список дополнительных листенеров.
Для ALB:
  - protocol: HTTP|HTTPS
  - port: number
  - ssl_policy (для HTTPS)
  - certificate_arn (для HTTPS)
Для NLB:
  - protocol: TCP|TLS|UDP|TCP_UDP
  - port: number
EOT
  type = list(object({
    protocol        = string
    port            = number
    ssl_policy      = optional(string)
    certificate_arn = optional(string)
  }))
  default = []

  validation {
    condition = alltrue([
      for l in var.additional_listeners :
      contains(["HTTP", "HTTPS", "TCP", "TLS", "UDP", "TCP_UDP"], upper(l.protocol))
    ])
    error_message = "Listener.protocol must be one of HTTP, HTTPS (ALB) or TCP, TLS, UDP, TCP_UDP (NLB)."
  }
}

############################################
# Target groups
############################################

variable "target_type" {
  description = "Тип таргета: instance, ip или lambda (для ALB). Для NLB обычно instance/ip."
  type        = string
  default     = "ip"

  validation {
    condition     = contains(["instance", "ip", "lambda"], var.target_type)
    error_message = "target_type must be one of: instance, ip, lambda."
  }
}

variable "health_check" {
  description = <<-EOT
Настройки health check целевой группы.
Для ALB (HTTP/HTTPS): path, matcher, healthy/unhealthy thresholds, interval/timeout.
Для NLB (TCP/HTTP/HTTPS): protocol, port, thresholds, interval/timeout.
EOT
  type = object({
    enabled             = optional(bool, true)
    protocol            = optional(string, "HTTP")
    port                = optional(string, "traffic-port")
    path                = optional(string, "/healthz")
    matcher             = optional(string, "200-399")
    healthy_threshold   = optional(number, 3)
    unhealthy_threshold = optional(number, 3)
    interval            = optional(number, 30)
    timeout             = optional(number, 5)
  })
  default = {}
}

variable "default_tg_port" {
  description = "Порт целевой группы по умолчанию (если не переопределён на уровне listener rule)."
  type        = number
  default     = 3000
}

variable "stickiness" {
  description = <<-EOT
Параметры stickiness для ALB:
  - enabled: включать sticky-сессии
  - type: lb_cookie | app_cookie (обычно lb_cookie)
  - duration: секунды
EOT
  type = object({
    enabled  = optional(bool, false)
    type     = optional(string, "lb_cookie")
    duration = optional(number, 3600)
  })
  default = {}

  validation {
    condition     = var.lb_type == "application" ? contains(["lb_cookie", "app_cookie"], var.stickiness.type) : true
    error_message = "stickiness.type must be 'lb_cookie' or 'app_cookie' for ALB."
  }
}

############################################
# Listener rules (path/host routing for ALB)
############################################

variable "listener_rules" {
  description = <<-EOT
Правила маршрутизации для ALB HTTPS листенера:
  - priority: уникальный приоритет
  - host_headers: список хостов (optional)
  - path_patterns: список путей (optional)
  - target_group:
      port: порт TG
      protocol: HTTP|HTTPS
      health_check: (опционально — перезапишет общие параметры)
EOT
  type = list(object({
    priority      = number
    host_headers  = optional(list(string))
    path_patterns = optional(list(string))
    target_group = object({
      port     = number
      protocol = string
      health_check = optional(object({
        enabled             = optional(bool)
        protocol            = optional(string)
        port                = optional(string)
        path                = optional(string)
        matcher             = optional(string)
        healthy_threshold   = optional(number)
        unhealthy_threshold = optional(number)
        interval            = optional(number)
        timeout             = optional(number)
      }))
    })
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.listener_rules :
      contains(["HTTP", "HTTPS"], upper(r.target_group.protocol))
    ])
    error_message = "listener_rules.target_group.protocol must be HTTP or HTTPS."
  }
}

############################################
# NLB-specific listeners/targets (optional)
############################################

variable "nlb_listeners" {
  description = <<-EOT
Опциональные NLB листенеры (если используете NLB):
  - port: number
  - protocol: TCP|TLS|UDP|TCP_UDP
  - ssl_policy / certificate_arn (только для TLS)
  - target_group_port: number
EOT
  type = list(object({
    port               = number
    protocol           = string
    target_group_port  = number
    ssl_policy         = optional(string)
    certificate_arn    = optional(string)
  }))
  default = []

  validation {
    condition = alltrue([
      for l in var.nlb_listeners :
      contains(["TCP", "TLS", "UDP", "TCP_UDP"], upper(l.protocol))
    ])
    error_message = "nlb_listeners.protocol must be one of TCP, TLS, UDP, TCP_UDP."
  }
}

############################################
# Tags
############################################

variable "tags" {
  description = "Общие тэги для всех ресурсов LB."
  type        = map(string)
  default     = {}
}

variable "resource_tags" {
  description = <<-EOT
Тэги по типам ресурсов:
  - lb = { ... }
  - target_group = { ... }
  - listener = { ... }
EOT
  type = object({
    lb           = optional(map(string), {})
    target_group = optional(map(string), {})
    listener     = optional(map(string), {})
  })
  default = {}
}

############################################
# Advanced security / headers (ALB)
############################################

variable "xff_header_processing_mode" {
  description = "ALB: режим обработки X-Forwarded-For (append|remove|preserve)."
  type        = string
  default     = "append"

  validation {
    condition     = contains(["append", "remove", "preserve"], var.xff_header_processing_mode)
    error_message = "xff_header_processing_mode must be one of: append, remove, preserve."
  }
}

variable "x_amzn_tls_version_and_cipher_suite_enabled" {
  description = "ALB: включить добавление заголовка с TLS-версией/набором шифров."
  type        = bool
  default     = true
}

############################################
# KMS / logs encryption (optional)
############################################

variable "access_logs_sse_kms_key_arn" {
  description = "KMS Key ARN для шифрования S3 access logs (если бакет с SSE-KMS)."
  type        = string
  default     = ""
}

############################################
# Throttling / quotas for Partner API (pass-through)
############################################

variable "enable_partner_quota" {
  description = "Включить механизм квот/лимитов для партнёрских ключей (используется на уровне API Gateway/ingress annotations)."
  type        = bool
  default     = false
}

variable "partner_quota" {
  description = <<-EOT
Параметры квот: burst/rate на ключ.
Используются потребляющими ресурсами (Ingress/Nginx annotations или API Gateway).
EOT
  type = object({
    requests_per_second = number
    burst_size          = number
  })
  default = {
    requests_per_second = 50
    burst_size          = 100
  }

  validation {
    condition     = var.partner_quota.requests_per_second > 0 && var.partner_quota.burst_size >= var.partner_quota.requests_per_second
    error_message = "partner_quota.burst_size must be >= requests_per_second and both > 0."
  }
}
