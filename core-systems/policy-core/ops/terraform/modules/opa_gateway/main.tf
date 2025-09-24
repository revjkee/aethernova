#############################################
# module: policy-core/ops/terraform/modules/opa_gateway/main.tf
# Назначение: Открыть OPA (или проксируемый policy-core) через безопасный Ingress
# Фичи: mTLS (client CA), WAF (ModSecurity/OWASP CRS), rate-limit, whitelist, таймауты
#############################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.24.0"
    }
  }
}

###############
# Переменные
###############

variable "name" {
  description = "Базовое имя ресурсов (Ingress/Secrets)."
  type        = string
  default     = "opa-gateway"
}

variable "namespace" {
  description = "Namespace для размещения Ingress и секретов."
  type        = string
  default     = "policy"
}

variable "create_namespace" {
  description = "Создавать namespace, если он не существует."
  type        = bool
  default     = true
}

variable "ingress_class_name" {
  description = "Имя IngressClass (например, nginx)."
  type        = string
  default     = "nginx"
}

variable "host" {
  description = "Внешний hostname для доступа к шлюзу."
  type        = string

  validation {
    condition     = length(var.host) > 0
    error_message = "host обязателен и не может быть пустым."
  }
}

variable "opa_service_name" {
  description = "Имя сервиса в кластере, на который проксируем (OPA или policy-core)."
  type        = string
  default     = "opa"
}

variable "opa_service_port" {
  description = "Порт сервиса (числовой)."
  type        = number
  default     = 8181
}

# TLS termination на Ingress: либо создаём secret из PEM, либо используем существующий.
variable "create_tls_secret" {
  description = "Создавать TLS Secret из переданных PEM."
  type        = bool
  default     = false
}

variable "tls_secret_name" {
  description = "Имя существующего TLS Secret (если create_tls_secret=false)."
  type        = string
  default     = ""
}

variable "tls_cert_pem" {
  description = "PEM-содержимое tls.crt (используется при create_tls_secret=true)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "tls_key_pem" {
  description = "PEM-содержимое tls.key (используется при create_tls_secret=true)."
  type        = string
  default     = ""
  sensitive   = true
}

# mTLS (client-auth) на входе Ingress через NGINX auth-tls.
variable "require_mtls" {
  description = "Включить обязательную проверку клиентских сертификатов."
  type        = bool
  default     = true
}

variable "client_ca_secret_name" {
  description = "Имя существующего Secret с client CA (Opaque, ключ ca.crt)."
  type        = string
  default     = ""
}

variable "client_ca_pem" {
  description = "PEM-содержимое ca.crt для создания Secret (если client_ca_secret_name пуст)."
  type        = string
  default     = ""
  sensitive   = true
}

# Лимитирование и WAF
variable "rate_limit_rps" {
  description = "Ограничение RPS (nginx.ingress.kubernetes.io/limit-rps). 0 — выключено."
  type        = number
  default     = 200
}

variable "rate_limit_burst" {
  description = "Burst для RPS (nginx.ingress.kubernetes.io/limit-burst). 0 — выключено."
  type        = number
  default     = 400
}

variable "limit_connections" {
  description = "Ограничение одновременных соединений на IP (nginx.ingress.kubernetes.io/limit-connections). 0 — выключено."
  type        = number
  default     = 200
}

variable "enable_modsecurity" {
  description = "Включить ModSecurity и OWASP CRS в ingress-nginx."
  type        = bool
  default     = true
}

variable "modsecurity_snippet" {
  description = "Дополнительные правила ModSecurity (modsecurity-snippet)."
  type        = string
  default     = <<-EOT
    SecRuleEngine On
    SecRequestBodyAccess On
    SecResponseBodyAccess Off
    SecAuditEngine RelevantOnly
    SecAuditLogParts ABIJDEFHZ
    SecRuleRemoveById 920350
  EOT
}

# Сетевые и прокси-настройки
variable "allowed_source_ranges" {
  description = "Список CIDR, которым разрешён доступ (whitelist-source-range). Пусто — не ограничивать."
  type        = list(string)
  default     = []
}

variable "proxy_body_size" {
  description = "Максимальный размер тела запроса."
  type        = string
  default     = "16m"
}

variable "proxy_read_timeout_seconds" {
  description = "Таймаут чтения ответа бэкенда (сек)."
  type        = number
  default     = 60
}

variable "proxy_send_timeout_seconds" {
  description = "Таймаут отправки запроса бэкенду (сек)."
  type        = number
  default     = 60
}

variable "extra_annotations" {
  description = "Дополнительные аннотации для Ingress."
  type        = map(string)
  default     = {}
}

variable "extra_labels" {
  description = "Дополнительные метки для Ingress."
  type        = map(string)
  default     = {}
}

# Валидации комбинаций TLS/CA
locals {
  need_client_ca = var.require_mtls
}

# Проверяем TLS входные данные
resource "null_resource" "validate_tls" {
  triggers = {
    create_tls_secret = tostring(var.create_tls_secret)
    tls_secret_name   = var.tls_secret_name
    cert_len          = tostring(length(var.tls_cert_pem))
    key_len           = tostring(length(var.tls_key_pem))
  }
  lifecycle {
    ignore_changes = all
  }

  provisioner "local-exec" {
    when    = create
    command = "true"
    interpreter = ["/bin/sh", "-c"]
    environment = {}
  }
}

# Пользовательские проверки через условные выражения
locals {
  tls_check = var.create_tls_secret ?
    (length(var.tls_cert_pem) > 0 && length(var.tls_key_pem) > 0) :
    (length(var.tls_secret_name) > 0)

  ca_check  = local.need_client_ca ?
    (length(var.client_ca_secret_name) > 0 || length(var.client_ca_pem) > 0) :
    true
}

# Fail-fast через выражение, которое невозможно применить (условно)
# Примечание: для явных ошибок в Terraform 1.6+ можно использовать 'terraform' блок с 'test' провайдером,
# но здесь — безопасная проверка через условие в count.
resource "null_resource" "guard_tls" {
  count = (local.tls_check && local.ca_check) ? 0 : 1
  provisioner "local-exec" {
    command = "echo 'Invalid TLS/CA configuration for opa_gateway module' && exit 1"
    interpreter = ["/bin/sh", "-c"]
  }
}

##########################
# Namespace (опционально)
##########################
resource "kubernetes_namespace_v1" "ns" {
  count = var.create_namespace ? 1 : 0
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/part-of" = "policy-core"
      "app.kubernetes.io/component" = "gateway"
    }
  }
}

##############################
# TLS Secret (опционально)
##############################
resource "kubernetes_secret_v1" "tls" {
  count = var.create_tls_secret ? 1 : 0
  metadata {
    name      = "${var.name}-tls"
    namespace = var.namespace
    labels = merge({
      "app.kubernetes.io/name"       = var.name
      "app.kubernetes.io/part-of"    = "policy-core"
      "app.kubernetes.io/component"  = "gateway"
    }, var.extra_labels)
  }
  type = "kubernetes.io/tls"
  string_data = {
    "tls.crt" = var.tls_cert_pem
    "tls.key" = var.tls_key_pem
  }
}

locals {
  tls_secret_name_effective = var.create_tls_secret ? kubernetes_secret_v1.tls[0].metadata[0].name : var.tls_secret_name
}

##########################################
# Client CA Secret для mTLS (если нужно)
##########################################
resource "kubernetes_secret_v1" "client_ca" {
  count = (local.need_client_ca && length(var.client_ca_secret_name) == 0) ? 1 : 0
  metadata {
    name      = "${var.name}-client-ca"
    namespace = var.namespace
    labels = merge({
      "app.kubernetes.io/name"       = var.name
      "app.kubernetes.io/part-of"    = "policy-core"
      "app.kubernetes.io/component"  = "gateway"
    }, var.extra_labels)
  }
  type = "Opaque"
  string_data = {
    "ca.crt" = var.client_ca_pem
  }
}

locals {
  client_ca_secret_name_effective = local.need_client_ca ? (
    length(var.client_ca_secret_name) > 0 ? var.client_ca_secret_name : kubernetes_secret_v1.client_ca[0].metadata[0].name
  ) : ""
}

############################
# Аннотации Ingress
############################
locals {
  base_annotations = {
    "kubernetes.io/ingress.class"                 = var.ingress_class_name
    "nginx.ingress.kubernetes.io/backend-protocol" = "HTTP"
    "nginx.ingress.kubernetes.io/ssl-redirect"    = "true"
    "nginx.ingress.kubernetes.io/proxy-body-size" = var.proxy_body_size
    "nginx.ingress.kubernetes.io/proxy-read-timeout"  = tostring(var.proxy_read_timeout_seconds)
    "nginx.ingress.kubernetes.io/proxy-send-timeout"  = tostring(var.proxy_send_timeout_seconds)
    # Предотвращаем буферизацию больших ответов (опционально для стриминга решений)
    "nginx.ingress.kubernetes.io/proxy-buffering" = "off"
  }

  ratelimit_annotations = merge(
    var.rate_limit_rps > 0 ? { "nginx.ingress.kubernetes.io/limit-rps" = tostring(var.rate_limit_rps) } : {},
    var.rate_limit_burst > 0 ? { "nginx.ingress.kubernetes.io/limit-burst" = tostring(var.rate_limit_burst) } : {},
    var.limit_connections > 0 ? { "nginx.ingress.kubernetes.io/limit-connections" = tostring(var.limit_connections) } : {}
  )

  waf_annotations = var.enable_modsecurity ? {
    "nginx.ingress.kubernetes.io/enable-modsecurity"          = "true"
    "nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs" = "true"
    "nginx.ingress.kubernetes.io/modsecurity-snippet"          = trimspace(var.modsecurity_snippet)
  } : {}

  mtlx_annotations = (local.need_client_ca && length(local.client_ca_secret_name_effective) > 0) ? {
    "nginx.ingress.kubernetes.io/auth-tls-secret"                      = "${var.namespace}/${local.client_ca_secret_name_effective}"
    "nginx.ingress.kubernetes.io/auth-tls-verify-client"               = "on"
    "nginx.ingress.kubernetes.io/auth-tls-verify-depth"                = "1"
    "nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream" = "true"
  } : {}

  whitelist_annotations = length(var.allowed_source_ranges) > 0 ? {
    "nginx.ingress.kubernetes.io/whitelist-source-range" = join(", ", var.allowed_source_ranges)
  } : {}

  annotations = merge(
    local.base_annotations,
    local.ratelimit_annotations,
    local.waf_annotations,
    local.mtlx_annotations,
    local.whitelist_annotations,
    var.extra_annotations
  )
}

############################
# Ingress ресурс
############################
resource "kubernetes_ingress_v1" "opa" {
  metadata {
    name      = var.name
    namespace = var.namespace
    labels = merge({
      "app.kubernetes.io/name"       = var.name
      "app.kubernetes.io/instance"   = var.name
      "app.kubernetes.io/part-of"    = "policy-core"
      "app.kubernetes.io/component"  = "gateway"
    }, var.extra_labels)
    annotations = local.annotations
  }

  spec {
    ingress_class_name = var.ingress_class_name
    rule {
      host = var.host
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = var.opa_service_name
              port {
                number = var.opa_service_port
              }
            }
          }
        }
      }
    }

    tls {
      hosts       = [var.host]
      secret_name = local.tls_secret_name_effective
    }
  }

  depends_on = [
    kubernetes_namespace_v1.ns,
    kubernetes_secret_v1.tls,
    kubernetes_secret_v1.client_ca,
    null_resource.guard_tls
  ]
}

############################
# Outputs
############################
output "ingress_name" {
  description = "Имя созданного Ingress."
  value       = kubernetes_ingress_v1.opa.metadata[0].name
}

output "ingress_host" {
  description = "Внешний hostname Ingress."
  value       = var.host
}

output "tls_secret_name" {
  description = "Имя TLS Secret, используемого Ingress."
  value       = local.tls_secret_name_effective
}

output "client_ca_secret_name" {
  description = "Имя Secret с client CA (если mTLS включён)."
  value       = local.client_ca_secret_name_effective
}

output "namespace" {
  description = "Namespace, в котором размещён шлюз."
  value       = var.namespace
}
