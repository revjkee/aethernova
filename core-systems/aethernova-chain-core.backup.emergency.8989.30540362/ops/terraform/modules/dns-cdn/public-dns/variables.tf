###############################
# dns-cdn/public-dns/variables.tf
# Промышленная версия входных переменных для публичных DNS-зон
# Поддержка провайдеров: AWS Route53, Cloudflare, Google Cloud DNS, Azure DNS
###############################

################################
# Общие параметры зоны
################################
variable "zone_name" {
  description = "DNS-имя зоны (например, example.com или example.com.). Точка в конце допускается."
  type        = string

  validation {
    condition     = can(regex("^(?=.{1,253}$)(?!-)(?!.*--)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\.?$", var.zone_name))
    error_message = "zone_name должен быть валидным FQDN длиной до 253 символов."
  }
}

variable "description" {
  description = "Описание/назначение зоны (для провайдеров, где возможно: комментарий/description)."
  type        = string
  default     = null
}

# Некоторые провайдеры (например, Google Cloud DNS) требуют точку в конце dns_name.
# Этот флаг позволит main.tf при необходимости нормализовать имя.
variable "ensure_trailing_dot" {
  description = "Если true, main.tf будет добавлять завершающую точку для провайдеров, требующих этого (например, GCP Cloud DNS)."
  type        = bool
  default     = true
}

################################
# Таймауты (унифицированные)
################################
variable "timeouts" {
  description = "Глобальные таймауты ресурсов (если поддерживается провайдером). Формат Terraform durations, например \"30m\"."
  type = object({
    create = optional(string)
    update = optional(string)
    delete = optional(string)
  })
  default = {}
}

################################
# AWS Route 53
################################
variable "aws" {
  description = "Параметры создания публичной зоны в AWS Route 53."
  type = object({
    enabled            = bool
    comment            = optional(string)          # aws_route53_zone.comment
    force_destroy      = optional(bool, false)     # aws_route53_zone.force_destroy
    delegation_set_id  = optional(string)          # aws_route53_zone.delegation_set_id (для публичных зон)
    tags               = optional(map(string), {}) # Теги на зоне
    dnssec = optional(object({
      enabled      = bool                          # Включение DNSSEC
      kms_key_arn  = optional(string)              # ARN KMS-ключа для KSK (обязателен при enabled=true)
    }), {
      enabled     = false
      kms_key_arn = null
    })
  })

  default = {
    enabled = false
    # прочие поля по умолчанию как указано в type/optional
  }

  validation {
    condition     = var.aws.enabled ? true : true
    error_message = "aws.enabled должен быть bool."
  }

  validation {
    condition     = !(try(var.aws.dnssec.enabled, false)) || try(length(var.aws.dnssec.kms_key_arn) > 0, false)
    error_message = "При включенном AWS DNSSEC необходимо указать dnssec.kms_key_arn (ARN KMS-ключа для KSK)."
  }

  validation {
    condition     = var.aws.delegation_set_id == null || can(regex("^([A-Z0-9]+)$", var.aws.delegation_set_id))
    error_message = "delegation_set_id должен быть валидным идентификатором Route53 Delegation Set."
  }
}

################################
# Cloudflare
################################
variable "cloudflare" {
  description = "Параметры создания публичной зоны в Cloudflare."
  type = object({
    enabled     = bool
    account_id  = optional(string)                 # Идентификатор аккаунта Cloudflare
    # Тип зоны: 'full' (DNS у Cloudflare) или 'partial' (CNAME setup/partner). См. провайдер.
    zone_type   = optional(string, "full")
    # Статус DNSSEC на зоне: в Terraform будет маппиться на cloudflare_zone_dnssec.status (например, 'active'/'disabled')
    dnssec = optional(object({
      enabled = bool
    }), {
      enabled = false
    })
    # Дополнительные zone settings (могут использоваться в ресурсах zone_settings_override)
    settings = optional(map(any), {})
  })

  default = {
    enabled   = false
    zone_type = "full"
    dnssec = {
      enabled = false
    }
    settings = {}
  }

  validation {
    condition     = contains(["full", "partial"], lower(var.cloudflare.zone_type))
    error_message = "cloudflare.zone_type должен быть 'full' или 'partial'."
  }

  validation {
    condition     = !var.cloudflare.enabled || try(length(var.cloudflare.account_id) > 0, false)
    error_message = "При включенном Cloudflare необходимо указать account_id."
  }
}

################################
# Google Cloud DNS
################################
variable "gcp" {
  description = "Параметры создания публичной зоны в Google Cloud DNS."
  type = object({
    enabled      = bool
    project_id   = optional(string)
    labels       = optional(map(string), {})       # google_dns_managed_zone.labels
    # DNSSEC-конфигурация (см. dnssec_config у google_dns_managed_zone)
    dnssec = optional(object({
      # state: 'off' | 'on' | 'transfer'
      state          = optional(string, "off")
      # non_existence: 'nsec' | 'nsec3' (по умолчанию NSEC3 чаще рекомендуется)
      non_existence  = optional(string, "nsec3")
      # Алгоритмы/длины ключей по желанию; если задаются - должны быть заданы для обоих типов ключей.
      ksk_algorithm  = optional(string, "rsasha256")
      zsk_algorithm  = optional(string, "rsasha256")
      ksk_key_length = optional(number, 2048)
      zsk_key_length = optional(number, 1024)
    }), {
      state          = "off"
      non_existence  = "nsec3"
      ksk_algorithm  = "rsasha256"
      zsk_algorithm  = "rsasha256"
      ksk_key_length = 2048
      zsk_key_length = 1024
    })
  })

  default = {
    enabled = false
    labels  = {}
    dnssec = {
      state          = "off"
      non_existence  = "nsec3"
      ksk_algorithm  = "rsasha256"
      zsk_algorithm  = "rsasha256"
      ksk_key_length = 2048
      zsk_key_length = 1024
    }
  }

  validation {
    condition     = contains(["off", "on", "transfer"], lower(try(var.gcp.dnssec.state, "off")))
    error_message = "gcp.dnssec.state должен быть 'off', 'on' или 'transfer'."
  }
  validation {
    condition     = contains(["nsec", "nsec3"], lower(try(var.gcp.dnssec.non_existence, "nsec3")))
    error_message = "gcp.dnssec.non_existence должен быть 'nsec' или 'nsec3'."
  }
  validation {
    condition = contains(["rsasha256","rsasha512","ecdsap256sha256","ecdsap384sha384","rsasha1"], lower(try(var.gcp.dnssec.ksk_algorithm, "rsasha256"))) &&
                contains(["rsasha256","rsasha512","ecdsap256sha256","ecdsap384sha384","rsasha1"], lower(try(var.gcp.dnssec.zsk_algorithm, "rsasha256")))
    error_message = "Допустимые алгоритмы: rsasha256, rsasha512, ecdsap256sha256, ecdsap384sha384, rsasha1."
  }
}

################################
# Azure DNS
################################
variable "azure" {
  description = "Параметры создания публичной зоны в Azure DNS."
  type = object({
    enabled              = bool
    resource_group_name  = optional(string)
    tags                 = optional(map(string), {})
    # Поддержка DNSSEC у Azure Public DNS имеется; наличие поля в провайдере Terraform зависит от версии.
    dnssec = optional(object({
      enabled = bool
    }), {
      enabled = false
    })
  })

  default = {
    enabled = false
    tags    = {}
    dnssec = {
      enabled = false
    }
  }

  validation {
    condition     = var.azure.enabled ? try(length(var.azure.resource_group_name) > 0, false) : true
    error_message = "При включенном Azure необходимо указать resource_group_name."
  }
}

################################
# Общие метки/теги (будут совмещаться провайдер-специфично)
################################
variable "global_tags" {
  description = "Глобальные теги/метки для всех провайдеров (объединяются с провайдер-специфичными)."
  type        = map(string)
  default     = {}
}
