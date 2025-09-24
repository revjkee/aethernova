// aethernova-chain-core/ops/terraform/modules/dns-cdn/public-dns/main.tf
// Универсальный модуль публичного DNS: AWS Route53 / Google Cloud DNS / Azure DNS.
// Выбор провайдера: var.cloud = "aws" | "gcp" | "azure".
// Примечания:
// - AWS/GCP: единый формат var.records для большинства типов (A/AAAA/CNAME/TXT/MX/NS/SRV/CAA).
// - Azure: единый формат для A/AAAA/CNAME/TXT; для MX/SRV/CAA — отдельные переменные c нативными схемами.
// - DNSSEC/alias к CDN можно добавить расширением; базовый модуль фокусируется на зоне и записях.
//
// ВНИМАНИЕ: Провайдеры (aws/google/azurerm) настраиваются на уровне корня проекта (credentials/aliases).

// ------------------------------- Переменные ----------------------------------

variable "cloud" {
  type        = string
  description = "Целевое облако: aws | gcp | azure"
  validation {
    condition     = contains(["aws", "gcp", "azure"], var.cloud)
    error_message = "cloud должен быть одним из: aws, gcp, azure."
  }
}

variable "zone_name" {
  type        = string
  description = "Имя публичной зоны (пример: example.com). Точка в конце не требуется."
}

variable "comment" {
  type        = string
  description = "Описание/комментарий к зоне."
  default     = "managed by Terraform"
}

variable "project_id" {
  type        = string
  description = "GCP: ID проекта для Cloud DNS."
  default     = null
}

variable "gcp_location" {
  type        = string
  description = "GCP: локация зоны (global по умолчанию)."
  default     = "global"
}

variable "resource_group_name" {
  type        = string
  description = "Azure: Resource Group для DNS зоны."
  default     = null
}

variable "azure_location" {
  type        = string
  description = "Azure: регион для ресурсов, если требуется (обычно в зоне не используется)."
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Теги для ресурсов (где поддерживается)."
  default     = {}
}

// Унифицированные записи для AWS/GCP и (частично) Azure
variable "records" {
  description = <<EOT
Универсальные DNS-записи (AWS/GCP полностью; Azure — A/AAAA/CNAME/TXT).
Типы:
- type: "A" | "AAAA" | "CNAME" | "TXT" | "MX" | "NS" | "SRV" | "CAA"
- name: относительное имя ('@' или субдомен без зоны), например: "@", "www", "api"
- ttl:  TTL в секундах
- rrdatas: список строк значений:
   * A/AAAA: IP адреса
   * CNAME: одно значение, FQDN с точкой или без (без точки в AWS/GCP допустимо; в AWS не нужна финальная точка)
   * TXT: строки (в AWS для длинных TXT будет сегментация провайдером)
   * MX: строки вида "10 mail.example.com."
   * NS: FQDN NS-серверов
   * SRV: строки вида "10 5 8080 target.example.com."
   * CAA: строки вида "0 issue \"letsencrypt.org\""
EOT
  type = list(object({
    type    = string
    name    = string
    ttl     = number
    rrdatas = list(string)
  }))
  default = []
}

// Специальные схемы для Azure (нативные типы, если нужны MX/SRV/CAA)
variable "azure_mx_records" {
  type = list(object({
    name = string
    ttl  = number
    records = list(object({
      preference = number
      exchange   = string
    }))
  }))
  description = "Azure MX: список записей с нативной схемой."
  default     = []
}

variable "azure_srv_records" {
  type = list(object({
    name = string
    ttl  = number
    records = list(object({
      priority = number
      weight   = number
      port     = number
      target   = string
    }))
  }))
  description = "Azure SRV: список записей с нативной схемой."
  default     = []
}

variable "azure_caa_records" {
  type = list(object({
    name = string
    ttl  = number
    records = list(object({
      flags = number
      tag   = string
      value = string
    }))
  }))
  description = "Azure CAA: список записей с нативной схемой."
  default     = []
}

// Управление NS/SOA в корне зоны
variable "manage_default_ns_soa" {
  type        = bool
  description = "Создавать/управлять пользовательскими NS/SOA в корне. Обычно false, чтобы не конфликтовать с провайдером."
  default     = false
}

// ------------------------------- Локальные -----------------------------------

locals {
  is_aws   = var.cloud == "aws"
  is_gcp   = var.cloud == "gcp"
  is_azure = var.cloud == "azure"

  // Унифицированная нормализация имени без завершающей точки
  zone_fqdn = replace(var.zone_name, "/\\.$/", "")

  // Отфильтрованные записи на типы
  rec_a     = [for r in var.records : r if upper(r.type) == "A"]
  rec_aaaa  = [for r in var.records : r if upper(r.type) == "AAAA"]
  rec_cname = [for r in var.records : r if upper(r.type) == "CNAME"]
  rec_txt   = [for r in var.records : r if upper(r.type) == "TXT"]
  rec_mx    = [for r in var.records : r if upper(r.type) == "MX"]
  rec_ns    = [for r in var.records : r if upper(r.type) == "NS"]
  rec_srv   = [for r in var.records : r if upper(r.type) == "SRV"]
  rec_caa   = [for r in var.records : r if upper(r.type) == "CAA"]

  // Функции-хелперы
  // Абсолютное имя для AWS/GCP (добавляет зону при необходимости)
  // name="@": корень зоны; иначе добавляет ".zone".
  abs_name = function(name) => (
    name == "@" || name == "" ? local.zone_fqdn : format("%s.%s", name, local.zone_fqdn)
  )
}

// ------------------------------- AWS Route53 ---------------------------------

resource "aws_route53_zone" "this" {
  count = local.is_aws ? 1 : 0

  name = local.zone_fqdn
  comment = var.comment

  tags = var.tags
}

// Утилита: генерация ключа для map с уникальностью
locals {
  aws_zone_id = local.is_aws ? aws_route53_zone.this[0].zone_id : null
}

// A
resource "aws_route53_record" "a" {
  for_each = local.is_aws ? {
    for r in local.rec_a : "${r.name}|A" => r
  } : {}

  zone_id = local.aws_zone_id
  name    = local.abs_name(each.value.name)
  type    = "A"
  ttl     = each.value.ttl
  records = each.value.rrdatas
}

// AAAA
resource "aws_route53_record" "aaaa" {
  for_each = local.is_aws ? {
    for r in local.rec_aaaa : "${r.name}|AAAA" => r
  } : {}

  zone_id = local.aws_zone_id
  name    = local.abs_name(each.value.name)
  type    = "AAAA"
  ttl     = each.value.ttl
  records = each.value.rrdatas
}

// CNAME
resource "aws_route53_record" "cname" {
  for_each = local.is_aws ? {
    for r in local.rec_cname : "${r.name}|CNAME" => r
  } : {}

  zone_id = local.aws_zone_id
  name    = local.abs_name(each.value.name)
  type    = "CNAME"
  ttl     = each.value.ttl
  records = each.value.rrdatas
}

// TXT
resource "aws_route53_record" "txt" {
  for_each = local.is_aws ? {
    for r in local.rec_txt : "${r.name}|TXT" => r
  } : {}

  zone_id = local.aws_zone_id
  name    = local.abs_name(each.value.name)
  type    = "TXT"
  ttl     = each.value.ttl
  records = each.value.rrdatas
}

// MX
resource "aws_route53_record" "mx" {
  for_each = local.is_aws ? {
    for r in local.rec_mx : "${r.name}|MX" => r
  } : {}

  zone_id = local.aws_zone_id
  name    = local.abs_name(each.value.name)
  type    = "MX"
  ttl     = each.value.ttl
  records = each.value.rrdatas
}

// NS (кастомные NS-записи, если нужно управлять субделегированием)
resource "aws_route53_record" "ns" {
  for_each = local.is_aws && var.manage_default_ns_soa ? {
    for r in local.rec_ns : "${r.name}|NS" => r
  } : {}

  zone_id = local.aws_zone_id
  name    = local.abs_name(each.value.name)
  type    = "NS"
  ttl     = each.value.ttl
  records = each.value.rrdatas
}

// SRV
resource "aws_route53_record" "srv" {
  for_each = local.is_aws ? {
    for r in local.rec_srv : "${r.name}|SRV" => r
  } : {}

  zone_id = local.aws_zone_id
  name    = local.abs_name(each.value.name)
  type    = "SRV"
  ttl     = each.value.ttl
  records = each.value.rrdatas
}

// CAA
resource "aws_route53_record" "caa" {
  for_each = local.is_aws ? {
    for r in local.rec_caa : "${r.name}|CAA" => r
  } : {}

  zone_id = local.aws_zone_id
  name    = local.abs_name(each.value.name)
  type    = "CAA"
  ttl     = each.value.ttl
  records = each.value.rrdatas
}

// ------------------------------- Google Cloud DNS ----------------------------

resource "google_dns_managed_zone" "this" {
  count = local.is_gcp ? 1 : 0

  project     = var.project_id
  name        = replace(local.zone_fqdn, "/\\./", "-")          // имя ресурса
  dns_name    = "${local.zone_fqdn}."
  description = var.comment
  labels      = var.tags
}

// A/AAAA/CNAME/TXT/MX/NS/SRV/CAA — через google_dns_record_set
// Хелпер: общее построение for_each
locals {
  gcp_zone_name = local.is_gcp ? google_dns_managed_zone.this[0].name : null
}

resource "google_dns_record_set" "a" {
  for_each = local.is_gcp ? {
    for r in local.rec_a : "${r.name}|A" => r
  } : {}

  name         = "${local.abs_name(each.value.name)}."
  managed_zone = local.gcp_zone_name
  type         = "A"
  ttl          = each.value.ttl
  rrdatas      = each.value.rrdatas
}

resource "google_dns_record_set" "aaaa" {
  for_each = local.is_gcp ? {
    for r in local.rec_aaaa : "${r.name}|AAAA" => r
  } : {}

  name         = "${local.abs_name(each.value.name)}."
  managed_zone = local.gcp_zone_name
  type         = "AAAA"
  ttl          = each.value.ttl
  rrdatas      = each.value.rrdatas
}

resource "google_dns_record_set" "cname" {
  for_each = local.is_gcp ? {
    for r in local.rec_cname : "${r.name}|CNAME" => r
  } : {}

  name         = "${local.abs_name(each.value.name)}."
  managed_zone = local.gcp_zone_name
  type         = "CNAME"
  ttl          = each.value.ttl
  rrdatas      = each.value.rrdatas
}

resource "google_dns_record_set" "txt" {
  for_each = local.is_gcp ? {
    for r in local.rec_txt : "${r.name}|TXT" => r
  } : {}

  name         = "${local.abs_name(each.value.name)}."
  managed_zone = local.gcp_zone_name
  type         = "TXT"
  ttl          = each.value.ttl
  rrdatas      = each.value.rrdatas
}

resource "google_dns_record_set" "mx" {
  for_each = local.is_gcp ? {
    for r in local.rec_mx : "${r.name}|MX" => r
  } : {}

  name         = "${local.abs_name(each.value.name)}."
  managed_zone = local.gcp_zone_name
  type         = "MX"
  ttl          = each.value.ttl
  rrdatas      = each.value.rrdatas
}

resource "google_dns_record_set" "ns" {
  for_each = local.is_gcp && var.manage_default_ns_soa ? {
    for r in local.rec_ns : "${r.name}|NS" => r
  } : {}

  name         = "${local.abs_name(each.value.name)}."
  managed_zone = local.gcp_zone_name
  type         = "NS"
  ttl          = each.value.ttl
  rrdatas      = each.value.rrdatas
}

resource "google_dns_record_set" "srv" {
  for_each = local.is_gcp ? {
    for r in local.rec_srv : "${r.name}|SRV" => r
  } : {}

  name         = "${local.abs_name(each.value.name)}."
  managed_zone = local.gcp_zone_name
  type         = "SRV"
  ttl          = each.value.ttl
  rrdatas      = each.value.rrdatas
}

resource "google_dns_record_set" "caa" {
  for_each = local.is_gcp ? {
    for r in local.rec_caa : "${r.name}|CAA" => r
  } : {}

  name         = "${local.abs_name(each.value.name)}."
  managed_zone = local.gcp_zone_name
  type         = "CAA"
  ttl          = each.value.ttl
  rrdatas      = each.value.rrdatas
}

// ------------------------------- Azure DNS -----------------------------------

resource "azurerm_dns_zone" "this" {
  count               = local.is_azure ? 1 : 0
  name                = local.zone_fqdn
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

// Хелперы Azure
locals {
  azure_zone_name = local.is_azure ? azurerm_dns_zone.this[0].name : null
  // Унифицированный name: '@' -> root, иначе относительное имя
  azure_name = function(name) => (name == "@" || name == "" ? "@" : name)
}

// A
resource "azurerm_dns_a_record" "a" {
  for_each = local.is_azure ? {
    for r in local.rec_a : "${r.name}|A" => r
  } : {}

  name                = local.azure_name(each.value.name)
  zone_name           = local.azure_zone_name
  resource_group_name = var.resource_group_name
  ttl                 = each.value.ttl
  records             = each.value.rrdatas
  tags                = var.tags
}

// AAAA
resource "azurerm_dns_aaaa_record" "aaaa" {
  for_each = local.is_azure ? {
    for r in local.rec_aaaa : "${r.name}|AAAA" => r
  } : {}

  name                = local.azure_name(each.value.name)
  zone_name           = local.azure_zone_name
  resource_group_name = var.resource_group_name
  ttl                 = each.value.ttl
  records             = each.value.rrdatas
  tags                = var.tags
}

// CNAME (в Azure CNAME допускает только одно значение)
resource "azurerm_dns_cname_record" "cname" {
  for_each = local.is_azure ? {
    for r in local.rec_cname : "${r.name}|CNAME" => r
  } : {}

  name                = local.azure_name(each.value.name)
  zone_name           = local.azure_zone_name
  resource_group_name = var.resource_group_name
  ttl                 = each.value.ttl
  record              = length(each.value.rrdatas) > 0 ? each.value.rrdatas[0] : ""
  tags                = var.tags
}

// TXT
resource "azurerm_dns_txt_record" "txt" {
  for_each = local.is_azure ? {
    for r in local.rec_txt : "${r.name}|TXT" => r
  } : {}

  name                = local.azure_name(each.value.name)
  zone_name           = local.azure_zone_name
  resource_group_name = var.resource_group_name
  ttl                 = each.value.ttl
  tags                = var.tags

  dynamic "record" {
    for_each = toset(each.value.rrdatas)
    content {
      value = record.value
    }
  }
}

// Дополнительные типы для Azure с нативными схемами

resource "azurerm_dns_mx_record" "mx" {
  for_each = local.is_azure ? {
    for r in var.azure_mx_records : r.name => r
  } : {}

  name                = local.azure_name(each.value.name)
  zone_name           = local.azure_zone_name
  resource_group_name = var.resource_group_name
  ttl                 = each.value.ttl
  tags                = var.tags

  dynamic "record" {
    for_each = each.value.records
    content {
      preference = record.value.preference
      exchange   = record.value.exchange
    }
  }
}

resource "azurerm_dns_srv_record" "srv" {
  for_each = local.is_azure ? {
    for r in var.azure_srv_records : r.name => r
  } : {}

  name                = local.azure_name(each.value.name)
  zone_name           = local.azure_zone_name
  resource_group_name = var.resource_group_name
  ttl                 = each.value.ttl
  tags                = var.tags

  dynamic "record" {
    for_each = each.value.records
    content {
      priority = record.value.priority
      weight   = record.value.weight
      port     = record.value.port
      target   = record.value.target
    }
  }
}

resource "azurerm_dns_caa_record" "caa" {
  for_each = local.is_azure ? {
    for r in var.azure_caa_records : r.name => r
  } : {}

  name                = local.azure_name(each.value.name)
  zone_name           = local.azure_zone_name
  resource_group_name = var.resource_group_name
  ttl                 = each.value.ttl
  tags                = var.tags

  dynamic "record" {
    for_each = each.value.records
    content {
      flags = record.value.flags
      tag   = record.value.tag
      value = record.value.value
    }
  }
}

// ------------------------------- Outputs -------------------------------------

output "zone_name" {
  value       = local.zone_fqdn
  description = "Имя публичной зоны."
}

output "zone_id" {
  value = (
    local.is_aws   ? aws_route53_zone.this[0].zone_id :
    local.is_gcp   ? google_dns_managed_zone.this[0].id :
    local.is_azure ? azurerm_dns_zone.this[0].id :
    null
  )
  description = "Идентификатор зоны в провайдере."
}

output "name_servers" {
  value = (
    local.is_aws   ? aws_route53_zone.this[0].name_servers :
    local.is_gcp   ? google_dns_managed_zone.this[0].name_servers :
    local.is_azure ? azurerm_dns_zone.this[0].name_servers :
    []
  )
  description = "Список NS-серверов зоны."
}

output "zone_fqdn" {
  value       = local.zone_fqdn
  description = "FQDN зоны (без финальной точки)."
}
