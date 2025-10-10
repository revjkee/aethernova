############################################
# modules/networking/peering-and-endpoints/variables.tf
#
# Источники (проверяемые):
# - VPC Peering: AWS Docs
#   https://docs.aws.amazon.com/vpc/latest/peering/what-is-vpc-peering.html
#   https://docs.aws.amazon.com/vpc/latest/peering/modify-peering-connections.html
# - Terraform VPC Peering:
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_peering_connection
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_peering_connection_options
# - VPC Endpoints: AWS Docs
#   https://docs.aws.amazon.com/vpc/latest/privatelink/what-is-privatelink.html
#   https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints.html
#   (Gateway endpoints S3/DynamoDB)
#   https://docs.aws.amazon.com/vpc/latest/privatelink/gateway-endpoints.html
#   (Interface endpoints & Private DNS)
#   https://docs.aws.amazon.com/vpc/latest/privatelink/manage-dns-names.html
#   (Endpoint policy)
#   https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html
# - Terraform VPC Endpoint:
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint_subnet_association
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint_route_table_association
# - Маршрутизация (Route Tables): AWS Docs
#   https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html
############################################

########################################################
# Базовые метаданные/теги
########################################################
variable "name" {
  type        = string
  description = "Базовый префикс имени для ресурсов (используется в тегах Name)."
  default     = "aethernova-core"
}

variable "tags" {
  type        = map(string)
  description = "Глобальные теги, применяемые ко всем создаваемым ресурсам."
  default     = {}
}

########################################################
# Контекст VPC (локальная сторона)
# Требуется для пира и для привязки VPC Endpoint-ов.
########################################################
variable "vpc_id" {
  type        = string
  description = "ID локальной VPC, в которой создаются endpoints и с которой инициируется peering."
}

variable "vpc_cidr_block" {
  type        = string
  description = "IPv4 CIDR локальной VPC. Используется для валидации маршрутов при peering и gateway endpoints."
}

variable "private_route_table_ids" {
  type        = list(string)
  description = "Список Route Table IDs для приватных подсетей (используются для маршрутов к пиру и gateway endpoints)."
  default     = []
}

variable "public_route_table_ids" {
  type        = list(string)
  description = "Список Route Table IDs для публичных подсетей (обычно маршруты к пиру могут не требоваться, но оставлено как опция)."
  default     = []
}

variable "additional_route_table_ids" {
  type        = list(string)
  description = "Дополнительные Route Table IDs (NAT/выделенные RT), куда тоже нужно прописать маршруты к пиру и/или ассоциации для gateway endpoints."
  default     = []
}

########################################################
# Пиринг VPC (VPC Peering)
# См. AWS Docs + Terraform (ссылки выше).
########################################################
variable "create_peering" {
  type        = bool
  description = "Создавать ли VPC Peering между локальной VPC и удалённой VPC."
  default     = false
}

variable "peer_vpc_id" {
  type        = string
  description = "ID удалённой VPC (peer). Обязательно, если create_peering = true."
  default     = null
}

variable "peer_owner_id" {
  type        = string
  description = "AWS Account ID владельца удалённой VPC. Нужен при межаккаунтном пирах."
  default     = null
}

variable "peer_region" {
  type        = string
  description = "Регион удалённой VPC (для межрегионного пира). Оставьте null для внутригRegion-ого пира."
  default     = null
}

variable "peer_cidr_blocks" {
  type        = list(string)
  description = "Список IPv4 CIDR удалённой VPC (и/или дополнительных подсетей), для которых будут созданы маршруты."
  default     = []
}

variable "auto_accept" {
  type        = bool
  description = "Автоматически принимать пировое соединение (доступно для внутри-аккаунтных/часть сценариев). Terraform aws_vpc_peering_connection: auto_accept."
  default     = false
}

variable "requester_allow_remote_vpc_dns_resolution" {
  type        = bool
  description = "Разрешить ли resolution Private Hosted Zones между VPC со стороны requester (см. aws_vpc_peering_connection_options)."
  default     = true
}

variable "accepter_allow_remote_vpc_dns_resolution" {
  type        = bool
  description = "Разрешить ли resolution Private Hosted Zones между VPC со стороны accepter (см. aws_vpc_peering_connection_options)."
  default     = true
}

variable "manage_peering_routes" {
  type        = bool
  description = "Если true, модуль создаёт маршруты к peer_cidr_blocks во все указанные route tables."
  default     = true
}

variable "apply_routes_to_public" {
  type        = bool
  description = "Добавлять ли маршруты к пиру в public_route_table_ids (обычно не требуется, но оставлено как опция)."
  default     = false
}

variable "apply_routes_to_private" {
  type        = bool
  description = "Добавлять ли маршруты к пиру в private_route_table_ids."
  default     = true
}

variable "apply_routes_to_additional" {
  type        = bool
  description = "Добавлять ли маршруты к пиру в additional_route_table_ids."
  default     = true
}

########################################################
# VPC Endpoints — Gateway (S3/DynamoDB)
# См. AWS Docs по gateway endpoints и Terraform aws_vpc_endpoint.
########################################################
variable "enable_gateway_endpoints" {
  type        = bool
  description = "Создавать ли gateway endpoints (S3/DynamoDB)."
  default     = true
}

variable "gateway_endpoints" {
  description = <<-EOT
  Карта gateway endpoints:
  Ключ — логическое имя, значение — объект с настройками:
    {
      service_name          = string   # 's3' или 'dynamodb' (Gateway endpoints доступны только для этих сервисов в AWS)
      route_table_ids       = list(string) # RTs для ассоциации (обычно приватные и/или дополнительные)
      policy                = string   # JSON-политика (null для политики по умолчанию)
      tags                  = map(string)
    }
  См. AWS: gateway-endpoints и Terraform aws_vpc_endpoint (vpc_endpoint_type='Gateway').
  EOT
  type = map(object({
    service_name    = string
    route_table_ids = list(string)
    policy          = string
    tags            = map(string)
  }))
  default = {
    s3 = {
      service_name    = "s3"
      route_table_ids = []
      policy          = null
      tags            = {}
    }
    dynamodb = {
      service_name    = "dynamodb"
      route_table_ids = []
      policy          = null
      tags            = {}
    }
  }

########################################################
# VPC Endpoints — Interface (AWS PrivateLink)
# См. AWS Docs по Interface Endpoints и Terraform aws_vpc_endpoint.
########################################################
variable "enable_interface_endpoints" {
  type        = bool
  description = "Создавать ли interface endpoints (PrivateLink)."
  default     = true
}

variable "interface_endpoints" {
  description = <<-EOT
  Карта interface endpoints:
  Ключ — логическое имя, значение — объект:
    {
      service_name          = string          # например, "com.amazonaws.eu-central-1.ecr.api"
      subnet_ids            = list(string)    # приватные сабсети, где будут ENI endpoints
      security_group_ids    = list(string)    # SG для ENI
      private_dns_enabled   = bool            # вкл/выкл Private DNS (см. AWS Docs)
      policy                = string          # JSON-политика endpoint'а (опционально)
      tags                  = map(string)
    }
  Внимание: для некоторых сервисов Private DNS требует включённый private_dns_enabled и корректные Route53 разрешения (см. 'manage-dns-names').
  EOT
  type = map(object({
    service_name        = string
    subnet_ids          = list(string)
    security_group_ids  = list(string)
    private_dns_enabled = bool
    policy              = string
    tags                = map(string)
  }))
  default = {
    # Примеры часто используемых сервисов (имена сервисов зависят от региона):
    # Значения по умолчанию оставлены пустыми/нейтральными — заполняйте в корневом примере.
    ecr_api = {
      service_name        = "com.amazonaws.eu-central-1.ecr.api"
      subnet_ids          = []
      security_group_ids  = []
      private_dns_enabled = true
      policy              = null
      tags                = {}
    }
    ecr_dkr = {
      service_name        = "com.amazonaws.eu-central-1.ecr.dkr"
      subnet_ids          = []
      security_group_ids  = []
      private_dns_enabled = true
      policy              = null
      tags                = {}
    }
    logs = {
      service_name        = "com.amazonaws.eu-central-1.logs"
      subnet_ids          = []
      security_group_ids  = []
      private_dns_enabled = true
      policy              = null
      tags                = {}
    }
    ssm = {
      service_name        = "com.amazonaws.eu-central-1.ssm"
      subnet_ids          = []
      security_group_ids  = []
      private_dns_enabled = true
      policy              = null
      tags                = {}
    }
    ssmmessages = {
      service_name        = "com.amazonaws.eu-central-1.ssmmessages"
      subnet_ids          = []
      security_group_ids  = []
      private_dns_enabled = true
      policy              = null
      tags                = {}
    }
    ec2messages = {
      service_name        = "com.amazonaws.eu-central-1.ec2messages"
      subnet_ids          = []
      security_group_ids  = []
      private_dns_enabled = true
      policy              = null
      tags                = {}
    }
    monitoring = {
      service_name        = "com.amazonaws.eu-central-1.monitoring"
      subnet_ids          = []
      security_group_ids  = []
      private_dns_enabled = true
      policy              = null
      tags                = {}
    }
    sts = {
      service_name        = "com.amazonaws.eu-central-1.sts"
      subnet_ids          = []
      security_group_ids  = []
      private_dns_enabled = true
      policy              = null
      tags                = {}
    }
  }

########################################################
# Дополнительные проверки и флаги
########################################################
variable "fail_if_no_routes_on_peering" {
  type        = bool
  description = "Если true, проваливать план/апплай, если manage_peering_routes=true и не указано ни одной таблицы маршрутов."
  default     = true
}

variable "fail_if_interface_endpoints_without_subnets" {
  type        = bool
  description = "Если true, проваливать план/апплай при enable_interface_endpoints=true, но пустых subnet_ids."
  default     = true
}

variable "fail_if_gateway_endpoints_without_rts" {
  type        = bool
  description = "Если true, проваливать план/апплай при enable_gateway_endpoints=true, но пустых route_table_ids."
  default     = false
}

########################################################
# Валидации (Terraform 1.3+)
########################################################
validation {
  condition = (
    var.create_peering == false
    || (
      var.create_peering == true
      && var.peer_vpc_id != null
      && length(var.peer_cidr_blocks) > 0
    )
  )
  error_message = "Для create_peering=true требуется указать peer_vpc_id и непустой peer_cidr_blocks."
}

validation {
  condition = (
    var.manage_peering_routes == false
    || (
      var.manage_peering_routes == true
      && (
        length(var.private_route_table_ids) > 0
        || length(var.public_route_table_ids) > 0
        || length(var.additional_route_table_ids) > 0
      )
    )
    || var.fail_if_no_routes_on_peering == false
  )
  error_message = "manage_peering_routes=true, но не указаны route table ids (private/public/additional)."
}

validation {
  condition = (
    var.enable_interface_endpoints == false
    || (
      # Все объявленные interface_endpoints должны иметь хотя бы один subnet_id и SG, если включён строгий флаг.
      var.fail_if_interface_endpoints_without_subnets == false
      || alltrue([
        for ep in values(var.interface_endpoints) :
        (length(ep.subnet_ids) > 0 && length(ep.security_group_ids) > 0)
      ])
    )
  )
  error_message = "enable_interface_endpoints=true, но у одного или более endpoints пустые subnet_ids/security_group_ids."
}

validation {
  condition = (
    var.enable_gateway_endpoints == false
    || (
      var.fail_if_gateway_endpoints_without_rts == false
      || alltrue([
        for gep in values(var.gateway_endpoints) :
        length(gep.route_table_ids) > 0
      ])
    )
  )
  error_message = "enable_gateway_endpoints=true, но у одного или более gateway endpoints пустые route_table_ids."
}
