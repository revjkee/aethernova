terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.30"
    }
  }
}

############################
# ВХОДНЫЕ ПАРАМЕТРЫ
############################

variable "name" {
  description = "Базовое имя ресурсов модуля (префикс)."
  type        = string
  validation {
    condition     = length(var.name) >= 3 && length(var.name) <= 40
    error_message = "name должен быть от 3 до 40 символов."
  }
}

variable "tags" {
  description = "Общие теги для всех ресурсов."
  type        = map(string)
  default     = {}
}

variable "target_tag_key" {
  description = "Ключ тега, по которому SSM будет выбирать целевые EC2 инстансы."
  type        = string
  validation {
    condition     = length(var.target_tag_key) > 0
    error_message = "target_tag_key не может быть пустым."
  }
}

variable "target_tag_value" {
  description = "Значение тега, по которому SSM будет выбирать целевые EC2 инстансы."
  type        = string
  validation {
    condition     = length(var.target_tag_value) > 0
    error_message = "target_tag_value не может быть пустым."
  }
}

variable "peers" {
  description = "Список NTP-пиров (например, внутренние референсные серверы)."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for p in var.peers : length(trim(p)) > 0])
    error_message = "Каждый элемент peers должен быть непустой строкой."
  }
}

variable "pools" {
  description = "Список NTP-пулов (внешние или организационные пулы)."
  type        = list(string)
  default     = ["pool.ntp.org"]
  validation {
    condition     = length(var.pools) > 0
    error_message = "Нужен хотя бы один pool."
  }
}

variable "allow_ingress_cidrs" {
  description = "Список CIDR, которым разрешен вход по UDP/123 на хосты (создаст SG). Пустой список — SG не создается."
  type        = list(string)
  default     = []
}

variable "chrony_makestep" {
  description = "Параметры chrony makestep (начальная коррекция времени). Формат: 'makestep <threshold> <limit>'."
  type        = string
  default     = "makestep 1.0 3"
}

variable "chrony_rtcsync" {
  description = "Включить синхронизацию RTC (rtcsync)."
  type        = bool
  default     = true
}

variable "chrony_logdir" {
  description = "Каталог логов chrony."
  type        = string
  default     = "/var/log/chrony"
}

variable "chrony_driftfile" {
  description = "Путь к drift-файлу chrony."
  type        = string
  default     = "/var/lib/chrony/drift"
}

variable "ssm_schedule_expression" {
  description = "Расписание SSM Association (CloudWatch Events rate/cron). Пример: 'rate(1 hour)'."
  type        = string
  default     = "rate(6 hours)"
}

variable "enable_chrony_server" {
  description = "Если true — хосты будут слушать входящие NTP-запросы (server mode). Иначе — только клиент."
  type        = bool
  default     = false
}

############################
# ЛОКАЛЫ
############################

locals {
  module_tags = merge(
    {
      "managed-by" = "terraform"
      "module"     = "ntp_peers"
      "component"  = var.name
    },
    var.tags
  )

  chrony_peers_lines = [
    for p in var.peers : "server ${p} iburst"
  ]

  chrony_pools_lines = [
    for p in var.pools : "pool ${p} iburst"
  ]

  chrony_allow_lines = var.enable_chrony_server ? ["allow 0.0.0.0/0"] : []

  chrony_conf_template = trimspace(join("\n", concat(
    [
      "# Managed by Terraform via AWS SSM",
      "driftfile ${var.chrony_driftfile}",
      var.chrony_rtcsync ? "rtcsync" : "# rtcsync disabled",
      var.chrony_makestep,
      "logdir ${var.chrony_logdir}",
      "leapsectz right/UTC"
    ],
    local.chrony_peers_lines,
    local.chrony_pools_lines,
    local.chrony_allow_lines,
    [
      "",
      "# NTP access control and options",
      "bindcmdaddress 127.0.0.1",
      "bindcmdaddress ::1",
      "cmdport 0"
    ]
  )))
}

############################
# SECURITY GROUP (опционально)
############################

resource "aws_security_group" "ntp" {
  count       = length(var.allow_ingress_cidrs) > 0 ? 1 : 0
  name        = "${var.name}-ntp-sg"
  description = "NTP UDP/123 ingress for ${var.name}"
  vpc_id      = data.aws_vpc.selected.id
  tags        = local.module_tags

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "ntp_udp" {
  for_each          = { for idx, cidr in var.allow_ingress_cidrs : idx => cidr }
  security_group_id = aws_security_group.ntp[0].id
  ip_protocol       = "udp"
  from_port         = 123
  to_port           = 123
  cidr_ipv4         = each.value
  description       = "Allow NTP from ${each.value}"
}

############################
# DATA: текущий VPC по умолчанию (или переопределите в родительском модуле)
############################

data "aws_vpc" "selected" {
  default = true
}

############################
# SSM DOCUMENT (установка и настройка chrony)
############################

resource "aws_ssm_document" "chrony_config" {
  name          = "${var.name}-chrony-config"
  document_type = "Command"
  tags          = local.module_tags

  content = yamlencode({
    schemaVersion = "2.2"
    description   = "Install & configure chrony with organization peers/pools (managed by Terraform)."
    mainSteps = [
      {
        action      = "aws:runShellScript"
        name        = "installAndConfigureChrony"
        onFailure   = "Abort"
        inputs = {
          timeoutSeconds = "1200"
          runCommand = [
            # Detect distro and install chrony
            "set -euo pipefail",
            "OS_ID=$(. /etc/os-release && echo \"$ID\")",
            "echo \"Detected OS: ${OS_ID}\"",
            "if command -v chronyd >/dev/null 2>&1; then echo 'chrony already installed'; else",
            "  case \"$OS_ID\" in",
            "    amzn|rhel|centos|rocky|almalinux) sudo yum -y install chrony ;;",
            "    debian|ubuntu) sudo apt-get update -y && sudo apt-get install -y chrony ;;",
            "    *) echo \"Unsupported distro: $OS_ID\" >&2; exit 1 ;;",
            "  esac",
            "fi",

            # Write configuration
            "sudo mkdir -p $(dirname /etc/chrony.conf)",
            "sudo tee /etc/chrony.conf >/dev/null <<'EOF_CHRONY'",
            local.chrony_conf_template,
            "EOF_CHRONY",

            # Enable server mode if requested (iptables/nftables responsibility left to SG/VPC)
            "sudo systemctl enable chronyd || sudo systemctl enable chrony || true",
            "sudo systemctl restart chronyd || sudo systemctl restart chrony",

            # Show status for diagnostics
            "sleep 2",
            "chronyc tracking || true",
            "chronyc sources -v || true"
          ]
        }
      }
    ]
  })
}

############################
# SSM ASSOCIATION (применение к целевым инстансам)
############################

resource "aws_ssm_association" "chrony_apply" {
  name = aws_ssm_document.chrony_config.name

  schedule_expression = var.ssm_schedule_expression

  targets = [
    {
      key    = "tag:${var.target_tag_key}"
      values = [var.target_tag_value]
    }
  ]

  compliance_severity = "MEDIUM"

  output_location {
    s3_bucket_name = null
  }

  # Теги не поддерживаются напрямую, добавляем через depends_on для порядка
  depends_on = [aws_ssm_document.chrony_config]
}

############################
# ВЫВОДЫ
############################

output "ssm_document_name" {
  description = "Имя SSM документа для конфигурации chrony."
  value       = aws_ssm_document.chrony_config.name
}

output "ssm_association_id" {
  description = "ID ассоциации SSM для применения конфигурации."
  value       = aws_ssm_association.chrony_apply.id
}

output "ntp_security_group_id" {
  description = "ID Security Group с разрешением UDP/123 (если создан)."
  value       = length(var.allow_ingress_cidrs) > 0 ? aws_security_group.ntp[0].id : null
}

output "rendered_chrony_conf" {
  description = "Сгенерированный конфиг chrony для аудита."
  value       = local.chrony_conf_template
  sensitive   = false
}
