#######################################################################
# aethernova-chain-core/ops/terraform/modules/storage/postgres/variables.tf
#
# Проверяемые источники (основные):
# - Terraform variables & validation:
#   https://developer.hashicorp.com/terraform/language/values/variables
#   https://www.hashicorp.com/en/blog/terraform-1-9-enhances-input-variable-validations
# - AWS RDS PostgreSQL (ресурсы и параметры):
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster
#   Multi-AZ (обзор и типы): https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html
#   Backup retention диапазон: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.BackupRetention.html
#   Автобоевой бэкап/PI TR: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html
#   Типы/минимумы хранилища (20 GiB GP2/GP3): https://aws.amazon.com/rds/postgresql/pricing/
#   Storage autoscaling: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIOPS.Autoscaling.html
# - Azure PostgreSQL Flexible Server:
#   https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_flexible_server
#   Storage min 32 GiB, поведение autogrow/лимиты: https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-storage
#   Общие лимиты/поведение: https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-limits
# - GCP Cloud SQL for PostgreSQL:
#   https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance
#   Обзор создания/настроек инстанса: https://cloud.google.com/sql/docs/postgres/create-instance
#   Квоты/лимиты хранения: https://cloud.google.com/sql/docs/postgres/quotas
#######################################################################

############################
# Общие метаданные/теги
############################
variable "name" {
  type        = string
  description = "Базовый префикс имени ресурсов БД (используется в именах и тегах)."
}

variable "environment" {
  type        = string
  description = "Идентификатор окружения (prod/stage/dev и т.п.)."
  default     = "prod"
}

variable "tags" {
  type        = map(string)
  description = "Глобальные теги для создаваемых ресурсов."
  default     = {}
}

##########################################
# Выбор провайдера/модели развертывания
##########################################
variable "engine_provider" {
  type        = string
  description = <<-EOT
    Облачный провайдер/модель PostgreSQL:
      - "aws_rds"      — Amazon RDS for PostgreSQL (инстанс) [см. aws_db_instance]
      - "aws_aurora"   — Amazon Aurora PostgreSQL (кластер) [см. aws_rds_cluster]
      - "azure_flexible" — Azure Database for PostgreSQL Flexible Server
      - "gcp_cloudsql" — Google Cloud SQL for PostgreSQL
    EOT
  validation {
    condition     = contains(["aws_rds", "aws_aurora", "azure_flexible", "gcp_cloudsql"], var.engine_provider)
    error_message = "engine_provider должен быть одним из: aws_rds, aws_aurora, azure_flexible, gcp_cloudsql."
  }
}

variable "postgres_version" {
  type        = string
  description = "Версия PostgreSQL (например, '16', '15'). Должна соответствовать поддерживаемой версии у выбранного провайдера."
  default     = "16"
}

##########################################
# Профиль вычислительных ресурсов по провайдеру
##########################################
variable "compute" {
  description = <<-EOT
    Профиль вычислительных ресурсов для целевого провайдера.
    - AWS RDS/Aurora: instance_class (например, 'db.r6g.large'), performance_insights_enabled (bool)
    - Azure Flexible: sku_name (например, 'Standard_D4s_v5')
    - GCP Cloud SQL: tier (например, 'db-custom-4-16384' для 4 vCPU, 16 GiB RAM)
  EOT
  type = object({
    # AWS
    instance_class              = optional(string)
    performance_insights_enabled = optional(bool, false)

    # Azure
    sku_name = optional(string)

    # GCP
    tier = optional(string)
  })
  default = {}
}

##########################################
# Хранилище и производительность
##########################################
variable "storage" {
  description = <<-EOT
    Параметры хранилища/IOPS.
    ВАЖНО:
    - AWS RDS/GP2/GP3: минимум 20 GiB (см. Pricing page). Storage autoscaling доступен (см. docs).
    - Azure Flexible: минимум 32 GiB (32768 MB), autogrow доступен (см. docs).
    - GCP Cloud SQL: лимиты зависят от конфигурации, квоты описаны в официальной документации.
  EOT
  type = object({
    size_gib     = number                       # Запрошенный размер, GiB.
    type         = optional(string, "gp3")      # "gp3"|"io1"|Azure: "Premium_SSD_v2"|GCP: "PD_SSD"/"HYPERDISK_BALANCED" и т.д.
    iops         = optional(number)             # Необязательно; имеет смысл для AWS gp3/io1 и GCP Hyperdisk.
    throughput_mb = optional(number)            # Пропускная способность (для дисков, где доступно).
    autoscaling  = optional(bool, true)         # Включить авторасширение хранения (если поддерживается провайдером).
    max_size_gib = optional(number)             # Порог авторасширения (если поддерживается).
  })
}

# Провайдер-специфичные проверки объема хранилища
# AWS: минимум 20 GiB для General Purpose SSD (GP2/GP3) — pricing/доки RDS
validation {
  condition = (
    var.engine_provider != "aws_rds" && var.engine_provider != "aws_aurora"
    || var.storage.size_gib >= 20
  )
  error_message = "Для AWS RDS/Aurora минимальный размер General Purpose SSD — 20 GiB."
}

# Azure Flexible: минимум 32 GiB (32768 MB)
validation {
  condition = (
    var.engine_provider != "azure_flexible"
    || var.storage.size_gib >= 32
  )
  error_message = "Для Azure PostgreSQL Flexible минимальный размер хранилища — 32 GiB."
}

##########################################
# Доступность/HA
##########################################
variable "high_availability" {
  description = <<-EOT
    Высокая доступность:
    - AWS RDS: multi_az=true для standby в другой AZ (см. Multi-AZ instance).
    - AWS Aurora: кластер HA по AZ, опционально reader(s).
    - Azure Flexible: mode = "ZoneRedundant" или "SameZone".
    - GCP Cloud SQL: availability_type = "REGIONAL" или "ZONAL".
  EOT
  type = object({
    enabled           = optional(bool, true)
    # AWS
    multi_az          = optional(bool)       # RDS instance Multi-AZ (standby в другой AZ)
    # Azure
    mode              = optional(string)     # "ZoneRedundant"|"SameZone"
    # GCP
    availability_type = optional(string)     # "REGIONAL"|"ZONAL"
  })
  default = {}
}

##########################################
# Бэкап/восстановление (PITR)
##########################################
variable "backup" {
  description = <<-EOT
    Настройки бэкапа:
    - AWS: backup_retention_days от 0 до 35 (0 отключает для DB instance; для Multi-AZ DB cluster — 1..35).
    - Azure/GCP: использовать допустимые диапазоны/окна провайдера.
  EOT
  type = object({
    retention_days            = number            # Диапазон зависит от провайдера (ниже валидации).
    preferred_backup_window   = optional(string)  # Формат окна по требованиям провайдера.
    delete_automated_backups  = optional(bool, false) # AWS-специфика при удалении инстанса.
    pitr_enabled              = optional(bool, true)
  })
}

# Валидация для AWS DB instance/Aurora: 0..35 (для DB instance допустим 0, для Multi-AZ DB cluster — 1..35)
validation {
  condition = (
    var.engine_provider != "aws_rds"
    || (var.backup.retention_days >= 0 && var.backup.retention_days <= 35)
  )
  error_message = "AWS RDS: backup_retention_days должен быть в диапазоне 0..35 (0 отключает автоматические бэкапы)."
}

validation {
  condition = (
    var.engine_provider != "aws_aurora"
    || (var.backup.retention_days >= 1 && var.backup.retention_days <= 35)
  )
  error_message = "AWS Aurora (Multi-AZ DB cluster): backup_retention_days должен быть 1..35."
}

##########################################
# Окно обслуживания/плановые работы
##########################################
variable "maintenance" {
  type = object({
    preferred_maintenance_window = optional(string) # Формат зависит от провайдера (строка)
    auto_minor_version_upgrade   = optional(bool, true)
  })
  default = {}
}

##########################################
# Шифрование и ключи (KMS/CMK)
##########################################
variable "encryption" {
  description = "Шифрование хранения и настройки KMS/CMK."
  type = object({
    enabled         = optional(bool, true)
    kms_key_id      = optional(string)  # AWS KMS Key ARN
    cmk_resource_id = optional(string)  # Azure Key Vault CMK / GCP CMEK Resource ID
  })
  default = {}
}

##########################################
# Сеть и доступ
##########################################
variable "network" {
  description = <<-EOT
    Сетевые параметры:
    - AWS: vpc_security_group_ids, subnet_group_name
    - Azure: delegated_subnet_id (обязателен для приватного Flexible Server), private_dns_zone_id (необязательно)
    - GCP: authorized_networks (список CIDR)
  EOT
  type = object({
    # AWS
    vpc_security_group_ids = optional(list(string), [])
    subnet_group_name      = optional(string)

    # Azure
    delegated_subnet_id = optional(string)
    private_dns_zone_id = optional(string)

    # GCP
    authorized_networks = optional(list(string), [])
  })
  default = {}
}

##########################################
# Журналы/аудит
##########################################
variable "logs" {
  description = <<-EOT
    Экспорт логов:
    - AWS: log_exports (например, ['postgresql','upgrade','slowquery'])
    - Azure/GCP: включение категорий телеметрии в соответствии с возможностями провайдера
  EOT
  type = object({
    enabled     = optional(bool, true)
    categories  = optional(list(string), [])
  })
  default = {}
}

##########################################
# Пользователи/секреты
##########################################
variable "admin_username" {
  type        = string
  description = "Имя администратора БД (postgres/svc_user и т.п.)."
  default     = "postgres"
}

variable "admin_password" {
  type        = string
  description = "Пароль администратора БД (если не используется внешний Secret Manager/Key Vault)."
  sensitive   = true
  default     = null
}

variable "manage_admin_secret" {
  type        = bool
  description = "Создавать и хранить секрет администратора во внешнем секрет-хранилище (AWS Secrets Manager/Azure Key Vault/GCP Secret Manager) на уровне модуля."
  default     = true
}

variable "users" {
  description = <<-EOT
    Дополнительные пользователи БД.
    Поля:
      - name (string)
      - password (string, опционально; если null и manage_admin_secret=true — может быть сгенерирован во внешнем секрет-хранилище)
      - roles (список ролей, например, ['CREATEDB','CREATEROLE'])
  EOT
  type = list(object({
    name     = string
    password = optional(string)
    roles    = optional(list(string), [])
  }))
  default = []
}

##########################################
# Защита от удаления/снапшоты
##########################################
variable "deletion_protection" {
  type        = bool
  description = "Включить защиту от удаления (если поддерживается провайдером)."
  default     = true
}

variable "final_snapshot_identifier" {
  type        = string
  description = "Идентификатор финального снапшота при удалении (если поддерживается)."
  default     = null
}

##########################################
# Дополнительные проверки целостности ввода
##########################################

# Если включен HA, требуем хотя бы один из механизмов, допустимых для провайдера
validation {
  condition = (
    try(var.high_availability.enabled, true) == false
    || (
      (var.engine_provider == "aws_rds"     && try(var.high_availability.multi_az, false) == true) ||
      (var.engine_provider == "aws_aurora"  && try(var.high_availability.enabled, false) == true)  ||
      (var.engine_provider == "azure_flexible" && contains(["ZoneRedundant","SameZone"], try(var.high_availability.mode, "ZoneRedundant"))) ||
      (var.engine_provider == "gcp_cloudsql" && contains(["REGIONAL","ZONAL"], try(var.high_availability.availability_type, "REGIONAL")))
    )
  )
  error_message = "Запрошен HA, но для выбранного провайдера не указана корректная схема HA (multi_az/mode/availability_type)."
}

# Базовый sanity-check для размера хранилища
validation {
  condition     = var.storage.size_gib > 0
  error_message = "storage.size_gib должен быть > 0."
}

# Для AWS autoscaling указываем верхний порог, если autoscaling=true
validation {
  condition = (
    try(var.storage.autoscaling, false) == false
    || try(var.storage.max_size_gib, 0) >= var.storage.size_gib
  )
  error_message = "При включенном autoscaling требуется max_size_gib >= size_gib."
}
