########################################################################
# aethernova-chain-core/ops/terraform/modules/backups/velero/variables.tf
########################################################################

############################
# Метаданные Helm/Release
############################
variable "namespace" {
  type        = string
  description = "Namespace для установки Velero (обычно 'velero')."
  default     = "velero"
}

variable "helm_chart" {
  description = <<-EOT
    Параметры Helm-чарта Velero:
      - repository: официальный репозиторий Helm (напр. https://vmware-tanzu.github.io/helm-charts)
      - chart: имя чарта (обычно 'velero')
      - version: версия чарта (строка semver)
  EOT
  type = object({
    repository = string
    chart      = string
    version    = string
  })
  default = {
    repository = "https://vmware-tanzu.github.io/helm-charts"
    chart      = "velero"
    version    = ">=2.0.0" # зафиксируйте на вашей версии чартов
  }
}

variable "create_namespace" {
  type        = bool
  description = "Создавать namespace при установке Helm."
  default     = true
}

variable "helm_values_extra" {
  type        = list(string)
  description = "Сырой YAML для дополнительных значений Helm (передаётся списком строк)."
  default     = []
}

############################
# Базовая конфигурация Velero
############################
variable "provider" {
  type        = string
  description = <<-EOT
    Провайдер object storage / снапшотов:
      - aws
      - azure
      - gcp
      - s3 (для S3-совместимых стореджей, например MinIO/Backblaze и т.п.)
  EOT
  validation {
    condition     = contains(["aws","azure","gcp","s3"], var.provider)
    error_message = "provider должен быть одним из: aws | azure | gcp | s3."
  }
}

variable "features" {
  type        = list(string)
  description = <<-EOT
    Список флагов функций Velero (например, EnableCSI).
    См. документацию Velero про CSI и feature flags.
  EOT
  default = []
}

############################
# Креденшалы/секреты
############################
variable "credentials" {
  description = <<-EOT
    Управление секретом с облачными ключами:
      - use_existing_secret: true → использовать существующий секрет.
      - existing_secret_name: имя секрета (обычно 'cloud-credentials').
      - cloud_credentials: содержимое файла с креденшалами (ключ 'cloud'), если секрет создаёт Helm chart.
        В Helm values это попадает в credentials.secretContents.cloud.
  EOT
  type = object({
    use_existing_secret  = optional(bool, false)
    existing_secret_name = optional(string, "cloud-credentials")
    cloud_credentials    = optional(string) # содержимое файла credentials-velero
  })
  default = {}

  validation {
    condition = (
      (try(var.credentials.use_existing_secret, false) == true && try(var.credentials.existing_secret_name, "") != "")
      ||
      (try(var.credentials.use_existing_secret, false) == false && try(var.credentials.cloud_credentials, null) != null)
    )
    error_message = "Либо укажите существующий секрет (use_existing_secret=true), либо передайте credentials.cloud_credentials."
  }
}

############################
# Backup Storage Location (BSL)
############################
variable "backup_storage_locations" {
  description = <<-EOT
    Список BackupStorageLocation (BSL), соответствующих CRD Velero:
      - name: имя BSL
      - bucket: имя бакета/контейнера
      - prefix: префикс внутри бакета (опционально)
      - provider: aws|azure|gcp|s3
      - default: пометить ли данный BSL как default
      - access_mode: ReadWrite|ReadOnly
      - ca_cert: PEM CA (для кастомных endpoint'ов), строка (опционально)
      - config: map провайдер-специфичных ключей (например, region, s3Url/publicUrl, resourceGroup/storageAccount и т.п.)
      - credential: опциональная ссылка на секрет (name/key), если нужно переопределить cloud-credentials
  EOT
  type = list(object({
    name        = string
    bucket      = string
    prefix      = optional(string)
    provider    = string
    default     = optional(bool, false)
    access_mode = optional(string, "ReadWrite")
    ca_cert     = optional(string)
    config      = optional(map(string), {})
    credential  = optional(object({
      name = string
      key  = string
    }))
  }))
  default = []

  validation {
    condition = length(var.backup_storage_locations) > 0
    error_message = "Должен быть задан хотя бы один backup_storage_locations."
  }
}

############################
# Volume Snapshot Location (VSL)
############################
variable "volume_snapshot_locations" {
  description = <<-EOT
    Список VolumeSnapshotLocation (VSL), соответствующих CRD Velero:
      - name: имя VSL
      - provider: aws|azure|gcp|csi
      - config: map провайдер-специфичных ключей (например, region, snapshotLocation, resourceGroup и т.п.)
  EOT
  type = list(object({
    name     = string
    provider = string
    config   = optional(map(string), {})
  }))
  default = []
}

############################
# CSI / File System Backup (Node Agent)
############################
variable "csi" {
  description = <<-EOT
    Настройки поддержки CSI snapshot'ов:
      - enabled: включает интеграцию с CSI (требуется feature flag EnableCSI и плагин velero-plugin-for-csi).
      - data_mover: "", "velero" или альтернативный (если используется поддерживаемый data mover).
  EOT
  type = object({
    enabled    = optional(bool, false)
    data_mover = optional(string, "")
  })
  default = {}
}

variable "file_system_backup" {
  description = <<-EOT
    Настройки File System Backup (FSB) / Node Agent:
      - enabled: включает Node Agent/FSB
      - opt_in: если true — использовать только для помеченных PVC/Pod; если false — поведение по умолчанию chart'а
  EOT
  type = object({
    enabled = optional(bool, false)
    opt_in  = optional(bool, true)
  })
  default = {}
}

############################
# Плагины (initContainers/плагины провайдера)
############################
variable "plugins" {
  description = <<-EOT
    Контейнеры плагинов (объект-хелпер):
      - aws_image: репозиторий/тег AWS plugin (например, velero/velero-plugin-for-aws:<tag>)
      - azure_image: аналогично для Azure
      - gcp_image: аналогично для GCP
      - csi_image: velero/velero-plugin-for-csi:<tag>
      - extra_init_containers: список дополнительных initContainers (как YAML-строки либо map)
  EOT
  type = object({
    aws_image             = optional(string)
    azure_image           = optional(string)
    gcp_image             = optional(string)
    csi_image             = optional(string)
    extra_init_containers = optional(list(map(any)), [])
  })
  default = {}
}

############################
# Расписания бэкапов (Schedule CR)
############################
variable "schedules" {
  description = <<-EOT
    Список CR Schedule:
      - name: имя расписания
      - cron: выражение cron
      - ttl: срок хранения (Go duration, например '24h0m0s'; default у Velero — 30 дней)
      - include_namespaces / exclude_namespaces: списки ns
      - include_resources / exclude_resources: списки ресурсов
      - label_selector: map для селектора
      - default_volumes_to_fs_backup: bool — использовать FSB для всех томов по умолчанию
      - snapshot_move_data: bool — перемещать данные для CSI снапшотов
      - datamover: строка (напр., "velero") — выбор data mover (если поддерживается)
      - storage_location: имя BSL
      - volume_snapshot_locations: список имён VSL
  EOT
  type = list(object({
    name                         = string
    cron                         = string
    ttl                          = optional(string, "720h0m0s")
    include_namespaces           = optional(list(string), [])
    exclude_namespaces           = optional(list(string), [])
    include_resources            = optional(list(string), [])
    exclude_resources            = optional(list(string), [])
    label_selector               = optional(map(string), {})
    default_volumes_to_fs_backup = optional(bool, false)
    snapshot_move_data           = optional(bool, false)
    datamover                    = optional(string, "")
    storage_location             = optional(string)
    volume_snapshot_locations    = optional(list(string), [])
  }))
  default = []
}

############################
# Сервисные параметры (опционально)
############################
variable "service_account" {
  description = "Имя и аннотации ServiceAccount для Velero."
  type = object({
    name        = optional(string)
    annotations = optional(map(string), {})
  })
  default = {}
}

variable "pod_affinity" {
  type        = map(any)
  description = "Правила (анти)аффинности Pod (как map, если пробрасываете в Helm values)."
  default     = {}
}

variable "node_selector" {
  type        = map(string)
  description = "NodeSelector для Velero/Node Agent."
  default     = {}
}

variable "tolerations" {
  type        = list(map(string))
  description = "Список tolerations."
  default     = []
}

variable "priority_class_name" {
  type        = string
  description = "PriorityClassName для подов Velero."
  default     = ""
}

############################
# Мониторинг/метрики
############################
variable "servicemonitor" {
  description = "Создавать ServiceMonitor для Prometheus Operator."
  type = object({
    enabled = optional(bool, false)
    labels  = optional(map(string), {})
  })
  default = {}
}

############################
# Безопасность/PSP (если применимо к вашему кластера/политикам)
############################
variable "pod_security_context" {
  type        = map(any)
  description = "podSecurityContext (map для проброса в Helm values)."
  default     = {}
}

variable "container_security_context" {
  type        = map(any)
  description = "securityContext контейнера (map для проброса в Helm values)."
  default     = {}
}

############################
# Валидации
############################
# Проверка BSL: bucket и provider обязательны
validation {
  condition = alltrue([
    for b in var.backup_storage_locations :
    (length(b.bucket) > 0 && contains(["aws","azure","gcp","s3"], b.provider))
  ])
  error_message = "Для каждого backup_storage_locations требуется bucket и provider ∈ {aws,azure,gcp,s3}."
}

# access_mode только ReadWrite или ReadOnly
validation {
  condition = alltrue([
    for b in var.backup_storage_locations :
    contains(["ReadWrite","ReadOnly"], try(b.access_mode, "ReadWrite"))
  ])
  error_message = "backup_storage_locations[*].access_mode должен быть ReadWrite или ReadOnly."
}

# Если включён CSI — рекомендуется добавить флаг EnableCSI или указать в features
validation {
  condition = (
    try(var.csi.enabled, false) == false
    || contains(var.features, "EnableCSI")
  )
  error_message = "При csi.enabled=true рекомендуется установить feature-флаг EnableCSI (features содержит 'EnableCSI')."
}
