##############################################
# modules/k8s-observability/tempo/variables.tf
##############################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    # Чарт устанавливается обычно через provider "helm" или "kubernetes".
    # Здесь фиксируем лишь примерную версию azurerm/google/aws не требуется.
  }
}

########################################################
# Базовые параметры релиза Helm
########################################################

variable "release_name" {
  description = "Имя релиза Helm для Tempo."
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace для установки Tempo."
  type        = string
  default     = "observability"
}

variable "create_namespace" {
  description = "Создавать ли namespace."
  type        = bool
  default     = true
}

# Имя чарта: tempo (монолит) или tempo-distributed (микросервисы)
# Оба официально поддерживаются Helm-гайдом Tempo. :contentReference[oaicite:3]{index=3}
variable "chart_name" {
  description = "Имя Helm-чарта: 'tempo' (monolithic) или 'tempo-distributed' (distributed)."
  type        = string
  default     = "tempo-distributed"
  validation {
    condition     = contains(["tempo", "tempo-distributed"], var.chart_name)
    error_message = "chart_name должен быть 'tempo' или 'tempo-distributed'."
  }
}

variable "chart_version" {
  description = "Версия Helm-чарта Tempo (semver). Если null — берётся последняя из репозитория."
  type        = string
  default     = null
}

variable "helm_repository" {
  description = "Helm-репозиторий графаны с чартами Tempo."
  type        = string
  default     = "https://grafana.github.io/helm-charts"
}

########################################################
# Режим установки и компоненты Tempo
########################################################
# Tempo поддерживает monolithic и distributed (микросервисный) режимы. :contentReference[oaicite:4]{index=4}
variable "install_mode" {
  description = "Режим установки Tempo: 'monolithic' или 'distributed'."
  type        = string
  default     = "distributed"
  validation {
    condition     = contains(["monolithic", "distributed"], var.install_mode)
    error_message = "install_mode должен быть 'monolithic' или 'distributed'."
  }
}

# В распределённом чарте гарантированно устанавливаются эти компоненты. :contentReference[oaicite:5]{index=5}
variable "replicas" {
  description = <<-EOT
    Кол-во реплик компонентов Tempo.
    Для distributed режима ожидаются ключи: distributor, ingester, querier, query_frontend, compactor.
    Для monolithic — требуется только 'monolithic'.
  EOT
  type = object({
    distributor     = optional(number)
    ingester        = optional(number)
    querier         = optional(number)
    query_frontend  = optional(number)
    compactor       = optional(number)
    monolithic      = optional(number)
    metrics_generator = optional(number)
  })
  default = {}
}

variable "resources" {
  description = <<-EOT
    Ресурсы контейнеров по компонентам Tempo (requests/limits).
    Ключи как в 'replicas'. Структура: { component = { requests = { cpu, memory }, limits = { cpu, memory } } }
  EOT
  type = map(object({
    requests = optional(object({
      cpu    = optional(string)
      memory = optional(string)
    }), {})
    limits = optional(object({
      cpu    = optional(string)
      memory = optional(string)
    }), {})
  }))
  default = {}
}

########################################################
# Приёмники трасс (receivers)
########################################################
# Distributor поддерживает OTLP, Jaeger, Zipkin, OpenCensus, Kafka. :contentReference[oaicite:6]{index=6}
variable "receivers" {
  description = "Включение/выключение протоколов приёма трасс в distributor."
  type = object({
    otlp_grpc             = optional(bool, true)   # 4317 по умолчанию
    otlp_http             = optional(bool, true)   # 4318 по умолчанию
    jaeger_grpc           = optional(bool, false)
    jaeger_thrift_http    = optional(bool, false)
    jaeger_thrift_compact = optional(bool, false)
    jaeger_thrift_binary  = optional(bool, false)
    zipkin                = optional(bool, false)
    opencensus            = optional(bool, false)
    kafka                 = optional(bool, false)
    listen_address        = optional(string, "0.0.0.0") # слушать не только localhost
  })
  default = {}
}

########################################################
# Хранилище трасс (TempoDB)
########################################################
# Tempo поддерживает S3, GCS, Azure и local (для monolithic). :contentReference[oaicite:7]{index=7}
variable "storage_backend" {
  description = "Бэкенд хранилища трасс: 's3' | 'gcs' | 'azure' | 'local' (local поддерживается в monolithic)."
  type        = string
  default     = "s3"
  validation {
    condition     = contains(["s3", "gcs", "azure", "local"], var.storage_backend)
    error_message = "storage_backend должен быть одним из: s3, gcs, azure, local."
  }
}

variable "storage_s3" {
  description = "Параметры S3-хранилища для Tempo (используются, если storage_backend='s3')."
  type = object({
    bucket      = optional(string)
    prefix      = optional(string)
    region      = optional(string)
    endpoint    = optional(string)
    access_key  = optional(string)
    secret_key  = optional(string)
    insecure    = optional(bool)
    sse         = optional(string) # алгоритм шифрования, если нужен
  })
  default = {}
}

variable "storage_gcs" {
  description = "Параметры GCS, если storage_backend='gcs'."
  type = object({
    bucket_name = optional(string)
    prefix      = optional(string)
    endpoint    = optional(string)
    insecure    = optional(bool)
  })
  default = {}
}

variable "storage_azure" {
  description = "Параметры Azure Blob Storage, если storage_backend='azure'."
  type = object({
    container_name = optional(string)
    account_name   = optional(string)
    endpoint       = optional(string)
    use_managed_identity = optional(bool)
  })
  default = {}
}

########################################################
# Ретенция и работа компактора
########################################################
# Ретенцию в Tempo обеспечивает компактор; настраивается через compactor.compaction.block_retention и связанные поля.
# (см. docs и autogenerated values артефакта чарта) :contentReference[oaicite:8]{index=8}
variable "compactor_block_retention" {
  description = "Срок хранения блоков (например, '720h' для 30 дней)."
  type        = string
  default     = null
}

variable "compactor_compacted_block_retention" {
  description = "Срок хранения уже компактированных блоков (например, '1h')."
  type        = string
  default     = null
}

# Пользовательские overrides per-tenant возможны через overrides.user_configurable_overrides. :contentReference[oaicite:9]{index=9}
variable "enable_user_configurable_overrides" {
  description = "Включить модуль user-configurable overrides (per-tenant)."
  type        = bool
  default     = false
}

########################################################
# Metrics generator (метрики из трасс)
########################################################
# В Tempo есть компонент metrics-generator; по умолчанию процессоры выключены. :contentReference[oaicite:10]{index=10}
variable "metrics_generator" {
  description = "Настройки metrics-generator."
  type = object({
    enabled            = optional(bool, false)
    remote_write_url   = optional(string) # Prometheus Remote Write (например, Mimir/Prometheus)
    service_graphs     = optional(bool, false)
    span_metrics       = optional(bool, false)
  })
  default = {}
}

########################################################
# Мониторинг чарта (metaMonitoring / ServiceMonitor)
########################################################
# В tempo-distributed serviceMonitor перенесён под metaMonitoring.* (breaking change в чарте). :contentReference[oaicite:11]{index=11}
variable "meta_monitoring" {
  description = "Meta-monitoring для Tempo (включая ServiceMonitor/PodMonitor)."
  type = object({
    enabled                     = optional(bool, true)
    install_operator            = optional(bool, false)
    service_monitor_enabled     = optional(bool, true)
    pod_monitor_enabled         = optional(bool, false)
    grafana_agent_enabled       = optional(bool, false)
  })
  default = {}
}

########################################################
# Сетевые и операционные параметры
########################################################

variable "pod_annotations" {
  description = "Аннотации Pod для всех компонентов Tempo."
  type        = map(string)
  default     = {}
}

variable "node_selector" {
  description = "Node selector для подов Tempo."
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Tolerations для подов Tempo."
  type = list(object({
    key      = optional(string)
    operator = optional(string)
    value    = optional(string)
    effect   = optional(string)
  }))
  default = []
}

variable "topology_spread_constraints" {
  description = "Политика распределения подов по топологии."
  type = list(object({
    max_skew           = number
    topology_key       = string
    when_unsatisfiable = string
    label_selector     = optional(map(string))
  }))
  default = []
}

########################################################
# Низкоуровневые overrides Helm (values.yaml как map)
########################################################

variable "extra_values" {
  description = "Произвольные Helm values для тонкой настройки (map будет слит поверх генерируемых значений)."
  type        = map(any)
  default     = {}
}
