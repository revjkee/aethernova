# aethernova-chain-core/ops/terraform/modules/storage/redis/variables.tf
#
# Назначение:
# Универсальный модуль переменных для Redis-хранилища:
#  - Управляемые: AWS ElastiCache, GCP Memorystore, Azure Cache for Redis.
#  - Self-managed: Helm/Kubernetes, VM-инсталляции.
#
# Принципы:
#  - Все опции заданы как переменные с валидациями.
#  - Без хардкода провайдер-специфичных значений: всё настраивается извне.
#  - Поддержка TLS, ACL/паролей, кластерного режима, бэкапов, тайм-аутов,
#    сетевых ограничений, тегов/лейблов, HPA (для k8s), ресурсов, логирования.
#
# В этом файле только входные переменные. Реализация ресурсов — в main.tf и пр.

################################################################################
# CORE
################################################################################

variable "name" {
  description = "Логическое имя инсталляции Redis (префикс ресурсов)."
  type        = string
}

variable "environment" {
  description = "Окружение: dev|stage|prod."
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "stage", "prod"], var.environment)
    error_message = "environment должен быть одним из: dev, stage, prod."
  }
}

variable "project" {
  description = "Идентификатор проекта/продукта (для тегов/лейблов)."
  type        = string
  default     = null
}

variable "deployment_model" {
  description = "Модель развёртывания: aws_elasticache | gcp_memorystore | azurerm_redis | k8s_helm | vm."
  type        = string
  default     = "k8s_helm"
  validation {
    condition     = contains(["aws_elasticache", "gcp_memorystore", "azurerm_redis", "k8s_helm", "vm"], var.deployment_model)
    error_message = "deployment_model должен быть одним из: aws_elasticache, gcp_memorystore, azurerm_redis, k8s_helm, vm."
  }
}

variable "redis_version" {
  description = "Версия Redis (строка). Для управляемых сервисов — передаётся в провайдер-специфичную опцию."
  type        = string
  default     = null
}

variable "cluster_enabled" {
  description = "Включить кластерный режим Redis (cluster-mode / sharded)."
  type        = bool
  default     = false
}

variable "shard_count" {
  description = "Число шардов (актуально при cluster_enabled=true)."
  type        = number
  default     = 1
  validation {
    condition     = var.shard_count >= 1
    error_message = "shard_count должен быть >= 1."
  }
}

variable "replicas_per_shard" {
  description = "Число реплик на шард (0 — без реплик)."
  type        = number
  default     = 1
  validation {
    condition     = var.replicas_per_shard >= 0
    error_message = "replicas_per_shard должен быть >= 0."
  }
}

################################################################################
# AUTH / ACL
################################################################################

variable "auth_enabled" {
  description = "Включить аутентификацию (пароль/ACL/токен)."
  type        = bool
  default     = true
}

variable "auth_mode" {
  description = "Режим аутентификации: requirepass | acl | provider_native."
  type        = string
  default     = "requirepass"
  validation {
    condition     = contains(["requirepass", "acl", "provider_native"], var.auth_mode)
    error_message = "auth_mode должен быть одним из: requirepass, acl, provider_native."
  }
}

variable "auth_password" {
  description = "Пароль для requirepass (или default user). Не используйте вместе с provider_native."
  type        = string
  default     = null
  sensitive   = true
  validation {
    condition     = var.auth_enabled == false || var.auth_mode != "requirepass" || (var.auth_password != null && length(var.auth_password) >= 16)
    error_message = "При auth_mode=requirepass необходимо задать auth_password длиной >= 16 символов."
  }
}

variable "acl_users" {
  description = <<-EOT
    Список ACL-пользователей (для auth_mode=acl). Пример:
    [
      {
        name      = "svc-reader"
        passwords = ["<strong_password1>", "<strong_password2>"]
        commands  = ["+@read", "-FLUSHDB", "-FLUSHALL"]
        keys      = ["~*"]
      }
    ]
  EOT
  type = list(object({
    name      = string
    passwords = list(string)
    commands  = list(string)
    keys      = list(string)
  }))
  default   = []
  sensitive = true
}

################################################################################
# SECURITY / TLS / ENCRYPTION
################################################################################

variable "tls_enabled" {
  description = "Включить TLS для подключения к Redis."
  type        = bool
  default     = true
}

variable "min_tls_version" {
  description = "Минимальная версия TLS: TLS1.2 | TLS1.3."
  type        = string
  default     = "TLS1.2"
  validation {
    condition     = contains(["TLS1.2", "TLS1.3"], var.min_tls_version)
    error_message = "min_tls_version должен быть одним из: TLS1.2, TLS1.3."
  }
}

variable "encryption_at_rest" {
  description = "Шифрование хранилища (если поддерживается провайдером)."
  type        = bool
  default     = true
}

variable "kms_key_id" {
  description = "KMS/CMK ключ (если требуется провайдером для шифрования)."
  type        = string
  default     = null
}

################################################################################
# CAPACITY / SIZING / PERFORMANCE
################################################################################

variable "node_type" {
  description = "Тип узла/инстанса (управляемые провайдеры) или VM flavor. Для k8s игнорируется."
  type        = string
  default     = null
}

variable "maxmemory_policy" {
  description = "Политика вытеснения ключей (например, allkeys-lru, volatile-lru и т.д.)."
  type        = string
  default     = null
}

variable "parameter_overrides" {
  description = "Карта параметров Redis (redis.conf / параметр-группа провайдера)."
  type        = map(string)
  default     = {}
}

################################################################################
# PORTS / ENDPOINTS
################################################################################

variable "port" {
  description = "Порт Redis."
  type        = number
  default     = 6379
  validation {
    condition     = var.port > 0 && var.port < 65536
    error_message = "port должен быть в диапазоне 1..65535."
  }
}

################################################################################
# AVAILABILITY / MAINTENANCE
################################################################################

variable "multi_az" {
  description = "Мульти-AZ/зональная отказоустойчивость (если поддерживается)."
  type        = bool
  default     = true
}

variable "preferred_azs" {
  description = "Предпочтительные зоны/локации (список)."
  type        = list(string)
  default     = []
}

variable "maintenance_window" {
  description = "Окно обслуживания в провайдер-специфичном формате (строка)."
  type        = string
  default     = null
}

################################################################################
# BACKUP / SNAPSHOTS
################################################################################

variable "backup_enabled" {
  description = "Включить бэкапы/снимки."
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Число дней хранения бэкапов (если поддерживается)."
  type        = number
  default     = 7
  validation {
    condition     = var.backup_retention_days >= 0
    error_message = "backup_retention_days должен быть >= 0."
  }
}

variable "backup_window" {
  description = "Окно бэкапа (строка, формат зависит от провайдера)."
  type        = string
  default     = null
}

variable "backup_provider" {
  description = "Назначение хранилища бэкапов для self-managed: s3 | gcs | azblob | pvc | none."
  type        = string
  default     = "none"
  validation {
    condition     = contains(["s3", "gcs", "azblob", "pvc", "none"], var.backup_provider)
    error_message = "backup_provider должен быть одним из: s3, gcs, azblob, pvc, none."
  }
}

variable "backup_bucket" {
  description = "Имя бакета/контейнера (для s3/gcs/azblob)."
  type        = string
  default     = null
}

variable "backup_prefix" {
  description = "Префикс пути для бэкапов."
  type        = string
  default     = null
}

variable "backup_schedule_cron" {
  description = "CRON-расписание Job (self-managed)."
  type        = string
  default     = null
}

variable "backup_retention_count" {
  description = "Число бэкап-артефактов, сохраняемых в хранилище (self-managed)."
  type        = number
  default     = 7
  validation {
    condition     = var.backup_retention_count >= 0
    error_message = "backup_retention_count должен быть >= 0."
  }
}

################################################################################
# NETWORKING (VPC / SUBNETS / SG / FIREWALL)
################################################################################

variable "vpc_id" {
  description = "VPC/Network ID (для управляемых сервисов или VM)."
  type        = string
  default     = null
}

variable "subnet_ids" {
  description = "Список подсетей для управляемых сервисов или VM."
  type        = list(string)
  default     = []
}

variable "create_subnet_group" {
  description = "Создавать subnet group (актуально для некоторых провайдеров)."
  type        = bool
  default     = false
}

variable "subnet_group_name" {
  description = "Имя существующей subnet group (если не создаём новую)."
  type        = string
  default     = null
}

variable "security_group_ids" {
  description = "Список SG/Firewall групп для инстансов/ендпойнтов."
  type        = list(string)
  default     = []
}

variable "create_security_group" {
  description = "Создавать Security Group с правилами доступа."
  type        = bool
  default     = false
}

variable "allowed_cidr_blocks" {
  description = "Разрешённые CIDR для входящих подключений (если создаётся SG/Firewall)."
  type        = list(string)
  default     = []
}

variable "extra_security_rules" {
  description = <<-EOT
    Дополнительные правила безопасности (ingress/egress) для создаваемого SG/Firewall.
    Пример элемента:
    {
      type        = "ingress"
      protocol    = "tcp"
      from_port   = 6379
      to_port     = 6379
      cidr_blocks = ["10.0.0.0/8"]
      description = "Internal Redis access"
    }
  EOT
  type = list(object({
    type        = string
    protocol    = string
    from_port   = number
    to_port     = number
    cidr_blocks = list(string)
    description = optional(string)
  }))
  default = []
}

################################################################################
# KUBERNETES (HELM SELF-MANAGED)
################################################################################

variable "k8s_namespace" {
  description = "Namespace для Helm-деплоя Redis."
  type        = string
  default     = "redis"
}

variable "k8s_release_name" {
  description = "Helm release name."
  type        = string
  default     = "redis"
}

variable "k8s_chart_name" {
  description = "Имя Helm chart (например, bitnami/redis)."
  type        = string
  default     = null
}

variable "k8s_chart_version" {
  description = "Версия Helm chart."
  type        = string
  default     = null
}

variable "k8s_repository" {
  description = "Helm repository URL/alias."
  type        = string
  default     = null
}

variable "k8s_values" {
  description = "Дополнительные значения Helm (map для override)."
  type        = any
  default     = {}
}

variable "k8s_service_type" {
  description = "Тип Kubernetes Service: ClusterIP | NodePort | LoadBalancer."
  type        = string
  default     = "ClusterIP"
  validation {
    condition     = contains(["ClusterIP", "NodePort", "LoadBalancer"], var.k8s_service_type)
    error_message = "k8s_service_type должен быть одним из: ClusterIP, NodePort, LoadBalancer."
  }
}

variable "k8s_service_annotations" {
  description = "Аннотации для Service."
  type        = map(string)
  default     = {}
}

variable "k8s_labels" {
  description = "Лейблы для ресурсов Kubernetes."
  type        = map(string)
  default     = {}
}

variable "k8s_annotations" {
  description = "Аннотации для Pod/Deployment/StatefulSet."
  type        = map(string)
  default     = {}
}

variable "k8s_persistence_enabled" {
  description = "Включить PVC-персистентность (self-managed)."
  type        = bool
  default     = false
}

variable "k8s_storage_class" {
  description = "StorageClass для PVC."
  type        = string
  default     = null
}

variable "k8s_storage_size" {
  description = "Размер PVC (напр., 10Gi)."
  type        = string
  default     = null
}

variable "k8s_resources" {
  description = "Ресурсы контейнеров (requests/limits)."
  type = object({
    requests = optional(object({
      cpu    = optional(string)
      memory = optional(string)
    }))
    limits = optional(object({
      cpu    = optional(string)
      memory = optional(string)
    }))
  })
  default = {}
}

variable "k8s_hpa_enabled" {
  description = "Включить Horizontal Pod Autoscaler."
  type        = bool
  default     = false
}

variable "k8s_hpa" {
  description = "Параметры HPA."
  type = object({
    min_replicas = number
    max_replicas = number
    cpu_utilization_percentage    = optional(number)
    memory_utilization_percentage = optional(number)
  })
  default = {
    min_replicas = 1
    max_replicas = 3
  }
  validation {
    condition     = var.k8s_hpa.min_replicas >= 1 && var.k8s_hpa.max_replicas >= var.k8s_hpa.min_replicas
    error_message = "k8s_hpa.max_replicas должен быть >= k8s_hpa.min_replicas, а min_replicas >= 1."
  }
}

################################################################################
# MONITORING / LOGGING
################################################################################

variable "monitoring_enabled" {
  description = "Включить мониторинг метрик Redis."
  type        = bool
  default     = true
}

variable "prometheus_service_monitor_enabled" {
  description = "Создавать ServiceMonitor (k8s) для scraping-а."
  type        = bool
  default     = false
}

variable "metrics_namespace" {
  description = "Пространство имён метрик/префикс (CloudWatch/Prom/Grafana)."
  type        = string
  default     = null
}

variable "slowlog_enabled" {
  description = "Включить сбор slowlog (при поддержке реализации)."
  type        = bool
  default     = false
}

################################################################################
# TIMEOUTS / LIFECYCLE
################################################################################

variable "timeouts" {
  description = "Тайм-ауты операций создания/обновления/удаления ресурсов."
  type = object({
    create = optional(string)
    update = optional(string)
    delete = optional(string)
  })
  default = {}
}

################################################################################
# TAGS / EXTRA
################################################################################

variable "tags" {
  description = "Теги для управляемых ресурсов (AWS/GCP/Azure) и аннотации по возможности."
  type        = map(string)
  default     = {}
}

variable "extra_labels" {
  description = "Дополнительные лейблы для всех поддерживающих объекты."
  type        = map(string)
  default     = {}
}

variable "provider_specific" {
  description = <<-EOT
    Свободная карта провайдер-специфичных опций (без жёсткой схемы).
    Пример (AWS):
      {
        parameter_group_name = "custom-group"
        snapshot_arns        = []
      }
    Пример (GCP):
      {
        tier            = "STANDARD_HA"
        connect_mode    = "PRIVATE_SERVICE_CONNECT"
      }
  EOT
  type    = any
  default = {}
}

################################################################################
# VALIDATIONS (cross-field)
################################################################################

variable "persistence_safety_guard" {
  description = "Защитный флаг: при k8s_persistence_enabled=true требуется задать k8s_storage_class и k8s_storage_size."
  type        = bool
  default     = true
  validation {
    condition = (!var.k8s_persistence_enabled) || (
      var.k8s_storage_class != null && trim(var.k8s_storage_class) != "" &&
      var.k8s_storage_size  != null && trim(var.k8s_storage_size)  != ""
    )
    error_message = "При k8s_persistence_enabled=true необходимо указать k8s_storage_class и k8s_storage_size."
  }
}

variable "backup_safety_guard" {
  description = "Защитный флаг: при backup_enabled=true и backup_provider in [s3,gcs,azblob] требуется задать backup_bucket."
  type        = bool
  default     = true
  validation {
    condition = (!var.backup_enabled) || (var.backup_provider == "none") || (
      var.backup_provider == "pvc" && true
    ) || (
      contains(["s3", "gcs", "azblob"], var.backup_provider) && var.backup_bucket != null && trim(var.backup_bucket) != ""
    )
    error_message = "При backup_enabled=true и backup_provider=s3|gcs|azblob необходимо задать backup_bucket."
  }
}

variable "tls_safety_guard" {
  description = "Защитный флаг: при tls_enabled=true может понадобиться внешний TLS/сертификаты (передаются через k8s_values/provider_specific)."
  type        = bool
  default     = true
  # Только информативная проверка невозможна на уровне variables.tf — реализуется в main.tf через условные ресурсы.
}

