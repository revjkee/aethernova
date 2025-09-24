###############################################################
# modules/k8s-observability/loki-stack/variables.tf
#
# PURPOSE: Industrial-grade input variables for deploying the
# Grafana Loki Stack via Terraform (helm_release).
#
# SOURCES (официальные документы для проверки):
# - Grafana Helm Charts (репозиторий loki-stack):
#   https://github.com/grafana/helm-charts/tree/main/charts/loki-stack
#   (helm repo index) https://grafana.github.io/helm-charts
# - Loki (configuration, storage, retention, compactor, boltdb-shipper):
#   https://grafana.com/docs/loki/latest/configuration/
#   https://grafana.com/docs/loki/latest/storage/
#   https://grafana.com/docs/loki/latest/operations/storage/ (object storage)
#   https://grafana.com/docs/loki/latest/operations/storage/retention/
# - Promtail (service discovery & scrape):
#   https://grafana.com/docs/loki/latest/clients/promtail/
# - Terraform Helm provider:
#   https://registry.terraform.io/providers/hashicorp/helm/latest/docs
# - Prometheus Operator CRDs (ServiceMonitor/PodMonitor):
#   https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md
#
# Примечание: файл определяет переменные и их валидацию. Конкретные
# соответствия ключам values.yaml чарта задаются в main.tf/values.
###############################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12.1"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.29.0"
    }
  }
}

########################
# Helm Release basics  #
########################

variable "release_name" {
  description = "Имя Helm-релиза Loki Stack."
  type        = string
  default     = "loki-stack"
  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.release_name))
    error_message = "release_name должен соответствовать RFC 1123: строчные буквы, цифры, дефис."
  }
}

variable "namespace" {
  description = "Namespace, в который будет установлен Loki Stack."
  type        = string
  default     = "observability"
  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace))
    error_message = "namespace должен соответствовать RFC 1123."
  }
}

variable "create_namespace" {
  description = "Создавать namespace автоматически."
  type        = bool
  default     = true
}

variable "helm_repository" {
  description = "URL репозитория Helm-чартов Grafana."
  type        = string
  default     = "https://grafana.github.io/helm-charts"
}

variable "helm_chart" {
  description = "Имя чарта Grafana для стека Loki."
  type        = string
  default     = "loki-stack"
}

variable "helm_chart_version" {
  description = "Версия чарта loki-stack. null — использовать тот, что разрешит Helm по умолчанию."
  type        = string
  default     = null
  validation {
    condition     = var.helm_chart_version == null || can(regex("^\\d+\\.\\d+\\.\\d+(-.+)?$", var.helm_chart_version))
    error_message = "helm_chart_version должен быть semver (например, 2.10.1) или null."
  }
}

variable "force_update" {
  description = "Helm: позволять замену ресурсов при несовместимых изменениях (helm upgrade --force)."
  type        = bool
  default     = false
}

variable "atomic_install" {
  description = "Helm: atomic=true откатывает релиз при неуспехе установки/обновления."
  type        = bool
  default     = true
}

variable "timeout_seconds" {
  description = "Таймаут ожидания Helm операций в секундах."
  type        = number
  default     = 600
  validation {
    condition     = var.timeout_seconds >= 60 && var.timeout_seconds <= 3600
    error_message = "timeout_seconds должен быть в диапазоне 60..3600."
  }
}

##############################
# Generic values management  #
##############################

variable "values" {
  description = <<-EOT
    Карта значений для рендеринга values.yaml Loki Stack.
    Рекомендуемый формат: map(any), соответствующий структуре чарта.
    При необходимости можно комбинировать с values_files.
  EOT
  type        = any
  default     = {}
}

variable "values_files" {
  description = "Список путей к внешним values-файлам (yaml), применяемым в порядке."
  type        = list(string)
  default     = []
}

variable "set" {
  description = "Список точечных override (helm set), если нужно переопределить отдельные ключи."
  type = list(object({
    name  = string
    value = string
    type  = optional(string) # string, bool, int
  }))
  default = []
}

#########################
# Core enablement flags #
#########################

variable "enable_loki" {
  description = "Включить установку Loki (loki)."
  type        = bool
  default     = true
}

variable "enable_promtail" {
  description = "Включить установку Promtail (клиент логов)."
  type        = bool
  default     = true
}

variable "enable_grafana" {
  description = "Включить установку Grafana из чарта loki-stack (если управляете Grafana отдельно — false)."
  type        = bool
  default     = false
}

variable "enable_prometheus" {
  description = "Включить связанный Prometheus (если это поддерживается конфигурацией чарта в вашей версии)."
  type        = bool
  default     = false
}

########################################
# Storage backend & retention settings #
########################################

variable "storage_backend" {
  description = "Бэкенд хранилища для Loki: s3 | gcs | azure | filesystem."
  type        = string
  default     = "filesystem"
  validation {
    condition     = contains(["s3", "gcs", "azure", "filesystem"], var.storage_backend)
    error_message = "storage_backend должен быть одним из: s3, gcs, azure, filesystem."
  }
}

variable "loki_retention_period" {
  description = "Период хранения логов (например, 168h, 7d). Конфигурируется через limits_config/retention в values."
  type        = string
  default     = "168h"
  validation {
    condition     = can(regex("^(\\d+)(h|d|w|m|y)$", var.loki_retention_period))
    error_message = "loki_retention_period должен быть duration, например 168h, 7d, 4w."
  }
}

variable "loki_index_store" {
  description = "Тип индекс-хранилища Loki (например, boltdb-shipper)."
  type        = string
  default     = "boltdb-shipper"
}

variable "loki_compactor_enabled" {
  description = "Включить compactor для retention/compaction."
  type        = bool
  default     = true
}

variable "loki_ruler_enabled" {
  description = "Включить ruler (алерты/правила для логов)."
  type        = bool
  default     = false
}

#################################
# Object storage: S3 parameters #
#################################

variable "s3_bucket_name" {
  description = "Имя S3 бакета для Loki (если storage_backend = s3)."
  type        = string
  default     = null
}

variable "s3_region" {
  description = "Регион S3 (например, eu-west-1)."
  type        = string
  default     = null
}

variable "s3_endpoint" {
  description = "Кастомный S3 Endpoint (для S3-совместимых хранилищ, MinIO и т.п.)."
  type        = string
  default     = null
}

variable "s3_access_key_id" {
  description = "S3 Access Key ID (можно передать через Kubernetes Secret, см. секцию secret management)."
  type        = string
  default     = null
  sensitive   = true
}

variable "s3_secret_access_key" {
  description = "S3 Secret Access Key."
  type        = string
  default     = null
  sensitive   = true
}

variable "s3_sse" {
  description = "Тип шифрования на стороне сервера (SSE): AES256 или aws:kms."
  type        = string
  default     = null
}

variable "s3_sse_kms_key_id" {
  description = "KMS Key ID (если используете aws:kms)."
  type        = string
  default     = null
}

#################################
# Object storage: GCS parameters #
#################################

variable "gcs_bucket_name" {
  description = "Имя GCS бакета (если storage_backend = gcs)."
  type        = string
  default     = null
}

variable "gcp_service_account_json" {
  description = "Содержимое JSON ключа GCP SA для доступа к GCS (рекомендуется передавать через Secret)."
  type        = string
  default     = null
  sensitive   = true
}

#####################################
# Object storage: Azure parameters  #
#####################################

variable "azure_storage_account" {
  description = "Имя учетной записи хранения Azure (если storage_backend = azure)."
  type        = string
  default     = null
}

variable "azure_container_name" {
  description = "Имя контейнера в Azure Blob Storage."
  type        = string
  default     = null
}

variable "azure_account_key" {
  description = "Ключ учетной записи хранения Azure (хранить как Secret)."
  type        = string
  default     = null
  sensitive   = true
}

#######################################
# Kubernetes Secret management (creds) #
#######################################

variable "create_object_storage_secret" {
  description = "Создавать Kubernetes Secret с кредами object-storage (S3/GCS/Azure) автоматически."
  type        = bool
  default     = false
}

variable "object_storage_secret_name" {
  description = "Имя Secret с кредами object-storage (если create_object_storage_secret = true, он будет создан)."
  type        = string
  default     = "loki-object-storage"
}

variable "object_storage_secret_annotations" {
  description = "Аннотации, применяемые к Secret с кредами object-storage."
  type        = map(string)
  default     = {}
}

##########################################
# Persistence (PVC) and StorageClass     #
##########################################

variable "loki_persistence_enabled" {
  description = "Включить PVC для Loki (например, для индекс-/кэша и т.п., по конфигурации чарта)."
  type        = bool
  default     = false
}

variable "loki_persistence_size" {
  description = "Размер PVC для Loki (например, 50Gi)."
  type        = string
  default     = "50Gi"
}

variable "loki_storage_class" {
  description = "Имя StorageClass для PVC (null — по умолчанию кластерный)."
  type        = string
  default     = null
}

##########################################
# Service / Ingress / NetworkPolicy      #
##########################################

variable "service_type" {
  description = "Тип Service для компонентов Gateway/Query-Frontend: ClusterIP | NodePort | LoadBalancer."
  type        = string
  default     = "ClusterIP"
  validation {
    condition     = contains(["ClusterIP", "NodePort", "LoadBalancer"], var.service_type)
    error_message = "service_type должен быть ClusterIP, NodePort или LoadBalancer."
  }
}

variable "enable_ingress" {
  description = "Включить Ingress для входа в Loki (gateway/query-frontend), если таковой настраивается values."
  type        = bool
  default     = false
}

variable "ingress_class_name" {
  description = "IngressClassName для создаваемого Ingress."
  type        = string
  default     = null
}

variable "ingress_hosts" {
  description = "Список host-ов для Ingress."
  type        = list(string)
  default     = []
}

variable "ingress_tls" {
  description = "Список TLS-секций для Ingress (host, secretName)."
  type = list(object({
    hosts       = list(string)
    secret_name = string
  }))
  default = []
}

variable "ingress_annotations" {
  description = "Аннотации для Ingress."
  type        = map(string)
  default     = {}
}

variable "enable_network_policy" {
  description = "Создавать NetworkPolicy для ограничения трафика Loki/Promtail."
  type        = bool
  default     = false
}

variable "network_policy_allowed_namespaces" {
  description = "Namespace-ы, которым разрешен доступ согласно NetworkPolicy."
  type        = list(string)
  default     = []
}

variable "network_policy_allowed_cidrs" {
  description = "Список разрешенных CIDR для входящего трафика."
  type        = list(string)
  default     = []
}

##################################
# ServiceMonitor / PodMonitor    #
##################################

variable "enable_service_monitor" {
  description = "Включить создание ServiceMonitor (Prometheus Operator) для Loki/Promtail."
  type        = bool
  default     = true
}

variable "service_monitor_namespace" {
  description = "Namespace для ServiceMonitor (если нужен отдельный)."
  type        = string
  default     = null
}

variable "service_monitor_labels" {
  description = "Доп. метки для ServiceMonitor (например, для выбора Prometheus инстансом)."
  type        = map(string)
  default     = {}
}

variable "service_monitor_interval" {
  description = "Интервал опроса ServiceMonitor (например, 30s)."
  type        = string
  default     = "30s"
}

variable "service_monitor_scrape_timeout" {
  description = "Таймаут опроса ServiceMonitor (например, 10s)."
  type        = string
  default     = "10s"
}

#####################################
# Resources / Scheduling & Security #
#####################################

variable "loki_resources" {
  description = "Resources для Loki (requests/limits)."
  type = object({
    requests = optional(map(string))
    limits   = optional(map(string))
  })
  default = {
    requests = { cpu = "100m", memory = "256Mi" }
    limits   = { cpu = "2000m", memory = "4Gi" }
  }
}

variable "promtail_resources" {
  description = "Resources для Promtail."
  type = object({
    requests = optional(map(string))
    limits   = optional(map(string))
  })
  default = {
    requests = { cpu = "50m", memory = "128Mi" }
    limits   = { cpu = "500m", memory = "512Mi" }
  }
}

variable "node_selector" {
  description = "nodeSelector для компонентов Loki Stack."
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Список tolerations."
  type = list(object({
    key               = optional(string)
    operator          = optional(string)
    value             = optional(string)
    effect            = optional(string)
    toleration_seconds= optional(number)
  }))
  default = []
}

variable "affinity" {
  description = "Kubernetes affinity (raw map для передачи в values)."
  type        = any
  default     = null
}

variable "topology_spread_constraints" {
  description = "Список TopologySpreadConstraints."
  type        = any
  default     = null
}

variable "pod_security_context" {
  description = "PodSecurityContext (fsGroup и т.п.)."
  type = object({
    run_as_user  = optional(number)
    run_as_group = optional(number)
    fs_group     = optional(number)
    run_as_non_root = optional(bool)
  })
  default = {
    run_as_non_root = true
  }
}

variable "container_security_context" {
  description = "SecurityContext контейнеров."
  type = object({
    allow_privilege_escalation = optional(bool)
    read_only_root_filesystem  = optional(bool)
    run_as_user                = optional(number)
    run_as_group               = optional(number)
    capabilities               = optional(map(list(string)))
  })
  default = {
    allow_privilege_escalation = false
    read_only_root_filesystem  = true
  }
}

#########################
# Grafana (optional)    #
#########################

variable "grafana_admin_existing_secret" {
  description = "Имя существующего Secret с ключами admin-user / admin-password для Grafana."
  type        = string
  default     = null
}

variable "grafana_dashboards_enabled" {
  description = "Включить загрузку стандартных дашбордов Loki (если поддерживается сборкой чарта)."
  type        = bool
  default     = true
}

variable "grafana_service_type" {
  description = "Тип Service для Grafana."
  type        = string
  default     = "ClusterIP"
  validation {
    condition     = contains(["ClusterIP", "NodePort", "LoadBalancer"], var.grafana_service_type)
    error_message = "grafana_service_type должен быть ClusterIP, NodePort или LoadBalancer."
  }
}

#########################
# Image registry mirroring
#########################

variable "image_registry_overrides" {
  description = "Переопределения реестров образов для air-gapped/частных окружений: компонент => реестр."
  type        = map(string)
  default     = {}
}

#########################
# Extra labels/annotations
#########################

variable "common_labels" {
  description = "Доп. метки, применяемые ко всем управляемым ресурсам (где применимо)."
  type        = map(string)
  default     = {}
}

variable "common_annotations" {
  description = "Доп. аннотации, применяемые ко всем управляемым ресурсам (где применимо)."
  type        = map(string)
  default     = {}
}

#########################
# Validations / Guards  #
#########################

variable "fail_if_backend_misconfigured" {
  description = "Жестко валидировать, что для выбранного storage_backend заданы необходимые креды/параметры (проверяется в main.tf через preconditions)."
  type        = bool
  default     = true
}
