#############################################
# variables.tf — providers (industrial)
# Terraform >= 1.5
#############################################

############################
# Global toggles
############################
variable "enable_aws" {
  description = "Включить конфигурацию провайдера AWS."
  type        = bool
  default     = false
}

variable "enable_gcp" {
  description = "Включить конфигурацию провайдера Google Cloud."
  type        = bool
  default     = false
}

variable "enable_azure" {
  description = "Включить конфигурацию провайдера AzureRM."
  type        = bool
  default     = false
}

variable "enable_kubernetes" {
  description = "Включить провайдера Kubernetes."
  type        = bool
  default     = false
}

variable "enable_helm" {
  description = "Включить провайдера Helm (использует доступ к кластеру Kubernetes)."
  type        = bool
  default     = false
}

############################
# Common metadata
############################
variable "environment" {
  description = "Имя окружения (dev/stage/prod и т.д.)."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.environment))
    error_message = "environment допускает только [a-z0-9-]."
  }
}

variable "name_prefix" {
  description = "Единый префикс имён ресурсов/меток."
  type        = string
  default     = ""
  validation {
    condition     = var.name_prefix == "" || can(regex("^[a-z0-9-]+$", var.name_prefix))
    error_message = "name_prefix допускает только [a-z0-9-]."
  }
}

variable "global_tags" {
  description = "Глобальные теги/метки для поддерживаемых провайдеров."
  type        = map(string)
  default     = {}
}

############################
# Network & TLS/Proxy (generic)
############################
variable "http_proxy" {
  description = "HTTP proxy URL, если требуется (например, http://proxy:3128). Пусто — не использовать."
  type        = string
  default     = ""
}

variable "https_proxy" {
  description = "HTTPS proxy URL, если требуется."
  type        = string
  default     = ""
}

variable "no_proxy" {
  description = "Список доменов/хостов, исключённых из прокси (через запятую)."
  type        = string
  default     = ""
}

variable "custom_ca_bundle" {
  description = "Путь к кастомному корневому сертификату (PEM) для TLS-проверок. Пусто — не использовать."
  type        = string
  default     = ""
}

############################
# AWS provider
############################
variable "aws_region" {
  description = "Регион AWS."
  type        = string
  default     = "eu-north-1"
}

variable "aws_profile" {
  description = "AWS CLI/SDK профиль. Пусто — автодетект по окружению."
  type        = string
  default     = ""
}

variable "aws_access_key" {
  description = "AWS Access Key ID (не рекомендуется хранить в коде; используйте переменные окружения или профиль)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "aws_secret_key" {
  description = "AWS Secret Access Key (не рекомендуется хранить в коде)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "aws_session_token" {
  description = "AWS Session Token, если используется временная сессия."
  type        = string
  default     = ""
  sensitive   = true
}

variable "aws_shared_config_files" {
  description = "Кастомные пути к shared config files (~/.aws/config)."
  type        = list(string)
  default     = []
}

variable "aws_shared_credentials_files" {
  description = "Кастомные пути к shared credentials files (~/.aws/credentials)."
  type        = list(string)
  default     = []
}

variable "aws_assume_role" {
  description = <<-EOT
  Настройки AssumeRole для AWS:
  - role_arn: ARN роли
  - session_name: имя сессии
  - external_id: внешний идентификатор
  - duration_seconds: длительность сессии
  EOT
  type = object({
    role_arn         = optional(string)
    session_name     = optional(string)
    external_id      = optional(string)
    duration_seconds = optional(number)
  })
  default = {}
}

variable "aws_retries" {
  description = "Количество ретраев AWS SDK (0..10 рекомендованно по вашей политике)."
  type        = number
  default     = 5
  validation {
    condition     = var.aws_retries >= 0 && var.aws_retries <= 15
    error_message = "aws_retries должен быть в диапазоне 0..15."
  }
}

variable "aws_skip_credentials_validation" {
  description = "Пропустить проверку креденшелов (использовать осторожно)."
  type        = bool
  default     = false
}

variable "aws_skip_region_validation" {
  description = "Пропустить валидацию региона (использовать осторожно)."
  type        = bool
  default     = false
}

variable "aws_skip_requesting_account_id" {
  description = "Не запрашивать Account ID (ускоряет init, если доступ ограничен)."
  type        = bool
  default     = false
}

variable "aws_endpoints" {
  description = "Кастомные AWS endpoints (для локальных/проксированных окружений)."
  type        = map(string)
  default     = {}
}

variable "aws_default_tags" {
  description = "Теги по умолчанию для провайдера AWS."
  type        = map(string)
  default     = {}
}

############################
# Google provider
############################
variable "gcp_project" {
  description = "GCP Project ID."
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "Регион GCP."
  type        = string
  default     = "europe-north1"
}

variable "gcp_zone" {
  description = "Зона GCP."
  type        = string
  default     = ""
}

variable "gcp_credentials_json" {
  description = "Содержимое JSON ключа сервисного аккаунта (inlined). Предпочтительно — через переменные окружения/ Vault."
  type        = string
  default     = ""
  sensitive   = true
}

variable "gcp_credentials_file" {
  description = "Путь к файлу JSON с креденшелами. Пусто — автодетект."
  type        = string
  default     = ""
}

variable "gcp_impersonate_service_account" {
  description = "Имперсонация сервисного аккаунта: email аккаунта, если требуется."
  type        = string
  default     = ""
}

variable "gcp_access_token" {
  description = "Предоставленный access token вместо стандартной аутентификации."
  type        = string
  default     = ""
  sensitive   = true
}

variable "gcp_request_timeout_sec" {
  description = "Таймаут запросов GCP (сек)."
  type        = number
  default     = 120
  validation {
    condition     = var.gcp_request_timeout_sec >= 30 && var.gcp_request_timeout_sec <= 600
    error_message = "gcp_request_timeout_sec должен быть 30..600 сек."
  }
}

variable "gcp_user_project_override" {
  description = "Включить User Project Override для биллинга некоторых API."
  type        = bool
  default     = false
}

variable "gcp_labels" {
  description = "Метки по умолчанию для GCP ресурсов."
  type        = map(string)
  default     = {}
}

############################
# AzureRM provider
############################
variable "azure_subscription_id" {
  description = "Azure Subscription ID."
  type        = string
  default     = ""
}

variable "azure_tenant_id" {
  description = "Azure Tenant ID."
  type        = string
  default     = ""
}

variable "azure_client_id" {
  description = "Azure Client ID (Service Principal)."
  type        = string
  default     = ""
}

variable "azure_client_secret" {
  description = "Azure Client Secret (Service Principal)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "azure_use_msi" {
  description = "Использовать Managed Identity (MSI)."
  type        = bool
  default     = false
}

variable "azure_use_cli" {
  description = "Аутентификация через Azure CLI."
  type        = bool
  default     = false
}

variable "azure_environment" {
  description = "Имя облачной среды Azure (Public, ChinaCloud, GermanCloud, USGovernment и т.п.)."
  type        = string
  default     = "public"
}

variable "azure_auxiliary_tenants" {
  description = "Список дополнительных tenants для кросс-тенантных сценариев."
  type        = list(string)
  default     = []
}

variable "azure_features" {
  description = <<-EOT
  Тонкие настройки features {} провайдера:
  - key_vault_purge_soft_delete_on_destroy (bool)
  - key_vault_recover_soft_deleted_key_vaults (bool)
  - resource_group_prevent_deletion_if_contains_resources (bool)
  - vnet_use_legacy_registration (bool)
  EOT
  type = object({
    key_vault_purge_soft_delete_on_destroy                   = optional(bool)
    key_vault_recover_soft_deleted_key_vaults                = optional(bool)
    resource_group_prevent_deletion_if_contains_resources    = optional(bool)
    vnet_use_legacy_registration                             = optional(bool)
  })
  default = {}
}

variable "azure_disable_telemetry" {
  description = "Отключить телеметрию провайдера."
  type        = bool
  default     = true
}

variable "azure_default_tags" {
  description = "Теги по умолчанию для Azure ресурсов."
  type        = map(string)
  default     = {}
}

############################
# Kubernetes provider
############################
variable "kube_host" {
  description = "Kubernetes API сервер (https://...)."
  type        = string
  default     = ""
}

variable "kube_ca_cert" {
  description = "Баз64 PEM CA серт кластера."
  type        = string
  default     = ""
}

variable "kube_token" {
  description = "Bearer-токен для аутентификации."
  type        = string
  default     = ""
  sensitive   = true
}

variable "kube_client_cert" {
  description = "Клиентский сертификат (base64 PEM)."
  type        = string
  default     = ""
}

variable "kube_client_key" {
  description = "Клиентский приватный ключ (base64 PEM)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "kube_config_path" {
  description = "Путь к kubeconfig. Пусто — использовать переменные выше или автодетект."
  type        = string
  default     = ""
}

variable "kube_config_context" {
  description = "Контекст kubeconfig, если используется kube_config_path."
  type        = string
  default     = ""
}

variable "kube_insecure" {
  description = "Разрешить небезопасное соединение (skip TLS verify). Не рекомендуется."
  type        = bool
  default     = false
}

variable "kube_exec_auth" {
  description = <<-EOT
  Exec-аутентификация (например, gcloud, aws eks get-token):
  - command: строка команды
  - args: список аргументов
  - env: карта переменных окружения
  - api_version: версия client.authentication.k8s.io/*
  EOT
  type = object({
    command     = optional(string)
    args        = optional(list(string))
    env         = optional(map(string))
    api_version = optional(string)
  })
  default = {}
}

variable "kube_load_config_file" {
  description = "Загружать ли kubeconfig файл (true) или использовать inlined параметры (false)."
  type        = bool
  default     = true
}

variable "kube_timeout_seconds" {
  description = "Таймаут клиентских запросов к Kubernetes API (сек)."
  type        = number
  default     = 120
  validation {
    condition     = var.kube_timeout_seconds >= 30 && var.kube_timeout_seconds <= 600
    error_message = "kube_timeout_seconds должен быть 30..600."
  }
}

############################
# Helm provider
############################
variable "helm_kube_namespace" {
  description = "Namespace по умолчанию для релизов Helm."
  type        = string
  default     = "default"
}

variable "helm_registry_config" {
  description = "Путь к файлу реестра Helm (registry.json)."
  type        = string
  default     = ""
}

variable "helm_repository_cache" {
  description = "Путь к локальному кэшу репозиториев Helm."
  type        = string
  default     = ""
}

variable "helm_repository_config" {
  description = "Путь к файлу конфигурации репозиториев Helm."
  type        = string
  default     = ""
}

############################
# Defensive validations (meta)
############################
variable "enable_strict_validations" {
  description = "Включить дополнительные проверки согласованности переменных."
  type        = bool
  default     = true
}

############################
# Optional cross-cutting timeouts/retries (generic)
############################
variable "generic_request_timeout_sec" {
  description = "Единый таймаут запросов (если поддерживается провайдером), сек."
  type        = number
  default     = 120
}

variable "generic_max_retries" {
  description = "Единое число ретраев (если поддерживается провайдером)."
  type        = number
  default     = 5
  validation {
    condition     = var.generic_max_retries >= 0 && var.generic_max_retries <= 15
    error_message = "generic_max_retries должен быть 0..15."
  }
}
