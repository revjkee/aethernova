terraform {
  # Требования к версии Terraform CLI (фиксируем 1.x)
  # Docs: version constraints & terraform block
  # https://developer.hashicorp.com/terraform/language/expressions/version-constraints
  # https://developer.hashicorp.com/terraform/language/terraform
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    # Kubernetes provider (управление K8s-ресурсами)
    # Registry: https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.30.0, < 3.0.0"
    }

    # Helm provider (управление чартами; поддержка Helm 3 подтверждена)
    # Registry: https://registry.terraform.io/providers/hashicorp/helm/latest/docs
    helm = {
      source  = "hashicorp/helm"
      version = ">= 3.0.0, < 4.0.0"
    }

    # Утилитарные провайдеры без сложной конфигурации
    # Time: https://registry.terraform.io/providers/hashicorp/time/latest/docs
    time = {
      source  = "hashicorp/time"
      version = ">= 0.11.0"
    }
    # Random: https://registry.terraform.io/providers/hashicorp/random/latest
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}

############################################
# ВХОДНЫЕ ДАННЫЕ ДЛЯ DEFAULT-КОНФИГУРАЦИИ
############################################

variable "kubeconfig_path" {
  description = "Путь к kubeconfig (если задан — используется им)."
  type        = string
  default     = null
}
variable "kubeconfig_context" {
  description = "Kubeconfig context (опционально)."
  type        = string
  default     = null
}

variable "kube_host" {
  description = "API-адрес кластера (используется, если kubeconfig не задан)."
  type        = string
  default     = null
}
variable "kube_cluster_ca_certificate" {
  description = "PEM CA сертификат кластера (Base64/PEM)."
  type        = string
  default     = null
  sensitive   = true
}
variable "kube_token" {
  description = "Bearer-токен для аутентификации."
  type        = string
  default     = null
  sensitive   = true
}
variable "kube_client_certificate" {
  description = "PEM клиентский сертификат (mTLS)."
  type        = string
  default     = null
  sensitive   = true
}
variable "kube_client_key" {
  description = "PEM приватный ключ клиента (mTLS)."
  type        = string
  default     = null
  sensitive   = true
}

############################################
# ВХОДНЫЕ ДАННЫЕ ДЛЯ MGMT-АЛИАСА (ВТОРОЙ КЛАСТЕР)
############################################

variable "mgmt_kubeconfig_path" {
  description = "Kubeconfig для управляемого (mgmt) кластера."
  type        = string
  default     = null
}
variable "mgmt_kubeconfig_context" {
  description = "Kubeconfig context (mgmt)."
  type        = string
  default     = null
}

variable "mgmt_kube_host" {
  description = "API-адрес mgmt-кластера."
  type        = string
  default     = null
}
variable "mgmt_kube_cluster_ca_certificate" {
  description = "PEM CA сертификат mgmt-кластера."
  type        = string
  default     = null
  sensitive   = true
}
variable "mgmt_kube_token" {
  description = "Bearer-токен mgmt-кластера."
  type        = string
  default     = null
  sensitive   = true
}
variable "mgmt_kube_client_certificate" {
  description = "PEM клиентский сертификат (mgmt)."
  type        = string
  default     = null
  sensitive   = true
}
variable "mgmt_kube_client_key" {
  description = "PEM приватный ключ клиента (mgmt)."
  type        = string
  default     = null
  sensitive   = true
}

############################
# PROVIDER: KUBERNETES (default)
############################
provider "kubernetes" {
  # Вариант 1: kubeconfig (самый простой)
  # Вариант 2: прямые параметры (host + TLS/Token)
  host                   = var.kube_host
  cluster_ca_certificate = var.kube_cluster_ca_certificate
  token                  = var.kube_token
  client_certificate     = var.kube_client_certificate
  client_key             = var.kube_client_key

  config_path    = var.kubeconfig_path
  config_context = var.kubeconfig_context
}

############################
# PROVIDER: HELM (default)
############################
provider "helm" {
  # Helm использует встроенный блок kubernetes со схожими параметрами
  # Docs: Helm provider + kubeconfig/config_path
  kubernetes {
    host                   = var.kube_host
    cluster_ca_certificate = var.kube_cluster_ca_certificate
    token                  = var.kube_token
    client_certificate     = var.kube_client_certificate
    client_key             = var.kube_client_key

    config_path    = var.kubeconfig_path
    config_context = var.kubeconfig_context
  }
}

############################
# PROVIDER: KUBERNETES (mgmt alias)
############################
provider "kubernetes" {
  alias = "mgmt"

  host                   = var.mgmt_kube_host
  cluster_ca_certificate = var.mgmt_kube_cluster_ca_certificate
  token                  = var.mgmt_kube_token
  client_certificate     = var.mgmt_kube_client_certificate
  client_key             = var.mgmt_kube_client_key

  config_path    = var.mgmt_kubeconfig_path
  config_context = var.mgmt_kubeconfig_context
}

############################
# PROVIDER: HELM (mgmt alias)
############################
provider "helm" {
  alias = "mgmt"

  kubernetes {
    host                   = var.mgmt_kube_host
    cluster_ca_certificate = var.mgmt_kube_cluster_ca_certificate
    token                  = var.mgmt_kube_token
    client_certificate     = var.mgmt_kube_client_certificate
    client_key             = var.mgmt_kube_client_key

    config_path    = var.mgmt_kubeconfig_path
    config_context = var.mgmt_kubeconfig_context
  }
}

# ПРИМЕЧАНИЕ:
# — Чтобы child-модули могли использовать алиасы провайдеров,
#   объявляйте у них configuration_aliases и передавайте провайдеры через meta-аргумент "providers".
#   Docs: Providers Within Modules & Using an alternate provider configuration.
#   https://developer.hashicorp.com/terraform/language/modules/develop/providers
#   https://developer.hashicorp.com/terraform/language/block/provider
