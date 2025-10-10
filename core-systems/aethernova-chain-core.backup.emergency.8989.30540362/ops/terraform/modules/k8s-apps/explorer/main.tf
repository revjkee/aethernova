# Path: aethernova-chain-core/ops/terraform/modules/k8s-apps/explorer/main.tf
# Purpose: Промышленное развёртывание узла Erigon (RPC) и стека Blockscout (индексер+API+UI)
# Notes:
# - Оба приложения устанавливаются через Helm из официальных репозиториев.
# - Blockscout получает RPC-эндвойинты Erigon через ENV (HTTP/TRACE/WS).
# - Для БД указывается DATABASE_URL (например, управляемый Postgres). 
#   Чарт Blockscout-Stack поддерживает backend+frontend+stats; ENV передаются в контейнеры.
# - Порядок: namespace -> Erigon -> Blockscout.
# - Включены таймауты/atomic/wait для предсказуемых установок.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.23.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.11.0"
    }
  }
}

# ---------------------------
# Variables
# ---------------------------

variable "kubeconfig_path" {
  description = "Путь к kubeconfig"
  type        = string
  default     = "~/.kube/config"
}

variable "namespace" {
  description = "Namespace для explorer-стека"
  type        = string
  default     = "explorer"
}

variable "erigon_chart_version" {
  description = "Версия чарта erigon из ethpandaops (опционально)"
  type        = string
  default     = ""
}

variable "blockscout_stack_chart_version" {
  description = "Версия чарта blockscout-stack (опционально)"
  type        = string
  default     = ""
}

variable "chain_id" {
  description = "EVM Chain ID (целое)"
  type        = number
  default     = 1
}

variable "network_name" {
  description = "Человекочитаемое имя сети (NETWORK)"
  type        = string
  default     = "Ethereum"
}

variable "subnetwork_name" {
  description = "Подсеть/вариант сети (SUBNETWORK)"
  type        = string
  default     = "Mainnet"
}

variable "coin_symbol" {
  description = "Символ нативной монеты (COIN_NAME)"
  type        = string
  default     = "ETH"
}

variable "database_url" {
  description = "Строка подключения к Postgres для Blockscout (DATABASE_URL)"
  type        = string
  sensitive   = true
}

variable "secret_key_base" {
  description = "SECRET_KEY_BASE для Blockscout backend"
  type        = string
  sensitive   = true
}

variable "frontend_host" {
  description = "Публичный хост Blockscout UI (NEXT_PUBLIC_APP_HOST), например https://explorer.example.com"
  type        = string
  default     = "http://localhost:3000"
}

# ---------------------------
# Providers
# ---------------------------

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig_path
  }
}

# ---------------------------
# Namespace
# ---------------------------

resource "kubernetes_namespace" "explorer" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name"       = "explorer"
      "app.kubernetes.io/part-of"    = "aethernova-chain-core"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
}

# ---------------------------
# Erigon (Execution client + RPC)
# Repo: https://ethpandaops.github.io/ethereum-helm-charts
# Chart: erigon
# ---------------------------

resource "helm_release" "erigon" {
  name             = "erigon"
  namespace        = var.namespace
  repository       = "https://ethpandaops.github.io/ethereum-helm-charts"
  chart            = "erigon"
  # version        = var.erigon_chart_version != "" ? var.erigon_chart_version : null

  create_namespace  = false
  atomic            = true
  cleanup_on_fail   = true
  dependency_update = true
  wait              = true
  timeout           = 1200

  # Значения по-умолчанию чарта адекватны; при необходимости добавляйте настройки сети/хранилища.
  # Ниже — пример безопасных опций сервиса (без NodePort/Ingress).
  values = [
    yamlencode({
      service = {
        type = "ClusterIP"
      }
      # Примечание: конкретные ключи конфигурации сети/пиров задаются по документации чарта ethpandaops.
      # Документация/список чартов подтверждены официальным репозиторием.
    })
  ]

  depends_on = [kubernetes_namespace.explorer]
}

# Локальные DNS-имена сервисов Erigon (предполагаемые стандартные порты RPC/WS).
# Конкретные имена и порты ориентированы на типичные значения JSON-RPC (8545/8546).
locals {
  erigon_rpc_http = "http://erigon.${var.namespace}.svc.cluster.local:8545"
  erigon_rpc_ws   = "ws://erigon.${var.namespace}.svc.cluster.local:8546"
  erigon_trace    = local.erigon_rpc_http
}

# ---------------------------
# Blockscout Stack (Indexer + API + UI)
# Repo: https://blockscout.github.io/helm-charts
# Chart: blockscout-stack  (включает backend, frontend и stats)
# ---------------------------

resource "helm_release" "blockscout_stack" {
  name             = "blockscout-stack"
  namespace        = var.namespace
  repository       = "https://blockscout.github.io/helm-charts"
  chart            = "blockscout-stack"
  # version        = var.blockscout_stack_chart_version != "" ? var.blockscout_stack_chart_version : null

  create_namespace  = false
  atomic            = true
  cleanup_on_fail   = true
  dependency_update = true
  wait              = true
  timeout           = 1800

  # Передаём ENV в backend (индексер+API) и frontend согласно документации Blockscout.
  # DATABASE_URL обязателен; RPC URL/WS/TRACE — по страницам ENV Variables.
  values = [
    yamlencode({
      blockscout = {
        env = [
          { name = "DATABASE_URL",                     value = var.database_url },
          { name = "SECRET_KEY_BASE",                  value = var.secret_key_base },
          { name = "CHAIN_ID",                         value = tostring(var.chain_id) },
          { name = "NETWORK",                          value = var.network_name },
          { name = "SUBNETWORK",                       value = var.subnetwork_name },
          { name = "COIN_NAME",                        value = var.coin_symbol },
          { name = "ETHEREUM_JSONRPC_HTTP_URL",        value = local.erigon_rpc_http },
          { name = "ETHEREUM_JSONRPC_TRACE_URL",       value = local.erigon_trace },
          { name = "ETHEREUM_JSONRPC_WS_URL",          value = local.erigon_rpc_ws },
          # При необходимости можно использовать *_URLS для множественных RPC.
          # См. Backend ENVs: Common.
          { name = "API_V2_ENABLED",                   value = "true" }
        ]
      }
      frontend = {
        env = [
          { name = "NEXT_PUBLIC_APP_HOST", value = var.frontend_host }
        ]
        # Включение ingress/hostов выполняйте здесь, если требуется публичный доступ.
        # Конкретные ключи ingress зависят от версии чарта.
      }
      # По умолчанию чарт поставляет backend+frontend+stats; дополнительные сервисы настраиваются через values чарта.
    })
  ]

  depends_on = [helm_release.erigon]
}

# ---------------------------
# Outputs
# ---------------------------

output "explorer_namespace" {
  description = "Namespace с установленным explorer-стеком"
  value       = var.namespace
}

output "erigon_http_rpc" {
  description = "Внутренний HTTP RPC от Erigon для Blockscout"
  value       = local.erigon_rpc_http
}

output "blockscout_ui_hint" {
  description = "Подсказка по внешнему хосту UI"
  value       = var.frontend_host
}
