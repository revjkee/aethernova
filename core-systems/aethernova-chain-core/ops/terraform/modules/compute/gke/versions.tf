###############################################
# modules/compute/gke/versions.tf
# Industrial-grade GKE version resolution
#
# SOURCES:
# - Data source: google_container_engine_versions
#   https://registry.terraform.io/providers/hashicorp/google/latest/docs/data-sources/container_engine_versions
# - Provider release note (adds release_channel_default_version)
#   https://newreleases.io/project/github/hashicorp/terraform-provider-google/release/v3.35.0
# - GKE Release Channels (concepts/how-to) and current versions
#   https://cloud.google.com/kubernetes-engine/docs/concepts/release-channels
#   https://cloud.google.com/kubernetes-engine/docs/how-to/release-channels
#   https://cloud.google.com/kubernetes-engine/docs/release-notes
# - google_container_cluster supports release_channel
#   https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster
###############################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      # 7.0 GA доступен; ставим гибкое ограничение для совместимости.
      version = ">= 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.0"
    }
  }
}

############################
# Inputs
############################

variable "project_id" {
  description = "GCP Project ID."
  type        = string
}

variable "location" {
  description = "Region или zone для кластера (поддерживается data source)."
  type        = string
}

variable "release_channel" {
  description = "Канал релизов GKE: RAPID | REGULAR | STABLE | EXTENDED."
  type        = string
  default     = "REGULAR"
}

variable "version_prefix" {
  description = "Префикс версии (например, \"1.29.\"), чтобы брать latest внутри мажор-минор."
  type        = string
  default     = null
}

variable "pin_master_version" {
  description = "Жестко зафиксировать версию master (если задано — игнорируются другие стратегии)."
  type        = string
  default     = null
}

variable "pin_node_version" {
  description = "Жестко зафиксировать версию node (если не задано — вычисляется логикой ниже)."
  type        = string
  default     = null
}

variable "prefer_node_version_from_master" {
  description = "Если true — выставлять node_version = выбранный master_version."
  type        = bool
  default     = true
}

############################
# Data sources
############################

# Полный набор версий для локации
data "google_container_engine_versions" "full" {
  provider = google-beta
  project  = var.project_id
  # data source поддерживает единое поле location (region/zone)
  # (исторические доки показывают zone, новые — location; используем актуальное поле)
  location = var.location
}

# Ограниченный по префиксу набор версий (если задан version_prefix)
data "google_container_engine_versions" "prefix" {
  count    = var.version_prefix == null ? 0 : 1
  provider = google-beta
  project  = var.project_id
  location = var.location

  # argument version_prefix задокументирован в провайдере; помогает выбрать latest в рамках минорной ветки
  version_prefix = var.version_prefix
}

############################
# Locals: compute strategy
############################

locals {
  # Канал (верхним регистром как в API)
  channel_key = upper(var.release_channel)

  # Карты версий по каналам (могут отсутствовать в некоторых версиях провайдера; используем try)
  channel_default_map = try(data.google_container_engine_versions.full.release_channel_default_version, {})
  channel_latest_map  = try(data.google_container_engine_versions.full.release_channel_latest_version, {})

  # Кандидаты master по приоритету:
  # 1) ручной пин
  # 2) latest по префиксу (latest_master_version из prefix data source)
  # 3) latest по каналу (если доступен)
  # 4) default по каналу
  # 5) default_cluster_version (дефолт сервиса)
  master_candidate_manual      = var.pin_master_version
  master_candidate_prefix      = try(data.google_container_engine_versions.prefix[0].latest_master_version, null)
  master_candidate_channel_lat = try(local.channel_latest_map[local.channel_key], null)
  master_candidate_channel_def = try(local.channel_default_map[local.channel_key], null)
  master_candidate_service_def = try(data.google_container_engine_versions.full.default_cluster_version, null)

  # Итоговая версия master
  master_version = coalesce(
    local.master_candidate_manual,
    local.master_candidate_prefix,
    local.master_candidate_channel_lat,
    local.master_candidate_channel_def,
    local.master_candidate_service_def
  )

  # Список валидных версий по локации
  valid_master_versions = try(data.google_container_engine_versions.full.valid_master_versions, [])
  valid_node_versions   = try(data.google_container_engine_versions.full.valid_node_versions, [])

  # Проверка, что выбранная master входит в валидные
  master_version_valid = contains(local.valid_master_versions, local.master_version)

  # Кандидаты node:
  node_candidate_manual  = var.pin_node_version
  node_candidate_prefix  = try(data.google_container_engine_versions.prefix[0].latest_node_version, null)
  node_candidate_service = try(data.google_container_engine_versions.full.default_node_version, null)

  # Итоговая версия node
  node_version = coalesce(
    local.node_candidate_manual,
    var.prefer_node_version_from_master ? local.master_version : null,
    local.node_candidate_prefix,
    local.node_candidate_service,
    local.master_version
  )

  node_version_valid = contains(local.valid_node_versions, local.node_version)

  # Диагностика выбранной стратегии
  strategy = (
    local.master_version == local.master_candidate_manual      ? "manual_pin" :
    local.master_version == local.master_candidate_prefix      ? "prefix_latest" :
    local.master_version == local.master_candidate_channel_lat ? "channel_latest" :
    local.master_version == local.master_candidate_channel_def ? "channel_default" :
    "service_default"
  )
}

############################
# Outputs
############################

output "gke_master_version" {
  description = "Итоговая версия master Kubernetes для GKE."
  value       = local.master_version
}

output "gke_node_version" {
  description = "Итоговая версия node Kubernetes для GKE."
  value       = local.node_version
}

output "gke_version_strategy" {
  description = "Как выбрана версия: manual_pin | prefix_latest | channel_latest | channel_default | service_default."
  value       = local.strategy
}

output "gke_release_channel_key" {
  description = "Используемый канал релизов (верхний регистр)."
  value       = local.channel_key
}

output "gke_valid_master_versions" {
  description = "Список валидных master версий в данной локации."
  value       = local.valid_master_versions
}

output "gke_valid_node_versions" {
  description = "Список валидных node версий в данной локации."
  value       = local.valid_node_versions
}

output "gke_channel_default_map" {
  description = "Карта дефолтных версий по каналам (если доступно в провайдере)."
  value       = local.channel_default_map
}

output "gke_channel_latest_map" {
  description = "Карта latest версий по каналам (если доступно в провайдере)."
  value       = local.channel_latest_map
}

output "gke_version_validity" {
  description = "Флаги валидности выбранных master/node относительно списков провайдера."
  value = {
    master = local.master_version_valid
    node   = local.node_version_valid
  }
}
