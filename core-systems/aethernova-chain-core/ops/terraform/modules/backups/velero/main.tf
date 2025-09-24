###############################################################################
# AETHERNOVA — modules/backups/velero/main.tf
#
# Устанавливает Velero через официальный Helm-чарт (vmware-tanzu/velero),
# подключает плагин object-store/snapshotter (AWS | GCP | Azure),
# создаёт BackupStorageLocation/VolumeSnapshotLocation и опциональный Schedule.
#
# Проверяемые источники:
# - Официальный Helm-репозиторий VMware Tanzu (velero chart): 
#   https://vmware-tanzu.github.io/helm-charts                                    # :contentReference[oaicite:5]{index=5}
# - Креды через Helm values (secret name cloud-credentials, key cloud): 
#   https://velero.io/docs/main/troubleshooting/                                   # :contentReference[oaicite:6]{index=6}
#   https://velero.io/docs/v1.0.0/install-overview/                                # :contentReference[oaicite:7]{index=7}
# - BackupStorageLocation/VolumeSnapshotLocation (назначение и поля config): 
#   https://velero.io/docs/main/locations/                                         # :contentReference[oaicite:8]{index=8}
#   https://velero.io/docs/v1.9/api-types/backupstoragelocation/                   # :contentReference[oaicite:9]{index=9}
# - Init-контейнеры плагинов и официальные образы:
#   AWS:  https://hub.docker.com/r/velero/velero-plugin-for-aws                    # :contentReference[oaicite:10]{index=10}
#         https://github.com/vmware-tanzu/velero-plugin-for-aws                    # :contentReference[oaicite:11]{index=11}
#   GCP:  https://hub.docker.com/r/velero/velero-plugin-for-gcp                    # :contentReference[oaicite:12]{index=12}
#         https://github.com/vmware-tanzu/velero-plugin-for-gcp                    # :contentReference[oaicite:13]{index=13}
#   Azure:https://github.com/vmware-tanzu/velero-plugin-for-microsoft-azure        # :contentReference[oaicite:14]{index=14}
#         https://hub.docker.com/r/velero/velero-plugin-for-microsoft-azure/tags   # :contentReference[oaicite:15]{index=15}
# - Node Agent вместо устаревшего --use-restic: 
#   https://github.com/vmware-tanzu/velero/discussions/7888                        # :contentReference[oaicite:16]{index=16}
###############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.11.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20.0"
    }
  }
}

#######################
# ВХОДНЫЕ ПЕРЕМЕННЫЕ  #
#######################

variable "namespace" {
  description = "Namespace, куда устанавливается Velero."
  type        = string
  default     = "velero"
}

variable "helm_chart_version" {
  description = "Версия Helm-чарта vmware-tanzu/velero."
  type        = string
  # Не могу подтвердить это: «последняя» версия без проверки. Укажите конкретную, проверенную под ваш кластер.
  default     = null
}

variable "provider" {
  description = "Целевой провайдер плагина: aws | gcp | azure"
  type        = string
}

variable "bucket" {
  description = "Имя бакета/контейнера object-store для backup storage (S3/GCS/Blob)."
  type        = string
}

variable "bsl_name" {
  description = "Имя BackupStorageLocation (обычно default)."
  type        = string
  default     = "default"
}

variable "prefix" {
  description = "Префикс в бакете для артефактов Velero (опционально)."
  type        = string
  default     = null
}

variable "bsl_config" {
  description = <<-EOT
  Provider-specific config map для BSL.
  Примеры:
  - AWS/S3-совместимые: { region = "us-east-1", s3ForcePathStyle = "true", s3Url = "https://s3.example.com" }
  - GCP: обычно не требуется, достаточно bucket (см. docs провайдера).
  - Azure: { resourceGroup = "...", storageAccount = "..." } и т.п.
  См. поля 'config' у BackupStorageLocation.                                               
  EOT
  type        = map(string)
  default     = {}
}

variable "vsl_enabled" {
  description = "Создавать VolumeSnapshotLocation (если у вас есть снапшоты дисков)."
  type        = bool
  default     = false
}

variable "vsl_name" {
  description = "Имя VolumeSnapshotLocation."
  type        = string
  default     = "default"
}

variable "vsl_config" {
  description = "Provider-specific config для VSL (например, region для AWS/Azure)."
  type        = map(string)
  default     = {}
}

variable "cloud_credentials" {
  description = <<-EOT
  Содержимое секрета 'cloud-credentials' (ключ 'cloud'), которое чарт смонтирует в /credentials/cloud.
  Формат — согласно документации вашего плагина (AWS: INI c aws_access_key_id/...; GCP: JSON сервис-аккаунта; Azure: env-пары).
  Чарт принимает это через values: credentials.secretContents.cloud.                                                        
  EOT
  type      = string
  sensitive = true
}

variable "deploy_node_agent" {
  description = "Устанавливать Velero Node Agent (файловые бэкапы PV) — современная замена устаревшему --use-restic."
  type        = bool
  default     = true
}

variable "uploader_type" {
  description = "Тип uploader'а для файловых бэкапов (например, Kopia | Restic)."
  type        = string
  default     = "Kopia"
}

variable "plugin_image_overrides" {
  description = <<-EOT
  Переопределение образов плагинов (initContainers). По умолчанию — официальные velero/*.
  Ключи: aws|gcp|azure. Значение — образ:тег.
  EOT
  type = map(string)
  default = {
    aws   = "velero/velero-plugin-for-aws:v1.10.0"
    gcp   = "velero/velero-plugin-for-gcp:v1.12.2"
    azure = "velero/velero-plugin-for-microsoft-azure:v1.13.0"
  }
}

variable "pod_annotations" {
  description = "Доп. аннотации для Pod Velero/NodeAgent."
  type        = map(string)
  default     = {}
}

variable "pod_labels" {
  description = "Доп. метки для Pod Velero/NodeAgent."
  type        = map(string)
  default     = {}
}

# Опциональный расписанный бэкап (Schedule CR)
variable "enable_schedule" {
  description = "Создавать velero.io/v1 Schedule (регулярный бэкап)."
  type        = bool
  default     = false
}

variable "schedule_cron" {
  description = "CRON-расписание (мин час день месяц деньНедели), напр. '0 2 * * *' — ежедневно в 02:00."
  type        = string
  default     = "0 2 * * *"
}

variable "schedule_ttl" {
  description = "TTL бэкапа, напр. '168h' (7 суток)."
  type        = string
  default     = "168h"
}

variable "included_namespaces" {
  description = "Список включённых пространств имён ('*' = все)."
  type        = list(string)
  default     = ["*"]
}

variable "excluded_namespaces" {
  description = "Список исключённых пространств имён."
  type        = list(string)
  default     = []
}

variable "labels" {
  description = "Общие метки для ресурсов Helm release."
  type        = map(string)
  default     = {}
}

#################
# ЛОКАЛЬНЫЕ ДАННЫЕ
#################

locals {
  plugin_image = coalesce(
    var.plugin_image_overrides[var.provider],
    var.plugin_image_overrides["aws"]
  )

  init_containers = [
    {
      name            = "velero-plugin-for-${var.provider}"
      image           = local.plugin_image
      imagePullPolicy = "IfNotPresent"
      volumeMounts = [
        {
          mountPath = "/target"   # стандартный путь для копирования плагина в shared volume "plugins"
          name      = "plugins"
        }
      ]
    }
  ]

  # Полная карта значений для Helm-чарта, см. репозиторий vmware-tanzu/helm-charts.
  values_map = {
    initContainers   = local.init_containers
    deployNodeAgent  = var.deploy_node_agent  # замена --use-restic; см. обсуждение maintainers
    uploaderType     = var.uploader_type
    podAnnotations   = var.pod_annotations
    podLabels        = var.pod_labels

    credentials = {
      useSecret      = true
      secretContents = { cloud = var.cloud_credentials } # создаст Secret 'cloud-credentials' c ключом 'cloud'
    }

    configuration = {
      provider = var.provider
      backupStorageLocation = [
        merge({
          name    = var.bsl_name
          provider= var.provider
          bucket  = var.bucket
          default = true
        },
        var.prefix == null ? {} : { prefix = var.prefix },
        { config = var.bsl_config })
      ]
      volumeSnapshotLocation = var.vsl_enabled ? [
        {
          name     = var.vsl_name
          provider = var.provider
          config   = var.vsl_config
        }
      ] : []
    }
  }
}

###############
# РЕСУРСЫ
###############

resource "helm_release" "velero" {
  name             = "velero"
  repository       = "https://vmware-tanzu.github.io/helm-charts"
  chart            = "velero"
  namespace        = var.namespace
  create_namespace = true

  # Фиксируйте версию чарта под вашу версию Velero/K8s.
  version = var.helm_chart_version

  # Передаём values одной структурой через yamlencode — надёжнее, чем 'set' по одному полю.
  values = [yamlencode(local.values_map)]

  # Метки релиза (в Helm annotations/labels можно пробросить частично)
  metadata {
    labels = var.labels
  }
}

#############################################
# ОПЦИОНАЛЬНО: Schedule CR для регулярных бэкапов
# CRD устанавливаются чартом Velero (см. release-инструкции проекта).
# После установки чарта можно создавать CR velero.io/v1/Schedule.
# :contentReference[oaicite:17]{index=17}
#############################################

resource "kubernetes_manifest" "velero_schedule" {
  count = var.enable_schedule ? 1 : 0

  manifest = {
    apiVersion = "velero.io/v1"
    kind       = "Schedule"
    metadata = {
      name      = "cluster-daily"
      namespace = var.namespace
      labels    = var.labels
    }
    spec = {
      schedule = var.schedule_cron
      template = {
        includedNamespaces = var.included_namespaces
        excludedNamespaces = var.excluded_namespaces
        ttl                = var.schedule_ttl
        backupLocation     = var.bsl_name
        # при необходимости можно добавить: snapshotVolumes, defaultVolumesToFsBackup, hooks и пр.
      }
    }
  }

  depends_on = [helm_release.velero]
}
