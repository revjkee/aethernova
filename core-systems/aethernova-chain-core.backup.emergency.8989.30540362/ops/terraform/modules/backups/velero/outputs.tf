/************************************************************
 * Velero — outputs.tf (industrial-grade)
 * Экспортирует:
 *  - Helm release метаданные (имя/namespace/версия/статус/чарт)
 *  - Namespace Velero
 *  - Cекрет с провайдерскими кредами (только ссылка, без значений)
 *  - CRD Velero: BackupStorageLocation, VolumeSnapshotLocation, Schedule
 *    (как карты с name/spec из kubernetes_manifest.object)
 ************************************************************/

/* ---------- Helm release ---------- */

output "velero_helm_release" {
  description = "Метаданные Helm-релиза Velero."
  value = {
    name      = helm_release.velero.name
    namespace = helm_release.velero.namespace
    chart     = helm_release.velero.chart
    version   = try(helm_release.velero.version, null)
    status    = try(helm_release.velero.status, null)
    repository = try(helm_release.velero.repository, null)
  }
}

/* ---------- Namespace ---------- */

output "velero_namespace" {
  description = "Имя namespace, в котором развёрнут Velero."
  value       = kubernetes_namespace.velero.metadata[0].name
}

/* ---------- Provider credentials secret (reference only) ---------- */

output "velero_credentials_secret" {
  description = "Ссылка на Secret с облачными кредами Velero (без раскрытия данных)."
  value = {
    name      = kubernetes_secret.velero_credentials.metadata[0].name
    namespace = try(kubernetes_secret.velero_credentials.metadata[0].namespace, null)
    type      = try(kubernetes_secret.velero_credentials.type, null)
  }
  sensitive = false
}

/* ---------- BackupStorageLocations (CRD) ---------- */

output "velero_backup_storage_locations" {
  description = "Карта BSL (BackupStorageLocation): <key> -> { name, spec }."
  value = {
    for k, v in kubernetes_manifest.velero_bsl :
    k => {
      name = v.object.metadata.name
      spec = v.object.spec
    }
  }
}

/* ---------- VolumeSnapshotLocations (CRD) ---------- */

output "velero_volume_snapshot_locations" {
  description = "Карта VSL (VolumeSnapshotLocation): <key> -> { name, spec }."
  value = {
    for k, v in kubernetes_manifest.velero_vsl :
    k => {
      name = v.object.metadata.name
      spec = v.object.spec
    }
  }
}

/* ---------- Schedules (CRD) ---------- */

output "velero_schedules" {
  description = "Карта расписаний бэкапов: <key> -> { name, schedule (cron), template }."
  value = {
    for k, v in kubernetes_manifest.velero_schedule :
    k => {
      name      = v.object.metadata.name
      schedule  = try(v.object.spec.schedule, null)
      template  = try(v.object.spec.template, null)
    }
  }
}

/* ---------- Derived summaries ---------- */

output "velero_default_bsl_name" {
  description = "Имя BSL по умолчанию (если создан и именован 'default', как рекомендует Velero)."
  value       = try(kubernetes_manifest.velero_bsl["default"].object.metadata.name, null)
}

output "velero_backup_targets" {
  description = "Сводка целевых хранилищ резервных копий: список provider/bucket(or prefix)/region, если доступны в spec."
  value = [
    for _, v in kubernetes_manifest.velero_bsl : {
      name     = v.object.metadata.name
      provider = try(v.object.spec.provider, null)
      bucket   = try(v.object.spec.objectStorage.bucket, null)
      prefix   = try(v.object.spec.objectStorage.prefix, null)
      region   = try(v.object.spec.config.region, null)
    }
  ]
}
