############################################
# outputs.tf — Google Artifact Registry (GAR)
# Модуль: aethernova-chain-core/ops/terraform/modules/registry/gar
# Промышленный набор output'ов с безопасными try()/coalesce()
############################################

locals {
  gar_location = coalesce(
    try(google_artifact_registry_repository.gar.location, null),
    try(var.location, null)
  )

  gar_project = coalesce(
    try(google_artifact_registry_repository.gar.project, null),
    try(var.project, null)
  )

  gar_repo_id = coalesce(
    try(google_artifact_registry_repository.gar.repository_id, null),
    try(google_artifact_registry_repository.gar.name, null) != null ?
      regex("^projects/.+/locations/.+/repositories/(.+)$", google_artifact_registry_repository.gar.name)[0] :
      null
  )

  gar_format = try(google_artifact_registry_repository.gar.format, null)

  docker_host  = local.gar_location != null ? format("%s-docker.pkg.dev", local.gar_location) : null
  generic_host = local.gar_location != null ? format("%s.pkg.dev", local.gar_location)         : null

  # Полные пути репозитория
  docker_repo_url  = (local.docker_host  != null && local.gar_project != null && local.gar_repo_id != null) ? format("%s/%s/%s", local.docker_host,  local.gar_project, local.gar_repo_id) : null
  generic_repo_url = (local.generic_host != null && local.gar_project != null && local.gar_repo_id != null) ? format("%s/%s/%s", local.generic_host, local.gar_project, local.gar_repo_id) : null

  # Универсальная «основная» ссылка в зависимости от формата
  primary_repo_url = (
    local.gar_format == "DOCKER" || local.gar_format == "OCI"
  ) ? local.docker_repo_url : local.generic_repo_url
}

############################################
# Базовые идентификаторы/атрибуты
############################################

output "repository_name" {
  description = "Полное имя ресурса GAR: projects/{project}/locations/{location}/repositories/{repository_id}"
  value       = try(google_artifact_registry_repository.gar.name, null)
}

output "repository_id" {
  description = "Локальный идентификатор репозитория (repository_id)."
  value       = local.gar_repo_id
}

output "project" {
  description = "Проект GCP, в котором создан репозиторий."
  value       = local.gar_project
}

output "location" {
  description = "Локация (region) репозитория."
  value       = local.gar_location
}

output "format" {
  description = "Формат репозитория (DOCKER, OCI, MAVEN, NPM, PYPI и т.д.)."
  value       = local.gar_format
}

############################################
# URL/host для push/pull
############################################

output "host_docker" {
  description = "Хост для Docker/OCI артефактов: {region}-docker.pkg.dev"
  value       = local.docker_host
}

output "host_generic" {
  description = "Хост для прочих форматов: {region}.pkg.dev"
  value       = local.generic_host
}

output "repository_url_primary" {
  description = "Основной URL репозитория для текущего формата."
  value       = local.primary_repo_url
}

output "repository_url_docker" {
  description = "Полный путь до Docker/OCI репозитория: {region}-docker.pkg.dev/{project}/{repo}"
  value       = local.docker_repo_url
}

output "repository_url_generic" {
  description = "Полный путь до generic-репозитория: {region}.pkg.dev/{project}/{repo}"
  value       = local.generic_repo_url
}

############################################
# KMS / шифрование (если задействовано CMEK)
############################################

output "kms_key_name" {
  description = "Имя KMS-ключа, если модуль создаёт/использует пользовательский ключ (CMEK)."
  value       = coalesce(
    try(google_kms_crypto_key.repo.name, null),
    try(google_artifact_registry_repository.gar.kms_key_name, null),
    null
  )
}

output "kms_key_self_link" {
  description = "Self-link/полный путь KMS-ключа, если доступен."
  value       = try(google_kms_crypto_key.repo.id, null)
}

############################################
# Политики/доступ (IAM)
############################################

output "iam_bindings_roles" {
  description = "Список ролей, назначенных репозиторию через iam_binding/iam_member."
  value = distinct(compact(concat(
    try([for b in google_artifact_registry_repository_iam_binding.repo : b.role], []),
    try([for m in google_artifact_registry_repository_iam_member.repo  : m.role], [])
  )))
}

output "iam_bindings" {
  description = "Карта роль → список principals, собранная из iam_binding/iam_member."
  value = { for r in distinct(compact(concat(
    try([for b in google_artifact_registry_repository_iam_binding.repo : b.role], []),
    try([for m in google_artifact_registry_repository_iam_member.repo  : m.role], [])
  ))) :
    r => distinct(compact(concat(
      try(flatten([for b in google_artifact_registry_repository_iam_binding.repo : b.members]), []),
      try([for m in google_artifact_registry_repository_iam_member.repo : m.member], [])
    )))
  }
}

############################################
# Retention/cleanup/логирование (если модулем включено)
############################################

output "cleanup_scheduler_job_id" {
  description = "ID Cloud Scheduler job (если модуль создаёт задачу очистки старых артефактов)."
  value       = try(google_cloud_scheduler_job.gar_cleanup.id, null)
}

output "cleanup_pubsub_topic" {
  description = "Имя Pub/Sub топика, если очистка триггерится через Pub/Sub."
  value       = try(google_pubsub_topic.gar_cleanup.name, null)
}

output "log_sink_id" {
  description = "ID Log Sink (если включён экспорт аудита/доступа для GAR)."
  value       = try(google_logging_project_sink.gar.name, null)
}

############################################
# Репликация/региональные настройки (если модуль управляет ими)
############################################

output "virtual_repository_mirror_mode" {
  description = "Признак режима mirror для виртуального репозитория (если используется)."
  value       = try(google_artifact_registry_repository.gar.virtual_repository_config[0].upstream_policies[0].policy_id != "", false)
}

output "remote_repository_endpoint" {
  description = "Удалённый endpoint для remote-репозитория (если настроен)."
  value       = try(google_artifact_registry_repository.gar.remote_repository_config[0].apt_repository.public_repository.base_repository, null)
}

############################################
# Связанная служебная информация
############################################

output "labels_all" {
  description = "Итоговые метки (labels), применённые к репозиторию."
  value       = try(google_artifact_registry_repository.gar.labels, {})
}

output "api_enabled_services" {
  description = "Сервисы GCP, которые модуль мог включать (artifactregistry.googleapis.com, cloudkms.googleapis.com и пр.)."
  value       = distinct(compact(concat(
    try([for s in google_project_service.required : s.service], []),
    try([for s in google_project_service.optional : s.service], [])
  )))
}
