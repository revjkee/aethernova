############################################
# Core identifiers
############################################
output "redis_replication_group_id" {
  description = "ID ElastiCache Redis replication group (если используется)."
  value       = try(aws_elasticache_replication_group.redis.id, null)
}

output "redis_cluster_ids" {
  description = "Список ID ElastiCache кластеров, если модуль создаёт CLUSTER API (для Cluster Mode Disabled/num_cache_nodes)."
  value       = try([for c in aws_elasticache_cluster.redis : c.id], [])
}

output "redis_arn" {
  description = "ARN основного ресурса Redis (replication group ARN если есть, иначе кластерного ресурса)."
  value       = coalesce(
    try(aws_elasticache_replication_group.redis.arn, null),
    try(aws_elasticache_cluster.redis[0].arn, null)
  )
}

output "engine_version_actual" {
  description = "Фактическая версия Redis движка, применённая AWS."
  value       = coalesce(
    try(aws_elasticache_replication_group.redis.engine_version_actual, null),
    try(aws_elasticache_cluster.redis[0].engine_version, null)
  )
}

output "parameter_group_name" {
  description = "Имя параметр-группы Redis, привязанной к кластеру/репликации."
  value       = coalesce(
    try(aws_elasticache_replication_group.redis.parameter_group_name, null),
    try(aws_elasticache_cluster.redis[0].parameter_group_name, null),
    try(aws_elasticache_parameter_group.redis.name, null)
  )
}

############################################
# Endpoints & ports
############################################
output "primary_endpoint_address" {
  description = "Primary endpoint адрес (для replication group)."
  value       = try(aws_elasticache_replication_group.redis.primary_endpoint_address, null)
}

output "reader_endpoint_address" {
  description = "Reader endpoint адрес (для replication group)."
  value       = try(aws_elasticache_replication_group.redis.reader_endpoint_address, null)
}

output "configuration_endpoint_address" {
  description = "Configuration endpoint адрес (для Cluster Mode Enabled)."
  value       = try(aws_elasticache_replication_group.redis.configuration_endpoint_address, null)
}

output "node_endpoints" {
  description = "Список адресов узлов (для случаев, когда нужны прямые коннекты на ноды)."
  value       = try([for n in aws_elasticache_replication_group.redis.member_clusters : n], [])
}

output "port" {
  description = "Порт Redis (обычно 6379)."
  value       = coalesce(
    try(aws_elasticache_replication_group.redis.port, null),
    try(aws_elasticache_cluster.redis[0].port, null)
  )
}

############################################
# Secure URIs (rediss://)
############################################
locals {
  _primary_host = coalesce(
    try(aws_elasticache_replication_group.redis.primary_endpoint_address, null),
    try(aws_elasticache_cluster.redis[0].configuration_endpoint, null),
    try(aws_elasticache_cluster.redis[0].cache_nodes[0].address, null)
  )

  _reader_host = coalesce(
    try(aws_elasticache_replication_group.redis.reader_endpoint_address, null),
    null
  )

  _port_val = coalesce(
    try(aws_elasticache_replication_group.redis.port, null),
    try(aws_elasticache_cluster.redis[0].port, null),
    6379
  )
}

# Примечание: ElastiCache Redis обычно без пароля; если используете ACL/Redis Auth Token,
# прокиньте секрет отдельно и склейте URI на уровне потребителя.
output "primary_rediss_uri" {
  description = "Безпарольный rediss:// URI до primary (TLS). Если используется ACL/token — добавляйте креды на стороне потребителя."
  value       = local._primary_host != null ? format("rediss://%s:%d", local._primary_host, local._port_val) : null
  sensitive   = true
}

output "reader_rediss_uri" {
  description = "Безпарольный rediss:// URI до reader (TLS), если доступен."
  value       = local._reader_host != null ? format("rediss://%s:%d", local._reader_host, local._port_val) : null
  sensitive   = true
}

############################################
# Networking & Security
############################################
output "subnet_group_name" {
  description = "Имя сабнет-группы ElastiCache."
  value       = coalesce(
    try(aws_elasticache_replication_group.redis.subnet_group_name, null),
    try(aws_elasticache_subnet_group.redis.name, null),
    try(aws_elasticache_cluster.redis[0].subnet_group_name, null)
  )
}

output "security_group_ids" {
  description = "Security Group IDs, применённые к Redis."
  value       = compact(concat(
    try([aws_security_group.redis.id], []),
    try(aws_elasticache_replication_group.redis.security_group_ids, []),
    try([for c in aws_elasticache_cluster.redis : c.security_group_ids]..., [])
  ))
}

output "at_rest_encryption_enabled" {
  description = "Признак шифрования данных 'на диске' (at-rest)."
  value       = coalesce(
    try(aws_elasticache_replication_group.redis.at_rest_encryption_enabled, null),
    try(aws_elasticache_cluster.redis[0].at_rest_encryption_enabled, null)
  )
}

output "transit_encryption_enabled" {
  description = "Признак шифрования трафика (in-transit TLS)."
  value       = coalesce(
    try(aws_elasticache_replication_group.redis.transit_encryption_enabled, null),
    try(aws_elasticache_cluster.redis[0].transit_encryption_enabled, null)
  )
}

output "tls_enabled" {
  description = "Алиас признака TLS (равен transit_encryption_enabled)."
  value       = coalesce(
    try(aws_elasticache_replication_group.redis.transit_encryption_enabled, null),
    try(aws_elasticache_cluster.redis[0].transit_encryption_enabled, null)
  )
}

output "kms_key_id" {
  description = "KMS Key ID/ARN, если включено at-rest шифрование KMS."
  value       = coalesce(
    try(aws_elasticache_replication_group.redis.kms_key_id, null),
    try(aws_elasticache_cluster.redis[0].kms_key_id, null),
    try(aws_kms_key.redis.arn, null)
  )
}

############################################
# Maintenance / Backups
############################################
output "maintenance_window" {
  description = "Окно обслуживания ElastiCache."
  value       = coalesce(
    try(aws_elasticache_replication_group.redis.maintenance_window, null),
    try(aws_elasticache_cluster.redis[0].maintenance_window, null)
  )
}

output "snapshot_retention_limit" {
  description = "Число сохраняемых автоматических снапшотов."
  value       = coalesce(
    try(aws_elasticache_replication_group.redis.snapshot_retention_limit, null),
    try(aws_elasticache_cluster.redis[0].snapshot_retention_limit, null)
  )
}

output "snapshot_window" {
  description = "Окно создания автоматических снапшотов."
  value       = coalesce(
    try(aws_elasticache_replication_group.redis.snapshot_window, null),
    try(aws_elasticache_cluster.redis[0].snapshot_window, null)
  )
}

############################################
# Observability
############################################
output "cloudwatch_log_group_name" {
  description = "Имя CloudWatch Log Group, если настроен экспорт логов."
  value       = try(aws_cloudwatch_log_group.redis.name, null)
}

output "alarm_arns" {
  description = "Список ARN CloudWatch Alarm’ов, связанных с Redis."
  value       = try([for a in aws_cloudwatch_metric_alarm.redis : a.arn], [])
}

############################################
# Tags and Metadata
############################################
output "tags_all" {
  description = "Итоговые тэги, применённые к основному ресурсу Redis."
  value       = coalesce(
    try(aws_elasticache_replication_group.redis.tags_all, null),
    try(aws_elasticache_cluster.redis[0].tags_all, null)
  )
}

output "cluster_mode_enabled" {
  description = "Включён ли Cluster Mode (sharding)."
  value       = try(aws_elasticache_replication_group.redis.cluster_mode, null) != null
}

############################################
# ACL / Users (Optional, if module manages them)
############################################
output "user_group_id" {
  description = "ID группы пользователей Redis ACL (если модуль её создаёт/использует)."
  value       = try(aws_elasticache_user_group.redis.id, null)
}

output "acl_users" {
  description = "Список имён пользователей ACL (если управляются модулем)."
  value       = try([for u in aws_elasticache_user.redis : u.user_name], [])
}

############################################
# Connection helpers (placeholders for secret refs)
############################################
output "auth_token_secret_arn" {
  description = "ARN секрета (например, в AWS Secrets Manager) с Redis AUTH/ACL токеном, если используется."
  value       = try(aws_secretsmanager_secret.redis_auth.arn, null)
  sensitive   = true
}

output "connection_info" {
  description = "Структурированная сводка для потребителей: хосты, порт, TLS, URI."
  value = {
    primary_host = local._primary_host
    reader_host  = local._reader_host
    port         = local._port_val
    tls          = coalesce(
      try(aws_elasticache_replication_group.redis.transit_encryption_enabled, null),
      try(aws_elasticache_cluster.redis[0].transit_encryption_enabled, null)
    )
    primary_uri  = local._primary_host != null ? format("rediss://%s:%d", local._primary_host, local._port_val) : null
    reader_uri   = local._reader_host  != null ? format("rediss://%s:%d", local._reader_host,  local._port_val) : null
  }
  sensitive = true
}
