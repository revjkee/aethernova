/************************************************************
 * storage/postgres — outputs.tf (industrial-grade)
 * Экспортирует:
 *  - Унифицированный объект подключения postgres_connection
 *  - Провайдер-специфичные метаданные (AWS/GCP/Azure)
 *  - Ссылки на секреты (без вывода значений)
 *
 * Примечание:
 *  - Выходы используют try()/coalesce() и будут null, если
 *    соответствующие ресурсы в модуле отсутствуют.
 *  - Имена ресурсов ожидаются следующими:
 *      AWS:   aws_db_instance.postgres
 *             aws_secretsmanager_secret.postgres_credentials
 *      GCP:   google_sql_database_instance.postgres
 *             google_secret_manager_secret.postgres_credentials
 *      Azure: azurerm_postgresql_flexible_server.postgres
 *             azurerm_key_vault_secret.postgres-credentials
 *    Если в вашем модуле имена другие, обновите ссылки ниже.
 ************************************************************/

/* =========================
   Унифицированные подключения
   ========================= */

output "postgres_connection" {
  description = <<EOT
Унифицированные параметры подключения к PostgreSQL:
- host: DNS-имя/адрес (RDS address, Cloud SQL private/public IP, Azure FQDN)
- port: TCP-порт (берётся из провайдера, иначе 5432)
- endpoint: строка endpoint (если доступна), например AWS endpoint
- connection_name: GCP Cloud SQL connection_name (для сокетов/коннекторов)
EOT

  value = {
    host = coalesce(
      try(aws_db_instance.postgres.address, null),
      try(google_sql_database_instance.postgres.private_ip_address, null),
      try(google_sql_database_instance.postgres.public_ip_address, null),
      try(azurerm_postgresql_flexible_server.postgres.fqdn, null)
    )

    # Предпочитаем порт из провайдера; если недоступен — стандарт 5432 (PostgreSQL).
    port = coalesce(
      try(aws_db_instance.postgres.port, null),
      5432
    )

    endpoint        = coalesce(
      try(aws_db_instance.postgres.endpoint, null),
      try(azurerm_postgresql_flexible_server.postgres.fqdn, null),
      null
    )
    connection_name = try(google_sql_database_instance.postgres.connection_name, null)
  }
}

/* =========================
   Провайдер-специфичные метаданные
   ========================= */

# AWS RDS (postgres)
output "aws_rds_metadata" {
  description = "Метаданные AWS RDS PostgreSQL (если развернуто в AWS)."
  value = {
    id       = try(aws_db_instance.postgres.id, null)
    arn      = try(aws_db_instance.postgres.arn, null)
    address  = try(aws_db_instance.postgres.address, null)
    endpoint = try(aws_db_instance.postgres.endpoint, null)
    port     = try(aws_db_instance.postgres.port, null)
    db_name  = try(aws_db_instance.postgres.db_name, null)
    engine   = try(aws_db_instance.postgres.engine, null)
    version  = try(aws_db_instance.postgres.engine_version, null)
  }
  sensitive = false
}

# GCP Cloud SQL for PostgreSQL
output "gcp_cloudsql_metadata" {
  description = "Метаданные GCP Cloud SQL PostgreSQL (если развернуто в GCP)."
  value = {
    id               = try(google_sql_database_instance.postgres.id, null)
    self_link        = try(google_sql_database_instance.postgres.self_link, null)
    connection_name  = try(google_sql_database_instance.postgres.connection_name, null)
    private_ip       = try(google_sql_database_instance.postgres.private_ip_address, null)
    public_ip        = try(google_sql_database_instance.postgres.public_ip_address, null)
    database_version = try(google_sql_database_instance.postgres.database_version, null)
    region           = try(google_sql_database_instance.postgres.region, null)
  }
  sensitive = false
}

# Azure PostgreSQL Flexible Server
output "azure_flexible_server_metadata" {
  description = "Метаданные Azure PostgreSQL Flexible Server (если развернуто в Azure)."
  value = {
    id                  = try(azurerm_postgresql_flexible_server.postgres.id, null)
    name                = try(azurerm_postgresql_flexible_server.postgres.name, null)
    fqdn                = try(azurerm_postgresql_flexible_server.postgres.fqdn, null)
    administrator_login = try(azurerm_postgresql_flexible_server.postgres.administrator_login, null)
    version             = try(azurerm_postgresql_flexible_server.postgres.version, null)
    location            = try(azurerm_postgresql_flexible_server.postgres.location, null)
  }
  sensitive = false
}

/* =========================
   Секреты (ссылки, не значения)
   ========================= */

# AWS Secrets Manager
output "aws_secret_reference" {
  description = "Ссылка на секрет с учётными данными в AWS Secrets Manager (без значения)."
  value = {
    arn  = try(aws_secretsmanager_secret.postgres_credentials.arn, null)
    name = try(aws_secretsmanager_secret.postgres_credentials.name, null)
  }
  sensitive = false
}

# GCP Secret Manager
output "gcp_secret_reference" {
  description = "Ссылка на секрет с учётными данными в Google Secret Manager (без значения)."
  value = {
    id   = try(google_secret_manager_secret.postgres_credentials.id, null)
    name = try(google_secret_manager_secret.postgres_credentials.name, null)
  }
  sensitive = false
}

# Azure Key Vault
output "azure_key_vault_secret_reference" {
  description = "Ссылка на секрет с учётными данными в Azure Key Vault (без значения)."
  value = {
    id   = try(azurerm_key_vault_secret.postgres-credentials.id, null)
    name = try(azurerm_key_vault_secret.postgres-credentials.name, null)
  }
  sensitive = false
}
