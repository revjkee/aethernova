#############################################
# Argo CD — Outputs (Terraform / Helm)
# Модульные выходные артефакты без утечки чувствительных данных
#############################################

# ============ Пользовательские переключатели безопасности ============
# По умолчанию мы НЕ читаем начальный пароль admin из Kubernetes Secret,
# т.к. это записывается в state. Включайте только осознанно.
variable "expose_admin_password" {
  description = "If true, fetch initial admin password from argocd-initial-admin-secret (stores in TF state; use with caution)."
  type        = bool
  default     = false
}

# Получать параметры Service argocd-server (LoadBalancer/ClusterIP/NodePort)
variable "lookup_server_service" {
  description = "If true, query the argocd-server Service to expose ports and LB ingress in outputs."
  type        = bool
  default     = false
}

variable "argocd_server_service_name" {
  description = "Kubernetes Service name for Argo CD API/UI server (helm chart default: argocd-server)."
  type        = string
  default     = "argocd-server"
}

# Получать параметры Ingress (если используется)
variable "lookup_server_ingress" {
  description = "If true, query the argocd-server Ingress to expose hostnames in outputs."
  type        = bool
  default     = false
}

variable "argocd_server_ingress_name" {
  description = "Kubernetes Ingress name for Argo CD server (commonly argocd-server when enabled)."
  type        = string
  default     = "argocd-server"
}

# ============ Внешние объекты, создаваемые в этом же модуле ==========
# Допущение: основной Helm-релиз Argo CD называется helm_release.argocd.
# При другом имени — переименуйте в ссылках ниже.
# Ресурс helm_release.argocd должен создаваться в этом модуле.
# Документация по атрибутам: name, namespace, chart, repository, version, status.
# https://registry.terraform.io/providers/hashicorp/helm/latest/docs/resources/release
# (см. проверяемые источники внизу ответа)

# ============ Дополнительные запросы к кластеру (опционально) =========
# Начальный пароль админа (секрет создаёт сам Argo CD). По умолчанию отключено.
data "kubernetes_secret_v1" "argocd_initial_admin" {
  count = var.expose_admin_password ? 1 : 0
  metadata {
    name      = "argocd-initial-admin-secret"
    namespace = helm_release.argocd.namespace
  }
}

# Сервис argocd-server (для получения IP/hostname и портов). По умолчанию отключено.
data "kubernetes_service_v1" "argocd_server" {
  count = var.lookup_server_service ? 1 : 0
  metadata {
    name      = var.argocd_server_service_name
    namespace = helm_release.argocd.namespace
  }
}

# Ingress argocd-server (для получения hostnames). По умолчанию отключено.
data "kubernetes_ingress_v1" "argocd_server" {
  count = var.lookup_server_ingress ? 1 : 0
  metadata {
    name      = var.argocd_server_ingress_name
    namespace = helm_release.argocd.namespace
  }
}

# ============ Локальные вычисления (безопасно через try/nullable) =====
locals {
  ns = helm_release.argocd.namespace

  # Service (LoadBalancer) ingress (если lookup включён и есть внешний адрес)
  lb_hostname = try(data.kubernetes_service_v1.argocd_server[0].status[0].load_balancer[0].ingress[0].hostname, null)
  lb_ip       = try(data.kubernetes_service_v1.argocd_server[0].status[0].load_balancer[0].ingress[0].ip, null)

  # Ingress hostnames (если включено)
  ingress_hosts = try(
    [
      for r in data.kubernetes_ingress_v1.argocd_server[0].status[0].load_balancer[0].ingress : r.hostname
    ],
    []
  )

  # Попытка получить host из Ingress правил (если они заданы)
  ingress_rule_host = try(data.kubernetes_ingress_v1.argocd_server[0].spec[0].rule[0].host, null)

  # Выбор приоритета: Ingress host → LB hostname → LB IP
  server_host = coalesce(local.ingress_rule_host, (length(local.ingress_hosts) > 0 ? local.ingress_hosts[0] : null), local.lb_hostname, local.lb_ip)

  # Предполагаемый URL UI/API Argo CD (используем HTTPS по умолчанию)
  server_url_guess = local.server_host != null ? format("https://%s", local.server_host) : null

  # Начальный пароль (если включено): секрет хранит base64, декодируем
  admin_password_b64 = try(data.kubernetes_secret_v1.argocd_initial_admin[0].data["password"], null)
  admin_password     = local.admin_password_b64 != null ? base64decode(local.admin_password_b64) : null
}

# =============================== OUTPUTS ===============================

# Идентификация Helm-релиза Argo CD
output "argocd_release" {
  description = "Helm release identity and status for Argo CD."
  value = {
    name       = helm_release.argocd.name
    namespace  = helm_release.argocd.namespace
    chart      = helm_release.argocd.chart
    repository = helm_release.argocd.repository
    version    = helm_release.argocd.version
    status     = helm_release.argocd.status
  }
}

# Namespace, в котором установлен Argo CD
output "argocd_namespace" {
  description = "Kubernetes namespace where Argo CD is installed."
  value       = local.ns
}

# Сводная информация по Service argocd-server (если lookup включён)
output "argocd_server_service" {
  description = "argocd-server Service details (type, ClusterIP, ports). Null if lookup disabled."
  value = try({
    type        = data.kubernetes_service_v1.argocd_server[0].spec[0].type
    cluster_ip  = try(data.kubernetes_service_v1.argocd_server[0].spec[0].cluster_ip, null)
    ports = [
      for p in try(data.kubernetes_service_v1.argocd_server[0].spec[0].port, []) : {
        name       = try(p.name, null)
        port       = p.port
        targetPort = try(p.target_port, null)
        protocol   = try(p.protocol, null)
      }
    ]
  }, null)
}

# Внешние адреса (LB/Ingress), если доступны
output "argocd_server_lb" {
  description = "LoadBalancer ingress for argocd-server Service (hostname/ip). Null if not available."
  value = try({
    hostname = local.lb_hostname
    ip       = local.lb_ip
  }, null)
}

output "argocd_server_ingress_hosts" {
  description = "Ingress hostnames for Argo CD server. Empty if ingress lookup disabled or no hosts."
  value       = local.ingress_hosts
}

# Гипотетический URL входа в UI/CLI (на основе Ingress/LB)
output "argocd_server_url_guess" {
  description = "Guessed Argo CD server URL (prefers Ingress host, falls back to LB hostname/IP)."
  value       = local.server_url_guess
}

# Учетные данные администратора (username фиксированный, пароль — опционально)
output "argocd_admin_username" {
  description = "Built-in Argo CD admin username (fixed)."
  value       = "admin"
}

output "argocd_admin_password" {
  description = "Initial admin password (from argocd-initial-admin-secret). Null unless expose_admin_password=true."
  value       = local.admin_password
  sensitive   = true
}
