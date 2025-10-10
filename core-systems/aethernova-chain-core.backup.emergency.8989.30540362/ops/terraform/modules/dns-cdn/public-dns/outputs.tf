#############################################
# dns-cdn/public-dns/outputs.tf
# Terraform >= 1.5
# Примечание: ресурсы должны существовать в модуле с count (0/1/…),
# чтобы try() мог отработать при отключённых провайдерах.
#############################################

# -----------------------------
# Базовая информация по публичной DNS-зоне
# -----------------------------

output "zone_name" {
  description = "DNS-имя публичной зоны (без точки в конце)."
  value = trim(
    try(aws_route53_zone.public_zone[0].name, try(azurerm_dns_zone.public_zone[0].name, try(google_dns_managed_zone.public_zone[0].dns_name, ""))),
    "."
  )
}

output "zone_id" {
  description = "Универсальный идентификатор зоны (Route53 Zone ID / Azure ID / GCP ManagedZone ID)."
  value = try(
    aws_route53_zone.public_zone[0].zone_id,
    try(azurerm_dns_zone.public_zone[0].id, try(google_dns_managed_zone.public_zone[0].id, null))
  )
}

output "zone_arn" {
  description = "ARN зоны для AWS Route53 (иначе null)."
  value       = try(aws_route53_zone.public_zone[0].arn, null)
}

output "zone_name_servers" {
  description = "Список NS-серверов зоны (для делегирования у регистратора)."
  value = compact(
    flatten([
      try(aws_route53_zone.public_zone[0].name_servers, []),
      try(azurerm_dns_zone.public_zone[0].name_servers, []),
      try(google_dns_managed_zone.public_zone[0].name_servers, [])
    ])
  )
}

# -----------------------------
# CDN / фронты
# -----------------------------

output "cdn_aws_cloudfront_domain" {
  description = "Домен CloudFront (если используется)."
  value       = try(aws_cloudfront_distribution.cdn[0].domain_name, null)
}

output "cdn_aws_cloudfront_hosted_zone_id" {
  description = "Hosted Zone ID для ALIAS на CloudFront (Route53)."
  value       = try(aws_cloudfront_distribution.cdn[0].hosted_zone_id, null)
}

output "cdn_azure_frontdoor_hostname" {
  description = "Hostname Azure Front Door (Standard/Premium) endpoint, если используется."
  value = try(
    azurerm_cdn_frontdoor_endpoint.cdn[0].host_name,
    null
  )
}

output "cdn_azure_cdn_endpoint_hostname" {
  description = "Hostname Azure CDN endpoint (Classic), если используется."
  value = try(
    azurerm_cdn_endpoint.cdn[0].host_name,
    null
  )
}

output "cdn_gcp_global_ip_v4" {
  description = "Глобальный IPv4 адрес HTTPS LB (GCP GLB с Cloud CDN), если используется."
  value = try(google_compute_global_address.cdn_ipv4[0].address, null)
}

output "cdn_gcp_global_ip_v6" {
  description = "Глобальный IPv6 адрес HTTPS LB (GCP GLB с Cloud CDN), если используется."
  value = try(google_compute_global_address.cdn_ipv6[0].address, null)
}

# -----------------------------
# Apex/WWW записи (агрегированные)
# -----------------------------

# AWS Route53 (fqdn/type/ttl/alias_target)
output "route53_records" {
  description = "Сводка записей в Route53 (если используется)."
  value = concat(
    try([for r in aws_route53_record.apex_a : {
      fqdn         = try(r.fqdn, null)
      type         = try(r.type, "A")
      ttl          = try(r.ttl, null)
      alias_target = null
    }], []),
    try([for r in aws_route53_record.apex_aaaa : {
      fqdn         = try(r.fqdn, null)
      type         = try(r.type, "AAAA")
      ttl          = try(r.ttl, null)
      alias_target = null
    }], []),
    try([for r in aws_route53_record.cname : {
      fqdn         = try(r.fqdn, null)
      type         = try(r.type, "CNAME")
      ttl          = try(r.ttl, null)
      alias_target = null
    }], []),
    try([for r in aws_route53_record.txt : {
      fqdn         = try(r.fqdn, null)
      type         = try(r.type, "TXT")
      ttl          = try(r.ttl, null)
      alias_target = null
    }], []),
    try([for r in aws_route53_record.alias_cf : {
      fqdn         = try(r.fqdn, null)
      type         = try(r.type, "A")
      ttl          = null
      alias_target = try(r.alias[0].name, null)
    }], [])
  )
}

# Azure DNS (fqdn/type/ttl)
output "azure_dns_records" {
  description = "Сводка записей в Azure DNS (если используется)."
  value = concat(
    try([for r in azurerm_dns_a_record.apex : {
      fqdn = try(r.fqdn, null)
      type = "A"
      ttl  = try(r.ttl, null)
    }], []),
    try([for r in azurerm_dns_aaaa_record.apex : {
      fqdn = try(r.fqdn, null)
      type = "AAAA"
      ttl  = try(r.ttl, null)
    }], []),
    try([for r in azurerm_dns_cname_record.www : {
      fqdn = try(r.fqdn, null)
      type = "CNAME"
      ttl  = try(r.ttl, null)
    }], []),
    try([for r in azurerm_dns_txt_record.txt : {
      fqdn = try(r.fqdn, null)
      type = "TXT"
      ttl  = try(r.ttl, null)
    }], [])
  )
}

# Google Cloud DNS (name/type/ttl/rrdatas)
output "google_dns_records" {
  description = "Сводка записей в Google Cloud DNS (если используется)."
  value = concat(
    try([for r in google_dns_record_set.apex_a : {
      name    = try(trim(r.name, "."), null)
      type    = "A"
      ttl     = try(r.ttl, null)
      rrdatas = try(r.rrdatas, null)
    }], []),
    try([for r in google_dns_record_set.apex_aaaa : {
      name    = try(trim(r.name, "."), null)
      type    = "AAAA"
      ttl     = try(r.ttl, null)
      rrdatas = try(r.rrdatas, null)
    }], []),
    try([for r in google_dns_record_set.www_cname : {
      name    = try(trim(r.name, "."), null)
      type    = "CNAME"
      ttl     = try(r.ttl, null)
      rrdatas = try(r.rrdatas, null)
    }], []),
    try([for r in google_dns_record_set.txt : {
      name    = try(trim(r.name, "."), null)
      type    = "TXT"
      ttl     = try(r.ttl, null)
      rrdatas = try(r.rrdatas, null)
    }], [])
  )
}

# -----------------------------
# Сертификаты/валидации (опционально)
# -----------------------------

output "aws_acm_cert_domain" {
  description = "Домен ACM-сертификата для CDN (если создаётся в модуле)."
  value       = try(aws_acm_certificate.cdn[0].domain_name, null)
}

output "aws_acm_validation_records" {
  description = "CNAME записи для валидации ACM (если модуль управляет ими)."
  value = try([
    for o in aws_acm_certificate.cdn[0].domain_validation_options : {
      resource_record_name  = try(o.resource_record_name, null)
      resource_record_type  = try(o.resource_record_type, null)
      resource_record_value = try(o.resource_record_value, null)
    }
  ], null)
}

# -----------------------------
# Удобные агрегаты
# -----------------------------

output "apex_fqdn" {
  description = "Apex FQDN зоны (например, example.com)."
  value       = trim(try(aws_route53_zone.public_zone[0].name, try(azurerm_dns_zone.public_zone[0].name, try(google_dns_managed_zone.public_zone[0].dns_name, ""))), ".")
}

output "www_fqdn" {
  description = "FQDN www-хоста (если создаётся)."
  value = try(
    trim(aws_route53_record.cname["www"].fqdn, "."),
    try(trim(azurerm_dns_cname_record.www[0].fqdn, "."), try(trim(google_dns_record_set.www_cname[0].name, "."), null))
  )
}

output "cdn_endpoints" {
  description = "Сводка доступных CDN-входных точек."
  value = {
    cloudfront_domain          = try(aws_cloudfront_distribution.cdn[0].domain_name, null)
    cloudfront_hosted_zone_id  = try(aws_cloudfront_distribution.cdn[0].hosted_zone_id, null)
    azure_frontdoor_hostname   = try(azurerm_cdn_frontdoor_endpoint.cdn[0].host_name, null)
    azure_cdn_endpoint_host    = try(azurerm_cdn_endpoint.cdn[0].host_name, null)
    gcp_global_ip_v4           = try(google_compute_global_address.cdn_ipv4[0].address, null)
    gcp_global_ip_v6           = try(google_compute_global_address.cdn_ipv6[0].address, null)
  }
}
