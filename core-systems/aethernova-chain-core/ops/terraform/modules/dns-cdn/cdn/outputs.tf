/**
 * Aethernova — dns-cdn/cdn
 * File: outputs.tf
 *
 * Назначение:
 *   Стандартизированные выходные значения для модуля CDN/DNS на базе AWS CloudFront + Route53.
 *   Предполагаются следующие ресурсы (их наличие/состав определяется реализацией модуля):
 *     - aws_cloudfront_distribution.primary
 *     - aws_cloudfront_distribution.staging            (count = 0 или 1)
 *     - aws_cloudfront_continuous_deployment_policy.this (count = 0 или 1)
 *     - aws_cloudfront_origin_access_control.this      (OAC)
 *     - aws_cloudfront_origin_access_identity.this     (OAI, count = 0 или 1 — если используется legacy-подход)
 *     - aws_cloudfront_response_headers_policy.*       (например: security, cors, base)
 *     - aws_cloudfront_cache_policy.*                  (например: static, dynamic, disabled)
 *     - aws_cloudfront_origin_request_policy.*         (например: all_viewer, s3_cors)
 *     - aws_route53_record.cdn_alias                   (ALIAS/CNAME запись на дистрибутив)
 *     - aws_route53_record.cdn_apex_alias              (опционально, алиас на apex)
 *     - aws_s3_bucket.logs                             (опционально, bucket для логов)
 *
 * Важно:
 *   Если какие-то ресурсы в модуле создаются условно через count=0 — обращения к ним ниже
 *   выполнены через try(...) и индексацию [0], чтобы безопасно возвращать null.
 */

############################################
# CloudFront — основной дистрибутив
############################################

output "cloudfront_distribution" {
  description = "Сводная информация об основном CloudFront-дистрибутиве."
  value = {
    id               = aws_cloudfront_distribution.primary.id
    arn              = aws_cloudfront_distribution.primary.arn
    domain_name      = aws_cloudfront_distribution.primary.domain_name
    hosted_zone_id   = aws_cloudfront_distribution.primary.hosted_zone_id
    status           = aws_cloudfront_distribution.primary.status
    enabled          = aws_cloudfront_distribution.primary.enabled
    etag             = aws_cloudfront_distribution.primary.etag
    aliases          = try(aws_cloudfront_distribution.primary.aliases, [])
    price_class      = try(aws_cloudfront_distribution.primary.price_class, null)
    http_version     = try(aws_cloudfront_distribution.primary.http_version, null)
    is_ipv6_enabled  = try(aws_cloudfront_distribution.primary.is_ipv6_enabled, null)
    default_root_object = try(aws_cloudfront_distribution.primary.default_root_object, null)
    web_acl_id       = try(aws_cloudfront_distribution.primary.web_acl_id, null) # для WAF Classic; для WAFv2 ассоциация на стороне ACL
    last_modified_time = try(aws_cloudfront_distribution.primary.last_modified_time, null)
  }
}

############################################
# CloudFront — staging/continuous deployment (опционально)
############################################

output "cloudfront_staging_distribution" {
  description = "Staging-дистрибутив (если включён Continuous Deployment)."
  value = try({
    id             = aws_cloudfront_distribution.staging[0].id
    arn            = aws_cloudfront_distribution.staging[0].arn
    domain_name    = aws_cloudfront_distribution.staging[0].domain_name
    hosted_zone_id = aws_cloudfront_distribution.staging[0].hosted_zone_id
    status         = aws_cloudfront_distribution.staging[0].status
  }, null)
}

output "cloudfront_continuous_deployment_policy" {
  description = "Политика Continuous Deployment (если создана)."
  value = try({
    id   = aws_cloudfront_continuous_deployment_policy.this[0].id
    etag = aws_cloudfront_continuous_deployment_policy.this[0].etag
  }, null)
}

############################################
# Origin Access: OAC / OAI
############################################

output "origin_access" {
  description = "Идентификаторы доступа к origin (современный OAC и, при наличии, legacy OAI)."
  value = {
    oac_id   = try(aws_cloudfront_origin_access_control.this.id, null)
    oac_name = try(aws_cloudfront_origin_access_control.this.name, null)
    oai_id   = try(aws_cloudfront_origin_access_identity.this[0].id, null)
    oai_iam_arn = try(aws_cloudfront_origin_access_identity.this[0].iam_arn, null)
    mode     = try(aws_cloudfront_origin_access_control.this.signing_behavior, null) # always|no-override
  }
}

############################################
# Политики CloudFront: Response Headers / Cache / Origin Request
############################################

output "response_headers_policies" {
  description = "Идентификаторы созданных или управляемых Response Headers Policies."
  value = {
    security = try(aws_cloudfront_response_headers_policy.security.id, null)
    cors     = try(aws_cloudfront_response_headers_policy.cors.id, null)
    base     = try(aws_cloudfront_response_headers_policy.base.id, null)
  }
}

output "cache_policies" {
  description = "Идентификаторы созданных Cache Policies."
  value = {
    static   = try(aws_cloudfront_cache_policy.static.id, null)
    dynamic  = try(aws_cloudfront_cache_policy.dynamic.id, null)
    disabled = try(aws_cloudfront_cache_policy.disabled.id, null)
  }
}

output "origin_request_policies" {
  description = "Идентификаторы созданных Origin Request Policies."
  value = {
    all_viewer = try(aws_cloudfront_origin_request_policy.all_viewer.id, null)
    s3_cors    = try(aws_cloudfront_origin_request_policy.s3_cors.id, null)
  }
}

############################################
# DNS (Route53)
############################################

output "dns_records" {
  description = "DNS-записи, указывающие на CloudFront."
  value = {
    cdn_alias = try({
      fqdn      = aws_route53_record.cdn_alias.fqdn
      name      = aws_route53_record.cdn_alias.name
      type      = aws_route53_record.cdn_alias.type
      zone_id   = aws_route53_record.cdn_alias.zone_id
      set_identifier = try(aws_route53_record.cdn_alias.set_identifier, null)
    }, null)

    cdn_apex_alias = try({
      fqdn      = aws_route53_record.cdn_apex_alias.fqdn
      name      = aws_route53_record.cdn_apex_alias.name
      type      = aws_route53_record.cdn_apex_alias.type
      zone_id   = aws_route53_record.cdn_apex_alias.zone_id
      set_identifier = try(aws_route53_record.cdn_apex_alias.set_identifier, null)
    }, null)
  }
}

############################################
# Логирование CloudFront в S3 (опционально)
############################################

output "logging" {
  description = "Bucket для логов CloudFront (если создаётся модулем)."
  value = try({
    bucket_name        = aws_s3_bucket.logs[0].bucket
    bucket_arn         = aws_s3_bucket.logs[0].arn
    bucket_domain_name = aws_s3_bucket.logs[0].bucket_domain_name
    bucket_regional_domain_name = aws_s3_bucket.logs[0].bucket_regional_domain_name
  }, null)
}

############################################
# Связанные артефакты (Functions / Lambda@Edge) — опционально
############################################

output "cloudfront_functions" {
  description = "Список CloudFront Functions (если создаются модулем)."
  value = try([
    for f in aws_cloudfront_function.this :
    {
      name = f.name
      arn  = f.arn
      runtime = try(f.runtime, null)
      etag = try(f.etag, null)
    }
  ], [])
}

output "lambda_at_edge_functions" {
  description = "Список Lambda@Edge функций (если создаются модулем)."
  value = try([
    for lf in aws_lambda_function.edge :
    {
      function_name = lf.function_name
      arn           = lf.arn
      qualified_arn = try(lf.qualified_arn, null)
      version       = try(lf.version, null)
      description   = try(lf.description, null)
    }
  ], [])
}

############################################
# Итоговая сводка
############################################

output "cdn_summary" {
  description = "Сводный объект по CDN: ключевые атрибуты дистрибутива, DNS и логирования."
  value = {
    distribution = {
      id           = aws_cloudfront_distribution.primary.id
      arn          = aws_cloudfront_distribution.primary.arn
      domain_name  = aws_cloudfront_distribution.primary.domain_name
      aliases      = try(aws_cloudfront_distribution.primary.aliases, [])
      hosted_zone_id = aws_cloudfront_distribution.primary.hosted_zone_id
    }
    dns = {
      cdn_alias_fqdn      = try(aws_route53_record.cdn_alias.fqdn, null)
      cdn_apex_alias_fqdn = try(aws_route53_record.cdn_apex_alias.fqdn, null)
    }
    logging_bucket = try(aws_s3_bucket.logs[0].bucket, null)
  }
}
