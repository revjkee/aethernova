#############################################
# Multi-cloud CDN module: AWS / GCP / Azure
#############################################

# --------------------------
# Inputs
# --------------------------
variable "cloud" {
  description = "Target cloud: aws | gcp | azure"
  type        = string
  validation {
    condition     = contains(["aws", "gcp", "azure"], var.cloud)
    error_message = "cloud must be one of: aws, gcp, azure"
  }
}

variable "name" {
  description = "Resource base name / prefix"
  type        = string
}

variable "domain_names" {
  description = "Fully-qualified domain names served by CDN (aliases/custom domains). For GCP/Azure used for managed certs or hostnames."
  type        = list(string)
  default     = []
}

# --------------------------
# AWS-specific
# --------------------------
variable "aws_origin_type" {
  description = "Origin type for CloudFront: s3 or custom"
  type        = string
  default     = "s3"
  validation {
    condition     = contains(["s3", "custom"], var.aws_origin_type)
    error_message = "aws_origin_type must be 's3' or 'custom'."
  }
}

variable "aws_origin_domain_name" {
  description = "Origin DNS name. For S3 use regional bucket domain (e.g. my-bucket.s3.eu-west-1.amazonaws.com)."
  type        = string
  default     = ""
}

variable "aws_origin_path" {
  description = "Optional origin path prefix (e.g. /static)."
  type        = string
  default     = ""
}

variable "aws_use_oac" {
  description = "Attach Origin Access Control (OAC) for S3 origins (recommended)."
  type        = bool
  default     = true
}

variable "aws_cache_policy_name" {
  description = "CloudFront cache policy name to use (e.g. Managed-CachingOptimized)."
  type        = string
  default     = "Managed-CachingOptimized"
}

variable "aws_acm_certificate_arn" {
  description = "ACM certificate ARN in us-east-1 for custom domains. If empty -> use default CloudFront cert and no aliases."
  type        = string
  default     = ""
}

variable "aws_price_class" {
  description = "CloudFront price class."
  type        = string
  default     = "PriceClass_All"
}

variable "aws_log_bucket" {
  description = "S3 bucket for CloudFront access logs (optional)."
  type        = string
  default     = ""
}

variable "aws_log_prefix" {
  description = "Prefix for CloudFront access logs."
  type        = string
  default     = ""
}

variable "aws_web_acl_id" {
  description = "Optional WAFv2 WebACL ARN."
  type        = string
  default     = ""
}

# --------------------------
# GCP-specific
# --------------------------
variable "gcp_backend_bucket_name" {
  description = "Existing GCS bucket name to serve via Cloud CDN. Required for GCP."
  type        = string
  default     = ""
}

variable "gcp_create_static_ip" {
  description = "Allocate a global static IP for the LB."
  type        = bool
  default     = true
}

variable "gcp_managed_cert_domains" {
  description = "List of domains for Google-managed certificate. If empty -> HTTPS proxy not created."
  type        = list(string)
  default     = []
}

# --------------------------
# Azure-specific (Front Door Standard/Premium)
# --------------------------
variable "azure_resource_group_name" {
  description = "Resource Group for Azure Front Door."
  type        = string
  default     = ""
}

variable "azure_location" {
  description = "Azure location for metadata resources (Front Door is global)."
  type        = string
  default     = "eastus"
}

variable "azure_profile_sku" {
  description = "Front Door SKU: Standard_AzureFrontDoor or Premium_AzureFrontDoor."
  type        = string
  default     = "Standard_AzureFrontDoor"
}

variable "azure_origin_hostname" {
  description = "Origin hostname for Front Door (e.g. mystorageaccount.blob.core.windows.net)."
  type        = string
  default     = ""
}

variable "azure_origin_host_header" {
  description = "Host header to send to origin; defaults to origin hostname."
  type        = string
  default     = ""
}

variable "azure_origin_http_port" {
  type        = number
  default     = 80
}

variable "azure_origin_https_port" {
  type        = number
  default     = 443
}

variable "azure_route_patterns" {
  description = "Path patterns to route."
  type        = list(string)
  default     = ["/*"]
}

# --------------------------
# Locals
# --------------------------
locals {
  is_aws   = var.cloud == "aws"
  is_gcp   = var.cloud == "gcp"
  is_azure = var.cloud == "azure"

  aws_aliases_enabled = local.is_aws && length(var.domain_names) > 0 && var.aws_acm_certificate_arn != ""

  azure_origin_host_header_eff = coalesce(
    length(trimspace(var.azure_origin_host_header)) > 0 ? var.azure_origin_host_header : null,
    var.azure_origin_hostname
  )
}

# =========================================================
# AWS CloudFront
# =========================================================
data "aws_cloudfront_cache_policy" "this" {
  count = local.is_aws ? 1 : 0
  name  = var.aws_cache_policy_name
}

# OAC only for S3 origin type
resource "aws_cloudfront_origin_access_control" "this" {
  count                             = local.is_aws && var.aws_origin_type == "s3" && var.aws_use_oac ? 1 : 0
  name                              = "${var.name}-oac"
  description                       = "OAC for ${var.name}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "this" {
  count               = local.is_aws ? 1 : 0
  enabled             = true
  comment             = var.name
  price_class         = var.aws_price_class
  is_ipv6_enabled     = true
  wait_for_deployment = true

  aliases = local.aws_aliases_enabled ? var.domain_names : []

  origin {
    domain_name              = var.aws_origin_domain_name
    origin_id                = "${var.name}-origin-0"
    origin_path              = var.aws_origin_path
    origin_access_control_id = var.aws_origin_type == "s3" && var.aws_use_oac ? aws_cloudfront_origin_access_control.this[0].id : null

    # For custom origins, you may set custom_origin_config. For S3 origins with OAC this block is not needed.
    dynamic "custom_origin_config" {
      for_each = var.aws_origin_type == "custom" ? [1] : []
      content {
        http_port              = 80
        https_port             = 443
        origin_protocol_policy = "https-only"
        origin_ssl_protocols   = ["TLSv1.2"]
      }
    }
  }

  default_cache_behavior {
    target_origin_id       = "${var.name}-origin-0"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD", "OPTIONS"]
    compress               = true
    cache_policy_id        = data.aws_cloudfront_cache_policy.this[0].id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  dynamic "logging_config" {
    for_each = length(var.aws_log_bucket) > 0 ? [1] : []
    content {
      bucket = var.aws_log_bucket
      prefix = var.aws_log_prefix
      include_cookies = false
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = var.aws_acm_certificate_arn == ""
    acm_certificate_arn            = var.aws_acm_certificate_arn != "" ? var.aws_acm_certificate_arn : null
    ssl_support_method             = var.aws_acm_certificate_arn != "" ? "sni-only" : null
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  web_acl_id = var.aws_web_acl_id != "" ? var.aws_web_acl_id : null

  tags = {
    Name  = var.name
    Cloud = "aws"
  }
}

# =========================================================
# Google Cloud CDN (External HTTP(S) LB + Backend Bucket)
# =========================================================
resource "google_compute_backend_bucket" "this" {
  count       = local.is_gcp ? 1 : 0
  name        = "${var.name}-backend-bucket"
  bucket_name = var.gcp_backend_bucket_name
  enable_cdn  = true
  description = "Backend bucket for Cloud CDN"
}

resource "google_compute_url_map" "this" {
  count        = local.is_gcp ? 1 : 0
  name         = "${var.name}-url-map"
  default_service = google_compute_backend_bucket.this[0].self_link
}

# HTTP proxy + forwarding rule (80)
resource "google_compute_target_http_proxy" "this" {
  count = local.is_gcp ? 1 : 0
  name  = "${var.name}-http-proxy"
  url_map = google_compute_url_map.this[0].self_link
}

resource "google_compute_global_address" "this" {
  count = local.is_gcp && var.gcp_create_static_ip ? 1 : 0
  name  = "${var.name}-ip"
}

resource "google_compute_global_forwarding_rule" "http" {
  count       = local.is_gcp ? 1 : 0
  name        = "${var.name}-fr-http"
  target      = google_compute_target_http_proxy.this[0].self_link
  port_range  = "80"
  ip_protocol = "TCP"
  ip_address  = var.gcp_create_static_ip ? google_compute_global_address.this[0].address : null
}

# Managed SSL (optional) + HTTPS proxy + forwarding rule (443)
resource "google_compute_managed_ssl_certificate" "this" {
  count   = local.is_gcp && length(var.gcp_managed_cert_domains) > 0 ? 1 : 0
  name    = "${var.name}-managed-cert"
  managed { domains = var.gcp_managed_cert_domains }
}

resource "google_compute_target_https_proxy" "this" {
  count    = local.is_gcp && length(var.gcp_managed_cert_domains) > 0 ? 1 : 0
  name     = "${var.name}-https-proxy"
  url_map  = google_compute_url_map.this[0].self_link
  ssl_certificates = [google_compute_managed_ssl_certificate.this[0].self_link]
}

resource "google_compute_global_forwarding_rule" "https" {
  count       = local.is_gcp && length(var.gcp_managed_cert_domains) > 0 ? 1 : 0
  name        = "${var.name}-fr-https"
  target      = google_compute_target_https_proxy.this[0].self_link
  port_range  = "443"
  ip_protocol = "TCP"
  ip_address  = var.gcp_create_static_ip ? google_compute_global_address.this[0].address : null
}

# =========================================================
# Azure Front Door (Standard/Premium)
# =========================================================
resource "azurerm_cdn_frontdoor_profile" "this" {
  count               = local.is_azure ? 1 : 0
  name                = "${var.name}-afd"
  resource_group_name = var.azure_resource_group_name
  sku_name            = var.azure_profile_sku
}

resource "azurerm_cdn_frontdoor_endpoint" "this" {
  count                      = local.is_azure ? 1 : 0
  name                       = "${var.name}-endpoint"
  cdn_frontdoor_profile_id   = azurerm_cdn_frontdoor_profile.this[0].id
}

resource "azurerm_cdn_frontdoor_origin_group" "this" {
  count                    = local.is_azure ? 1 : 0
  name                     = "${var.name}-og"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this[0].id

  health_probe {
    interval_in_seconds = 30
    path                = "/"
    protocol            = "Https"
    request_type        = "GET"
  }

  load_balancing {
    additional_latency_in_milliseconds = 0
    sample_size                        = 4
    successful_samples_required        = 3
  }
}

resource "azurerm_cdn_frontdoor_origin" "this" {
  count                         = local.is_azure ? 1 : 0
  name                          = "${var.name}-origin"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.this[0].id
  enabled                       = true
  host_name                     = var.azure_origin_hostname
  http_port                     = var.azure_origin_http_port
  https_port                    = var.azure_origin_https_port
  origin_host_header            = local.azure_origin_host_header_eff
  priority                      = 1
  weight                        = 1000
}

resource "azurerm_cdn_frontdoor_route" "this" {
  count                         = local.is_azure ? 1 : 0
  name                          = "${var.name}-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.this[0].id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.this[0].id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.this[0].id]
  supported_protocols           = ["Http", "Https"]
  https_redirect_enabled        = true
  patterns_to_match             = var.azure_route_patterns
  forwarding_protocol           = "HttpsOnly"
  cache {
    query_string_caching_behavior = "IgnoreQueryString"
  }
  link_to_default_domain = true
  enabled               = true
}

# --------------------------
# Outputs
# --------------------------
output "aws_cloudfront_domain_name" {
  value       = local.is_aws ? aws_cloudfront_distribution.this[0].domain_name : null
  description = "CloudFront distribution domain (aws)."
}

output "gcp_global_ip" {
  value       = local.is_gcp && var.gcp_create_static_ip ? google_compute_global_address.this[0].address : null
  description = "Global IPv4 address of external HTTP(S) LB (gcp)."
}

output "azure_frontdoor_endpoint_hostname" {
  value       = local.is_azure ? azurerm_cdn_frontdoor_endpoint.this[0].host_name : null
  description = "Azure Front Door default hostname (azureedge.net)."
}
