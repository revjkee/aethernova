############################################################
# File: aethernova-chain-core/ops/terraform/modules/dns-cdn/cdn/variables.tf
# Purpose: Multi-cloud CDN + DNS (AWS CloudFront, GCP Cloud CDN, Azure Front Door)
# Terraform: >= 1.4
############################################################

############################
# Core selector
############################
variable "cdn_provider" {
  description = "Target CDN: aws | gcp | azure"
  type        = string
  validation {
    condition     = contains(["aws", "gcp", "azure"], var.cdn_provider)
    error_message = "cdn_provider must be one of: aws, gcp, azure."
  }
}

variable "dns_provider" {
  description = "Target DNS: aws | gcp | azure"
  type        = string
  validation {
    condition     = contains(["aws", "gcp", "azure"], var.dns_provider)
    error_message = "dns_provider must be one of: aws, gcp, azure."
  }
}

variable "project_name" {
  description = "Logical project/name prefix for tagging"
  type        = string
}

variable "tags" {
  description = "Common tags/labels for all supported providers"
  type        = map(string)
  default     = {}
}

############################
# Domains / certificates (common)
############################
variable "domains" {
  description = "List of FQDNs to serve via CDN (first is primary)"
  type        = list(string)
  validation {
    condition     = length(var.domains) >= 1 && alltrue([for d in var.domains : can(regex("^([a-z0-9-]+\\.)+[a-z]{2,}$", d))])
    error_message = "Provide at least one valid FQDN."
  }
}

variable "enable_ipv6" {
  description = "Enable IPv6 on edge if supported by provider"
  type        = bool
  default     = true
}

variable "force_https" {
  description = "Redirect HTTP->HTTPS at edge"
  type        = bool
  default     = true
}

############################
# AWS CloudFront specifics
############################
variable "aws" {
  description = <<EOT
AWS CloudFront options (effective when cdn_provider = "aws").
Notes:
- For custom viewer HTTPS, ACM certificate must be in us-east-1 (N. Virginia).
- Route 53 alias A/AAAA can target CloudFront distributions including apex.
EOT
  type = object({
    # Certificate for viewer HTTPS (ACM in us-east-1)
    acm_certificate_arn   = optional(string, null)

    # WAF (AWS WAFv2 web ACL ARN)
    waf_web_acl_arn       = optional(string, null)

    # Price class (PriceClass_All|PriceClass_200|PriceClass_100)
    price_class           = optional(string, "PriceClass_100")

    # Logging to S3
    logging = optional(object({
      enabled         = bool
      bucket_name     = string
      prefix          = optional(string, "")
      include_cookies = optional(bool, false)
    }), {
      enabled     = false
      bucket_name = ""
    })

    # Origins
    origins = list(object({
      origin_id       = string
      domain_name     = string
      origin_path     = optional(string, "")
      protocol_policy = optional(string, "https-only") # http-only|https-only|match-viewer
      custom_headers  = optional(map(string), {})
      origin_shield = optional(object({
        enabled = bool
        region  = optional(string, null) # e.g., "us-east-1"
      }), {
        enabled = false
      })
    }))

    # Default behavior
    default_behavior = object({
      origin_id                 = string
      allowed_methods           = optional(list(string), ["GET","HEAD"])
      cached_methods            = optional(list(string), ["GET","HEAD"])
      viewer_protocol_policy    = optional(string, "redirect-to-https") # allow-all|https-only|redirect-to-https
      compress                  = optional(bool, true)
      cache_policy_id           = optional(string, null) # managed or custom
      origin_request_policy_id  = optional(string, null) # managed or custom
      response_headers_policy_id= optional(string, null) # managed or custom
      function_associations = optional(list(object({
        event_type   = string        # viewer-request|viewer-response
        function_arn = string        # CloudFront Function ARN
      })), [])
      lambda_associations = optional(list(object({
        event_type   = string        # viewer-request|viewer-response|origin-request|origin-response
        lambda_arn   = string        # Lambda@Edge versioned ARN
        include_body = optional(bool, false)
      })), [])
    })

    # Additional behaviors
    ordered_behaviors = optional(list(object({
      path_pattern              = string
      origin_id                 = string
      allowed_methods           = optional(list(string), ["GET","HEAD"])
      cached_methods            = optional(list(string), ["GET","HEAD"])
      viewer_protocol_policy    = optional(string, "redirect-to-https")
      compress                  = optional(bool, true)
      cache_policy_id           = optional(string, null)
      origin_request_policy_id  = optional(string, null)
      response_headers_policy_id= optional(string, null)
      function_associations     = optional(list(object({
        event_type   = string
        function_arn = string
      })), [])
      lambda_associations       = optional(list(object({
        event_type   = string
        lambda_arn   = string
        include_body = optional(bool, false)
      })), [])
    })), [])

    # Geo restrictions
    geo_restriction = optional(object({
      restriction_type = string      # none|whitelist|blacklist
      locations        = optional(list(string), [])
    }), {
      restriction_type = "none"
    })

    # Custom error responses
    custom_errors = optional(list(object({
      error_code         = number   # 400..599
      response_code      = optional(number, null)
      response_page_path = optional(string, null)
      error_caching_min_ttl = optional(number, 300)
    })), [])
  })
  default = {
    acm_certificate_arn = null
    waf_web_acl_arn     = null
    price_class         = "PriceClass_100"
    logging = {
      enabled     = false
      bucket_name = ""
      prefix      = ""
      include_cookies = false
    }
    origins = []
    default_behavior = {
      origin_id = ""
    }
    ordered_behaviors = []
    geo_restriction = {
      restriction_type = "none"
      locations        = []
    }
    custom_errors = []
  }
}

############################
# GCP Cloud CDN specifics
############################
variable "gcp" {
  description = <<EOT
Google Cloud CDN options (effective when cdn_provider = "gcp").
Cloud CDN runs behind an external Application Load Balancer; TLS via Google-managed
or self-managed certificates; Cloud Armor policies can be attached.
EOT
  type = object({
    project_id = string
    region     = optional(string, null) # used for regional LB where applicable

    # SSL / certificates (Certificate Manager or classic managed certs)
    ssl = optional(object({
      managed_certificate_domains = optional(list(string), []) # Google-managed certs
      certificate_ids             = optional(list(string), []) # Self/managed cert resource names
    }), {
      managed_certificate_domains = []
      certificate_ids             = []
    })

    # Cloud Armor
    cloud_armor_policy    = optional(string, null) # policy name or full URL

    # Backend definitions (abstracted for module)
    backends = list(object({
      name                  = string
      type                  = string           # "backend_service" | "backend_bucket"
      enable_cloud_cdn      = optional(bool, true)
      cache_mode            = optional(string, "CACHE_ALL_STATIC") # or use origin headers
      signed_url_enabled    = optional(bool, false)
      compression_enabled   = optional(bool, true)
      custom_response_headers = optional(list(string), [])
    }))

    # URL map rules (host/path routing)
    url_map = object({
      default_backend = string
      host_rules = optional(list(object({
        hosts       = list(string)
        path_matcher= string
      })), [])
      path_matchers = optional(list(object({
        name            = string
        default_backend = string
        path_rules = optional(list(object({
          paths   = list(string)
          backend = string
        })), [])
      })), [])
    })

    # Logging
    logging = optional(object({
      enabled     = bool
      sample_rate = optional(number, 1.0)
    }), {
      enabled     = false
      sample_rate = 1.0
    })
  })
}

############################
# Azure Front Door Std/Premium specifics
############################
variable "azure" {
  description = <<EOT
Azure Front Door (Standard/Premium) options (effective when cdn_provider = "azure").
Supports Azure-managed or customer-managed certificates, WAF association,
Rules Engine caching/headers, and apex/custom domains with Azure DNS.
EOT
  type = object({
    resource_group = string
    location       = string
    sku            = optional(string, "Standard_AzureFrontDoor") # or "Premium_AzureFrontDoor"

    # TLS for custom domains
    tls = optional(object({
      use_azure_managed_cert = optional(bool, true)
      key_vault_cert_secret_id = optional(string, null) # when customer-managed
      minimum_tls_version      = optional(string, "TLS1.2")
    }), {
      use_azure_managed_cert   = true
      key_vault_cert_secret_id = null
      minimum_tls_version      = "TLS1.2"
    })

    # WAF
    waf_policy_id = optional(string, null)

    # Origins and routes
    origins = list(object({
      name        = string
      host_name   = string
      http_port   = optional(number, 80)
      https_port  = optional(number, 443)
      enabled     = optional(bool, true)
      priority    = optional(number, 1)
      weight      = optional(number, 1000)
      origin_host_header = optional(string, null)
    }))

    routes = list(object({
      name                 = string
      patterns_to_match    = list(string)
      origin_group_name    = string
      https_redirect       = optional(bool, true)
      caching = optional(object({
        enabled        = bool
        behavior       = optional(string, "HonorOrigin") # HonorOrigin|OverrideAlways|OverrideIfOriginMissing
        duration       = optional(string, "1h")          # e.g., 1h, 30m
      }), {
        enabled  = false
        behavior = "HonorOrigin"
        duration = "1h"
      })
      response_headers = optional(map(string), {})  # name->value
    }))
  })
}

############################
# DNS integration (per provider)
############################
variable "dns" {
  description = "DNS records for CDN entrypoints per provider"
  type = object({
    # AWS Route 53
    aws = optional(object({
      zone_id      = string
      create_alias = optional(bool, true)
      record_names = optional(list(string), [])   # e.g., ["example.com","www.example.com"]
    }), null)

    # Google Cloud DNS
    gcp = optional(object({
      project_id   = string
      managed_zone = string
      record_names = optional(list(string), [])   # A/AAAA -> LB IP; CNAME for subdomains to LB hostname if applicable
      ttl          = optional(number, 300)
    }), null)

    # Azure DNS
    azure = optional(object({
      resource_group = string
      zone_name      = string
      record_names   = optional(list(string), [])
      use_alias      = optional(bool, true)       # Alias to Front Door/Azure resource for apex
      ttl            = optional(number, 300)
    }), null)
  })
}

############################
# Security / headers (common)
############################
variable "security_headers" {
  description = "Edge security headers (name -> value), applied where provider supports response headers policy"
  type        = map(string)
  default     = {}
}

############################
# Observability
############################
variable "enable_edge_logs" {
  description = "Enable edge access logs (provider-specific backends)"
  type        = bool
  default     = true
}

############################
# Validations / guardrails (cross-field)
############################
locals {
  _primary_domain = try(var.domains[0], null)
}

variable "fail_on_missing_cert" {
  description = "Fail planning if provider requires certificate but none provided/managed"
  type        = bool
  default     = true
}

variable "geo_restriction_policy" {
  description = "Organization-level geo policy label (informational)"
  type        = string
  default     = ""
}
