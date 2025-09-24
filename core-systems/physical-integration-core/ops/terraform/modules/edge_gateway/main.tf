# physical-integration-core/ops/terraform/modules/edge_gateway/main.tf
#######################################################################
# Industrial Edge Gateway Module (AWS)
# - CloudFront CDN with security headers (CloudFront Function)
# - WAFv2 (CLOUDFRONT scope) with managed rules, IP allowlist, rate-limit
# - ACM certificate (us-east-1) with Route53 DNS validation
# - Optional Route53 A/AAAA alias records
# - Optional ALB as origin (with SG, listeners, TG)
# - S3 logging (CloudFront)
#
# NOTE: Root must pass providers:
#   provider "aws" { region = var.region }
#   provider "aws" { alias = "us_east_1" region = "us-east-1" }
#
# Terraform >= 1.5, AWS provider >= 5.x
#######################################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50.0"
    }
  }
}

############################
# Variables (with validation)
############################

variable "project" {
  description = "Project/system name tag."
  type        = string
}

variable "environment" {
  description = "Environment (prod/stage/dev)."
  type        = string
  validation {
    condition     = contains(["prod", "stage", "dev", "test"], var.environment)
    error_message = "environment must be one of: prod, stage, dev, test."
  }
}

variable "region" {
  description = "Workload/home region for non-global resources (e.g., ALB)."
  type        = string
}

variable "tags" {
  description = "Common resource tags."
  type        = map(string)
  default     = {}
}

variable "domain_name" {
  description = "Primary domain (e.g., edge.example.com) used by CloudFront."
  type        = string
}

variable "subject_alternative_names" {
  description = "Optional SANs for ACM certificate."
  type        = list(string)
  default     = []
}

variable "hosted_zone_id" {
  description = "Route53 Hosted Zone ID for domain validation and optional records."
  type        = string
}

variable "create_dns_record" {
  description = "Create Route53 A/AAAA alias for domain_name (and SANs if in same zone)."
  type        = bool
  default     = true
}

variable "cloudfront_price_class" {
  description = "CloudFront price class (PriceClass_100/200/All)."
  type        = string
  default     = "PriceClass_100"
  validation {
    condition     = contains(["PriceClass_100", "PriceClass_200", "PriceClass_All"], var.cloudfront_price_class)
    error_message = "cloudfront_price_class must be one of PriceClass_100, PriceClass_200, PriceClass_All."
  }
}

variable "cloudfront_default_ttl" {
  description = "Default TTL (seconds) for CloudFront."
  type        = number
  default     = 300
}

variable "cloudfront_max_ttl" {
  description = "Max TTL (seconds) for CloudFront."
  type        = number
  default     = 3600
}

variable "cloudfront_min_ttl" {
  description = "Min TTL (seconds) for CloudFront."
  type        = number
  default     = 0
}

variable "cloudfront_logging_enabled" {
  description = "Enable CloudFront access logging."
  type        = bool
  default     = true
}

variable "log_bucket_name" {
  description = "Existing S3 bucket for logs (if empty, module will create one)."
  type        = string
  default     = ""
}

variable "log_bucket_force_destroy" {
  description = "Force destroy logs bucket on delete (use with caution)."
  type        = bool
  default     = false
}

variable "geo_restriction_type" {
  description = "Geo restriction type: none, whitelist, blacklist."
  type        = string
  default     = "none"
  validation {
    condition     = contains(["none", "whitelist", "blacklist"], var.geo_restriction_type)
    error_message = "geo_restriction_type must be none/whitelist/blacklist."
  }
}

variable "geo_locations" {
  description = "List of ISO 3166-1-alpha-2 country codes for geo restriction."
  type        = list(string)
  default     = []
}

variable "enable_waf" {
  description = "Enable WAFv2 for CloudFront."
  type        = bool
  default     = true
}

variable "waf_rate_limit" {
  description = "WAF rate limit (requests per 5 minutes) for a rate-based rule; 0 disables."
  type        = number
  default     = 0
}

variable "waf_ip_allowlist" {
  description = "Optional IP CIDR allowlist for WAF (limits to these CIDRs if non-empty)."
  type        = list(string)
  default     = []
}

variable "waf_enable_common_rules" {
  description = "Enable AWSManagedRulesCommonRuleSet."
  type        = bool
  default     = true
}

variable "waf_enable_bad_inputs" {
  description = "Enable AWSManagedRulesKnownBadInputsRuleSet."
  type        = bool
  default     = true
}

variable "waf_enable_ip_reputation" {
  description = "Enable AWSManagedRulesAmazonIpReputationList."
  type        = bool
  default     = true
}

variable "waf_enable_bot_control" {
  description = "Enable AWSManagedRulesBotControlRuleSet (may incur extra cost)."
  type        = bool
  default     = false
}

variable "origin_shared_secret" {
  description = "Optional secret sent as custom header from CloudFront to origin."
  type        = string
  default     = ""
  sensitive   = true
}

variable "require_origin_secret" {
  description = "Fail plan if origin_shared_secret is empty."
  type        = bool
  default     = false
  validation {
    condition     = (var.require_origin_secret == false) || (var.require_origin_secret && length(var.origin_shared_secret) > 0)
    error_message = "origin_shared_secret must be set when require_origin_secret=true."
  }
}

# Origin configuration options:
variable "create_alb" {
  description = "Create ALB as origin. If false, provide origin_domain_name."
  type        = bool
  default     = false
}

variable "origin_domain_name" {
  description = "Upstream origin DNS name (when create_alb=false)."
  type        = string
  default     = ""
}

variable "origin_protocol_policy" {
  description = "Origin protocol policy for CloudFront (http-only, https-only, match-viewer)."
  type        = string
  default     = "https-only"
  validation {
    condition     = contains(["http-only", "https-only", "match-viewer"], var.origin_protocol_policy)
    error_message = "origin_protocol_policy must be http-only, https-only, or match-viewer."
  }
}

# ALB specifics (used when create_alb=true)
variable "vpc_id" {
  description = "VPC ID for ALB."
  type        = string
  default     = ""
}

variable "alb_subnet_ids" {
  description = "Subnets for ALB."
  type        = list(string)
  default     = []
}

variable "alb_ingress_cidrs" {
  description = "Ingress CIDRs to ALB SG (default 0.0.0.0/0)."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "alb_target_type" {
  description = "Target group type: instance, ip, lambda."
  type        = string
  default     = "ip"
  validation {
    condition     = contains(["instance", "ip", "lambda"], var.alb_target_type)
    error_message = "alb_target_type must be instance, ip, or lambda."
  }
}

variable "alb_target_port" {
  description = "Target port for TG."
  type        = number
  default     = 8080
}

variable "alb_health_check_path" {
  description = "Health check path."
  type        = string
  default     = "/healthz"
}

variable "alb_certificate_arn" {
  description = "HTTPS certificate ARN for ALB (if set, HTTPS :443 listener is created and :80 redirects)."
  type        = string
  default     = ""
}

########################
# Locals & data sources
########################

locals {
  name_prefix = "${var.project}-${var.environment}"

  tags = merge(
    {
      "Project"     = var.project
      "Environment" = var.environment
      "Module"      = "edge-gateway"
      "ManagedBy"   = "Terraform"
    },
    var.tags
  )

  # Effective origin policy: if ALB without TLS cert -> fallback to http-only to avoid broken TLS.
  effective_origin_protocol_policy = (
    var.create_alb && var.alb_certificate_arn == "" && var.origin_protocol_policy == "https-only"
  ) ? "http-only" : var.origin_protocol_policy
}

data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

#################
# S3 Logs bucket
#################

resource "aws_s3_bucket" "logs" {
  count  = var.cloudfront_logging_enabled && var.log_bucket_name == "" ? 1 : 0
  bucket = "${local.name_prefix}-edge-logs-${data.aws_caller_identity.current.account_id}"
  tags   = local.tags

  lifecycle {
    prevent_destroy = !var.log_bucket_force_destroy
  }
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = length(aws_s3_bucket.logs) == 1 ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count                   = length(aws_s3_bucket.logs) == 1 ? 1 : 0
  bucket                  = aws_s3_bucket.logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = length(aws_s3_bucket.logs) == 1 ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  count  = length(aws_s3_bucket.logs) == 1 ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    id     = "expire-logs"
    status = "Enabled"
    expiration {
      days = 90
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

data "aws_s3_bucket" "logs_existing" {
  count  = var.cloudfront_logging_enabled && var.log_bucket_name != "" ? 1 : 0
  bucket = var.log_bucket_name
}

locals {
  log_bucket_name = var.cloudfront_logging_enabled ? (
    var.log_bucket_name != "" ? data.aws_s3_bucket.logs_existing[0].bucket : aws_s3_bucket.logs[0].bucket
  ) : null
}

##############################
# ACM for CloudFront (us-east-1)
##############################

resource "aws_acm_certificate" "cf" {
  provider                  = aws.us_east_1
  domain_name               = var.domain_name
  subject_alternative_names = var.subject_alternative_names
  validation_method         = "DNS"
  tags                      = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

# Create DNS validation records in the provided hosted zone
resource "aws_route53_record" "cf_validation" {
  for_each = {
    for dvo in aws_acm_certificate.cf.domain_validation_options :
    dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  }

  zone_id = var.hosted_zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.record]
}

resource "aws_acm_certificate_validation" "cf" {
  provider                = aws.us_east_1
  certificate_arn        = aws_acm_certificate.cf.arn
  validation_record_fqdns = [for r in aws_route53_record.cf_validation : r.fqdn]
}

##############################
# Optional ALB (origin)
##############################

resource "aws_security_group" "alb" {
  count       = var.create_alb ? 1 : 0
  name        = "${local.name_prefix}-edge-alb-sg"
  description = "Security group for Edge ALB"
  vpc_id      = var.vpc_id
  tags        = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  count             = var.create_alb ? 1 : 0
  security_group_id = aws_security_group.alb[0].id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  description       = "Allow HTTP"
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  count             = var.create_alb && var.alb_certificate_arn != "" ? 1 : 0
  security_group_id = aws_security_group.alb[0].id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Allow HTTPS"
}

resource "aws_vpc_security_group_egress_rule" "alb_all" {
  count             = var.create_alb ? 1 : 0
  security_group_id = aws_security_group.alb[0].id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Allow all egress"
}

resource "aws_lb" "this" {
  count              = var.create_alb ? 1 : 0
  name               = "${local.name_prefix}-edge-alb"
  load_balancer_type = "application"
  subnets            = var.alb_subnet_ids
  security_groups    = [aws_security_group.alb[0].id]
  idle_timeout       = 60
  tags               = local.tags
}

resource "aws_lb_target_group" "this" {
  count       = var.create_alb ? 1 : 0
  name        = "${local.name_prefix}-edge-tg"
  port        = var.alb_target_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = var.alb_target_type
  health_check {
    path                = var.alb_health_check_path
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 15
    timeout             = 5
    matcher             = "200-399"
  }
  tags = local.tags
}

# HTTP listener (redirect to HTTPS if HTTPS enabled)
resource "aws_lb_listener" "http" {
  count             = var.create_alb ? 1 : 0
  load_balancer_arn = aws_lb.this[0].arn
  port              = 80
  protocol          = "HTTP"

  dynamic "default_action" {
    for_each = var.alb_certificate_arn != "" ? [1] : []
    content {
      type = "redirect"
      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }

  dynamic "default_action" {
    for_each = var.alb_certificate_arn == "" ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.this[0].arn
    }
  }

  tags = local.tags
}

# HTTPS listener if certificate provided
resource "aws_lb_listener" "https" {
  count             = var.create_alb && var.alb_certificate_arn != "" ? 1 : 0
  load_balancer_arn = aws_lb.this[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.alb_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this[0].arn
  }

  tags = local.tags
}

#################################
# CloudFront Function (headers)
#################################

resource "aws_cloudfront_function" "security_headers" {
  name    = "${local.name_prefix}-headers"
  runtime = "cloudfront-js-1.0"
  comment = "Add strict security headers"
  code    = <<-EOF
    function handler(event) {
      var response = event.response;
      var headers = response.headers;

      headers['strict-transport-security'] = {value: 'max-age=63072000; includeSubDomains; preload'};
      headers['x-content-type-options'] = {value: 'nosniff'};
      headers['x-frame-options'] = {value: 'DENY'};
      headers['referrer-policy'] = {value: 'no-referrer'};
      // Keep CSP minimal; adjust as needed
      if (!headers['content-security-policy']) {
        headers['content-security-policy'] = {value: "default-src 'self'"};
      }
      // Permissions-Policy example (customize)
      headers['permissions-policy'] = {value: "geolocation=(), microphone=(), camera=()"};

      return response;
    }
  EOF
}

########################
# CloudFront Distribution
########################

locals {
  origin_domain_name = var.create_alb ? aws_lb.this[0].dns_name : var.origin_domain_name
}

resource "aws_cloudfront_distribution" "this" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "${local.name_prefix} edge gateway"
  price_class         = var.cloudfront_price_class
  aliases             = compact(concat([var.domain_name], var.subject_alternative_names))

  origin {
    domain_name = local.origin_domain_name
    origin_id   = "primary-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = local.effective_origin_protocol_policy
      origin_ssl_protocols   = ["TLSv1.2", "TLSv1.3"]
    }

    dynamic "origin_custom_header" {
      for_each = length(var.origin_shared_secret) > 0 ? [1] : []
      content {
        name  = "X-Origin-Secret"
        value = var.origin_shared_secret
      }
    }
  }

  default_cache_behavior {
    target_origin_id       = "primary-origin"
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "PATCH", "POST", "DELETE"]
    cached_methods  = ["GET", "HEAD"]

    compress               = true
    min_ttl                = var.cloudfront_min_ttl
    default_ttl            = var.cloudfront_default_ttl
    max_ttl                = var.cloudfront_max_ttl

    function_association {
      event_type   = "viewer-response"
      function_arn = aws_cloudfront_function.security_headers.arn
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = var.geo_restriction_type == "none" ? "none" : var.geo_restriction_type
      locations        = var.geo_restriction_type == "none" ? [] : var.geo_locations
    }
  }

  viewer_certificate {
    acm_certificate_arn            = aws_acm_certificate
