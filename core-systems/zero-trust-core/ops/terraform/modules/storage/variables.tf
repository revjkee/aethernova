variable "name" {
  description = "Short name for resources (used in bucket and tags)"
  type        = string
}

variable "environment" {
  description = "Deployment environment (prod/stage/etc.)"
  type        = string
  default     = "prod"
}

variable "region" {
  description = "AWS region (for kms key alias uniqueness, optional)"
  type        = string
  default     = null
}

variable "bucket_force_destroy" {
  description = "If true, allow Terraform to destroy bucket even if not empty (dangerous in prod)"
  type        = bool
  default     = false
}

variable "enable_versioning" {
  description = "Enable S3 versioning"
  type        = bool
  default     = true
}

variable "enable_bucket_logging" {
  description = "Create and use a dedicated log bucket"
  type        = bool
  default     = true
}

variable "log_bucket_name" {
  description = "Optional pre-existing log bucket name. If empty and enable_bucket_logging=true, module creates a log bucket."
  type        = string
  default     = ""
}

variable "lifecycle_rules" {
  description = "Lifecycle rules for objects (list of maps). Default: keep current versions, expire noncurrent versions after 90 days, expire delete markers after 365 days"
  type        = any
  default = [
    {
      id      = "noncurrent-versions"
      enabled = true
      noncurrent_version_expiration = { days = 90 }
    },
    {
      id      = "expired-multiparts"
      enabled = true
      abort_incomplete_multipart_upload = { days_after_initiation = 7 }
    }
  ]
}

variable "allowed_principals_arns" {
  description = "List of IAM principal ARNs (roles/users/services) that should have read/write access to the bucket"
  type        = list(string)
  default     = []
}

variable "kms_key_rotation" {
  description = "Enable automatic rotation for the KMS key"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags map"
  type        = map(string)
  default     = {}
}
