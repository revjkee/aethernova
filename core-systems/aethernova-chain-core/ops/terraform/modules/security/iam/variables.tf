/**
 * Module: security/iam
 * File: variables.tf
 * Purpose: Strongly-typed, validated inputs for managing IAM at org/folder/project
 *          scope, including bindings (with conditions), custom roles, service
 *          accounts, audit configs, and Workload Identity Federation.
 *
 * Notes:
 * - No provider/resource blocks here.
 * - Validations avoid environment dependencies.
 * - Keys management is intentionally disabled by default (security best practice).
 */

terraform {
  required_version = ">= 1.6.0"
}

############################################
# Scope selection: org/folder/project      #
############################################

variable "target_level" {
  description = "IAM scope level to manage: organization, folder, or project."
  type        = string
  default     = "project"

  validation {
    condition     = contains(["organization", "folder", "project"], var.target_level)
    error_message = "target_level must be one of: organization, folder, project."
  }
}

variable "organization_id" {
  description = "Numeric Organization ID when target_level == organization (e.g., 123456789012)."
  type        = string
  default     = null

  validation {
    condition     = var.target_level != "organization" || can(regex("^[0-9]{6,}$", var.organization_id))
    error_message = "organization_id must be a numeric string when target_level == organization."
  }
}

variable "folder_id" {
  description = "Folder ID when target_level == folder (format: folders/123456789012 or numeric id)."
  type        = string
  default     = null

  validation {
    condition = var.target_level != "folder" || can(regex("^(folders/)?[0-9]{6,}$", var.folder_id))
    error_message = "folder_id must be 'folders/<numeric>' or numeric string when target_level == folder."
  }
}

variable "project_id" {
  description = "Project ID when target_level == project."
  type        = string
  default     = null

  validation {
    condition     = var.target_level != "project" || length(var.project_id) > 0
    error_message = "project_id must be non-empty when target_level == project."
  }
}

############################################
# Labels and naming                        #
############################################

variable "labels" {
  description = "Labels applied where supported (for created resources like SAs)."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for k, v in var.labels :
      can(regex("^[a-z0-9_-]{1,63}$", k)) &&
      can(regex("^[a-z0-9_-]{0,63}$", v))
    ])
    error_message = "labels keys/values must match ^[a-z0-9_-]{1,63}$ (<=63 chars)."
  }
}

variable "name_prefix" {
  description = "Optional prefix for created resource names (service accounts, custom roles IDs)."
  type        = string
  default     = ""
}

variable "name_suffix" {
  description = "Optional suffix for created resource names."
  type        = string
  default     = ""
}

############################################
# IAM bindings (authoritative/additive)    #
############################################

/**
 * bindings: authoritative role->members map at the chosen scope.
 * Example:
 * {
 *   "roles/viewer" = ["user:alice@example.com", "group:devs@example.com"]
 *   "roles/resourcemanager.projectIamAdmin" = ["serviceAccount:ci@project.iam.gserviceaccount.com"]
 * }
 */
variable "bindings" {
  description = "Authoritative IAM bindings at selected scope: role => list of members."
  type        = map(list(string))
  default     = {}

  validation {
    condition = alltrue([
      for role, members in var.bindings :
      can(regex("^roles/[A-Za-z0-9_.]+$", role)) &&
      alltrue([for m in members : can(regex("^(user|group|serviceAccount|domain|principal|principalSet):.+$", m))])
    ])
    error_message = "bindings must use role names like roles/x.y and member strings like user:, group:, serviceAccount:, domain:, principal:, principalSet:."
  }
}

/**
 * additive_bindings: non-authoritative additions (merging with existing).
 * Same structure as bindings, but applied additively.
 */
variable "additive_bindings" {
  description = "Non-authoritative IAM bindings to be added (role => members)."
  type        = map(list(string))
  default     = {}

  validation {
    condition = alltrue([
      for role, members in var.additive_bindings :
      can(regex("^roles/[A-Za-z0-9_.]+$", role)) &&
      alltrue([for m in members : can(regex("^(user|group|serviceAccount|domain|principal|principalSet):.+$", m))])
    ])
    error_message = "additive_bindings must use valid role/member formats."
  }
}

/**
 * conditional_bindings: list of conditional role bindings at scope.
 * Each item: role, members, condition{title, expression, description?}
 * Example:
 * [{
 *   role     = "roles/storage.objectViewer"
 *   members  = ["user:alice@example.com"]
 *   condition = {
 *     title       = "ip-allowlist"
 *     expression  = "request.ip == '203.0.113.7'"
 *     description = "Restrict access to a single IP"
 *   }
 * }]
 */
variable "conditional_bindings" {
  description = "List of IAM bindings with conditions at the selected scope."
  type = list(object({
    role    = string
    members = list(string)
    condition = object({
      title       = string
      expression  = string
      description = optional(string, "")
    })
  }))
  default = []

  validation {
    condition = alltrue([
      for b in var.conditional_bindings :
      can(regex("^roles/[A-Za-z0-9_.]+$", b.role)) &&
      length(b.members) > 0 &&
      alltrue([for m in b.members : can(regex("^(user|group|serviceAccount|domain|principal|principalSet):.+$", m))]) &&
      b.condition.title != "" &&
      b.condition.expression != ""
    ])
    error_message = "conditional_bindings must specify valid role, non-empty members, and non-empty condition.title/expression."
  }
}

############################################
# Custom roles (organization/project)      #
############################################

/**
 * custom_roles: map of IDs to definitions.
 * The module will choose org- or project-level placement based on target_level.
 * ID must be 3–64 chars, start with a letter, contain letters, numbers, and underscores.
 * Example:
 * {
 *   "DataAuditor" = {
 *     title       = "Data Auditor"
 *     description = "Read-only data audit role"
 *     stage       = "GA"
 *     permissions = ["storage.objects.get", "bigquery.tables.get", "resourcemanager.projects.get"]
 *   }
 * }
 */
variable "custom_roles" {
  description = "Custom role definitions to create at org/project scope (based on target_level)."
  type = map(object({
    title       = string
    description = optional(string, "")
    stage       = optional(string, "GA") # ALPHA|BETA|GA|DEPRECATED|DISABLED|EAP
    permissions = list(string)
  }))
  default = {}

  validation {
    condition = alltrue([
      for id, def in var.custom_roles :
      can(regex("^[A-Za-z][A-Za-z0-9_]{2,63}$", id)) &&
      length(def.permissions) > 0 &&
      alltrue([for p in def.permissions : can(regex("^[a-zA-Z0-9.]+$", p))]) &&
      contains(["ALPHA","BETA","GA","DEPRECATED","DISABLED","EAP"], upper(coalesce(def.stage, "GA")))
    ])
    error_message = "custom_roles: key must match ^[A-Za-z][A-Za-z0-9_]{2,63}$; permissions non-empty and like 'service.verb'; stage in {ALPHA,BETA,GA,DEPRECATED,DISABLED,EAP}."
  }
}

############################################
# Service accounts                         #
############################################

/**
 * service_accounts: map of SA IDs to spec.
 * SA ID: 6–30 chars, lower-case letters, digits, '-', must start with letter.
 * Example:
 * {
 *   "ci-runner" = {
 *     display_name   = "CI Runner"
 *     description    = "Builds and deploys artifacts"
 *     disabled       = false
 *     iam_bindings   = {
 *       "roles/iam.serviceAccountTokenCreator" = ["user:alice@example.com"]
 *     }
 *   }
 * }
 */
variable "service_accounts" {
  description = "Service accounts to create at project scope, with optional per-SA IAM bindings."
  type = map(object({
    display_name = optional(string, "")
    description  = optional(string, "")
    disabled     = optional(bool, false)
    iam_bindings = optional(map(list(string)), {})
  }))
  default = {}

  validation {
    condition = alltrue([
      for id, spec in var.service_accounts :
      can(regex("^[a-z][a-z0-9-]{5,29}$", id)) &&
      alltrue([
        for role, members in coalesce(spec.iam_bindings, {}) :
        can(regex("^roles/[A-Za-z0-9_.]+$", role)) &&
        alltrue([for m in members : can(regex("^(user|group|serviceAccount|domain|principal|principalSet):.+$", m))])
      ])
    ])
    error_message = "service_accounts keys must match ^[a-z][a-z0-9-]{5,29}$; per-SA iam_bindings must use valid role/member formats."
  }
}

variable "enforce_unique_sa_ids" {
  description = "If true, enforces uniqueness of SA IDs across the supplied map (defensive guard)."
  type        = bool
  default     = true
}

variable "allow_service_account_key_creation" {
  description = "If true, module may create SA keys (not recommended). Default false for security."
  type        = bool
  default     = false
}

############################################
# Audit logging (AuditConfig)              #
############################################

/**
 * audit_configs: list of service-level audit configs at scope.
 * Example:
 * [{
 *   service = "allServices"
 *   audit_log_configs = [
 *     { log_type = "ADMIN_READ",  exempted_members = ["user:auditor@example.com"] },
 *     { log_type = "DATA_READ" },
 *     { log_type = "DATA_WRITE" }
 *   ]
 * }]
 */
variable "audit_configs" {
  description = "Audit logging configs (AuditConfig) at the selected scope."
  type = list(object({
    service = string
    audit_log_configs = list(object({
      log_type         = string # ADMIN_READ|DATA_READ|DATA_WRITE
      exempted_members = optional(list(string), [])
    }))
  }))
  default = []

  validation {
    condition = alltrue([
      for ac in var.audit_configs :
      ac.service != "" &&
      alltrue([
        for c in ac.audit_log_configs :
        contains(["ADMIN_READ","DATA_READ","DATA_WRITE"], upper(c.log_type)) &&
        alltrue([for m in coalesce(c.exempted_members, []) : can(regex("^(user|group|serviceAccount|domain):.+$", m))])
      ])
    ])
    error_message = "audit_configs: service must be non-empty; log_type in {ADMIN_READ,DATA_READ,DATA_WRITE}; exempted_members must be user/group/serviceAccount/domain."
  }
}

############################################
# Workload Identity Federation (WIF)       #
############################################

/**
 * workload_identity_pools: pools and providers (OIDC/SAML).
 * Example:
 * {
 *   "ext-pool" = {
 *     display_name = "External Pool"
 *     description  = "Partners"
 *     disabled     = false
 *     providers = {
 *       "github-oidc" = {
 *         display_name       = "GitHub OIDC"
 *         description        = "Actions"
 *         disabled           = false
 *         attribute_mappings = {
 *           "google.subject" = "assertion.sub"
 *           "attribute.actor"= "assertion.actor"
 *         }
 *         oidc = {
 *           issuer_uri        = "https://token.actions.githubusercontent.com"
 *           allowed_audiences = ["sts.googleapis.com"]
 *         }
 *       }
 *     }
 *   }
 * }
 */
variable "workload_identity_pools" {
  description = "Definition of Workload Identity Pools and Providers (OIDC/SAML) at org/project scope."
  type = map(object({
    display_name = optional(string, "")
    description  = optional(string, "")
    disabled     = optional(bool, false)
    providers = map(object({
      display_name       = optional(string, "")
      description        = optional(string, "")
      disabled           = optional(bool, false)
      attribute_mappings = optional(map(string), {})
      oidc = optional(object({
        issuer_uri        = string
        allowed_audiences = optional(list(string), [])
      }), null)
      saml = optional(object({
        idp_metadata_xml = string
      }), null)
    }))
  }))
  default = {}

  validation {
    condition = alltrue([
      for pool_name, pool in var.workload_identity_pools :
      can(regex("^[a-z]([a-z0-9-]{2,61}[a-z0-9])?$", pool_name)) &&
      alltrue([
        for prov_name, prov in pool.providers :
        can(regex("^[a-z]([a-z0-9-]{2,61}[a-z0-9])?$", prov_name)) &&
        (
          (prov.oidc != null && prov.saml == null) ||
          (prov.oidc == null && prov.saml != null)
        ) &&
        (
          prov.oidc == null ||
          (prov.oidc.issuer_uri != "" && can(regex("^https://", prov.oidc.issuer_uri)))
        ) &&
        (
          prov.saml == null || prov.saml.idp_metadata_xml != ""
        )
      ])
    ])
    error_message = "WIF: pool/provider names must be DNS-like; each provider must be either OIDC or SAML; OIDC issuer must be https URL; SAML metadata must be non-empty."
  }
}

############################################
# Impersonation and helper toggles         #
############################################

variable "enable_impersonation_bindings" {
  description = "If true, attach common impersonation roles (e.g., Service Account Token Creator) as specified in inputs."
  type        = bool
  default     = false
}

variable "prevent_destroy_protection" {
  description = "If true, resources created by this module should be protected via lifecycle prevent_destroy (applied by resources)."
  type        = bool
  default     = true
}

############################################
# Output controls                          #
############################################

variable "export_effective_bindings" {
  description = "If true, the module will compute and output effective bindings it manages (for diagnostics)."
  type        = bool
  default     = true
}

############################################
# Cross-variable guards                    #
############################################

# Ensure the scope identifier for the selected level is present.
locals {
  _scope_ok = (
    (var.target_level == "organization" && var.organization_id != null && var.organization_id != "") ||
    (var.target_level == "folder"       && var.folder_id       != null && var.folder_id       != "") ||
    (var.target_level == "project"      && var.project_id      != null && var.project_id      != "")
  )
}

variable "validation_noop" {
  description = "Internal NOOP to trigger cross-field validation via preconditions in resources."
  type        = bool
  default     = true
}

# Consumers (resources) should include a precondition using local._scope_ok, but we also provide a defensive hint here:
# (Terraform cannot fail purely from locals; enforcement occurs in resources using precondition.)
