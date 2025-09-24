##############################################
# modules/registry/gar/main.tf
# Production-grade GAR module (GCP + Terraform)
##############################################

# This module expects provider "google" to be configured in the root module.
# If you plan to use VPC-SC config (google_artifact_registry_vpcsc_config),
# also pass alias "google-beta" from the root (provider = google-beta).

##############################################
# Required APIs
##############################################

# Always enable Artifact Registry; enable Container Analysis if vulnerability scanning is desired.
# Docs: Enable service (Artifact Registry) and scanning via Container Scanning API.
# https://cloud.google.com/artifact-registry/docs/enable-service
# https://cloud.google.com/artifact-analysis/docs/enable-automatic-scanning

resource "google_project_service" "required" {
  for_each = toset(compact([
    "artifactregistry.googleapis.com",
    try(var.enable_container_scanning, true) ? "containeranalysis.googleapis.com" : null,
    try(var.enable_secret_manager_api, false) ? "secretmanager.googleapis.com" : null
  ]))

  project = var.project_id
  service = each.value

  disable_on_destroy        = false
  disable_dependent_services = false
}

##############################################
# Artifact Registry repositories
##############################################
# Input shape (example):
# variable "repositories" {
#   type = map(object({
#     location        = string
#     repository_id   = string
#     description     = optional(string)
#     format          = string           # "docker" | "maven" | "npm" | "python" | "apt" | "yum" | "go"
#     labels          = optional(map(string), {})
#     kms_key_name    = optional(string) # CMEK
#
#     # One of: "STANDARD_REPOSITORY" (default), "VIRTUAL_REPOSITORY", "REMOTE_REPOSITORY"
#     mode            = optional(string, "STANDARD_REPOSITORY")
#
#     # Docker-only repository options
#     docker_immutable_tags = optional(bool, true)
#
#     # Maven-only options
#     maven_version_policy       = optional(string) # "RELEASE" | "SNAPSHOT" | "VERSION_POLICY_UNSPECIFIED"
#     maven_allow_snapshot_overwrites = optional(bool, false)
#
#     # Virtual repo upstreams (same location/format)
#     virtual_upstreams = optional(list(object({
#       id         = string
#       repository = string # full resource name: projects/ID/locations/LOC/repositories/NAME
#       priority   = optional(number) # 1=highest; greater takes precedence in pull order (per docs)
#     })), [])
#
#     # Remote repo config (minimal portable subset for public upstreams)
#     remote_public_source = optional(object({
#       # one of: "docker_hub" | "maven_central" | "npmjs" | "pypi" | "debian" | "centos" | "ghcr"
#       preset = string
#       # optional path pieces for APT/YUM where applicable
#       path   = optional(string)
#       # optional description for remote config
#       description = optional(string)
#     }))
#
#     # Cleanup policies (Keep/Delete); dry run controlled globally below
#     cleanup_policies = optional(list(object({
#       id     = string
#       action = string # "Keep" | "Delete"
#       most_recent_versions = optional(object({
#         keep_count             = number
#         package_name_prefixes  = optional(list(string), [])
#       }))
#       condition = optional(object({
#         tag_state             = optional(string, "any") # "tagged" | "untagged" | "any"
#         tag_prefixes          = optional(list(string), [])
#         package_name_prefixes = optional(list(string), [])
#         older_than            = optional(string) # e.g. "30d", "72h"
#       }))
#     })), [])
#   }))
# }

locals {
  repos = var.repositories
}

# Docs (Terraform resource + features):
# - Repository resource supports kms_key_name and docker_config. Terraform Registry.
# - Virtual repositories and upstream_policies. Google Cloud docs (Terraform example).
# - Cleanup policies (keep/delete, dry run). Google Cloud docs.
# https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/artifact_registry_repository
# https://cloud.google.com/artifact-registry/docs/repositories/virtual-repo
# https://cloud.google.com/artifact-registry/docs/repositories/cleanup-policy

resource "google_artifact_registry_repository" "this" {
  for_each = local.repos

  project       = var.project_id
  location      = each.value.location
  repository_id = each.value.repository_id
  description   = try(each.value.description, null)
  format        = lower(each.value.format)
  labels        = try(each.value.labels, {})

  # CMEK (optional)
  kms_key_name = try(each.value.kms_key_name, null)

  # Mode: STANDARD (default) | VIRTUAL | REMOTE (per docs)
  # https://cloud.google.com/artifact-registry/docs/repositories/virtual-repo
  mode = try(each.value.mode, "STANDARD_REPOSITORY")

  # Docker-only immutable tags (prevents tag mutation)
  # https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/artifact_registry_repository
  dynamic "docker_config" {
    for_each = lower(each.value.format) == "docker" ? [1] : []
    content {
      immutable_tags = try(each.value.docker_immutable_tags, true)
    }
  }

  # Maven-only config (version policy)
  dynamic "maven_config" {
    for_each = lower(each.value.format) == "maven" && try(each.value.maven_version_policy, null) != null ? [1] : []
    content {
      version_policy            = try(each.value.maven_version_policy, null)
      allow_snapshot_overwrites = try(each.value.maven_allow_snapshot_overwrites, false)
    }
  }

  # Virtual repository upstream policies
  # Example structure per official docs:
  # virtual_repository_config { upstream_policies { id, repository, priority } }
  dynamic "virtual_repository_config" {
    for_each = try(each.value.mode, "STANDARD_REPOSITORY") == "VIRTUAL_REPOSITORY" ? [1] : []
    content {
      dynamic "upstream_policies" {
        for_each = try(each.value.virtual_upstreams, [])
        content {
          id         = upstream_policies.value.id
          repository = upstream_policies.value.repository
          # Per docs: lower numeric value is higher priority in some examples,
          # but page states "The highest priority is 1. Entries with a greater priority value take precedence."
          # We pass provided number as-is to reflect user intent.
          priority   = try(upstream_policies.value.priority, null)
        }
      }
    }
  }

  # Remote repository configuration (minimal portable presets)
  # Resource supports remote_repository_config with per-format blocks:
  # docker_repository.public_repository = "DOCKER_HUB"
  # maven_repository.public_repository  = "MAVEN_CENTRAL"
  # npm_repository.public_repository    = "NPMJS"
  # python_repository.public_repository = "PYPI"
  # apt_repository.public_repository    = e.g. DEBIAN
  # yum_repository.public_repository    = e.g. CENTOS_STREAM
  # https://cloud.google.com/artifact-registry/docs/repositories/remote-repo
  # https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/artifact_registry_repository
  dynamic "remote_repository_config" {
    for_each = try(each.value.mode, "STANDARD_REPOSITORY") == "REMOTE_REPOSITORY" && try(each.value.remote_public_source, null) != null ? [each.value.remote_public_source] : []
    content {
      description = try(remote_repository_config.value.description, null)

      # docker
      dynamic "docker_repository" {
        for_each = lower(each.value.format) == "docker" ? [1] : []
        content {
          public_repository = upper(
            contains(["ghcr", "github", "ghcr.io"], lower(remote_repository_config.value.preset)) ? "GITHUB" : "DOCKER_HUB"
          )
        }
      }

      # maven
      dynamic "maven_repository" {
        for_each = lower(each.value.format) == "maven" ? [1] : []
        content {
          public_repository = "MAVEN_CENTRAL"
        }
      }

      # npm
      dynamic "npm_repository" {
        for_each = lower(each.value.format) == "npm" ? [1] : []
        content {
          public_repository = "NPMJS"
        }
      }

      # python
      dynamic "python_repository" {
        for_each = lower(each.value.format) == "python" ? [1] : []
        content {
          public_repository = "PYPI"
        }
      }

      # apt
      dynamic "apt_repository" {
        for_each = lower(each.value.format) == "apt" ? [1] : []
        content {
          public_repository = "DEBIAN"
          # Some sources also require a path (e.g., dists/buster). Provide via var.remote_public_source.path if needed.
          # path = try(remote_repository_config.value.path, null)
        }
      }

      # yum
      dynamic "yum_repository" {
        for_each = lower(each.value.format) == "yum" ? [1] : []
        content {
          public_repository = "CENTOS_STREAM"
          # path = try(remote_repository_config.value.path, null)
        }
      }

      # go
      dynamic "go_repository" {
        for_each = lower(each.value.format) == "go" ? [1] : []
        content {
          # Upstream for Go is public proxy.golang.org per docs.
          # For Terraform, go_repository implicitly uses the public proxy.
          # No additional attributes typically required.
        }
      }
    }
  }

  # Cleanup policies (Keep/Delete) + dry run
  # https://cloud.google.com/artifact-registry/docs/repositories/cleanup-policy
  cleanup_policy_dry_run = try(var.cleanup_policy_dry_run, true)

  dynamic "cleanup_policies" {
    for_each = try(each.value.cleanup_policies, [])
    content {
      id = cleanup_policies.value.id

      action {
        type = cleanup_policies.value.action
      }

      dynamic "most_recent_versions" {
        for_each = try(cleanup_policies.value.most_recent_versions, null) != null ? [cleanup_policies.value.most_recent_versions] : []
        content {
          keep_count            = most_recent_versions.value.keep_count
          package_name_prefixes = try(most_recent_versions.value.package_name_prefixes, null)
        }
      }

      dynamic "condition" {
        for_each = try(cleanup_policies.value.condition, null) != null ? [cleanup_policies.value.condition] : []
        content {
          # tag_state: "tagged" | "untagged" | "any"
          tag_state             = try(condition.value.tag_state, null)
          tag_prefixes          = try(condition.value.tag_prefixes, null)
          package_name_prefixes = try(condition.value.package_name_prefixes, null)
          older_than            = try(condition.value.older_than, null) # e.g. "30d", "72h"
        }
      }
    }
  }

  # Optional repository-level vulnerability scanning config (commented for portability).
  # Requires provider version that exposes vulnerability_scanning_config.
  # https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/artifact_registry_repository
  # https://cloud.google.com/artifact-analysis/docs/enable-automatic-scanning
  # vulnerability_scanning_config {
  #   enablement_config {
  #     # "INHERITED" or "DISABLED" per provider docs; project-level Container Scanning API governs defaults.
  #     value = try(var.vulnerability_scanning_value, "INHERITED")
  #   }
  # }

  depends_on = [google_project_service.required]

  lifecycle {
    precondition {
      condition     = contains(["docker","maven","npm","python","apt","yum","go"], lower(each.value.format))
      error_message = "Unsupported Artifact Registry format."
    }
    precondition {
      condition     = regex("^[-a-z0-9]+$", each.value.repository_id) != null
      error_message = "repository_id must be lowercase alphanumeric and dashes."
    }
  }
}

##############################################
# Repository-level IAM (Reader/Writer/RepoAdmin etc.)
##############################################
# variable "repository_iam" is a map(repo_id => map(role => list(members)))
# Example:
# repository_iam = {
#   "my-docker" = {
#     "roles/artifactregistry.reader"    = ["user:dev@example.com"]
#     "roles/artifactregistry.writer"    = ["serviceAccount:ci@PROJECT.iam.gserviceaccount.com"]
#     "roles/artifactregistry.repoAdmin" = ["group:platform-admins@example.com"]
#   }
# }

locals {
  repo_iam_bindings = {
    for pair in flatten([
      for repo_key, repo_cfg in local.repos : [
        for role, members in lookup(var.repository_iam, repo_key, {}) : {
          key      = "${repo_key}|${role}"
          repo_key = repo_key
          role     = role
          members  = members
        }
      ]
    ]) : pair.key => pair
  }
}

resource "google_artifact_registry_repository_iam_binding" "repo" {
  for_each = local.repo_iam_bindings

  project    = var.project_id
  location   = google_artifact_registry_repository.this[each.value.repo_key].location
  repository = google_artifact_registry_repository.this[each.value.repo_key].repository_id

  role    = each.value.role
  members = each.value.members

  depends_on = [google_artifact_registry_repository.this]
}

##############################################
# Optional: VPC-SC configuration (per project/location)
# Resource exists in provider; uncomment if you pass provider alias google-beta.
# Docs: https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/artifact_registry_vpcsc_config
#       https://cloud.google.com/artifact-registry/docs/repositories/remote-repo (allow/deny upstream)
##############################################
# variable "vpcsc_rules" {
#   type = map(object({
#     location = string
#     status   = string # "ALLOW" | "DENY"
#   }))
#   default = {}
# }
#
# resource "google_artifact_registry_vpcsc_config" "this" {
#   provider = google-beta
#   for_each = var.vpcsc_rules
#   project  = var.project_id
#   location = each.value.location
#   vpcsc_config {
#     status = each.value.status
#   }
#   depends_on = [google_project_service.required]
# }
