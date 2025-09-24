#############################################
# Module: ops/terraform/modules/bootstrap/remote-state/locals.tf
# Purpose: Canonical naming, environment normalization, backend-specific
#          bucket/account/container names, deterministic state keys,
#          common tags/labels for remote state bootstrap.
#############################################

locals {
  ############################################################
  # 1) Workspace → Environment normalization
  ############################################################
  # terraform.workspace → short env codes
  _env_map = {
    "prod"        = "prod"
    "production"  = "prod"
    "stage"       = "stg"
    "staging"     = "stg"
    "preprod"     = "ppd"
    "uat"         = "uat"
    "qa"          = "qa"
    "test"        = "tst"
    "dev"         = "dev"
    "default"     = "dev"
  }

  workspace_raw = terraform.workspace
  environment   = coalesce(lookup(local._env_map, lower(local.workspace_raw), null), "dev") # default: dev
  env_short     = local.environment

  ############################################################
  # 2) Input normalization helpers (kebab/flat/region)
  ############################################################
  # Expect external variables:
  #   var.org (e.g. "aethernova")
  #   var.project (e.g. "chain-core")
  #   var.component (optional; defaults to "remote-state")
  #   var.region (e.g. "eu-north-1" or "westeurope" or "europe-west1")
  #   var.backend_provider ("aws" | "gcp" | "azure")
  #   var.state_component (optional logical component in key path)
  #   var.state_stage (optional logical stage in key path)
  #   var.tags (map(string)) / var.labels (map(string)) optional

  org_raw       = trim(var.org)
  project_raw   = trim(var.project)
  component_raw = trim(coalesce(var.component, "remote-state"))
  region_raw    = trim(var.region)

  # kebab-safe (a-z0-9-)
  org_kebab       = lower(regexreplace(local.org_raw,       "[^a-z0-9-]", "-"))
  project_kebab   = lower(regexreplace(local.project_raw,   "[^a-z0-9-]", "-"))
  component_kebab = lower(regexreplace(local.component_raw, "[^a-z0-9-]", "-"))
  region_kebab    = lower(regexreplace(local.region_raw,    "[^a-z0-9-]", "-"))

  # flat-safe (a-z0-9 only) — для Azure storage account
  org_flat       = lower(regexreplace(local.org_raw,       "[^a-z0-9]", ""))
  project_flat   = lower(regexreplace(local.project_raw,   "[^a-z0-9]", ""))
  component_flat = lower(regexreplace(local.component_raw, "[^a-z0-9]", ""))
  region_flat    = lower(regexreplace(local.region_raw,    "[^a-z0-9]", ""))

  # safe join helpers
  dash   = "-"
  slash  = "/"

  ############################################################
  # 3) Canonical names (pre-trim), then length guards per backend
  ############################################################
  # Common base names
  name_base_kebab = regexreplace(
    join(local.dash, compact([local.org_kebab, local.project_kebab, local.env_short])),
    "(-){2,}",
    "-"
  )

  name_with_region_kebab = regexreplace(
    join(local.dash, compact([local.name_base_kebab, local.region_kebab])),
    "(-){2,}",
    "-"
  )

  # AWS S3 bucket baseline (max 63)
  aws_bucket_pre = regexreplace(
    lower(local.name_with_region_kebab),
    "^-|-$",
    ""
  )
  aws_bucket_name = substr(local.aws_bucket_pre, 0, 63)

  # AWS DynamoDB table name (max practical ~255; we keep concise)
  aws_lock_table_pre = join(local.dash, compact([local.name_base_kebab, "tf-locks"]))
  aws_lock_table     = substr(regexreplace(local.aws_lock_table_pre, "^-|-$", ""), 0, 255)

  # AWS KMS alias (alias/<...>), we return only suffix; alias prefix add in resource
  aws_kms_alias_pre = join(local.dash, compact([local.name_base_kebab, "kms", "tfstate"]))
  aws_kms_alias     = substr(regexreplace(local.aws_kms_alias_pre, "^-|-$", ""), 0, 256)

  # GCP bucket (max 63)
  gcp_bucket_pre = regexreplace(lower(local.name_with_region_kebab), "^-|-$", "")
  gcp_bucket_name = substr(local.gcp_bucket_pre, 0, 63)

  # Azure storage account (3-24, [a-z0-9] only)
  azure_storage_pre = lower(join("", compact([local.org_flat, localproject_flat, localenv_flat, localregion_flat])))
  # Compose flats with safe fallbacks
  localproject_flat = length(local.project_flat) > 0 ? local.project_flat : "proj"
  localenv_flat     = length(local.env_short)    > 0 ? regexreplace(local.env_short, "[^a-z0-9]", "") : "env"
  localregion_flat  = length(local.region_flat)  > 0 ? local.region_flat : "region"

  azure_storage_name = substr(
    replace(replace(replace(local.azure_storage_pre, "-", ""), "_", ""), ".", ""),
    0,
    24
  )

  # Azure resource group (<= 90-100 typical soft limit)
  azure_rg_pre = join(local.dash, compact([local.name_with_region_kebab, "rg"]))
  azure_rg     = substr(regexreplace(lower(local.azure_rg_pre), "^-|-$", ""), 0, 90)

  # Azure container name (<= 63 recommended)
  azure_container_pre = join(local.dash, compact([local.env_short, "tfstate"]))
  azure_container     = substr(regexreplace(lower(local.azure_container_pre), "^-|-$", ""), 0, 63)

  ############################################################
  # 4) Deterministic state key (.tfstate path)
  ############################################################
  # Deterministic folder-like key for all backends
  # Format: <org>/<project>/<env>/<region>/<stage?>/<component or 'remote-state'>/<state_component?>
  state_stage      = try(trim(var.state_stage), "")
  state_component  = try(trim(var.state_component), "")

  state_path_elems = compact([
    local.org_kebab,
    local.project_kebab,
    local.env_short,
    local.region_kebab,
    length(local.state_stage) > 0 ? lower(regexreplace(local.state_stage, "[^a-z0-9-]", "-")) : "",
    local.component_kebab,
    length(local.state_component) > 0 ? lower(regexreplace(local.state_component, "[^a-z0-9-]", "-")) : ""
  ])

  state_key_noext = join(local.slash, local.state_path_elems)
  state_key       = "${local.state_key_noext}.tfstate"

  ############################################################
  # 5) Common tags/labels
  ############################################################
  common_tags = merge(
    {
      "org"        = local.org_kebab
      "project"    = local.project_kebab
      "component"  = local.component_kebab
      "env"        = local.env_short
      "region"     = local.region_kebab
      "managed_by" = "terraform"
      "module"     = "bootstrap/remote-state"
    },
    try(var.tags, {})
  )

  common_labels = merge(
    {
      "org"        = local.org_kebab
      "project"    = local.project_kebab
      "component"  = local.component_kebab
      "env"        = local.env_short
      "region"     = local.region_kebab
      "managed_by" = "terraform"
      "module"     = "bootstrap/remote-state"
    },
    try(var.labels, {})
  )

  ############################################################
  # 6) Backend profiles (computed block for consumers)
  ############################################################
  backend_provider = lower(trim(var.backend_provider))

  aws_backend = {
    bucket          = local.aws_bucket_name
    dynamodb_table  = local.aws_lock_table
    kms_alias_name  = local.aws_kms_alias
    region          = local.region_kebab
    key             = local.state_key
    # sse = "aws:kms" recommended; encryption resource created in module code
  }

  gcp_backend = {
    bucket  = local.gcp_bucket_name
    prefix  = dirname(local.state_key) # optional alternative to key
    key     = local.state_key
    # project can be sourced from provider config; expose if needed:
    project = try(trim(var.gcp_project), "")
  }

  azure_backend = {
    resource_group_name  = local.azure_rg
    storage_account_name = local.azure_storage_name
    container_name       = local.azure_container
    key                  = local.state_key
  }

  ############################################################
  # 7) Public outputs for reuse in module (via output blocks)
  ############################################################
  resolved_backend = (
    local.backend_provider == "aws"   ? local.aws_backend   :
    local.backend_provider == "gcp"   ? local.gcp_backend   :
    local.backend_provider == "azure" ? local.azure_backend :
    local.aws_backend # default to AWS if not specified
  )
}
