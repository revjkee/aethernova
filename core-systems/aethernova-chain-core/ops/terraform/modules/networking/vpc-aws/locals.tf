#############################################
# locals.tf — industrial-grade for VPC AWS  #
#############################################

terraform {
  required_version = ">= 1.5.0"
}

############################
# Naming & Tagging Schema  #
############################

locals {
  # Sanitize helpers
  _dlm        = try(var.name_delimiter, "-")
  _org        = lower(replace(try(var.org, ""), "/[^a-zA-Z0-9-]/", ""))
  _project    = lower(replace(try(var.project, ""), "/[^a-zA-Z0-9-]/", ""))
  _env        = lower(replace(try(var.environment, ""), "/[^a-zA-Z0-9-]/", ""))
  _region     = lower(replace(try(var.region, ""), "/[^a-z0-9-]/", ""))

  # Name prefix: org-project-env
  name_prefix = join(local._dlm, compact([local._org, local._project, local._env]))

  # Global tags (merge default -> computed -> user)
  base_tags = merge(
    try(var.default_tags, {}),
    {
      "Project"     = try(var.project, null)
      "Environment" = try(var.environment, null)
      "Region"      = try(var.region, null)
      "ManagedBy"   = "Terraform"
      "Module"      = "networking/vpc-aws"
    }
  )

  tags = merge(local.base_tags, try(var.tags, {}))
}

############################
# Availability Zones (AZs) #
############################

locals {
  # Input AZs preferred; else fallback list; then cap by max_az_count
  _input_azs     = try(var.azs, [])
  _fallback_azs  = try(var.fallback_azs, [])
  _raw_azs       = length(local._input_azs) > 0 ? local._input_azs : local._fallback_azs
  max_az_count   = max(1, try(var.max_az_count, 3))
  azs            = slice(local._raw_azs, 0, min(length(local._raw_azs), local.max_az_count))
  az_count       = length(local.azs)
}

#################
# VPC CIDR plan #
#################

locals {
  # Base IPv4 VPC CIDR (e.g. 10.0.0.0/16)
  vpc_ipv4_cidr = trimspace(try(var.vpc_ipv4_cidr, "10.0.0.0/16"))

  # Optional IPv6 /56 from Amazon-provided pool or explicit /56
  enable_ipv6        = try(var.enable_ipv6, false)
  vpc_ipv6_cidr      = try(var.vpc_ipv6_cidr, null) # expected /56 when provided
  ipv6_subnet_newbits = try(var.ipv6_subnet_newbits, 8) # /56 -> /64 per subnet if 8 new bits

  # Internet/NAT model
  enable_igw              = try(var.enable_igw, true)
  nat_gateway_strategy    = lower(try(var.nat_gateway_strategy, "single")) # single|per-az|none
  allocate_eip_per_nat    = try(var.allocate_eip_per_nat, true)

  # Endpoints
  enable_interface_endpoints = try(var.enable_interface_endpoints, true)
  enable_gateway_endpoints   = try(var.enable_gateway_endpoints, true)
  interface_endpoints        = toset(try(var.interface_endpoints, [])) # e.g. ["ec2","ecr.api","ecr.dkr","ssm","secretsmanager"]
  gateway_endpoints          = toset(try(var.gateway_endpoints, ["s3", "dynamodb"]))
}

#########################################
# Subnetting policy (per tier newbits)  #
#########################################

locals {
  # Enable/disable subnet tiers
  enable_public_subnets   = try(var.enable_public_subnets, true)
  enable_private_subnets  = try(var.enable_private_subnets, true)
  enable_intra_subnets    = try(var.enable_intra_subnets, false)   # no egress, for internal workloads
  enable_database_subnets = try(var.enable_database_subnets, false)

  # Newbits per tier (IPv4)
  public_newbits_v4   = try(var.public_newbits_v4, 4)   # e.g. /16 -> /20 across AZs
  private_newbits_v4  = try(var.private_newbits_v4, 4)
  intra_newbits_v4    = try(var.intra_newbits_v4, 6)
  database_newbits_v4 = try(var.database_newbits_v4, 6)

  # Order of tiers to keep deterministic netnum allocation
  _tiers = [
    { key = "public",   enabled = local.enable_public_subnets,   newbits_v4 = local.public_newbits_v4 },
    { key = "private",  enabled = local.enable_private_subnets,  newbits_v4 = local.private_newbits_v4 },
    { key = "intra",    enabled = local.enable_intra_subnets,    newbits_v4 = local.intra_newbits_v4 },
    { key = "database", enabled = local.enable_database_subnets, newbits_v4 = local.database_newbits_v4 },
  ]

  # Compute deterministic offset for each tier (so adding a later tier doesn't reshuffle earlier CIDRs)
  # netnum is cumulative over enabled tiers and AZ index
  _tier_sequence = [
    for t in local._tiers :
    t if t.enabled
  ]

  # Starting netnum per tier (sum of (az_count) blocks for all prior enabled tiers)
  _tier_start_netnum = {
    for idx, t in local._tier_sequence :
    t.key => sum([
      for j in range(idx) :
      local.az_count
    ])
  }
}

######################################
# CIDR allocation per AZ and per tier
######################################

# IPv4 subnets
locals {
  public_subnet_ipv4_cidrs = local.enable_public_subnets ? {
    for az_idx, az in local.azs :
    az => cidrsubnet(local.vpc_ipv4_cidr, local.public_newbits_v4, local._tier_start_netnum["public"] + az_idx)
  } : {}

  private_subnet_ipv4_cidrs = local.enable_private_subnets ? {
    for az_idx, az in local.azs :
    az => cidrsubnet(local.vpc_ipv4_cidr, local.private_newbits_v4, local._tier_start_netnum["private"] + az_idx)
  } : {}

  intra_subnet_ipv4_cidrs = local.enable_intra_subnets ? {
    for az_idx, az in local.azs :
    az => cidrsubnet(local.vpc_ipv4_cidr, local.intra_newbits_v4, local._tier_start_netnum["intra"] + az_idx)
  } : {}

  database_subnet_ipv4_cidrs = local.enable_database_subnets ? {
    for az_idx, az in local.azs :
    az => cidrsubnet(local.vpc_ipv4_cidr, local.database_newbits_v4, local._tier_start_netnum["database"] + az_idx)
  } : {}
}

# IPv6 subnets (optional)
locals {
  # For IPv6 we derive per-AZ blocks using /56 base and newbits 8 -> /64 per subnet by default.
  public_subnet_ipv6_cidrs = local.enable_ipv6 && local.enable_public_subnets ? {
    for az_idx, az in local.azs :
    az => cidrsubnet(try(local.vpc_ipv6_cidr, "::/56"), local.ipv6_subnet_newbits, local._tier_start_netnum["public"] + az_idx)
  } : {}

  private_subnet_ipv6_cidrs = local.enable_ipv6 && local.enable_private_subnets ? {
    for az_idx, az in local.azs :
    az => cidrsubnet(try(local.vpc_ipv6_cidr, "::/56"), local.ipv6_subnet_newbits, local._tier_start_netnum["private"] + az_idx)
  } : {}

  intra_subnet_ipv6_cidrs = local.enable_ipv6 && local.enable_intra_subnets ? {
    for az_idx, az in local.azs :
    az => cidrsubnet(try(local.vpc_ipv6_cidr, "::/56"), local.ipv6_subnet_newbits, local._tier_start_netnum["intra"] + az_idx)
  } : {}

  database_subnet_ipv6_cidrs = local.enable_ipv6 && local.enable_database_subnets ? {
    for az_idx, az in local.azs :
    az => cidrsubnet(try(local.vpc_ipv6_cidr, "::/56"), local.ipv6_subnet_newbits, local._tier_start_netnum["database"] + az_idx)
  } : {}
}

##########################
# Subnet name annotations
##########################

locals {
  subnet_names_public = {
    for az_idx, az in local.azs :
    az => format("%s%spub%02d-%s",
      local.name_prefix,
      length(local.name_prefix) > 0 ? local._dlm : "",
      az_idx + 1,
      az
    )
  }

  subnet_names_private = {
    for az_idx, az in local.azs :
    az => format("%s%spri%02d-%s",
      local.name_prefix,
      length(local.name_prefix) > 0 ? local._dlm : "",
      az_idx + 1,
      az
    )
  }

  subnet_names_intra = {
    for az_idx, az in local.azs :
    az => format("%s%sintra%02d-%s",
      local.name_prefix,
      length(local.name_prefix) > 0 ? local._dlm : "",
      az_idx + 1,
      az
    )
  }

  subnet_names_database = {
    for az_idx, az in local.azs :
    az => format("%s%sdb%02d-%s",
      local.name_prefix,
      length(local.name_prefix) > 0 ? local._dlm : "",
      az_idx + 1,
      az
    )
  }
}

##########################
# Route tables & gateways
##########################

locals {
  # Route table names
  rtb_public_name   = format("%s%srtt-public", local.name_prefix, length(local.name_prefix) > 0 ? local._dlm : "")
  rtb_private_name  = format("%s%srtt-private", local.name_prefix, length(local.name_prefix) > 0 ? local._dlm : "")
  rtb_intra_name    = format("%s%srtt-intra", local.name_prefix, length(local.name_prefix) > 0 ? local._dlm : "")
  rtb_database_name = format("%s%srtt-db", local.name_prefix, length(local.name_prefix) > 0 ? local._dlm : "")

  # NAT policy resolution
  use_nat    = local.enable_private_subnets && local.nat_gateway_strategy != "none"
  nat_per_az = local.nat_gateway_strategy == "per-az" && local.use_nat
  nat_single = local.nat_gateway_strategy == "single" && local.use_nat

  # Associate which subnets route through NAT
  nat_target_subnets = local.enable_private_subnets ? keys(local.private_subnet_ipv4_cidrs) : []

  # IGW name
  igw_name = local.enable_igw ? format("%s%sigw", local.name_prefix, length(local.name_prefix) > 0 ? local._dlm : "") : null
}

####################
# VPC Endpoints set
####################

locals {
  # Normalize interface VPCE service names (as given) and build deterministic map
  interface_endpoint_map = {
    for svc in sort(tolist(local.interface_endpoints)) :
    svc => {
      name        = format("%s%svpce-if-%s", local.name_prefix, length(local.name_prefix) > 0 ? local._dlm : "", replace(svc, "/[^a-z0-9.]/", ""))
      private_dns = true
      # Subnet tier to place ENIs — private by default
      subnet_tier = "private"
      # Security group name for endpoints
      sg_name     = format("%s%ssg-vpce-if-%s", local.name_prefix, length(local.name_prefix) > 0 ? local._dlm : "", replace(svc, "/[^a-z0-9.]/", ""))
    }
  }

  gateway_endpoint_map = {
    for svc in sort(tolist(local.gateway_endpoints)) :
    svc => {
      name       = format("%s%svpce-gw-%s", local.name_prefix, length(local.name_prefix) > 0 ? local._dlm : "", replace(svc, "/[^a-z0-9.]/", ""))
      rtb_target = "private" # attach to private route tables by default
    }
  }
}

#########################
# Flow logs & DNS flags #
#########################

locals {
  enable_flow_logs          = try(var.enable_flow_logs, true)
  flow_logs_traffic_type    = upper(try(var.flow_logs_traffic_type, "ALL")) # ACCEPT|REJECT|ALL
  flow_logs_log_format      = try(var.flow_logs_log_format, null)           # optional custom format
  flow_logs_destination     = lower(try(var.flow_logs_destination, "cloudwatch")) # cloudwatch|s3|kinesis
  flow_logs_retention_days  = try(var.flow_logs_retention_days, 30)
  flow_logs_s3_bucket_name  = try(var.flow_logs_s3_bucket_name, null)
  flow_logs_kinesis_arn     = try(var.flow_logs_kinesis_arn, null)
  flow_logs_cw_log_group    = try(var.flow_logs_cw_log_group, format("/aws/vpc/flow-logs/%s", local.name_prefix))

  enable_dns_hostnames = try(var.enable_dns_hostnames, true)
  enable_dns_support   = try(var.enable_dns_support, true)
}

#############################
# Exported structured locals #
#############################

locals {
  # Structured view for consumers inside the module
  plan = {
    name_prefix = local.name_prefix
    tags        = local.tags
    azs         = local.azs

    vpc = {
      ipv4_cidr         = local.vpc_ipv4_cidr
      enable_ipv6       = local.enable_ipv6
      ipv6_cidr         = local.vpc_ipv6_cidr
      enable_dns_support   = local.enable_dns_support
      enable_dns_hostnames = local.enable_dns_hostnames
    }

    subnets = {
      public = {
        enabled   = local.enable_public_subnets
        names     = local.subnet_names_public
        cidr_v4   = local.public_subnet_ipv4_cidrs
        cidr_v6   = local.public_subnet_ipv6_cidrs
        rtb_name  = local.rtb_public_name
      }
      private = {
        enabled   = local.enable_private_subnets
        names     = local.subnet_names_private
        cidr_v4   = local.private_subnet_ipv4_cidrs
        cidr_v6   = local.private_subnet_ipv6_cidrs
        rtb_name  = local.rtb_private_name
      }
      intra = {
        enabled   = local.enable_intra_subnets
        names     = local.subnet_names_intra
        cidr_v4   = local.intra_subnet_ipv4_cidrs
        cidr_v6   = local.intra_subnet_ipv6_cidrs
        rtb_name  = local.rtb_intra_name
      }
      database = {
        enabled   = local.enable_database_subnets
        names     = local.subnet_names_database
        cidr_v4   = local.database_subnet_ipv4_cidrs
        cidr_v6   = local.database_subnet_ipv6_cidrs
        rtb_name  = local.rtb_database_name
      }
    }

    igw = {
      enabled = local.enable_igw
      name    = local.igw_name
    }

    nat = {
      use_nat             = local.use_nat
      strategy            = local.nat_gateway_strategy
      per_az              = local.nat_per_az
      single              = local.nat_single
      allocate_eip_per_nat= local.allocate_eip_per_nat
      target_subnets      = local.nat_target_subnets
    }

    endpoints = {
      enable_interface = local.enable_interface_endpoints
      enable_gateway   = local.enable_gateway_endpoints
      interface_map    = local.interface_endpoint_map
      gateway_map      = local.gateway_endpoint_map
    }

    flow_logs = {
      enabled         = local.enable_flow_logs
      traffic_type    = local.flow_logs_traffic_type
      destination     = local.flow_logs_destination
      retention_days  = local.flow_logs_retention_days
      s3_bucket_name  = local.flow_logs_s3_bucket_name
      kinesis_arn     = local.flow_logs_kinesis_arn
      cw_log_group    = local.flow_logs_cw_log_group
      log_format      = local.flow_logs_log_format
    }
  }
}
