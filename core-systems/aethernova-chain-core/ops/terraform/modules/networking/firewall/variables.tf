/**
 * Module: networking/firewall
 * File:  variables.tf
 * Purpose:
 *   Industrial-grade variable schema for multi-layer AWS network security:
 *   - Security Groups (SG)
 *   - Network ACLs (NACL)
 *   - AWS Network Firewall (ANFW) with stateful/stateless rule groups, TLS inspection
 *   - Centralized logging to S3/CloudWatch/Kinesis
 *   Strong typing, validations, and tag layering for production environments.
 */

############################################
# Core identification & tagging
############################################

variable "name" {
  description = "Logical name prefix for firewall resources."
  type        = string
}

variable "environment" {
  description = "Environment identifier (e.g. dev, staging, prod)."
  type        = string
}

variable "region" {
  description = "AWS region; should match provider configuration."
  type        = string
}

variable "tags" {
  description = "Global tags applied to all resources."
  type        = map(string)
  default     = {}
}

variable "resource_tags" {
  description = <<EOT
Fine-grained tags per resource class. Merged over 'tags'.
Keys (optional): sg, nacl, anfw_firewall, anfw_policy, anfw_rulegroup_stateless, anfw_rulegroup_stateful,
anfw_logging, cw_logs, s3_logs, kinesis_logs
EOT
  type = object({
    sg                        = optional(map(string), {})
    nacl                      = optional(map(string), {})
    anfw_firewall             = optional(map(string), {})
    anfw_policy               = optional(map(string), {})
    anfw_rulegroup_stateless  = optional(map(string), {})
    anfw_rulegroup_stateful   = optional(map(string), {})
    anfw_logging              = optional(map(string), {})
    cw_logs                   = optional(map(string), {})
    s3_logs                   = optional(map(string), {})
    kinesis_logs              = optional(map(string), {})
  })
  default = {}
}

############################################
# VPC context
############################################

variable "vpc_id" {
  description = "Target VPC ID."
  type        = string
}

variable "subnet_ids" {
  description = "Subnets used by AWS Network Firewall endpoints (must be in distinct AZs)."
  type        = list(string)
  default     = []
}

############################################
# Feature switches
############################################

variable "enable_security_groups" {
  description = "Enable creation/management of Security Groups."
  type        = bool
  default     = true
}

variable "enable_network_acls" {
  description = "Enable creation/management of Network ACLs."
  type        = bool
  default     = true
}

variable "enable_network_firewall" {
  description = "Enable AWS Network Firewall (firewall + policy + rule groups)."
  type        = bool
  default     = false
}

############################################
# Security Groups
############################################

variable "security_groups" {
  description = <<EOT
Map of Security Groups to create. Key is SG logical name.
Fields:
  description: SG description
  ingress: list of rules:
    description, protocol, from_port, to_port,
    cidr_blocks (list), ipv6_cidr_blocks (list), security_groups (list of SG IDs),
    self (bool)
  egress: same fields as ingress
  vpc_id: optional override (defaults to module vpc_id)
  tags: optional map of tags
EOT
  type = map(object({
    description = string
    vpc_id      = optional(string)
    ingress = optional(list(object({
      description       = optional(string, "")
      protocol          = string                         # "-1" | "tcp" | "udp" | "icmp" etc.
      from_port         = number
      to_port           = number
      cidr_blocks       = optional(list(string), [])
      ipv6_cidr_blocks  = optional(list(string), [])
      security_groups   = optional(list(string), [])
      self              = optional(bool, false)
    })), [])
    egress = optional(list(object({
      description       = optional(string, "")
      protocol          = string
      from_port         = number
      to_port           = number
      cidr_blocks       = optional(list(string), [])
      ipv6_cidr_blocks  = optional(list(string), [])
      security_groups   = optional(list(string), [])
      self              = optional(bool, false)
    })), [])
    tags = optional(map(string), {})
  }))
  default = {}
}

############################################
# Network ACLs (per-subnet or per-tier)
############################################

variable "nacl_mode" {
  description = "NACL association strategy: 'per-subnet' or 'per-tier'."
  type        = string
  default     = "per-subnet"
  validation {
    condition     = contains(["per-subnet", "per-tier"], var.nacl_mode)
    error_message = "nacl_mode must be 'per-subnet' or 'per-tier'."
  }
}

variable "nacl_definitions" {
  description = <<EOT
NACL maps to create. Key is NACL logical name (or tier name).
Fields:
  subnet_ids: list of subnets to associate (ignored if per-tier logic implemented in module)
  ingress/egress: list of rules with:
    rule_number (1..32766), protocol ("-1","6","17","1"), action ("allow"|"deny"), cidr_block,
    from_port, to_port, icmp_type, icmp_code
  tags: optional
EOT
  type = map(object({
    subnet_ids = optional(list(string), [])
    ingress = optional(list(object({
      rule_number = number
      protocol    = string
      action      = string
      cidr_block  = string
      from_port   = optional(number)
      to_port     = optional(number)
      icmp_type   = optional(number)
      icmp_code   = optional(number)
    })), [])
    egress = optional(list(object({
      rule_number = number
      protocol    = string
      action      = string
      cidr_block  = string
      from_port   = optional(number)
      to_port     = optional(number)
      icmp_type   = optional(number)
      icmp_code   = optional(number)
    })), [])
    tags = optional(map(string), {})
  }))
  default = {}
}

############################################
# AWS Network Firewall — core
############################################

variable "anfw_name_override" {
  description = "Optional explicit name for the AWS Network Firewall; defaults to '${name}-${environment}'."
  type        = string
  default     = ""
}

variable "anfw_delete_protection" {
  description = "Enable delete protection on the firewall."
  type        = bool
  default     = true
}

variable "anfw_subnet_change_protection" {
  description = "Enable subnet change protection on the firewall."
  type        = bool
  default     = true
}

variable "anfw_policy_change_protection" {
  description = "Enable firewall policy change protection."
  type        = bool
  default     = false
}

variable "anfw_capacity_defaults" {
  description = <<EOT
Default capacities for created rule groups (if inline rule groups used).
stateless: number of stateless capacity units
stateful:  number of stateful capacity units
EOT
  type = object({
    stateless = optional(number, 2000)
    stateful  = optional(number, 100)
  })
  default = {}
}

############################################
# AWS Network Firewall — policy & rule groups
############################################

variable "anfw_firewall_policy" {
  description = <<EOT
Firewall policy configuration.
Provide either existing_policy_arn OR inline_policy with rule group references.
Fields:
  existing_policy_arn: use an existing policy if set (module will not create one)
  inline_policy:
    stateless_default_actions: e.g. ["aws:forward_to_sfe"]
    stateless_fragment_default_actions: e.g. ["aws:forward_to_sfe"]
    stateful_default_actions: optional, e.g. ["aws:drop_strict"]
    stateless_rule_group_refs: list of objects { name, priority, capacity, arn, inline_rules }
    stateful_rule_group_refs:  list of objects { name, capacity, arn, inline_rules, rule_variables, stateful_engine_options }
EOT
  type = object({
    existing_policy_arn = optional(string)
    inline_policy = optional(object({
      stateless_default_actions            = list(string)
      stateless_fragment_default_actions   = list(string)
      stateful_default_actions             = optional(list(string), [])
      stateless_rule_group_refs = optional(list(object({
        name         = string
        priority     = number
        capacity     = optional(number)
        arn          = optional(string)
        # If arn is not provided, inline_rules must be provided to create a new RG
        inline_rules = optional(object({
          rules_source_list = optional(object({
            target_types = list(string)        # ["TLS_SNI","HTTP_HOST","IP","HTTP_METHOD",...]
            targets      = list(string)
            generated_rules_type = string      # "ALLOWLIST" | "DENYLIST"
          }))
          rules_source_stateless = optional(object({
            # stateless rules via JSON fragments passed-through by parent module
            # caller is responsible for well-formedness; module will template
            json = string
          }))
        }))
      })), [])
      stateful_rule_group_refs = optional(list(object({
        name         = string
        capacity     = optional(number)
        arn          = optional(string)
        inline_rules = optional(object({
          rules_string = optional(string)      # Suricata compatible text
          rules_json   = optional(string)      # JSON spec (pass-through)
        }))
        rule_variables = optional(object({
          ip_sets = optional(map(object({
            definition = list(string)
          })), {})
          port_sets = optional(map(object({
            definition = list(string)
          })), {})
        }), {})
        stateful_engine_options = optional(object({
          rule_order = optional(string, "DEFAULT_ACTION_ORDER") # or "STRICT_ORDER"
        }), {})
      })), [])
    }))
  })
  default = {}
}

############################################
# AWS Network Firewall — TLS inspection (optional)
############################################

variable "anfw_tls_inspection" {
  description = <<EOT
TLS inspection configuration (optional).
Fields:
  enable: toggle TLS inspection
  configuration_arn: use existing TLS inspection configuration (if provided)
  inline_certificate_arn: ACM certificate ARN for inline TLS inspection config (module may create config from it)
EOT
  type = object({
    enable                 = bool
    configuration_arn      = optional(string)
    inline_certificate_arn = optional(string)
    tags                   = optional(map(string), {})
  })
  default = {
    enable = false
  }
}

############################################
# AWS Network Firewall — logging
############################################

variable "anfw_logging" {
  description = <<EOT
Logging destinations for ANFW. Provide zero or more entries.
Each entry:
  destination_type: "S3" | "CloudWatchLogs" | "KinesisDataFirehose"
  log_type: "ALERT" | "FLOW"
  s3:
    bucket_arn, prefix
  cloudwatch:
    log_group_arn
  kinesis:
    delivery_stream_arn
  tags: optional
EOT
  type = list(object({
    destination_type = string
    log_type         = string
    s3 = optional(object({
      bucket_arn = string
      prefix     = optional(string, "anfw/")
    }))
    cloudwatch = optional(object({
      log_group_arn = string
    }))
    kinesis = optional(object({
      delivery_stream_arn = string
    }))
    tags = optional(map(string), {})
  }))
  default = []
  validation {
    condition = alltrue([
      for l in var.anfw_logging :
      contains(["S3","CloudWatchLogs","KinesisDataFirehose"], l.destination_type)
      && contains(["ALERT","FLOW"], l.log_type)
    ])
    error_message = "destination_type must be one of S3|CloudWatchLogs|KinesisDataFirehose and log_type must be ALERT|FLOW."
  }
}

############################################
# Guardrails & validations
############################################

variable "strict_validation" {
  description = "If true, module enforces additional consistency checks (e.g., non-empty subnets when ANFW enabled)."
  type        = bool
  default     = true
}

############################################
# Outputs control
############################################

variable "expose_debug_outputs" {
  description = "Expose additional debug outputs (e.g., resolved rule group ARNs)."
  type        = bool
  default     = false
}
