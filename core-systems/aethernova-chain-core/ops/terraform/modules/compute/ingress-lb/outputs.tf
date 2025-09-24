#############################################
# Module: compute/ingress-lb - outputs.tf
# Purpose: Expose stable, machine-consumable outputs
# Notes:
# - Designed to be resilient whether resources use count/for_each
# - Safe access via splat + try() to avoid evaluation errors
# - Suitable for both ALB and NLB configurations
#############################################

#############################################
# Core Load Balancer identifiers
#############################################

output "lb_arn" {
  description = "ARN of the Load Balancer (ALB/NLB)"
  value       = try(one(aws_lb.this[*].arn), null)
}

output "lb_id" {
  description = "ID of the Load Balancer"
  value       = try(one(aws_lb.this[*].id), null)
}

output "lb_name" {
  description = "Name of the Load Balancer"
  value       = try(one(aws_lb.this[*].name), null)
}

output "lb_dns_name" {
  description = "DNS name of the Load Balancer"
  value       = try(one(aws_lb.this[*].dns_name), null)
}

output "lb_zone_id" {
  description = "Route53 zone ID to use for an alias"
  value       = try(one(aws_lb.this[*].zone_id), null)
}

#############################################
# Load Balancer configuration
#############################################

output "lb_type" {
  description = "Type of the LB: application or network"
  value       = try(one(aws_lb.this[*].load_balancer_type), null)
}

output "lb_internal" {
  description = "Whether the LB is internal"
  value       = try(one(aws_lb.this[*].internal), null)
}

output "lb_scheme" {
  description = "Scheme of the LB: internet-facing or internal"
  value       = try(one(aws_lb.this[*].scheme), null)
}

output "lb_ip_address_type" {
  description = "IP address type of the LB (ipv4 or dualstack)"
  value       = try(one(aws_lb.this[*].ip_address_type), null)
}

output "deletion_protection_enabled" {
  description = "Whether deletion protection is enabled on the LB"
  value       = try(one(aws_lb.this[*].deletion_protection_enabled), null)
}

# For NLBs (and ALBs where supported by provider versions)
output "cross_zone_load_balancing_enabled" {
  description = "Whether cross-zone load balancing is enabled (NLB)"
  value       = try(one(aws_lb.this[*].enable_cross_zone_load_balancing), null)
}

# ALB specific (NLB ignores)
output "idle_timeout" {
  description = "Idle timeout for ALB (seconds). Null for NLB."
  value       = try(one(aws_lb.this[*].idle_timeout), null)
}

output "http2_enabled" {
  description = "Whether HTTP/2 is enabled for ALB"
  value       = try(one(aws_lb.this[*].enable_http2), null)
}

#############################################
# Networking
#############################################

output "vpc_id" {
  description = "VPC ID where LB resides"
  value       = try(one(aws_lb.this[*].vpc_id), null)
}

output "subnet_ids" {
  description = "Subnets attached to the LB"
  value       = try(flatten([for lb in aws_lb.this : lb.subnets]), [])
}

output "security_group_id" {
  description = "Security Group ID attached to LB (ALB). Null for NLB."
  value       = try(one(aws_security_group.lb[*].id), null)
}

#############################################
# Access logs / Observability (if configured)
#############################################

output "access_logs_bucket" {
  description = "S3 bucket for LB access logs, if logs are enabled"
  value       = try(one(aws_lb.this[*].access_logs[0].bucket), null)
}

output "access_logs_prefix" {
  description = "S3 prefix for LB access logs, if logs are enabled"
  value       = try(one(aws_lb.this[*].access_logs[0].prefix), null)
}

output "access_logs_enabled" {
  description = "Whether access logs are enabled for the LB"
  value       = try(one(aws_lb.this[*].access_logs[0].enabled), null)
}

#############################################
# Listeners
#############################################

output "listeners" {
  description = "List of listeners with key attributes"
  value = try([
    for l in aws_lb_listener.this : {
      arn         = l.arn
      id          = l.id
      port        = l.port
      protocol    = l.protocol
      ssl_policy  = try(l.ssl_policy, null)
      alpn_policy = try(l.alpn_policy, null)
      certificate_arn = try(one(l.certificate_arn), null)
      default_actions = try([
        for a in l.default_action : {
          type             = a.type
          target_group_arn = try(a.target_group_arn, null)
          redirect = try(a.redirect[0], null)
          fixed_response = try(a.fixed_response[0], null)
          forward = try(a.forward[0], null)
        }
      ], [])
    }
  ], [])
}

#############################################
# Listener rules (optional)
#############################################

output "listener_rules" {
  description = "Listener rules details (if any)"
  value = try([
    for r in aws_lb_listener_rule.this : {
      id        = r.id
      arn       = r.arn
      listener  = r.listener_arn
      priority  = try(r.priority, null)
      actions   = try(r.action, [])
      conditions = try(r.condition, [])
    }
  ], [])
}

#############################################
# Target Groups
#############################################

output "target_groups" {
  description = "Target groups with health checks and target type"
  value = try([
    for tg in aws_lb_target_group.this : {
      arn         = tg.arn
      id          = tg.id
      name        = tg.name
      port        = tg.port
      protocol    = tg.protocol
      protocol_version = try(tg.protocol_version, null)
      target_type = tg.target_type
      vpc_id      = tg.vpc_id
      health_check = {
        enabled             = try(tg.health_check[0].enabled, null)
        path                = try(tg.health_check[0].path, null)
        port                = try(tg.health_check[0].port, null)
        protocol            = try(tg.health_check[0].protocol, null)
        healthy_threshold   = try(tg.health_check[0].healthy_threshold, null)
        unhealthy_threshold = try(tg.health_check[0].unhealthy_threshold, null)
        interval            = try(tg.health_check[0].interval, null)
        timeout             = try(tg.health_check[0].timeout, null)
        matcher             = try(tg.health_check[0].matcher, null)
      }
      stickiness = try(tg.stickiness[0], null)
      slow_start = try(tg.slow_start, null)
      deregistration_delay = try(tg.deregistration_delay, null)
    }
  ], [])
}

output "target_group_arns" {
  description = "List of target group ARNs"
  value       = try([for tg in aws_lb_target_group.this : tg.arn], [])
}

#############################################
# WAF (optional)
#############################################

output "waf_web_acl_arn" {
  description = "Associated WAFv2 Web ACL ARN, if configured"
  value       = try(one(aws_wafv2_web_acl_association.this[*].web_acl_arn), null)
}

#############################################
# Tags and computed labels
#############################################

output "lb_tags" {
  description = "Effective tags applied to the LB"
  value       = try(one(aws_lb.this[*].tags), {})
  sensitive   = false
}

#############################################
# Back-compat small, frequently used fields
#############################################

output "lb_dns_record" {
  description = "Convenience object for Route53 alias creation"
  value = try({
    name    = one(aws_lb.this[*].dns_name)
    zone_id = one(aws_lb.this[*].zone_id)
  }, null)
}

# Helpful booleans to drive consumers without re-deriving
output "is_alb" {
  description = "True if LB type is application"
  value       = try(one(aws_lb.this[*].load_balancer_type) == "application", null)
}

output "is_nlb" {
  description = "True if LB type is network"
  value       = try(one(aws_lb.this[*].load_balancer_type) == "network", null)
}
