terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_security_group" "this" {
  name        = var.sg_name
  description = var.sg_description
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      description      = ingress.value.description
      from_port        = ingress.value.from_port
      to_port          = ingress.value.to_port
      protocol         = ingress.value.protocol
      cidr_blocks      = lookup(ingress.value, "cidr_blocks", null)
      ipv6_cidr_blocks = lookup(ingress.value, "ipv6_cidr_blocks", null)
      security_groups  = lookup(ingress.value, "security_groups", null)
      prefix_list_ids  = lookup(ingress.value, "prefix_list_ids", null)
      self             = lookup(ingress.value, "self", false)
    }
  }

  dynamic "egress" {
    for_each = var.egress_rules
    content {
      description      = egress.value.description
      from_port        = egress.value.from_port
      to_port          = egress.value.to_port
      protocol         = egress.value.protocol
      cidr_blocks      = lookup(egress.value, "cidr_blocks", null)
      ipv6_cidr_blocks = lookup(egress.value, "ipv6_cidr_blocks", null)
      security_groups  = lookup(egress.value, "security_groups", null)
      prefix_list_ids  = lookup(egress.value, "prefix_list_ids", null)
      self             = lookup(egress.value, "self", false)
    }
  }

  tags = merge(
    var.tags,
    {
      "Name" = var.sg_name
    }
  )
}

resource "aws_network_acl" "this" {
  vpc_id = var.vpc_id
  subnet_ids = var.subnet_ids

  dynamic "ingress" {
    for_each = var.nacl_ingress_rules
    content {
      rule_number    = ingress.value.rule_number
      protocol       = ingress.value.protocol
      rule_action    = ingress.value.rule_action
      cidr_block     = ingress.value.cidr_block
      from_port      = ingress.value.from_port
      to_port        = ingress.value.to_port
      ipv6_cidr_block = lookup(ingress.value, "ipv6_cidr_block", null)
    }
  }

  dynamic "egress" {
    for_each = var.nacl_egress_rules
    content {
      rule_number    = egress.value.rule_number
      protocol       = egress.value.protocol
      rule_action    = egress.value.rule_action
      cidr_block     = egress.value.cidr_block
      from_port      = egress.value.from_port
      to_port        = egress.value.to_port
      ipv6_cidr_block = lookup(egress.value, "ipv6_cidr_block", null)
    }
  }

  tags = merge(
    var.tags,
    {
      "Name" = "${var.sg_name}-nacl"
    }
  )
}
