/***************************************
 * Module Outputs — Peering & Endpoints
 * Industrial-grade outputs with rich metadata
 ***************************************/

/* ---------- VPC PEERING ---------- */

output "vpc_peering_ids" {
  description = "Map: <peering_key> -> peering resource ID."
  value       = { for k, v in google_compute_network_peering.peerings : k => v.id }
}

output "vpc_peering_names" {
  description = "Map: <peering_key> -> peering name."
  value       = { for k, v in google_compute_network_peering.peerings : k => v.name }
}

output "vpc_peering_self_links" {
  description = "Map: <peering_key> -> self_link of network peering."
  value       = { for k, v in google_compute_network_peering.peerings : k => v.self_link }
}

output "vpc_peering_states" {
  description = "Map: <peering_key> -> peering state (e.g., ACTIVE/INACTIVE)."
  value       = { for k, v in google_compute_network_peering.peerings : k => v.state }
}

output "vpc_peering_state_details" {
  description = "Map: <peering_key> -> details of peering state."
  value       = { for k, v in google_compute_network_peering.peerings : k => v.state_details }
}

output "vpc_peering_networks" {
  description = "Map: <peering_key> -> { network, peer_network } self_links."
  value = {
    for k, v in google_compute_network_peering.peerings :
    k => {
      network      = v.network
      peer_network = v.peer_network
    }
  }
}

/* ---------- PRIVATE SERVICE ACCESS (Service Networking) ---------- */

output "service_networking_connections" {
  description = "Map: <connection_key> -> { id, network, service, peering } for Private Service Access."
  value = {
    for k, v in google_service_networking_connection.connections :
    k => {
      id      = v.id
      network = v.network
      service = v.service
      peering = try(v.peering, null)
    }
  }
}

/* ---------- PRIVATE SERVICE CONNECT — CONSUMER ENDPOINTS ---------- */

output "psc_consumer_endpoints" {
  description = "Map: <endpoint_key> -> core attributes of PSC consumer forwarding rules."
  value = {
    for k, v in google_compute_forwarding_rule.psc_endpoints :
    k => {
      id                  = v.id
      name                = v.name
      self_link           = v.self_link
      region              = try(v.region, null)
      network             = try(v.network, null)
      subnetwork          = try(v.subnetwork, null)
      ip_address          = try(v.ip_address, null)
      psc_connection_id   = try(v.psc_connection_id, null) # Present for PSC endpoints
      target              = try(v.target, null)            # For API endpoints or producer targets
      load_balancing_scheme = try(v.load_balancing_scheme, null)
    }
  }
}

/* ---------- PRIVATE SERVICE CONNECT — PRODUCER (SERVICE ATTACHMENTS) ---------- */

output "psc_service_attachments" {
  description = "Map: <attachment_key> -> attributes of PSC producer service attachments."
  value = {
    for k, v in google_compute_service_attachment.psc_attachments :
    k => {
      id                     = v.id
      name                   = v.name
      self_link              = v.self_link
      region                 = try(v.region, null)
      connection_preference  = try(v.connection_preference, null)
      nat_subnets            = try(v.nat_subnets, null)
      domain_names           = try(v.domain_names, [])
      consumer_accept_lists  = try(v.consumer_accept_lists, [])
      enable_proxy_protocol  = try(v.enable_proxy_protocol, null)
      reconciliation_status  = try(v.reconcile_connections, null)
      target_service         = try(v.target_service, null)
    }
  }
}

/* ---------- CLOUD DNS (PRIVATE ZONES & RECORDS) ---------- */

output "private_dns_zones" {
  description = "Map: <zone_key> -> attributes of private DNS zones."
  value = {
    for k, v in google_dns_managed_zone.private_zones :
    k => {
      id          = v.id
      name        = v.name
      dns_name    = v.dns_name
      visibility  = v.visibility
      self_link   = v.self_link
      private_visibility_config = try(v.private_visibility_config, null)
      description = try(v.description, null)
    }
  }
}

output "private_dns_records" {
  description = "Map: <record_key> -> DNS record details in private zones."
  value = {
    for k, v in google_dns_record_set.private_records :
    k => {
      name    = v.name
      type    = v.type
      ttl     = v.ttl
      rrdatas = v.rrdatas
    }
  }
}

/* ---------- DERIVED, HUMAN-FRIENDLY SUMMARIES ---------- */

output "summary_peering_active" {
  description = "List of peering keys that are ACTIVE."
  value       = [for k, v in google_compute_network_peering.peerings : k if v.state == "ACTIVE"]
}

output "summary_psc_endpoint_ips" {
  description = "List of all PSC endpoint IP addresses."
  value       = [for _, v in google_compute_forwarding_rule.psc_endpoints : try(v.ip_address, null)]
}

output "summary_private_zones_fqdns" {
  description = "List of FQDNs (dns_name) for created private zones."
  value       = [for _, v in google_dns_managed_zone.private_zones : v.dns_name]
}
