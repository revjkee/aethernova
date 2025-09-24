terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.29"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.5"
}

provider "digitalocean" {
  token = var.do_token
}

provider "cloudflare" {
  api_token = var.cloudflare_token
}

variable "region" {
  default = "fra1"
}

variable "droplet_name" {
  default = "genesis-c2"
}

resource "digitalocean_droplet" "c2_server" {
  image  = "ubuntu-22-04-x64"
  name   = var.droplet_name
  region = var.region
  size   = "s-1vcpu-2gb"
  ssh_keys = [var.ssh_fingerprint]
  tags     = ["c2", "redirector"]

  provisioner "remote-exec" {
    inline = [
      "apt update -y",
      "apt install -y nginx ufw wireguard",
      "ufw allow ssh",
      "ufw allow http",
      "ufw allow https",
      "ufw enable",
      "systemctl enable nginx"
    ]
  }
}

resource "digitalocean_firewall" "c2_firewall" {
  name = "c2-firewall"
  droplet_ids = [digitalocean_droplet.c2_server.id]

  inbound_rule {
    protocol = "tcp"
    port_range = "22"
    source_addresses = ["0.0.0.0/0"]
  }

  inbound_rule {
    protocol = "tcp"
    port_range = "80,443"
    source_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol = "tcp"
    port_range = "all"
    destination_addresses = ["0.0.0.0/0"]
  }
}

resource "cloudflare_record" "redirector_dns" {
  zone_id = var.cloudflare_zone_id
  name    = "edge"
  value   = digitalocean_droplet.c2_server.ipv4_address
  type    = "A"
  ttl     = 60
  proxied = true
}

resource "cloudflare_page_rule" "masking_rule" {
  zone_id = var.cloudflare_zone_id
  target  = "https://edge.${var.cloudflare_zone}/cdn-edge/*"
  actions {
    always_use_https = true
    disable_apps     = true
    disable_performance = true
  }
}

output "c2_server_ip" {
  value = digitalocean_droplet.c2_server.ipv4_address
}

output "cdn_redirector_url" {
  value = "https://edge.${var.cloudflare_zone}/cdn-edge"
}
