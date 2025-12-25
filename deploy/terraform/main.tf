terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

provider "digitalocean" {
  token = var.do_token
}

# Database node
resource "digitalocean_droplet" "db" {
  name     = "ecdsa-scanner-db"
  image    = "ubuntu-24-04-x64"
  size     = var.db_size
  region   = var.region
  ssh_keys = var.ssh_key_ids
  tags     = ["ecdsa-scanner", "database"]

  user_data = templatefile("${path.module}/cloud-init-db.yaml", {
    tailscale_auth_key = var.tailscale_auth_key
    postgres_password  = var.postgres_password
  })
}

# Scanner node
resource "digitalocean_droplet" "scanner" {
  name     = "ecdsa-scanner-app"
  image    = "ubuntu-24-04-x64"
  size     = var.scanner_size
  region   = var.region
  ssh_keys = var.ssh_key_ids
  tags     = ["ecdsa-scanner", "scanner"]

  user_data = templatefile("${path.module}/cloud-init-scanner.yaml", {
    tailscale_auth_key = var.tailscale_auth_key
    postgres_password  = var.postgres_password
    ankr_api_key       = var.ankr_api_key
    db_tailscale_name  = "ecdsa-scanner-db"
    tailscale_tailnet  = var.tailscale_tailnet
  })

  depends_on = [digitalocean_droplet.db]
}

# Firewall - block all public access except for initial SSH setup
# After Tailscale is up, SSH will be over Tailscale only
resource "digitalocean_firewall" "ecdsa_scanner" {
  name = "ecdsa-scanner-fw"

  droplet_ids = [
    digitalocean_droplet.db.id,
    digitalocean_droplet.scanner.id
  ]

  # Allow all outbound traffic (needed for Tailscale, package updates, RPC calls)
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Allow inbound UDP for Tailscale DERP/STUN
  inbound_rule {
    protocol         = "udp"
    port_range       = "41641"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
}
