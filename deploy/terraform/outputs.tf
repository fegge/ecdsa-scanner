output "db_public_ip" {
  description = "Database droplet public IP (for initial setup only)"
  value       = digitalocean_droplet.db.ipv4_address
}

output "scanner_public_ip" {
  description = "Scanner droplet public IP (for initial setup only)"
  value       = digitalocean_droplet.scanner.ipv4_address
}

output "tailscale_db_hostname" {
  description = "Database Tailscale hostname"
  value       = "ecdsa-scanner-db.${var.tailscale_tailnet}"
}

output "tailscale_scanner_hostname" {
  description = "Scanner Tailscale hostname"
  value       = "ecdsa-scanner-app.${var.tailscale_tailnet}"
}

output "scanner_url" {
  description = "Scanner web UI URL (via Tailscale)"
  value       = "http://ecdsa-scanner-app.${var.tailscale_tailnet}:8000"
}

output "database_url" {
  description = "PostgreSQL connection string (via Tailscale)"
  value       = "postgres://ecdsa_scanner:PASSWORD@ecdsa-scanner-db.${var.tailscale_tailnet}:5432/ecdsa_scanner"
  sensitive   = true
}
