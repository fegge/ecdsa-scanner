variable "tailscale_auth_key" {
  description = "Tailscale auth key for enrolling nodes (get from https://login.tailscale.com/admin/settings/keys)"
  type        = string
  sensitive   = true
}

variable "tailscale_tailnet" {
  description = "Tailscale tailnet name (e.g., example.ts.net)"
  type        = string
}

variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "DigitalOcean region"
  type        = string
  default     = "nyc1"
}

variable "scanner_size" {
  description = "Droplet size for scanner node"
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "db_size" {
  description = "Droplet size for database node"
  type        = string
  default     = "s-1vcpu-2gb"
}

variable "postgres_password" {
  description = "PostgreSQL password for ecdsa_scanner user"
  type        = string
  sensitive   = true
}

variable "ankr_api_key" {
  description = "Ankr API key for RPC access (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "ssh_key_ids" {
  description = "List of DigitalOcean SSH key IDs for access"
  type        = list(string)
}
