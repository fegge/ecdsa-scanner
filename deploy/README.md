# ECDSA Scanner Deployment

Deployment options for ECDSA Scanner, all secured with Tailscale.

## Deployment Options

| Option | Best For | Cost | Setup Time |
|--------|----------|------|------------|
| [Single Node](single-node/) | Personal use, testing | ~$6-24/mo | 5 minutes |
| [Terraform (2 nodes)](terraform/) | Production, separation of concerns | ~$18/mo | 10 minutes |

## Quick Start (Single Node)

On a fresh Ubuntu 22.04/24.04 server:

```bash
curl -fsSL https://raw.githubusercontent.com/fegge/ecdsa-scanner/main/deploy/single-node/setup.sh | \
  sudo bash -s -- --tailscale-key YOUR_TAILSCALE_KEY
```

Get a Tailscale auth key from: https://login.tailscale.com/admin/settings/keys

### What this does

1. Installs PostgreSQL, Go, and dependencies
2. Connects to your Tailscale network
3. Configures UFW to only allow Tailscale traffic
4. Builds and starts the scanner as a systemd service
5. Restricts SSH to Tailscale only

### Options

```bash
curl -fsSL https://raw.githubusercontent.com/fegge/ecdsa-scanner/main/deploy/single-node/setup.sh | \
  sudo bash -s -- \
    --tailscale-key tskey-auth-xxxxx \
    --hostname my-scanner \
    --ankr-key YOUR_ANKR_KEY \
    --port 8000
```

See [single-node/README.md](single-node/README.md) for full documentation.

---

## Terraform Deployment (2 Nodes)

For production use with separate scanner and database nodes.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Tailscale Network                        │
│                                                             │
│  ┌─────────────────┐         ┌─────────────────┐           │
│  │  Scanner Node   │         │  Database Node  │           │
│  │                 │         │                 │           │
│  │  - ecdsa-scanner│◄───────►│  - PostgreSQL   │           │
│  │  - Web UI :8000 │   TS    │  - Port 5432    │           │
│  │                 │         │                 │           │
│  └─────────────────┘         └─────────────────┘           │
│           ▲                                                 │
│           │ Tailscale                                       │
│           ▼                                                 │
│  ┌─────────────────┐                                       │
│  │   Your Device   │                                       │
│  │   (any OS)      │                                       │
│  └─────────────────┘                                       │
└─────────────────────────────────────────────────────────────┘
```

### Security Features

- **No public ports**: SSH, HTTP, and PostgreSQL only accessible via Tailscale
- **Tailscale SSH**: SSH access managed by Tailscale ACLs
- **Encrypted traffic**: All inter-node traffic encrypted by WireGuard
- **Firewall**: UFW configured to only allow Tailscale interface

### Prerequisites

1. [DigitalOcean account](https://cloud.digitalocean.com/) with API token
2. [Tailscale account](https://tailscale.com/) with auth key
3. [Terraform](https://terraform.io/) installed locally
4. SSH key added to DigitalOcean

### Quick Start

#### 1. Get credentials

- **DigitalOcean API token**: https://cloud.digitalocean.com/account/api/tokens
- **Tailscale auth key**: https://login.tailscale.com/admin/settings/keys
  - Create a reusable, ephemeral key
- **SSH key ID**: `doctl compute ssh-key list` or from DO console

#### 2. Configure

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
```

#### 3. Deploy

```bash
terraform init
terraform plan
terraform apply
```

#### 4. Access

Once deployed, access the scanner via Tailscale:

```bash
# Web UI
open http://ecdsa-scanner-app.<your-tailnet>:8000

# SSH (via Tailscale)
ssh root@ecdsa-scanner-app
ssh root@ecdsa-scanner-db

# Mosh (better for unstable connections)
mosh root@ecdsa-scanner-app
```

### Configuration Options

| Variable | Required | Description |
|----------|----------|-------------|
| `do_token` | Yes | DigitalOcean API token |
| `ssh_key_ids` | Yes | List of DO SSH key IDs |
| `tailscale_auth_key` | Yes | Tailscale auth key |
| `tailscale_tailnet` | Yes | Your tailnet (e.g., `example.ts.net`) |
| `postgres_password` | Yes | PostgreSQL password |
| `ankr_api_key` | No | Ankr API key for RPC |
| `region` | No | DO region (default: `nyc1`) |
| `scanner_size` | No | Scanner droplet size (default: `s-1vcpu-1gb`) |
| `db_size` | No | Database droplet size (default: `s-1vcpu-2gb`) |

### Costs

Estimated monthly costs (DigitalOcean):
- Scanner node (s-1vcpu-1gb): ~$6/month
- Database node (s-1vcpu-2gb): ~$12/month
- **Total**: ~$18/month

---

## Maintenance

### Update scanner

```bash
ssh root@ecdsa-scanner  # or ecdsa-scanner-app for 2-node
cd /opt/ecdsa-scanner-src
git pull
go build -o /opt/ecdsa-scanner/ecdsa-scanner ./cmd/scanner/
systemctl restart ecdsa-scanner
```

### View logs

```bash
journalctl -u ecdsa-scanner -f
```

### Database backup

```bash
# Single node
ssh root@ecdsa-scanner
pg_dump -U postgres ecdsa_scanner > backup.sql

# Two node
ssh root@ecdsa-scanner-db
pg_dump -U postgres ecdsa_scanner > backup.sql
```

### Destroy (Terraform only)

```bash
terraform destroy
```

**Note**: This will delete all data. Backup the database first if needed.
