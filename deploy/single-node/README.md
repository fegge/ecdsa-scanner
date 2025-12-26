# Single-Node Deployment

Deploys ECDSA Scanner with PostgreSQL on a single machine, secured with Tailscale and UFW.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Single Node                         │
│                                                     │
│  ┌─────────────────┐    ┌─────────────────┐        │
│  │  ecdsa-scanner  │───►│   PostgreSQL    │        │
│  │   (port 8000)   │    │   (port 5432)   │        │
│  └─────────────────┘    └─────────────────┘        │
│            │                    │                   │
│            └────────┬───────────┘                   │
│                     │                               │
│              ┌──────▼──────┐                       │
│              │  tailscale0 │ ◄── Only interface    │
│              │  100.x.x.x  │     accepting traffic │
│              └─────────────┘                       │
│                                                     │
│  UFW: deny all except tailscale0                   │
└─────────────────────────────────────────────────────┘
                     │
                     │ Tailscale (WireGuard)
                     ▼
            ┌─────────────────┐
            │   Your Device   │
            │   (any OS)      │
            └─────────────────┘
```

## Security

- **No public ports**: All services only accessible via Tailscale
- **UFW firewall**: Blocks all traffic except on `tailscale0` interface
- **Tailscale SSH**: SSH only available over Tailscale network
- **PostgreSQL**: Only accepts connections from localhost

## Quick Start

### 1. Get a Tailscale auth key

1. Go to https://login.tailscale.com/admin/settings/keys
2. Generate a new auth key (reusable, ephemeral recommended)

### 2. Run the setup script

On a fresh Ubuntu 22.04/24.04 server:

```bash
# One-liner (replace with your auth key)
curl -fsSL https://raw.githubusercontent.com/fegge/ecdsa-scanner/main/deploy/single-node/setup.sh | \
  sudo bash -s -- --tailscale-key tskey-auth-xxxxx

# Or with options
curl -fsSL https://raw.githubusercontent.com/fegge/ecdsa-scanner/main/deploy/single-node/setup.sh | \
  sudo bash -s -- \
    --tailscale-key tskey-auth-xxxxx \
    --hostname my-scanner \
    --ankr-key your-ankr-api-key \
    --port 8000
```

Or clone and run locally:

```bash
git clone https://github.com/fegge/ecdsa-scanner.git
cd ecdsa-scanner/deploy/single-node
sudo ./setup.sh --tailscale-key tskey-auth-xxxxx
```

### 3. Access the scanner

From any device on your Tailscale network:

```bash
# Web UI
open http://ecdsa-scanner.<your-tailnet>:8000

# SSH
ssh root@ecdsa-scanner

# Mosh (better for unstable connections)
mosh root@ecdsa-scanner

# Database (SSH to host first)
ssh root@ecdsa-scanner
psql postgres://ecdsa_scanner:PASSWORD@localhost:5432/ecdsa_scanner
```

## Options

| Option | Required | Description |
|--------|----------|-------------|
| `--tailscale-key` | Yes* | Tailscale auth key |
| `--hostname` | No | Tailscale hostname (default: `ecdsa-scanner`) |
| `--postgres-password` | No | PostgreSQL password (auto-generated if not provided) |
| `--ankr-key` | No | Ankr API key for better RPC access |
| `--port` | No | Web UI port (default: `8000`) |
| `--skip-tailscale` | No | Skip Tailscale (testing only, insecure) |

\* Required unless `--skip-tailscale` is used

## Requirements

- Ubuntu 22.04 or 24.04
- Root access
- Tailscale account
- ~2GB RAM minimum (4GB recommended for busy chains)
- ~20GB disk (grows with indexed transactions)

## Recommended VPS Providers

| Provider | Size | Cost | Notes |
|----------|------|------|-------|
| DigitalOcean | s-2vcpu-4gb | $24/mo | Good performance |
| Hetzner | CX22 | €4.50/mo | Best value |
| Vultr | vc2-2c-4gb | $24/mo | Many regions |
| Linode | g6-standard-2 | $24/mo | Good network |

## Maintenance

### Update scanner

```bash
ssh root@ecdsa-scanner
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
pg_dump -U postgres ecdsa_scanner > backup.sql
```

### Check status

```bash
systemctl status ecdsa-scanner
systemctl status postgresql
tailscale status
ufw status
```

## Troubleshooting

### Can't connect after setup

Make sure you're on the same Tailscale network:

```bash
tailscale status
tailscale ping ecdsa-scanner
```

### Scanner not starting

Check logs:

```bash
journalctl -u ecdsa-scanner -n 50
```

### Database connection issues

Verify PostgreSQL is running and configured:

```bash
systemctl status postgresql
sudo -u postgres psql -c "\l"  # List databases
cat /etc/postgresql/*/main/pg_hba.conf  # Check access rules
```

### UFW blocking traffic

Check UFW rules:

```bash
ufw status verbose
```

Should show:
```
Anywhere on tailscale0          ALLOW       Anywhere
41641/udp                       ALLOW       Anywhere
```
