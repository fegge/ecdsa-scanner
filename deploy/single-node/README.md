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

## Resource Requirements

The scanner monitors 21 EVM chains simultaneously:

| Metric | Value |
|--------|-------|
| Chains tracked | 21 |
| Blocks processed | ~17/sec |
| Transactions indexed | ~280/sec |
| Storage growth | ~2.5 GB/day, ~16 GB/week, ~70 GB/month |
| Bandwidth | ~10 GB/day, ~300 GB/month |

### Minimum Requirements

- **OS**: Ubuntu 22.04 or 24.04
- **RAM**: 2 GB minimum, 4 GB recommended
- **CPU**: 1 vCPU minimum, 2 vCPU recommended
- **Disk**: See sizing guide below
- **Bandwidth**: ~300 GB/month

### Disk Sizing Guide

| Duration | Data Size | Recommended Disk | Notes |
|----------|-----------|------------------|-------|
| 2 weeks | ~35 GB | 50 GB | Minimum viable |
| 4 weeks | ~65 GB | 80-100 GB | Standard operation |
| 2 months | ~140 GB | 160-200 GB | Extended operation |
| 3+ months | 200+ GB | Add volume storage | Use DigitalOcean volumes |

## DigitalOcean Droplet Recommendations

| Droplet | Specs | Cost | Unattended Duration |
|---------|-------|------|---------------------|
| `s-1vcpu-2gb` | 1 vCPU, 2 GB RAM, 50 GB disk | $12/mo | ~2 weeks |
| `s-2vcpu-4gb` | 2 vCPU, 4 GB RAM, 80 GB disk | $24/mo | ~4 weeks |
| `s-2vcpu-4gb` + 100GB volume | 2 vCPU, 4 GB RAM, 180 GB total | $34/mo | ~2 months |
| `s-4vcpu-8gb` | 4 vCPU, 8 GB RAM, 160 GB disk | $48/mo | ~2 months |

### Adding Volume Storage

For long-term operation, attach a DigitalOcean volume ($0.10/GB/month):

```bash
# After creating volume in DO console, mount it:
mkfs.ext4 /dev/disk/by-id/scsi-0DO_Volume_<volume-name>
mkdir -p /mnt/data
mount /dev/disk/by-id/scsi-0DO_Volume_<volume-name> /mnt/data
echo '/dev/disk/by-id/scsi-0DO_Volume_<volume-name> /mnt/data ext4 defaults,nofail 0 2' >> /etc/fstab

# Move PostgreSQL data to volume:
systemctl stop postgresql
mv /var/lib/postgresql /mnt/data/
ln -s /mnt/data/postgresql /var/lib/postgresql
systemctl start postgresql
```

## Other VPS Providers

| Provider | Recommended Size | Cost | Notes |
|----------|------------------|------|-------|
| Hetzner | CX32 (4 vCPU, 8 GB, 80 GB) | €7.50/mo | Best value, EU regions |
| Vultr | vc2-2c-4gb + block storage | $24+/mo | Many regions |
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
