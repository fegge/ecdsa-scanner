# ECDSA R-Value Scanner

A multi-chain scanner that detects ECDSA signature nonce reuse vulnerabilities across EVM-compatible blockchains.

## Overview

This tool scans blockchain transactions looking for duplicate R values in ECDSA signatures. Reusing the same R value (nonce) across different transactions allows an attacker to recover the private key using simple algebra.

### Why This Matters

ECDSA signatures consist of two values: `r` and `s`. The `r` value is derived from a random nonce `k`. If the same nonce is used twice with the same private key, the private key can be calculated as:

```
private_key = (s1 - s2)^(-1) * (z1 - z2) mod n
```

This vulnerability has led to significant losses in cryptocurrency history, including the 2013 Android Bitcoin wallet vulnerability.

### Types of Duplicates Detected

| Type | Description | Severity |
|------|-------------|----------|
| **Same Key** | Same R value from the same address | Critical - private key compromised |
| **Cross-Key** | Same R value from different addresses on same chain | Suspicious - potential weak RNG |
| **Cross-Chain** | Same R value appearing on different chains | Notable - may indicate key reuse |

## Features

- **Multi-chain scanning**: Monitors 11 EVM chains simultaneously
- **Real-time detection**: Continuous scanning with configurable rate limits
- **Health monitoring**: Circuit breakers, retry logic, and comprehensive health dashboard
- **Web UI**: Live statistics, chain status, and log viewer
- **Robust error handling**: Automatic reconnection and graceful degradation

## Project Structure

```
ecdsa-scanner/
├── cmd/scanner/          # Application entry point
├── internal/
│   ├── api/              # HTTP API handlers
│   ├── config/           # Configuration and chain definitions
│   ├── db/               # PostgreSQL database layer
│   ├── logger/           # Logging with ring buffer for UI
│   ├── retry/            # Retry logic and circuit breaker
│   └── scanner/          # Chain scanning logic
├── static/               # Web UI (single-page app)
├── .env.example          # Environment configuration template
└── ecdsa-scanner.service # Systemd service file
```

## Requirements

- Go 1.23+
- PostgreSQL 14+ (or compatible: Neon, Supabase, AWS RDS)

## Quick Start

### 1. Clone and build

```bash
git clone https://github.com/fegge/ecdsa-scanner.git
cd ecdsa-scanner
go build -o ecdsa-scanner ./cmd/scanner/
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your database URL
```

### 3. Run

```bash
source .env && ./ecdsa-scanner
```

Open http://localhost:8000 to view the dashboard.

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes* | PostgreSQL connection string |
| `ANKR_API_KEY` | No | Ankr API key for higher rate limits |
| `PORT` | No | HTTP server port (default: 8000) |
| `BIND_ADDRS` | No | Bind addresses, comma-separated (default: 0.0.0.0) |

*If not set, runs in demo mode without persistence.

### Example `.env`

```bash
DATABASE_URL=postgres://user:password@host:5432/ecdsa_scanner?sslmode=require
ANKR_API_KEY=your-api-key-here
PORT=8000
BIND_ADDRS=127.0.0.1
```

## Deployment

### Infrastructure Deployment (Recommended)

The easiest way to deploy is using Terraform to provision infrastructure on DigitalOcean with Tailscale for secure networking.

#### Prerequisites

1. [DigitalOcean account](https://cloud.digitalocean.com/) with API token
2. [Tailscale account](https://tailscale.com/) with auth key
3. [Terraform](https://terraform.io/) installed locally

#### Deploy

```bash
cd deploy/terraform

# Configure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your credentials:
#   - do_token: DigitalOcean API token
#   - tailscale_auth_key: From https://login.tailscale.com/admin/settings/keys
#   - tailscale_tailnet: Your tailnet (e.g., example.ts.net)
#   - postgres_password: Secure password for database
#   - ssh_key_ids: Your DigitalOcean SSH key IDs

# Deploy
terraform init
terraform apply
```

This creates:
- **Scanner node**: Runs ecdsa-scanner service
- **Database node**: PostgreSQL server
- Both secured via Tailscale (no public ports exposed)

#### Access

```bash
# Web UI (via Tailscale)
open http://ecdsa-scanner-app.<your-tailnet>:8000

# SSH (via Tailscale)
ssh root@ecdsa-scanner-app
ssh root@ecdsa-scanner-db

# Or use mosh for better connectivity
mosh root@ecdsa-scanner-app
```

#### Estimated Costs

- Scanner node (s-1vcpu-1gb): ~$6/month
- Database node (s-1vcpu-2gb): ~$12/month
- **Total**: ~$18/month

See [deploy/README.md](deploy/README.md) for full deployment documentation.

### Manual Deployment

#### Systemd Service

```bash
# Copy and configure service file
sudo cp ecdsa-scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ecdsa-scanner
sudo systemctl start ecdsa-scanner

# View logs
journalctl -u ecdsa-scanner -f
```

## API Reference

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Web UI dashboard |
| GET | `/api/stats` | Scanner statistics and chain status |
| GET | `/api/health` | System health check |
| GET | `/api/duplicates` | All duplicate R values found |
| GET | `/api/duplicates/same-key` | Same-key duplicates only |
| GET | `/api/duplicates/cross-key` | Cross-key duplicates only |
| GET | `/api/logs` | Recent log entries |
| POST | `/api/start` | Start scanning (optional `?chain=NAME`) |
| POST | `/api/stop` | Stop scanning (optional `?chain=NAME`) |

### Health Response

```json
{
  "status": "healthy",
  "database": {
    "connected": true,
    "latency_ms": 12,
    "open_connections": 5
  },
  "chains": [
    {"name": "Ethereum", "running": true, "circuit_open": false, "error_count": 0}
  ]
}
```

## Supported Chains

| Chain | Chain ID | Explorer |
|-------|----------|----------|
| Ethereum | 1 | etherscan.io |
| BSC | 56 | bscscan.com |
| Polygon | 137 | polygonscan.com |
| Arbitrum | 42161 | arbiscan.io |
| Avalanche | 43114 | snowtrace.io |
| Fantom | 250 | ftmscan.com |
| Optimism | 10 | optimistic.etherscan.io |
| Base | 8453 | basescan.org |
| zkSync Era | 324 | explorer.zksync.io |
| Gnosis | 100 | gnosisscan.io |
| Celo | 42220 | celoscan.io |

## Architecture

### Error Handling

- **Retry with exponential backoff**: Transient failures (timeouts, rate limits) are retried up to 3 times
- **Circuit breaker**: After 5 consecutive failures, a chain is paused for 60 seconds
- **Automatic reconnection**: RPC connections are re-established after persistent failures
- **Graceful degradation**: Individual chain failures don't affect other chains

### Database

- Uses PostgreSQL for reliable storage and concurrent access
- Batch inserts (1000 signatures per batch) to minimize write overhead
- Indexed queries for efficient duplicate detection

## Testing

```bash
go test ./...
```

## License

MIT
