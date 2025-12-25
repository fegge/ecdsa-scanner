# Multi-Chain ECDSA R-Value Scanner

Scans multiple EVM chains for ECDSA signature nonce reuse vulnerabilities.

## Overview

This tool scans blockchain transactions looking for duplicate R values in ECDSA signatures. Reusing the same R value (nonce) across different transactions can allow an attacker to recover the private key.

### Types of Duplicates Detected

- **Same Key Duplicates**: Same R value from the same address (critical - key is compromised)
- **Cross-Key Duplicates**: Same R value from different addresses on the same chain
- **Cross-Chain Duplicates**: Same R value appearing on different chains

## Project Structure

```
├── cmd/scanner/       # Application entry point
├── internal/
│   ├── api/          # HTTP API handlers
│   ├── config/       # Configuration and chain definitions
│   ├── db/           # Database operations (PostgreSQL)
│   ├── logger/       # Logging with ring buffer
│   └── scanner/      # Chain scanning logic
├── static/           # Web UI
└── .env.example      # Environment configuration template
```

## Requirements

- Go 1.23+
- PostgreSQL database

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
# Required: PostgreSQL connection string
DATABASE_URL=postgres://user:password@host:5432/dbname?sslmode=require

# Optional: Ankr API key for higher rate limits
ANKR_API_KEY=your-api-key

# Server settings
PORT=8000
BIND_ADDRS=127.0.0.1
```

## Building

```bash
go build -o bsc-scanner ./cmd/scanner/
```

## Running

```bash
# With .env file
source .env && ./bsc-scanner

# Or with environment variables
DATABASE_URL=postgres://... ./bsc-scanner
```

## Systemd Service

```bash
sudo cp bsc-scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable bsc-scanner
sudo systemctl start bsc-scanner
```

## API Endpoints

- `GET /` - Web UI
- `GET /api/stats` - Scanner statistics
- `GET /api/duplicates` - All duplicate R values
- `GET /api/duplicates/same-key` - Same key duplicates only
- `GET /api/duplicates/cross-key` - Cross-key duplicates only
- `GET /api/logs` - Recent log entries
- `POST /api/start` - Start scanning (optional `?chain=` param)
- `POST /api/stop` - Stop scanning (optional `?chain=` param)

## Supported Chains

- Ethereum
- BSC (Binance Smart Chain)
- Polygon
- Arbitrum
- Avalanche
- Fantom
- Optimism
- Base
- zkSync Era
- Gnosis
- Celo
