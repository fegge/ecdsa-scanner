# Agent Instructions

This is a Go web application that scans EVM chains for ECDSA signature nonce reuse.

## Key Files

- `cmd/scanner/main.go` - Entry point
- `internal/config/config.go` - Chain configurations and environment
- `internal/db/db.go` - PostgreSQL database layer (with batch operations)
- `internal/db/interface.go` - Database interface definition
- `internal/db/mock.go` - Mock database for testing/demo mode
- `internal/scanner/scanner.go` - Chain scanning logic
- `internal/api/api.go` - HTTP API handlers
- `internal/recovery/recovery.go` - ECDSA private key recovery math
- `static/index.html` - Web UI
- `deploy/single-node/setup.sh` - Single-node deployment script
- `deploy/terraform/` - Two-node Terraform deployment

## Building

```bash
go build -o ecdsa-scanner ./cmd/scanner/
```

## Testing

```bash
go test ./...
```

## Running

```bash
# Demo mode (no database)
./ecdsa-scanner

# With database
DATABASE_URL=postgres://... ./ecdsa-scanner
```

## Deployment

Single-node deployment (Ubuntu, with Tailscale):

```bash
curl -fsSL https://raw.githubusercontent.com/fegge/ecdsa-scanner/main/deploy/single-node/setup.sh | \
  sudo bash -s -- --tailscale-key tskey-auth-xxxxx
```

See `deploy/README.md` for all deployment options.

## Database

Uses PostgreSQL. Key tables:
- `r_value_index` - First occurrence of each R value (PRIMARY KEY on r_value)
- `collisions` - Subsequent occurrences (2nd, 3rd, etc.) of R values
- `recovered_keys` - Successfully recovered private keys
- `recovered_nonces` - Recovered nonces for cross-key recovery
- `scan_state` - Last scanned block per chain

Batch operations (`BatchCheckAndInsertRValues`) reduce per-block DB queries from ~400 to 2-3.
