# Agent Instructions

This is a Go web application that scans EVM chains for ECDSA signature nonce reuse.

## Key Files

- `cmd/scanner/main.go` - Entry point
- `internal/config/config.go` - Chain configurations and environment
- `internal/db/db.go` - PostgreSQL database layer
- `internal/scanner/scanner.go` - Chain scanning logic
- `internal/api/api.go` - HTTP API handlers
- `static/index.html` - Web UI

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
