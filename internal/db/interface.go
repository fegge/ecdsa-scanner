package db

import "context"

// Database defines the interface for database operations
type Database interface {
	Close() error
	Health(ctx context.Context) HealthStatus
	InsertSignatures(ctx context.Context, sigs []Signature) error
	GetLastBlock(ctx context.Context, chain string) (uint64, error)
	SaveLastBlock(ctx context.Context, chain string, block uint64) error
	GetChainTxCount(ctx context.Context, chain string) (uint64, error)
	GetStats(ctx context.Context) (*Stats, error)
	FindDuplicates(ctx context.Context) ([]DuplicateR, error)
}

// Ensure DB implements Database interface
var _ Database = (*DB)(nil)
var _ Database = (*MockDB)(nil)
