package db

import "context"

// Database defines the interface for database operations
type Database interface {
	Close() error
	Health(ctx context.Context) HealthStatus
	InsertSignatures(ctx context.Context, sigs []Signature) error
	InsertSignaturesAndFindDuplicates(ctx context.Context, sigs []Signature) ([]DuplicateR, error)
	GetLastBlock(ctx context.Context, chain string) (uint64, error)
	SaveLastBlock(ctx context.Context, chain string, block uint64) error
	GetChainTxCount(ctx context.Context, chain string) (uint64, error)
	GetStats(ctx context.Context) (*Stats, error)
	FindDuplicates(ctx context.Context) ([]DuplicateR, error)
	SaveRecoveredKey(ctx context.Context, key *RecoveredKey) error
	GetRecoveredKeys(ctx context.Context) ([]RecoveredKey, error)
	GetRecoveredKeyCount(ctx context.Context) (int, error)
	GetSameKeyDuplicatesForRecovery(ctx context.Context) ([]DuplicateR, error)
	IsKeyRecovered(ctx context.Context, address, chain string) (bool, error)
}

// Ensure DB implements Database interface
var _ Database = (*DB)(nil)
var _ Database = (*MockDB)(nil)
