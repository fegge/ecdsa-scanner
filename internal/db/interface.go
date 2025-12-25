package db

import "context"

// Database defines the interface for database operations
type Database interface {
	Close() error
	Health(ctx context.Context) HealthStatus

	// R-value collision detection
	CheckAndInsertRValue(ctx context.Context, rValue, txHash string, chainID int) (*TxRef, bool, error)
	RecordCollision(ctx context.Context, rValue, txHash string, chainID int, address string) error
	GetCollisionTxRefs(ctx context.Context, rValue string) ([]TxRef, error)
	GetAllCollisions(ctx context.Context) ([]Collision, error)

	// Scan state
	GetLastBlock(ctx context.Context, chainID int) (uint64, error)
	SaveLastBlock(ctx context.Context, chainID int, block uint64) error

	// Recovered keys
	SaveRecoveredKey(ctx context.Context, key *RecoveredKey) (int64, error)
	GetRecoveredKeys(ctx context.Context) ([]RecoveredKey, error)
	IsKeyRecovered(ctx context.Context, address string, chainID int) (bool, error)

	// Recovered nonces
	SaveRecoveredNonce(ctx context.Context, nonce *RecoveredNonce) error
	GetRecoveredNonce(ctx context.Context, rValue string) (*RecoveredNonce, error)
	GetRecoveredNonces(ctx context.Context) ([]RecoveredNonce, error)

	// Pending components (cross-key)
	SavePendingComponent(ctx context.Context, comp *PendingComponent) error
	GetPendingComponents(ctx context.Context) ([]PendingComponent, error)
	DeletePendingComponent(ctx context.Context, id int64) error

	// Stats
	GetStats(ctx context.Context) (*Stats, error)
}

var _ Database = (*DB)(nil)
var _ Database = (*MockDB)(nil)
