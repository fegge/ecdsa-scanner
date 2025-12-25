package db

import (
	"context"
)

// MockDB is a mock database for demo/testing purposes
type MockDB struct {
	systemAddresses map[string]bool
}

// NewMock creates a new mock database
func NewMock(systemAddresses map[string]bool) *MockDB {
	return &MockDB{systemAddresses: systemAddresses}
}

// Close is a no-op for mock
func (m *MockDB) Close() error {
	return nil
}

// Health returns mock health status
func (m *MockDB) Health(ctx context.Context) HealthStatus {
	return HealthStatus{
		Connected:       false,
		LatencyMs:       0,
		OpenConnections: 0,
		Error:           "Demo mode - no database configured",
	}
}

// InsertSignatures is a no-op for mock
func (m *MockDB) InsertSignatures(ctx context.Context, sigs []Signature) error {
	return nil
}

// GetLastBlock returns 0 for mock
func (m *MockDB) GetLastBlock(ctx context.Context, chain string) (uint64, error) {
	return 0, nil
}

// SaveLastBlock is a no-op for mock
func (m *MockDB) SaveLastBlock(ctx context.Context, chain string, block uint64) error {
	return nil
}

// GetChainTxCount returns 0 for mock
func (m *MockDB) GetChainTxCount(ctx context.Context, chain string) (uint64, error) {
	return 0, nil
}

// GetStats returns empty stats for mock
func (m *MockDB) GetStats(ctx context.Context) (*Stats, error) {
	return &Stats{Healthy: false}, nil
}

// FindDuplicates returns empty list for mock
func (m *MockDB) FindDuplicates(ctx context.Context) ([]DuplicateR, error) {
	return nil, nil
}
