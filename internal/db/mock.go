package db

import (
	"context"
	"strings"
	"sync"
)

// MockDB is a mock database for demo/testing
type MockDB struct {
	mu       sync.RWMutex
	rValues  map[string]TxRef // r_value -> first tx
	keys     []RecoveredKey
	nonces   map[string]RecoveredNonce
	comps    []PendingComponent
	blocks   map[int]uint64
}

// NewMock creates a new mock database
func NewMock() *MockDB {
	return &MockDB{
		rValues: make(map[string]TxRef),
		nonces:  make(map[string]RecoveredNonce),
		blocks:  make(map[int]uint64),
	}
}

// NewMockWithSampleData creates a mock database with sample data
func NewMockWithSampleData() *MockDB {
	m := NewMock()
	
	// Add sample recovered keys
	m.keys = []RecoveredKey{
		{
			ID:         1,
			Address:    "0x742d35cc6634c0532925a3b844bc9e7595f8b2d1",
			PrivateKey: "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
			ChainID:    1,
			RValues:    []string{"0x8a2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4"},
			TxHashes:   []string{"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"},
			CreatedAt:  "2024-12-25T10:30:00Z",
		},
		{
			ID:         2,
			Address:    "0x8ba1f109551bd432803012645ac136ddd64dba72",
			PrivateKey: "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
			ChainID:    137,
			RValues:    []string{"0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"},
			TxHashes:   []string{"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			CreatedAt:  "2024-12-24T15:45:00Z",
		},
	}
	
	// Add sample recovered nonces (for cross-key recovery)
	m.nonces = map[string]RecoveredNonce{
		"0x8a2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4": {
			RValue:           "0x8a2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
			KValue:           "0x7f6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c3b2a1908",
			DerivedFromKeyID: 1,
		},
	}
	
	// Add sample collisions
	m.rValues = map[string]TxRef{
		"0x8a2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4": {
			TxHash:  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			ChainID: 1,
		},
		"0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b": {
			TxHash:  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ChainID: 137,
		},
	}
	
	// Add a pending component (cross-key collision not yet solvable)
	m.comps = []PendingComponent{
		{
			ID:        1,
			RValues:   []string{"0x9f8e7d6c5b4a3928171605f4e3d2c1b0a9f8e7d6c5b4a3928171605f4e3d2c1b"},
			TxHashes:  []string{"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
			Addresses: []string{"0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222"},
			ChainIDs:  []int{1, 1},
			Equations: 2,
			Unknowns:  3,
		},
	}
	
	return m
}

func (m *MockDB) Close() error { return nil }

func (m *MockDB) Health(ctx context.Context) HealthStatus {
	return HealthStatus{Connected: true, LatencyMs: 1}
}

func (m *MockDB) CheckAndInsertRValue(ctx context.Context, rValue, txHash string, chainID int) (*TxRef, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.rValues[rValue]; ok {
		return &existing, true, nil
	}
	m.rValues[rValue] = TxRef{TxHash: txHash, ChainID: chainID}
	return nil, false, nil
}

func (m *MockDB) RecordCollision(ctx context.Context, rValue, txHash string, chainID int, address string) error {
	return nil
}

func (m *MockDB) BatchCheckAndInsertRValues(ctx context.Context, txs []TxInput) ([]CollisionResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var collisions []CollisionResult
	seen := make(map[string]bool)

	for _, tx := range txs {
		if seen[tx.RValue] {
			continue
		}
		seen[tx.RValue] = true

		if existing, ok := m.rValues[tx.RValue]; ok {
			// Only count as collision if tx hash is different
			if !strings.EqualFold(existing.TxHash, tx.TxHash) {
				collisions = append(collisions, CollisionResult{
					RValue:     tx.RValue,
					TxHash:     tx.TxHash,
					ChainID:    tx.ChainID,
					Address:    tx.Address,
					FirstTxRef: existing,
				})
			}
			// If same tx hash, skip (duplicate)
		} else {
			m.rValues[tx.RValue] = TxRef{TxHash: tx.TxHash, ChainID: tx.ChainID}
		}
	}

	return collisions, nil
}

func (m *MockDB) GetCollisionTxRefs(ctx context.Context, rValue string) ([]TxRef, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ref, ok := m.rValues[rValue]; ok {
		return []TxRef{ref}, nil
	}
	return nil, nil
}

func (m *MockDB) GetAllCollisions(ctx context.Context) ([]Collision, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Build collisions from rValues that have been recorded
	collisions := []Collision{}
	for rValue, ref := range m.rValues {
		collisions = append(collisions, Collision{
			RValue: rValue,
			TxRefs: []TxRef{ref},
		})
	}
	return collisions, nil
}

func (m *MockDB) HasCrossKeyPotential(ctx context.Context, rValue, excludeAddress string) (bool, error) {
	return false, nil
}

func (m *MockDB) GetLastBlock(ctx context.Context, chainID int) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.blocks[chainID], nil
}

func (m *MockDB) SaveLastBlock(ctx context.Context, chainID int, block uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocks[chainID] = block
	return nil
}

func (m *MockDB) SaveRecoveredKey(ctx context.Context, key *RecoveredKey) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key.ID = int64(len(m.keys) + 1)
	m.keys = append(m.keys, *key)
	return key.ID, nil
}

func (m *MockDB) GetRecoveredKeys(ctx context.Context) ([]RecoveredKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.keys == nil {
		return []RecoveredKey{}, nil
	}
	return m.keys, nil
}

func (m *MockDB) IsKeyRecovered(ctx context.Context, address string, chainID int) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, k := range m.keys {
		if k.Address == address && k.ChainID == chainID {
			return true, nil
		}
	}
	return false, nil
}

func (m *MockDB) SaveRecoveredNonce(ctx context.Context, nonce *RecoveredNonce) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonces[nonce.RValue] = *nonce
	return nil
}

func (m *MockDB) GetRecoveredNonce(ctx context.Context, rValue string) (*RecoveredNonce, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n, ok := m.nonces[rValue]; ok {
		return &n, nil
	}
	return nil, ErrNotFound
}

func (m *MockDB) GetRecoveredNonces(ctx context.Context) ([]RecoveredNonce, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	nonces := []RecoveredNonce{}
	for _, n := range m.nonces {
		nonces = append(nonces, n)
	}
	return nonces, nil
}

func (m *MockDB) SavePendingComponent(ctx context.Context, comp *PendingComponent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	comp.ID = int64(len(m.comps) + 1)
	m.comps = append(m.comps, *comp)
	return nil
}

func (m *MockDB) GetPendingComponents(ctx context.Context) ([]PendingComponent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.comps == nil {
		return []PendingComponent{}, nil
	}
	return m.comps, nil
}

func (m *MockDB) DeletePendingComponent(ctx context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, c := range m.comps {
		if c.ID == id {
			m.comps = append(m.comps[:i], m.comps[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *MockDB) GetStats(ctx context.Context) (*Stats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return &Stats{
		TotalRValues:      len(m.rValues),
		RecoveredKeys:     len(m.keys),
		RecoveredNonces:   len(m.nonces),
		PendingComponents: len(m.comps),
		Healthy:           true,
	}, nil
}
