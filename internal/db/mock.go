package db

import (
	"context"
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

func (m *MockDB) GetCollisionTxRefs(ctx context.Context, rValue string) ([]TxRef, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ref, ok := m.rValues[rValue]; ok {
		return []TxRef{ref}, nil
	}
	return nil, nil
}

func (m *MockDB) GetAllCollisions(ctx context.Context) ([]Collision, error) {
	return []Collision{}, nil
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
