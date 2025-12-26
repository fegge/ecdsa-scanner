package db

import (
	"context"
	"errors"
	"testing"
)

func TestWrapError(t *testing.T) {
	db := &DB{}

	tests := []struct {
		name        string
		err         error
		expectedNil bool
	}{
		{"nil error", nil, true},
		{"generic error", errors.New("some error"), false},
		{"context deadline", context.DeadlineExceeded, false},
		{"sql no rows", ErrNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := db.wrapError(tt.err)
			if tt.expectedNil && result != nil {
				t.Errorf("expected nil, got %v", result)
			}
			if !tt.expectedNil && result == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestHexConversion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"0xabcd", "0xabcd"},
		{"abcd", "0xabcd"},
		{"0x", "0x"},
	}

	for _, tt := range tests {
		b := hexToBytes(tt.input)
		result := bytesToHex(b)
		if result != tt.expected {
			t.Errorf("hexToBytes/bytesToHex(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMockDB(t *testing.T) {
	ctx := context.Background()
	db := NewMock()

	// Test R-value collision detection
	_, isCollision, err := db.CheckAndInsertRValue(ctx, "0xabc123", "0xtx1", 1)
	if err != nil {
		t.Fatalf("CheckAndInsertRValue failed: %v", err)
	}
	if isCollision {
		t.Error("Expected no collision on first insert")
	}

	// Second insert with same R should be a collision
	existing, isCollision, err := db.CheckAndInsertRValue(ctx, "0xabc123", "0xtx2", 1)
	if err != nil {
		t.Fatalf("CheckAndInsertRValue failed: %v", err)
	}
	if !isCollision {
		t.Error("Expected collision on second insert")
	}
	if existing == nil || existing.TxHash != "0xtx1" {
		t.Error("Expected to get first tx reference")
	}

	// Test recovered key
	keyID, err := db.SaveRecoveredKey(ctx, &RecoveredKey{
		Address:    "0xaddr",
		PrivateKey: "0xprivkey",
		ChainID:    1,
		RValues:    []string{"0xr1"},
		TxHashes:   []string{"0xtx1", "0xtx2"},
	})
	if err != nil {
		t.Fatalf("SaveRecoveredKey failed: %v", err)
	}
	if keyID == 0 {
		t.Error("Expected non-zero key ID")
	}

	recovered, err := db.IsKeyRecovered(ctx, "0xaddr", 1)
	if err != nil {
		t.Fatalf("IsKeyRecovered failed: %v", err)
	}
	if !recovered {
		t.Error("Expected key to be recovered")
	}

	// Test stats
	stats, err := db.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if stats.TotalRValues != 1 {
		t.Errorf("Expected 1 R value, got %d", stats.TotalRValues)
	}
	if stats.RecoveredKeys != 1 {
		t.Errorf("Expected 1 recovered key, got %d", stats.RecoveredKeys)
	}
}

func TestMockDBBatchCheckAndInsertRValues(t *testing.T) {
	ctx := context.Background()
	db := NewMock()

	// Insert some initial R values
	db.CheckAndInsertRValue(ctx, "0xexisting1", "0xtx_old1", 1)
	db.CheckAndInsertRValue(ctx, "0xexisting2", "0xtx_old2", 137)

	// Batch insert with mix of new and existing R values
	txs := []TxInput{
		{RValue: "0xnew1", TxHash: "0xtx_new1", ChainID: 1, Address: "0xaddr1"},
		{RValue: "0xexisting1", TxHash: "0xtx_collision1", ChainID: 1, Address: "0xaddr2"}, // collision
		{RValue: "0xnew2", TxHash: "0xtx_new2", ChainID: 42, Address: "0xaddr3"},
		{RValue: "0xexisting2", TxHash: "0xtx_collision2", ChainID: 137, Address: "0xaddr4"}, // collision
		{RValue: "0xnew1", TxHash: "0xtx_dup", ChainID: 1, Address: "0xaddr5"},             // duplicate in batch (should be ignored)
	}

	collisions, err := db.BatchCheckAndInsertRValues(ctx, txs)
	if err != nil {
		t.Fatalf("BatchCheckAndInsertRValues failed: %v", err)
	}

	// Should detect 2 collisions
	if len(collisions) != 2 {
		t.Errorf("Expected 2 collisions, got %d", len(collisions))
	}

	// Verify collision details
	collisionMap := make(map[string]CollisionResult)
	for _, c := range collisions {
		collisionMap[c.RValue] = c
	}

	if c, ok := collisionMap["0xexisting1"]; !ok {
		t.Error("Expected collision for 0xexisting1")
	} else {
		if c.FirstTxRef.TxHash != "0xtx_old1" {
			t.Errorf("Expected first tx ref 0xtx_old1, got %s", c.FirstTxRef.TxHash)
		}
		if c.TxHash != "0xtx_collision1" {
			t.Errorf("Expected collision tx 0xtx_collision1, got %s", c.TxHash)
		}
	}

	if c, ok := collisionMap["0xexisting2"]; !ok {
		t.Error("Expected collision for 0xexisting2")
	} else {
		if c.FirstTxRef.TxHash != "0xtx_old2" {
			t.Errorf("Expected first tx ref 0xtx_old2, got %s", c.FirstTxRef.TxHash)
		}
	}

	// Verify new R values were inserted
	stats, _ := db.GetStats(ctx)
	// 2 original + 2 new = 4 total
	if stats.TotalRValues != 4 {
		t.Errorf("Expected 4 R values, got %d", stats.TotalRValues)
	}

	// Verify new R values exist and would cause collision on next insert
	_, isCollision, _ := db.CheckAndInsertRValue(ctx, "0xnew1", "0xanother", 1)
	if !isCollision {
		t.Error("Expected 0xnew1 to exist and cause collision")
	}

	_, isCollision, _ = db.CheckAndInsertRValue(ctx, "0xnew2", "0xanother", 42)
	if !isCollision {
		t.Error("Expected 0xnew2 to exist and cause collision")
	}
}

func TestMockDBBatchEmpty(t *testing.T) {
	ctx := context.Background()
	db := NewMock()

	collisions, err := db.BatchCheckAndInsertRValues(ctx, []TxInput{})
	if err != nil {
		t.Fatalf("BatchCheckAndInsertRValues failed: %v", err)
	}
	if len(collisions) != 0 {
		t.Errorf("Expected 0 collisions for empty input, got %d", len(collisions))
	}
}
