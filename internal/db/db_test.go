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
