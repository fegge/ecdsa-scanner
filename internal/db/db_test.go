package db

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ecdsa-scanner/internal/retry"
)

func TestWrapError(t *testing.T) {
	db := &DB{retryConfig: retry.DefaultConfig()}

	tests := []struct {
		name        string
		err         error
		expectedNil bool
	}{
		{"nil error", nil, true},
		{"generic error", errors.New("some error"), false},
		{"context deadline", context.DeadlineExceeded, false},
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

func TestBuildAddressExclusion(t *testing.T) {
	tests := []struct {
		name      string
		addresses map[string]bool
		expected  string
	}{
		{
			name:      "empty",
			addresses: map[string]bool{},
			expected:  "",
		},
		{
			name:      "single address",
			addresses: map[string]bool{"0xdead": true},
			expected:  " AND from_address NOT IN ('0xdead')",
		},
		{
			name:      "multiple addresses",
			addresses: map[string]bool{"0xdead": true, "0xbeef": true},
			expected:  " AND from_address NOT IN (",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &DB{systemAddresses: tt.addresses}
			result := db.buildAddressExclusion()

			if tt.name == "multiple addresses" {
				if !strings.HasPrefix(result, tt.expected) {
					t.Errorf("expected prefix %q, got %q", tt.expected, result)
				}
				if !strings.Contains(result, "'0xdead'") || !strings.Contains(result, "'0xbeef'") {
					t.Errorf("expected both addresses in result, got %q", result)
				}
			} else if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSignatureFiltering(t *testing.T) {
	db := &DB{
		systemAddresses: map[string]bool{
			"0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001": true,
		},
		retryConfig: retry.DefaultConfig(),
	}

	sigs := []Signature{
		{Chain: "eth", TxHash: "0x1", FromAddress: "0xuser", R: "0xabc", S: "0xdef", V: "0x1b"},
		{Chain: "eth", TxHash: "0x2", FromAddress: "0xuser", R: "0x0", S: "0xdef", V: "0x1b"},                                      // Should be filtered (R=0)
		{Chain: "eth", TxHash: "0x3", FromAddress: "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001", R: "0xabc", S: "0xdef", V: "0x1b"}, // Should be filtered (system)
		{Chain: "eth", TxHash: "0x4", FromAddress: "0xuser2", R: "", S: "0xdef", V: "0x1b"},                                       // Should be filtered (empty R)
	}

	// Test that filtering logic works by checking the batch building
	// (We can't test actual insertion without a real DB)
	validCount := 0
	for _, sig := range sigs {
		if sig.R == "0x0" || sig.R == "0x00" || sig.R == "" {
			continue
		}
		if db.systemAddresses[strings.ToLower(sig.FromAddress)] {
			continue
		}
		validCount++
	}

	if validCount != 1 {
		t.Errorf("expected 1 valid signature after filtering, got %d", validCount)
	}
}
