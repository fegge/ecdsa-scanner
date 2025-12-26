package notify

import "testing"

func TestNotifierDisabledWhenNoCredentials(t *testing.T) {
	n := New("", "")
	if n.IsEnabled() {
		t.Error("Expected notifier to be disabled with empty credentials")
	}

	// Should not error when disabled
	if err := n.Send("test", "message"); err != nil {
		t.Errorf("Expected no error when disabled, got: %v", err)
	}
}

func TestNotifierEnabledWithCredentials(t *testing.T) {
	n := New("app-token", "user-key")
	if !n.IsEnabled() {
		t.Error("Expected notifier to be enabled with credentials")
	}
}

func TestShortenAddress(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"0x742d35Cc6634C0532925a3b844Bc9e7595f8b2d1", "0x742d35...f8b2d1"},
		{"0xABCD", "0xabcd"},
		{"", ""},
	}

	for _, tt := range tests {
		result := shortenAddress(tt.input)
		if result != tt.expected {
			t.Errorf("shortenAddress(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestShortenHash(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"0x1234567890abcdef1234567890abcdef", "0x1234567890abcdef..."},
		{"0x1234", "0x1234"},
	}

	for _, tt := range tests {
		result := shortenHash(tt.input)
		if result != tt.expected {
			t.Errorf("shortenHash(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
