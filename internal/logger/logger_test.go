package logger

import (
	"strings"
	"testing"
)

func TestLogger_LogLevels(t *testing.T) {
	log := New(10)

	log.Info("info message")
	log.Warn("warn message")
	log.Error("error message")

	entries := log.GetEntries()
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}

	if entries[0].Level != "INFO" {
		t.Errorf("expected INFO level, got %s", entries[0].Level)
	}
	if entries[1].Level != "WARN" {
		t.Errorf("expected WARN level, got %s", entries[1].Level)
	}
	if entries[2].Level != "ERROR" {
		t.Errorf("expected ERROR level, got %s", entries[2].Level)
	}
}

func TestLogger_RingBuffer(t *testing.T) {
	log := New(3)

	log.Info("message 1")
	log.Info("message 2")
	log.Info("message 3")
	log.Info("message 4")

	entries := log.GetEntries()
	if len(entries) != 3 {
		t.Errorf("expected 3 entries (buffer size), got %d", len(entries))
	}

	// Oldest entry should be "message 2" (message 1 was overwritten)
	if !strings.Contains(entries[0].Message, "message 2") {
		t.Errorf("expected oldest entry to be 'message 2', got %s", entries[0].Message)
	}

	// Newest entry should be "message 4"
	if !strings.Contains(entries[2].Message, "message 4") {
		t.Errorf("expected newest entry to be 'message 4', got %s", entries[2].Message)
	}
}

func TestLogger_Formatting(t *testing.T) {
	log := New(10)

	log.Info("[%s] Block %d scanned", "ETH", 12345)

	entries := log.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	expected := "[ETH] Block 12345 scanned"
	if entries[0].Message != expected {
		t.Errorf("expected %q, got %q", expected, entries[0].Message)
	}
}

func TestLogger_Timestamp(t *testing.T) {
	log := New(10)

	log.Info("test")

	entries := log.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	// Timestamp should be in format "2006-01-02 15:04:05.000"
	if len(entries[0].Timestamp) != 23 {
		t.Errorf("unexpected timestamp format: %s", entries[0].Timestamp)
	}
}

func TestLogger_EmptyBuffer(t *testing.T) {
	log := New(10)

	entries := log.GetEntries()
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty buffer, got %d", len(entries))
	}
}

func TestLevel_String(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{Level(99), "INFO"}, // Unknown defaults to INFO
	}

	for _, tt := range tests {
		if tt.level.String() != tt.expected {
			t.Errorf("Level(%d).String() = %s, want %s", tt.level, tt.level.String(), tt.expected)
		}
	}
}
