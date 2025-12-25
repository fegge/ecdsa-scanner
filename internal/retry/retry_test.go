package retry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"timeout", errors.New("connection timeout"), true},
		{"rate limit", errors.New("rate limit exceeded"), true},
		{"429", errors.New("HTTP 429 Too Many Requests"), true},
		{"503", errors.New("503 Service Unavailable"), true},
		{"connection refused", errors.New("connection refused"), true},
		{"EOF", errors.New("unexpected EOF"), true},
		{"not found", errors.New("resource not found"), false},
		{"invalid input", errors.New("invalid parameter"), false},
		{"auth error", errors.New("unauthorized"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryable(tt.err)
			if result != tt.expected {
				t.Errorf("IsRetryable(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestDo_Success(t *testing.T) {
	cfg := Config{
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    100 * time.Millisecond,
	}

	attempts := 0
	err := Do(context.Background(), cfg, func() error {
		attempts++
		return nil
	})

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

func TestDo_RetryableError(t *testing.T) {
	cfg := Config{
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    100 * time.Millisecond,
	}

	attempts := 0
	err := Do(context.Background(), cfg, func() error {
		attempts++
		if attempts < 3 {
			return errors.New("timeout")
		}
		return nil
	})

	if err != nil {
		t.Errorf("expected no error after retries, got %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestDo_NonRetryableError(t *testing.T) {
	cfg := Config{
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    100 * time.Millisecond,
	}

	attempts := 0
	expectedErr := errors.New("invalid input")
	err := Do(context.Background(), cfg, func() error {
		attempts++
		return expectedErr
	})

	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt for non-retryable error, got %d", attempts)
	}
}

func TestDo_MaxAttempts(t *testing.T) {
	cfg := Config{
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    100 * time.Millisecond,
	}

	attempts := 0
	err := Do(context.Background(), cfg, func() error {
		attempts++
		return errors.New("timeout")
	})

	if err == nil {
		t.Error("expected error after max attempts")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestDo_ContextCancelled(t *testing.T) {
	cfg := Config{
		MaxAttempts: 5,
		BaseDelay:   100 * time.Millisecond,
		MaxDelay:    1 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	attempts := 0
	err := Do(ctx, cfg, func() error {
		attempts++
		return errors.New("timeout")
	})

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context deadline exceeded, got %v", err)
	}
}

func TestDoWithResult_Success(t *testing.T) {
	cfg := Config{
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    100 * time.Millisecond,
	}

	result, err := DoWithResult(context.Background(), cfg, func() (int, error) {
		return 42, nil
	})

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
}

func TestDoWithResult_RetryThenSuccess(t *testing.T) {
	cfg := Config{
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    100 * time.Millisecond,
	}

	attempts := 0
	result, err := DoWithResult(context.Background(), cfg, func() (int, error) {
		attempts++
		if attempts < 2 {
			return 0, errors.New("timeout")
		}
		return 42, nil
	})

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestCircuitBreaker_AllowsWhenClosed(t *testing.T) {
	cb := NewCircuitBreaker(3, time.Minute)

	if !cb.Allow() {
		t.Error("circuit breaker should allow requests when closed")
	}
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(3, time.Minute)

	cb.RecordFailure()
	cb.RecordFailure()
	if cb.IsOpen() {
		t.Error("circuit should still be closed after 2 failures")
	}

	cb.RecordFailure()
	if !cb.IsOpen() {
		t.Error("circuit should be open after 3 failures")
	}

	if cb.Allow() {
		t.Error("circuit breaker should not allow requests when open")
	}
}

func TestCircuitBreaker_ResetsOnSuccess(t *testing.T) {
	cb := NewCircuitBreaker(3, time.Minute)

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess()

	if cb.IsOpen() {
		t.Error("circuit should be closed after success")
	}

	// Should need 3 more failures to open again
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.IsOpen() {
		t.Error("circuit should still be closed after 2 failures")
	}
}

func TestCircuitBreaker_ResetsAfterTimeout(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()

	if !cb.IsOpen() {
		t.Error("circuit should be open")
	}

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)

	if !cb.Allow() {
		t.Error("circuit should allow after reset timeout")
	}

	if cb.IsOpen() {
		t.Error("circuit should be closed after allowing a request")
	}
}
