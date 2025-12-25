package retry

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"strings"
	"time"
)

// Config holds retry configuration
type Config struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		MaxAttempts: 3,
		BaseDelay:   500 * time.Millisecond,
		MaxDelay:    30 * time.Second,
	}
}

// IsRetryable determines if an error should be retried
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// Retryable errors
	retryablePatterns := []string{
		"timeout",
		"connection refused",
		"connection reset",
		"eof",
		"temporary failure",
		"too many requests",
		"rate limit",
		"429",
		"503",
		"502",
		"504",
		"busy",
		"unavailable",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// Do executes fn with retries using exponential backoff
func Do(ctx context.Context, cfg Config, fn func() error) error {
	var lastErr error

	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		// Don't retry non-retryable errors
		if !IsRetryable(err) {
			return err
		}

		// Don't retry on last attempt
		if attempt == cfg.MaxAttempts-1 {
			break
		}

		// Calculate backoff with jitter
		delay := cfg.BaseDelay * time.Duration(math.Pow(2, float64(attempt)))
		if delay > cfg.MaxDelay {
			delay = cfg.MaxDelay
		}
		// Add jitter (0-25% of delay)
		jitter := time.Duration(rand.Int63n(int64(delay / 4)))
		delay += jitter

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}

	return lastErr
}

// DoWithResult executes fn with retries and returns the result
func DoWithResult[T any](ctx context.Context, cfg Config, fn func() (T, error)) (T, error) {
	var result T
	var lastErr error

	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		var err error
		result, err = fn()
		if err == nil {
			return result, nil
		}

		lastErr = err

		if !IsRetryable(err) {
			return result, err
		}

		if attempt == cfg.MaxAttempts-1 {
			break
		}

		delay := cfg.BaseDelay * time.Duration(math.Pow(2, float64(attempt)))
		if delay > cfg.MaxDelay {
			delay = cfg.MaxDelay
		}
		jitter := time.Duration(rand.Int63n(int64(delay / 4)))
		delay += jitter

		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(delay):
		}
	}

	return result, lastErr
}

// ErrCircuitOpen is returned when the circuit breaker is open
var ErrCircuitOpen = errors.New("circuit breaker is open")

// CircuitBreaker implements a simple circuit breaker pattern
type CircuitBreaker struct {
	failures    int
	threshold   int
	resetAfter  time.Duration
	lastFailure time.Time
	open        bool
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(threshold int, resetAfter time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold:  threshold,
		resetAfter: resetAfter,
	}
}

// Allow checks if a request should be allowed
func (cb *CircuitBreaker) Allow() bool {
	if !cb.open {
		return true
	}

	// Check if we should try to reset
	if time.Since(cb.lastFailure) > cb.resetAfter {
		cb.open = false
		cb.failures = 0
		return true
	}

	return false
}

// RecordSuccess records a successful request
func (cb *CircuitBreaker) RecordSuccess() {
	cb.failures = 0
	cb.open = false
}

// RecordFailure records a failed request
func (cb *CircuitBreaker) RecordFailure() {
	cb.failures++
	cb.lastFailure = time.Now()
	if cb.failures >= cb.threshold {
		cb.open = true
	}
}

// IsOpen returns whether the circuit is open
func (cb *CircuitBreaker) IsOpen() bool {
	return cb.open
}
