package logger

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// Level represents log severity
type Level int

const (
	LevelInfo Level = iota
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// Entry represents a single log entry
type Entry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

// Buffer is a ring buffer for storing recent log messages
type Buffer struct {
	mu      sync.RWMutex
	entries []Entry
	size    int
	pos     int
}

// Logger wraps standard logging with a ring buffer
type Logger struct {
	buffer *Buffer
}

// New creates a new Logger with the specified buffer size
func New(bufferSize int) *Logger {
	return &Logger{
		buffer: &Buffer{
			entries: make([]Entry, bufferSize),
			size:    bufferSize,
		},
	}
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fullMsg := fmt.Sprintf("[%s] %s", level.String(), msg)
	log.Print(fullMsg)

	l.buffer.mu.Lock()
	l.buffer.entries[l.buffer.pos] = Entry{
		Timestamp: time.Now().Format("2006-01-02 15:04:05.000"),
		Level:     level.String(),
		Message:   msg,
	}
	l.buffer.pos = (l.buffer.pos + 1) % l.buffer.size
	l.buffer.mu.Unlock()
}

// Info logs an informational message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(LevelWarn, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LevelError, format, args...)
}

// Log is an alias for Info (backward compatibility)
func (l *Logger) Log(format string, args ...interface{}) {
	l.Info(format, args...)
}

// GetEntries returns all log entries in chronological order
func (l *Logger) GetEntries() []Entry {
	l.buffer.mu.RLock()
	defer l.buffer.mu.RUnlock()

	result := make([]Entry, 0, l.buffer.size)
	for i := 0; i < l.buffer.size; i++ {
		idx := (l.buffer.pos + i) % l.buffer.size
		if l.buffer.entries[idx].Timestamp != "" {
			result = append(result, l.buffer.entries[idx])
		}
	}
	return result
}
