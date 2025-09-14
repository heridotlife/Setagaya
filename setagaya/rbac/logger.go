package rbac

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// Logger defines the interface for RBAC logging operations
type Logger interface {
	Info(message string, fields ...interface{})
	Warn(message string, fields ...interface{})
	Error(message string, fields ...interface{})
	Debug(message string, fields ...interface{})
}

// SimpleLogger provides a basic implementation of the Logger interface
type SimpleLogger struct {
	prefix      string
	debugMode   bool
	mu          sync.RWMutex
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	debugLogger *log.Logger
}

// NewSimpleLogger creates a new SimpleLogger instance
func NewSimpleLogger(prefix string, debugMode bool) Logger {
	return &SimpleLogger{
		prefix:      prefix,
		debugMode:   debugMode,
		infoLogger:  log.Default(),
		warnLogger:  log.Default(),
		errorLogger: log.Default(),
		debugLogger: log.Default(),
	}
}

// Info logs an informational message
func (l *SimpleLogger) Info(message string, fields ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logMessage := fmt.Sprintf("[%s] [INFO] [%s] %s", timestamp, l.prefix, message)
	
	if len(fields) > 0 {
		logMessage += fmt.Sprintf(" %v", fields)
	}
	
	l.infoLogger.Println(logMessage)
}

// Warn logs a warning message
func (l *SimpleLogger) Warn(message string, fields ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logMessage := fmt.Sprintf("[%s] [WARN] [%s] %s", timestamp, l.prefix, message)
	
	if len(fields) > 0 {
		logMessage += fmt.Sprintf(" %v", fields)
	}
	
	l.warnLogger.Println(logMessage)
}

// Error logs an error message
func (l *SimpleLogger) Error(message string, fields ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logMessage := fmt.Sprintf("[%s] [ERROR] [%s] %s", timestamp, l.prefix, message)
	
	if len(fields) > 0 {
		logMessage += fmt.Sprintf(" %v", fields)
	}
	
	l.errorLogger.Println(logMessage)
}

// Debug logs a debug message (only if debug mode is enabled)
func (l *SimpleLogger) Debug(message string, fields ...interface{}) {
	if !l.debugMode {
		return
	}
	
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logMessage := fmt.Sprintf("[%s] [DEBUG] [%s] %s", timestamp, l.prefix, message)
	
	if len(fields) > 0 {
		logMessage += fmt.Sprintf(" %v", fields)
	}
	
	l.debugLogger.Println(logMessage)
}