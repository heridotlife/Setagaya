package rbac

import (
	"log"
	"strings"
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

// Info logs an informational message with secure field handling
func (l *SimpleLogger) Info(message string, fields ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Safe string construction without format strings
	logMessage := "[" + timestamp + "] [INFO] [" + l.prefix + "] " + sanitizeLogMessage(message)

	if len(fields) > 0 {
		fieldsStr := sanitizeLogFields(fields)
		if fieldsStr != "" {
			logMessage += " " + fieldsStr
		}
	}

	l.infoLogger.Println(logMessage)
}

// Warn logs a warning message with secure field handling
func (l *SimpleLogger) Warn(message string, fields ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Safe string construction without format strings
	logMessage := "[" + timestamp + "] [WARN] [" + l.prefix + "] " + sanitizeLogMessage(message)

	if len(fields) > 0 {
		fieldsStr := sanitizeLogFields(fields)
		if fieldsStr != "" {
			logMessage += " " + fieldsStr
		}
	}

	l.warnLogger.Println(logMessage)
}

// Error logs an error message with secure field handling
func (l *SimpleLogger) Error(message string, fields ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Safe string construction without format strings
	logMessage := "[" + timestamp + "] [ERROR] [" + l.prefix + "] " + sanitizeLogMessage(message)

	if len(fields) > 0 {
		fieldsStr := sanitizeLogFields(fields)
		if fieldsStr != "" {
			logMessage += " " + fieldsStr
		}
	}

	l.errorLogger.Println(logMessage)
}

// Debug logs a debug message with secure field handling (only if debug mode is enabled)
func (l *SimpleLogger) Debug(message string, fields ...interface{}) {
	if !l.debugMode {
		return
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Safe string construction without format strings
	logMessage := "[" + timestamp + "] [DEBUG] [" + l.prefix + "] " + sanitizeLogMessage(message)

	if len(fields) > 0 {
		fieldsStr := sanitizeLogFields(fields)
		if fieldsStr != "" {
			logMessage += " " + fieldsStr
		}
	}

	l.debugLogger.Println(logMessage)
}

// sanitizeLogMessage sanitizes log messages to prevent log injection attacks
func sanitizeLogMessage(message string) string {
	if len(message) == 0 {
		return ""
	}

	// Replace control characters that could break log format
	sanitized := strings.ReplaceAll(message, "\n", "\\n")
	sanitized = strings.ReplaceAll(sanitized, "\r", "\\r")
	sanitized = strings.ReplaceAll(sanitized, "\t", "\\t")

	// Limit message length to prevent log flooding
	if len(sanitized) > 500 {
		sanitized = sanitized[:497] + "..."
	}

	return sanitized
}

// sanitizeLogFields safely converts and sanitizes log fields
func sanitizeLogFields(fields []interface{}) string {
	if len(fields) == 0 {
		return ""
	}

	var parts []string

	// Process fields in pairs (key, value)
	for i := 0; i < len(fields); i += 2 {
		var key, value string

		if i < len(fields) {
			if keyStr, ok := fields[i].(string); ok {
				key = sanitizeLogValue(keyStr)
			} else {
				key = "field" + string(rune('0'+i/2))
			}
		}

		if i+1 < len(fields) {
			value = sanitizeLogValue(convertToString(fields[i+1]))
		} else {
			value = "nil"
		}

		if key != "" && value != "" {
			parts = append(parts, key+"="+value)
		}
	}

	result := strings.Join(parts, " ")

	// Limit total fields length
	if len(result) > 1000 {
		result = result[:997] + "..."
	}

	return result
}

// sanitizeLogValue sanitizes individual log values
func sanitizeLogValue(value string) string {
	if len(value) == 0 {
		return ""
	}

	// Remove control characters and limit length
	sanitized := strings.ReplaceAll(value, "\n", "\\n")
	sanitized = strings.ReplaceAll(sanitized, "\r", "\\r")
	sanitized = strings.ReplaceAll(sanitized, "\t", "\\t")
	sanitized = strings.ReplaceAll(sanitized, "\"", "\\\"")

	// Limit individual value length
	if len(sanitized) > 100 {
		sanitized = sanitized[:97] + "..."
	}

	return sanitized
}

// convertToString safely converts interface{} to string
func convertToString(value interface{}) string {
	if value == nil {
		return "nil"
	}

	switch v := value.(type) {
	case string:
		return v
	case error:
		return v.Error()
	case bool:
		if v {
			return "true"
		}
		return "false"
	case int:
		return convertIntToString(int64(v))
	case int8:
		return convertIntToString(int64(v))
	case int16:
		return convertIntToString(int64(v))
	case int32:
		return convertIntToString(int64(v))
	case int64:
		return convertIntToString(v)
	case uint:
		// Check for overflow before conversion
		if v > 9223372036854775807 { // math.MaxInt64
			return "large_uint"
		}
		return convertIntToString(int64(v))
	case uint8:
		return convertIntToString(int64(v))
	case uint16:
		return convertIntToString(int64(v))
	case uint32:
		return convertIntToString(int64(v))
	case uint64:
		// Check for overflow before conversion
		if v > 9223372036854775807 { // math.MaxInt64
			return "large_uint64"
		}
		return convertIntToString(int64(v))
	case float32, float64:
		return "number"
	default:
		return "object"
	}
}

// convertIntToString safely converts int64 to string without fmt.Sprintf
func convertIntToString(value int64) string {
	if value == 0 {
		return "0"
	}

	negative := value < 0
	if negative {
		value = -value
	}

	digits := []byte{}
	for value > 0 {
		digits = append([]byte{byte('0' + (value % 10))}, digits...)
		value /= 10
	}

	result := string(digits)
	if negative {
		result = "-" + result
	}

	return result
}
