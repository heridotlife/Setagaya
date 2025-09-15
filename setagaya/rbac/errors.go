package rbac

import (
	"strings"
)

// Error codes for RBAC operations
const (
	ErrCodeInvalidConfig       = "invalid_config"
	ErrCodeInvalidSession      = "invalid_session"
	ErrCodeSessionNotFound     = "session_not_found"
	ErrCodeSessionExpired      = "session_expired"
	ErrCodeSessionStoreFull    = "session_store_full"
	ErrCodeTokenExchangeFailed = "token_exchange_failed"
	ErrCodeInvalidToken        = "invalid_token"
	ErrCodeCryptographicError  = "cryptographic_error"
)

// Error types for RBAC operations
type RBACError struct {
	Type    string
	Message string
	Details map[string]interface{}
}

func (e *RBACError) Error() string {
	// Safe string construction to prevent format string vulnerabilities
	return sanitizeErrorType(e.Type) + ": " + sanitizeErrorMessage(e.Message)
}

// NewRBACError creates a new RBAC error with the specified code and message
func NewRBACError(code, message string, details map[string]interface{}) *RBACError {
	if details == nil {
		details = make(map[string]interface{})
	}
	return &RBACError{
		Type:    code,
		Message: message,
		Details: details,
	}
}

// Specific error constructors
func NewValidationError(message string) *RBACError {
	return &RBACError{
		Type:    "validation_error",
		Message: message,
		Details: make(map[string]interface{}),
	}
}

func NewAuthorizationError(message string) *RBACError {
	return &RBACError{
		Type:    "authorization_error",
		Message: message,
		Details: make(map[string]interface{}),
	}
}

func NewConfigurationError(message string) *RBACError {
	return &RBACError{
		Type:    "configuration_error",
		Message: message,
		Details: make(map[string]interface{}),
	}
}

func NewAuthenticationError(message string) *RBACError {
	return &RBACError{
		Type:    "authentication_error",
		Message: message,
		Details: make(map[string]interface{}),
	}
}

func NewNotFoundError(resource, id string) *RBACError {
	// Safe string construction to prevent format string vulnerabilities with user-controlled data
	sanitizedResource := sanitizeErrorInput(resource)
	sanitizedID := sanitizeErrorInput(id)

	return &RBACError{
		Type:    "not_found",
		Message: sanitizedResource + " with ID " + sanitizedID + " not found",
		Details: map[string]interface{}{
			"resource": sanitizedResource,
			"id":       sanitizedID,
		},
	}
}

// NewNotFoundErrorSimple creates a not found error with a simple message
func NewNotFoundErrorSimple(message string) *RBACError {
	return &RBACError{
		Type:    "not_found",
		Message: message,
		Details: make(map[string]interface{}),
	}
}

func NewConflictError(message string) *RBACError {
	return &RBACError{
		Type:    "conflict",
		Message: message,
		Details: make(map[string]interface{}),
	}
}

func NewInternalError(message string) *RBACError {
	return &RBACError{
		Type:    "internal_error",
		Message: message,
		Details: make(map[string]interface{}),
	}
}

func NewForbiddenError(message string) *RBACError {
	return &RBACError{
		Type:    "forbidden",
		Message: message,
		Details: make(map[string]interface{}),
	}
}

// WithDetails adds additional context to an error
func (e *RBACError) WithDetails(key string, value interface{}) *RBACError {
	e.Details[key] = value
	return e
}

// IsType checks if error is of a specific type
func IsErrorType(err error, errorType string) bool {
	if rbacErr, ok := err.(*RBACError); ok {
		return rbacErr.Type == errorType
	}
	return false
}

// IsValidationError checks if error is a validation error
func IsValidationError(err error) bool {
	return IsErrorType(err, "validation_error")
}

// IsAuthorizationError checks if error is an authorization error
func IsAuthorizationError(err error) bool {
	return IsErrorType(err, "authorization_error")
}

// IsNotFoundError checks if error is a not found error
func IsNotFoundError(err error) bool {
	return IsErrorType(err, "not_found")
}

// IsConflictError checks if error is a conflict error
func IsConflictError(err error) bool {
	return IsErrorType(err, "conflict")
}

// IsForbiddenError checks if error is a forbidden error
func IsForbiddenError(err error) bool {
	return IsErrorType(err, "forbidden")
}

// IsInternalError checks if error is an internal error
func IsInternalError(err error) bool {
	return IsErrorType(err, "internal_error")
}

// sanitizeErrorType safely sanitizes error type strings to prevent injection
func sanitizeErrorType(errorType string) string {
	if len(errorType) == 0 {
		return "unknown_error"
	}

	// Use strings.Builder for efficient string building
	var builder strings.Builder
	builder.Grow(len(errorType)) // Pre-allocate capacity for efficiency

	// Only allow alphanumeric and underscores for error types
	for _, char := range errorType {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' {
			builder.WriteRune(char)
		}
	}

	sanitized := builder.String()

	// Limit length
	if len(sanitized) > 50 {
		sanitized = sanitized[:50]
	}

	if len(sanitized) == 0 {
		return "sanitized_error"
	}

	return sanitized
}

// sanitizeErrorMessage safely sanitizes error messages to prevent injection and information disclosure
func sanitizeErrorMessage(message string) string {
	if len(message) == 0 {
		return "An error occurred"
	}

	// Replace control characters and potentially dangerous sequences
	sanitized := strings.ReplaceAll(message, "\n", " ")
	sanitized = strings.ReplaceAll(sanitized, "\r", " ")
	sanitized = strings.ReplaceAll(sanitized, "\t", " ")
	sanitized = strings.ReplaceAll(sanitized, "\"", "'")
	sanitized = strings.ReplaceAll(sanitized, "<", "&lt;")
	sanitized = strings.ReplaceAll(sanitized, ">", "&gt;")

	// Limit length to prevent buffer overflow
	if len(sanitized) > 200 {
		sanitized = sanitized[:197] + "..."
	}

	return sanitized
}

// sanitizeErrorInput safely sanitizes user input for error messages
func sanitizeErrorInput(input string) string {
	if len(input) == 0 {
		return "unknown"
	}

	// Use strings.Builder for efficient string building
	var builder strings.Builder
	builder.Grow(len(input)) // Pre-allocate capacity for efficiency

	// Very strict sanitization for user inputs in error messages
	for _, char := range input {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '-' {
			builder.WriteRune(char)
		}
	}

	sanitized := builder.String()

	// Limit length
	if len(sanitized) > 30 {
		sanitized = sanitized[:30]
	}

	if len(sanitized) == 0 {
		return "sanitized_input"
	}

	return sanitized
}
