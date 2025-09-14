package rbac

import (
	"fmt"
)

// Error codes for RBAC operations
const (
	ErrCodeInvalidConfig      = "invalid_config"
	ErrCodeSessionNotFound    = "session_not_found"
	ErrCodeSessionExpired     = "session_expired"
	ErrCodeTokenExchangeFailed = "token_exchange_failed"
	ErrCodeInvalidToken       = "invalid_token"
)

// Error types for RBAC operations
type RBACError struct {
	Type    string
	Message string
	Details map[string]interface{}
}

func (e *RBACError) Error() string {
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
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
	return &RBACError{
		Type:    "not_found",
		Message: fmt.Sprintf("%s with ID %s not found", resource, id),
		Details: map[string]interface{}{
			"resource": resource,
			"id":       id,
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
