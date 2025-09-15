package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewValidationError(t *testing.T) {
	message := "test validation error"
	err := NewValidationError(message)

	assert.NotNil(t, err)
	assert.Equal(t, "validation_error", err.Type)
	assert.Equal(t, message, err.Message)
	assert.NotNil(t, err.Details)
	assert.Equal(t, "validation_error: test validation error", err.Error())
}

func TestNewAuthorizationError(t *testing.T) {
	message := "test authorization error"
	err := NewAuthorizationError(message)

	assert.NotNil(t, err)
	assert.Equal(t, "authorization_error", err.Type)
	assert.Equal(t, message, err.Message)
	assert.NotNil(t, err.Details)
}

func TestNewNotFoundError(t *testing.T) {
	resource := "tenant"
	id := "123"
	err := NewNotFoundError(resource, id)

	assert.NotNil(t, err)
	assert.Equal(t, "not_found", err.Type)
	assert.Contains(t, err.Message, resource)
	assert.Contains(t, err.Message, id)
	assert.Equal(t, resource, err.Details["resource"])
	assert.Equal(t, id, err.Details["id"])
}

func TestNewNotFoundErrorSimple(t *testing.T) {
	message := "resource not found"
	err := NewNotFoundErrorSimple(message)

	assert.NotNil(t, err)
	assert.Equal(t, "not_found", err.Type)
	assert.Equal(t, message, err.Message)
	assert.NotNil(t, err.Details)
	assert.Equal(t, "not_found: resource not found", err.Error())
}

func TestNewConflictError(t *testing.T) {
	message := "test conflict error"
	err := NewConflictError(message)

	assert.NotNil(t, err)
	assert.Equal(t, "conflict", err.Type)
	assert.Equal(t, message, err.Message)
}

func TestNewInternalError(t *testing.T) {
	message := "test internal error"
	err := NewInternalError(message)

	assert.NotNil(t, err)
	assert.Equal(t, "internal_error", err.Type)
	assert.Equal(t, message, err.Message)
}

func TestNewForbiddenError(t *testing.T) {
	message := "test forbidden error"
	err := NewForbiddenError(message)

	assert.NotNil(t, err)
	assert.Equal(t, "forbidden", err.Type)
	assert.Equal(t, message, err.Message)
}

func TestRBACError_WithDetails(t *testing.T) {
	err := NewValidationError("test error")

	// Add details
	_ = err.WithDetails("field", "name")
	_ = err.WithDetails("value", "invalid_value")

	assert.Equal(t, "name", err.Details["field"])
	assert.Equal(t, "invalid_value", err.Details["value"])
}

func TestIsErrorType(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		errorType string
		expected  bool
	}{
		{
			name:      "validation error matches",
			err:       NewValidationError("test"),
			errorType: "validation_error",
			expected:  true,
		},
		{
			name:      "validation error does not match authorization",
			err:       NewValidationError("test"),
			errorType: "authorization_error",
			expected:  false,
		},
		{
			name:      "non-RBAC error",
			err:       assert.AnError,
			errorType: "validation_error",
			expected:  false,
		},
		{
			name:      "nil error",
			err:       nil,
			errorType: "validation_error",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsErrorType(tt.err, tt.errorType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "validation error",
			err:      NewValidationError("test"),
			expected: true,
		},
		{
			name:     "authorization error",
			err:      NewAuthorizationError("test"),
			expected: false,
		},
		{
			name:     "non-RBAC error",
			err:      assert.AnError,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidationError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsAuthorizationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "authorization error",
			err:      NewAuthorizationError("test"),
			expected: true,
		},
		{
			name:     "validation error",
			err:      NewValidationError("test"),
			expected: false,
		},
		{
			name:     "non-RBAC error",
			err:      assert.AnError,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAuthorizationError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "not found error",
			err:      NewNotFoundError("tenant", "123"),
			expected: true,
		},
		{
			name:     "not found error simple",
			err:      NewNotFoundErrorSimple("resource not found"),
			expected: true,
		},
		{
			name:     "validation error",
			err:      NewValidationError("test"),
			expected: false,
		},
		{
			name:     "non-RBAC error",
			err:      assert.AnError,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNotFoundError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsConflictError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "conflict error",
			err:      NewConflictError("test"),
			expected: true,
		},
		{
			name:     "validation error",
			err:      NewValidationError("test"),
			expected: false,
		},
		{
			name:     "non-RBAC error",
			err:      assert.AnError,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsConflictError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsForbiddenError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "forbidden error",
			err:      NewForbiddenError("test"),
			expected: true,
		},
		{
			name:     "validation error",
			err:      NewValidationError("test"),
			expected: false,
		},
		{
			name:     "non-RBAC error",
			err:      assert.AnError,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsForbiddenError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsInternalError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "internal error",
			err:      NewInternalError("test"),
			expected: true,
		},
		{
			name:     "validation error",
			err:      NewValidationError("test"),
			expected: false,
		},
		{
			name:     "non-RBAC error",
			err:      assert.AnError,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsInternalError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
