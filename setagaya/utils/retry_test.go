package utils

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRetrySuccessOnFirstAttempt(t *testing.T) {
	attempts := 0

	err := Retry(func() error {
		attempts++
		return nil
	}, nil)

	assert.NoError(t, err)
	assert.Equal(t, 1, attempts)
}

func TestRetrySuccessAfterFailures(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping retry test in short mode due to timeout")
	}

	attempts := 0

	err := Retry(func() error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary failure")
		}
		return nil
	}, nil)

	assert.NoError(t, err)
	assert.Equal(t, 3, attempts)
}

func TestRetryExhaustsAllAttempts(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping retry test in short mode due to timeout")
	}

	attempts := 0
	expectedError := errors.New("persistent failure")

	err := Retry(func() error {
		attempts++
		return expectedError
	}, nil)

	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	assert.Equal(t, RETRY_LIMIT, attempts)
}

func TestRetryWithExemptError(t *testing.T) {
	attempts := 0
	exemptError := errors.New("exempt error")

	err := Retry(func() error {
		attempts++
		return exemptError
	}, exemptError)

	assert.Error(t, err)
	assert.Equal(t, exemptError, err)
	assert.Equal(t, 1, attempts) // Should not retry exempt errors
}

func TestRetryWithWrappedExemptError(t *testing.T) {
	attempts := 0
	exemptError := errors.New("exempt error")
	wrappedError := fmt.Errorf("wrapped: %w", exemptError)

	err := Retry(func() error {
		attempts++
		return wrappedError
	}, exemptError)

	assert.Error(t, err)
	assert.True(t, errors.Is(err, exemptError))
	assert.Equal(t, 1, attempts) // Should not retry when wrapped exempt error is returned
}

func TestRetryWithDifferentErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping retry test in short mode due to timeout")
	}

	attempts := 0
	exemptError := errors.New("exempt error")
	otherError := errors.New("other error")

	err := Retry(func() error {
		attempts++
		if attempts < 3 {
			return otherError // This should be retried
		}
		return exemptError // This should not be retried
	}, exemptError)

	assert.Error(t, err)
	assert.Equal(t, exemptError, err)
	assert.Equal(t, 3, attempts)
}

func TestRetryConstants(t *testing.T) {
	// Test that the retry constants have expected values
	assert.Equal(t, 5, RETRY_LIMIT)
	assert.Equal(t, 10, RETRY_INTERVAL)
}

func TestRetryTiming(t *testing.T) {
	// Skip this test in short mode to avoid long waits
	if testing.Short() {
		t.Skip("Skipping timing test in short mode")
	}

	// Test that retry respects the interval (shortened for test)
	attempts := 0
	startTime := time.Now()

	// This will fail twice, then succeed
	err := Retry(func() error {
		attempts++
		if attempts < 3 {
			return errors.New("failure")
		}
		return nil
	}, nil)

	duration := time.Since(startTime)

	assert.NoError(t, err)
	assert.Equal(t, 3, attempts)

	// Should take at least 2 * RETRY_INTERVAL seconds (2 failed attempts)
	expectedMinDuration := time.Duration(2*RETRY_INTERVAL) * time.Second
	assert.GreaterOrEqual(t, duration, expectedMinDuration)
}

func TestRetryWithNilError(t *testing.T) {
	attempts := 0

	err := Retry(func() error {
		attempts++
		return nil
	}, errors.New("some exempt error"))

	assert.NoError(t, err)
	assert.Equal(t, 1, attempts)
}

func TestRetryWithNilExemptError(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping retry test in short mode due to timeout")
	}

	attempts := 0
	testError := errors.New("test error")

	err := Retry(func() error {
		attempts++
		return testError
	}, nil)

	assert.Error(t, err)
	assert.Equal(t, testError, err)
	assert.Equal(t, RETRY_LIMIT, attempts)
}

func TestRetryWithPanic(t *testing.T) {
	// Test that if the function panics, it's not caught by retry
	assert.Panics(t, func() {
		_ = Retry(func() error {
			panic("test panic")
		}, nil)
	})
}

func TestRetryErrorComparison(t *testing.T) {
	// Test different ways errors can be compared
	baseError := errors.New("base error")
	exemptError := errors.New("exempt error")

	testCases := []struct {
		name        string
		returnError error
		exemptError error
		shouldRetry bool
	}{
		{
			name:        "exact same error instance",
			returnError: exemptError,
			exemptError: exemptError,
			shouldRetry: false,
		},
		{
			name:        "different error instances with same message",
			returnError: errors.New("same message"),
			exemptError: errors.New("same message"),
			shouldRetry: true, // errors.Is uses == comparison, not message comparison
		},
		{
			name:        "wrapped exempt error",
			returnError: fmt.Errorf("wrapped: %w", exemptError),
			exemptError: exemptError,
			shouldRetry: false,
		},
		{
			name:        "completely different error",
			returnError: baseError,
			exemptError: exemptError,
			shouldRetry: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.shouldRetry && testing.Short() {
				t.Skip("Skipping retry test in short mode due to timeout")
			}

			attempts := 0

			err := Retry(func() error {
				attempts++
				return tc.returnError
			}, tc.exemptError)

			assert.Error(t, err)
			if tc.shouldRetry {
				assert.Equal(t, RETRY_LIMIT, attempts)
			} else {
				assert.Equal(t, 1, attempts)
			}
		})
	}
}

func TestRetryRuntimeCaller(t *testing.T) {
	// Test that runtime.Caller information is captured
	// This is mainly for coverage since we can't easily verify the log output
	attempts := 0

	err := Retry(func() error {
		attempts++
		if attempts < 2 {
			return errors.New("failure for caller test")
		}
		return nil
	}, nil)

	assert.NoError(t, err)
	assert.Equal(t, 2, attempts)
}
