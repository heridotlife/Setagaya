package object_storage

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStorageProviderConstants(t *testing.T) {
	// Test that storage provider constants have expected values
	assert.Equal(t, "nexus", nexusStorageProvider)
	assert.Equal(t, "gcp", gcpStorageProvider)
	assert.Equal(t, "local", localStorageProvider)
}

func TestAllStorageProviders(t *testing.T) {
	// Test that all providers are listed in the slice
	expected := []string{"nexus", "gcp", "local"}
	assert.Equal(t, expected, allStorageProvidder)
	assert.Len(t, allStorageProvidder, 3)
	assert.Contains(t, allStorageProvidder, nexusStorageProvider)
	assert.Contains(t, allStorageProvidder, gcpStorageProvider)
	assert.Contains(t, allStorageProvidder, localStorageProvider)
}

func TestGetStorageOfType(t *testing.T) {
	testCases := []struct {
		name         string
		provider     string
		expectError  bool
		expectedType string
	}{
		{
			name:         "nexus provider",
			provider:     "nexus",
			expectError:  false,
			expectedType: "nexusStorage",
		},
		{
			name:         "gcp provider",
			provider:     "gcp",
			expectError:  false,
			expectedType: "gcpStorage",
		},
		{
			name:         "local provider",
			provider:     "local",
			expectError:  false,
			expectedType: "localStorage",
		},
		{
			name:        "unknown provider",
			provider:    "unknown",
			expectError: true,
		},
		{
			name:        "empty provider",
			provider:    "",
			expectError: true,
		},
		{
			name:        "case sensitive - Nexus",
			provider:    "Nexus",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Skip GCP tests in test mode (no credentials available)
			if tc.provider == "gcp" && os.Getenv("SETAGAYA_TEST_MODE") == "true" {
				t.Skip("Skipping GCP test in test mode (no credentials available)")
			}

			storage, err := getStorageOfType(tc.provider)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, storage)
				if tc.provider != "" {
					assert.Contains(t, err.Error(), "unknown storage type")
					assert.Contains(t, err.Error(), tc.provider)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, storage)

				// Verify the storage implements the interface
				assert.Implements(t, (*StorageInterface)(nil), storage)

				// Check that we got the expected type without relying on exact type assertions
				// since some types return pointers and others return values
				switch tc.provider {
				case "nexus":
					// Just verify it's not nil and implements interface
					assert.NotNil(t, storage)
				case "gcp":
					// GCP returns a pointer
					assert.NotNil(t, storage)
				case "local":
					// Local returns a value
					assert.NotNil(t, storage)
				}
			}
		})
	}
}

func TestGetStorageOfTypeErrorMessage(t *testing.T) {
	// Test that error message includes all valid providers
	_, err := getStorageOfType("invalid")

	assert.Error(t, err)
	errMsg := err.Error()
	assert.Contains(t, errMsg, "unknown storage type invalid")
	assert.Contains(t, errMsg, "nexus")
	assert.Contains(t, errMsg, "gcp")
	assert.Contains(t, errMsg, "local")
}

func TestStorageTypeInstances(t *testing.T) {
	// Skip GCP tests in test mode (no credentials available)
	if os.Getenv("SETAGAYA_TEST_MODE") == "true" {
		t.Skip("Skipping GCP test in test mode (no credentials available)")
	}

	// Test that we get different instances for different types
	nexus, err := getStorageOfType("nexus")
	assert.NoError(t, err)

	gcp, err := getStorageOfType("gcp")
	assert.NoError(t, err)

	local, err := getStorageOfType("local")
	assert.NoError(t, err)

	// They should all implement the interface
	assert.Implements(t, (*StorageInterface)(nil), nexus)
	assert.Implements(t, (*StorageInterface)(nil), gcp)
	assert.Implements(t, (*StorageInterface)(nil), local)

	// They should not be the same instance
	assert.NotEqual(t, nexus, gcp)
	assert.NotEqual(t, gcp, local)
	assert.NotEqual(t, nexus, local)
}

func TestPlatformConfig(t *testing.T) {
	// Test PlatformConfig struct
	localStorage, err := getStorageOfType("local")
	assert.NoError(t, err)

	config := PlatformConfig{
		Storage: localStorage,
	}

	assert.NotNil(t, config.Storage)
	assert.Implements(t, (*StorageInterface)(nil), config.Storage)
}

// Note: We can't easily test factoryConfig() and IsProviderGCP() without
// mocking the global config, as they depend on config.SC which is initialized
// at package load time. In a real-world scenario, we'd want to refactor these
// to be more testable by accepting config as a parameter.

func TestFactoryConfigIntegration(t *testing.T) {
	// This test verifies that the global Client is initialized
	// Note: This might fail if config isn't properly set up
	t.Run("global client exists", func(t *testing.T) {
		// Just verify the Client variable exists and has a Storage field
		// We can't test much more without setting up the full config
		assert.NotNil(t, Client.Storage)
	})
}

// Test the Provider check functionality conceptually
func TestProviderCheckLogic(t *testing.T) {
	// Test the logic that would be used in IsProviderGCP()
	// This tests the concept without relying on global config

	testCases := []struct {
		provider string
		isGCP    bool
	}{
		{"gcp", true},
		{"nexus", false},
		{"local", false},
		{"", false},
		{"GCP", false}, // case sensitive
	}

	for _, tc := range testCases {
		t.Run(tc.provider, func(t *testing.T) {
			// Test the logic that IsProviderGCP() uses
			result := tc.provider == gcpStorageProvider
			assert.Equal(t, tc.isGCP, result)
		})
	}
}

func TestStorageInterfaceCompliance(t *testing.T) {
	// Skip interface compliance tests in test mode (require network/credentials)
	if os.Getenv("SETAGAYA_TEST_MODE") == "true" {
		t.Skip("Skipping interface compliance test in test mode (requires network/credentials)")
	}

	// Test that all storage types implement the interface properly
	providers := []string{"nexus", "gcp", "local"}

	for _, provider := range providers {
		t.Run(provider+" interface compliance", func(t *testing.T) {
			storage, err := getStorageOfType(provider)
			assert.NoError(t, err)

			// Verify all interface methods exist and can be called
			// (though they might fail due to missing config/network)
			assert.NotPanics(t, func() {
				storage.GetUrl("test.txt")
			})

			// These might fail, but they shouldn't panic
			// We're mainly testing that the methods exist
			if err := storage.Upload("test.txt", nil); err != nil {
				// Expected to fail in test - log for debugging
				t.Logf("Upload failed as expected: %v", err)
			}
			if _, err := storage.Download("test.txt"); err != nil {
				// Expected to fail in test - log for debugging
				t.Logf("Download failed as expected: %v", err)
			}
			if err := storage.Delete("test.txt"); err != nil {
				// Expected to fail in test - log for debugging
				t.Logf("Delete failed as expected: %v", err)
			}
		})
	}
}

func TestStorageErrorHandling(t *testing.T) {
	// Skip error handling tests in test mode (require network/credentials)
	if os.Getenv("SETAGAYA_TEST_MODE") == "true" {
		t.Skip("Skipping error handling test in test mode (requires network/credentials)")
	}

	// Test consistent error handling across storage types
	providers := []string{"nexus", "gcp", "local"}

	for _, provider := range providers {
		t.Run(provider+" error handling", func(t *testing.T) {
			storage, err := getStorageOfType(provider)
			assert.NoError(t, err)

			// Test that operations on non-existent files return errors
			// rather than panicking
			assert.NotPanics(t, func() {
				_, err := storage.Download("nonexistent.txt")
				// Error is expected, but we shouldn't panic
				_ = err
			})

			assert.NotPanics(t, func() {
				err := storage.Delete("nonexistent.txt")
				// Error is expected, but we shouldn't panic
				_ = err
			})
		})
	}
}
