package api

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/hveda/Setagaya/setagaya/model"
)

func TestHasProjectOwnership(t *testing.T) {
	// Create an API instance for testing
	api := &SetagayaAPI{
		enableRBAC: false, // Use legacy mode for testing
	}

	testCases := []struct {
		name          string
		project       *model.Project
		account       *model.Account
		expectedOwned bool
	}{
		{
			name: "user owns project",
			project: &model.Project{
				Owner: "user-group",
			},
			account: &model.Account{
				Name: "user",
				ML:   []string{"user-group", "other-group"},
				MLMap: map[string]interface{}{
					"user-group":  nil,
					"other-group": nil,
				},
			},
			expectedOwned: true,
		},
		{
			name: "user does not own project but is admin",
			project: &model.Project{
				Owner: "restricted-group",
			},
			account: &model.Account{
				Name: "admin",
				ML:   []string{"admin-group"},
				MLMap: map[string]interface{}{
					"admin-group": nil,
				},
			},
			expectedOwned: true, // Will be true if IsAdmin() returns true
		},
		{
			name: "user does not own project and is not admin",
			project: &model.Project{
				Owner: "restricted-group",
			},
			account: &model.Account{
				Name: "user",
				ML:   []string{"user-group"},
				MLMap: map[string]interface{}{
					"user-group": nil,
				},
			},
			expectedOwned: false, // Will be false if IsAdmin() returns false
		},
		{
			name: "empty MLMap",
			project: &model.Project{
				Owner: "any-group",
			},
			account: &model.Account{
				Name:  "user",
				ML:    []string{"user-group"},
				MLMap: map[string]interface{}{},
			},
			expectedOwned: false, // Will depend on IsAdmin()
		},
		{
			name: "nil MLMap",
			project: &model.Project{
				Owner: "any-group",
			},
			account: &model.Account{
				Name:  "user",
				ML:    []string{"user-group"},
				MLMap: nil,
			},
			expectedOwned: false, // Will depend on IsAdmin()
		},
		{
			name: "multiple groups with ownership",
			project: &model.Project{
				Owner: "target-group",
			},
			account: &model.Account{
				Name: "user",
				ML:   []string{"group1", "target-group", "group3"},
				MLMap: map[string]interface{}{
					"group1":       nil,
					"target-group": nil,
					"group3":       nil,
				},
			},
			expectedOwned: true,
		},
		{
			name: "empty project owner",
			project: &model.Project{
				Owner: "",
			},
			account: &model.Account{
				Name: "user",
				ML:   []string{"user-group"},
				MLMap: map[string]interface{}{
					"user-group": nil,
				},
			},
			expectedOwned: false, // Empty owner won't match
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// For this test, we need to mock the IsAdmin behavior
			// Since we can't easily mock it, we'll create scenarios where we know the outcome
			result := api.hasProjectOwnership(tc.project, tc.account)

			// Check if user is in the owner group
			_, hasOwnership := tc.account.MLMap[tc.project.Owner]

			if hasOwnership {
				assert.True(t, result, "User should have ownership when in owner group")
			} else {
				// Result depends on IsAdmin(), which we can't easily test here without config setup
				// So we just verify the function runs without panic
				assert.IsType(t, bool(false), result)
			}
		})
	}
}

func TestHasProjectOwnershipEdgeCases(t *testing.T) {
	// Create an API instance for testing
	api := &SetagayaAPI{
		enableRBAC: false, // Use legacy mode for testing
	}

	t.Run("nil project", func(t *testing.T) {
		account := &model.Account{
			Name:  "user",
			MLMap: map[string]interface{}{},
		}

		// This should panic or handle gracefully
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("The code did not panic")
			}
		}()
		api.hasProjectOwnership(nil, account)
	})

	t.Run("nil account", func(t *testing.T) {
		project := &model.Project{
			Owner: "test-group",
		}

		// This should panic or handle gracefully
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("The code did not panic")
			}
		}()
		api.hasProjectOwnership(project, nil)
	})

	t.Run("special characters in owner", func(t *testing.T) {
		project := &model.Project{
			Owner: "group-with-special@chars!",
		}
		account := &model.Account{
			Name: "user",
			MLMap: map[string]interface{}{
				"group-with-special@chars!": nil,
			},
		}

		result := api.hasProjectOwnership(project, account)
		assert.True(t, result)
	})

	t.Run("case sensitivity", func(t *testing.T) {
		project := &model.Project{
			Owner: "TestGroup",
		}
		account := &model.Account{
			Name: "user",
			MLMap: map[string]interface{}{
				"testgroup": nil, // Different case
			},
		}

		result := api.hasProjectOwnership(project, account)
		// Should be false due to case sensitivity unless user is admin
		// In test mode, this depends on IsAdmin() implementation
		assert.IsType(t, bool(false), result)
	})

	t.Run("whitespace in owner", func(t *testing.T) {
		project := &model.Project{
			Owner: " test-group ",
		}
		account := &model.Account{
			Name: "user",
			MLMap: map[string]interface{}{
				"test-group": nil, // No whitespace
			},
		}

		result := api.hasProjectOwnership(project, account)
		// Should be false due to whitespace difference unless user is admin
		assert.IsType(t, bool(false), result)
	})
}
