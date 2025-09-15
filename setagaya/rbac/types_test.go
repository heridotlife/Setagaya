package rbac

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenant_Validate(t *testing.T) {
	tests := []struct {
		name    string
		tenant  *Tenant
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid tenant",
			tenant: &Tenant{
				Name:            "acme-corp",
				DisplayName:     "ACME Corporation",
				OktaGroupPrefix: "setagaya-acme-corp",
				Status:          TenantStatusActive,
			},
			wantErr: false,
		},
		{
			name: "empty name",
			tenant: &Tenant{
				DisplayName:     "ACME Corporation",
				OktaGroupPrefix: "setagaya-acme-corp",
			},
			wantErr: true,
			errMsg:  "tenant name is required",
		},
		{
			name: "empty display name",
			tenant: &Tenant{
				Name:            "acme-corp",
				OktaGroupPrefix: "setagaya-acme-corp",
			},
			wantErr: true,
			errMsg:  "tenant display name is required",
		},
		{
			name: "empty okta group prefix",
			tenant: &Tenant{
				Name:        "acme-corp",
				DisplayName: "ACME Corporation",
			},
			wantErr: true,
			errMsg:  "okta group prefix is required",
		},
		{
			name: "invalid name format - uppercase",
			tenant: &Tenant{
				Name:            "ACME-Corp",
				DisplayName:     "ACME Corporation",
				OktaGroupPrefix: "setagaya-acme-corp",
			},
			wantErr: true,
			errMsg:  "tenant name must contain only lowercase letters, numbers, and hyphens",
		},
		{
			name: "invalid name format - too short",
			tenant: &Tenant{
				Name:            "ab",
				DisplayName:     "ACME Corporation",
				OktaGroupPrefix: "setagaya-ab",
			},
			wantErr: true,
			errMsg:  "tenant name must contain only lowercase letters, numbers, and hyphens",
		},
		{
			name: "invalid okta group prefix - wrong prefix",
			tenant: &Tenant{
				Name:            "acme-corp",
				DisplayName:     "ACME Corporation",
				OktaGroupPrefix: "wrong-acme-corp",
			},
			wantErr: true,
			errMsg:  "okta group prefix must start with 'setagaya-'",
		},
		{
			name: "valid name with numbers and hyphens",
			tenant: &Tenant{
				Name:            "acme-corp-123",
				DisplayName:     "ACME Corporation 123",
				OktaGroupPrefix: "setagaya-acme-corp-123",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tenant.Validate()

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.True(t, IsValidationError(err))
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserContext_HasRole(t *testing.T) {
	userContext := &UserContext{
		UserID: "user123",
		GlobalRoles: []Role{
			{Name: RoleServiceProviderAdmin},
		},
		TenantAccess: map[int64][]Role{
			1: {{Name: RoleTenantAdmin}},
			2: {{Name: RoleTenantEditor}},
		},
	}

	tests := []struct {
		name     string
		roleName string
		expected bool
	}{
		{
			name:     "has global role",
			roleName: RoleServiceProviderAdmin,
			expected: true,
		},
		{
			name:     "has tenant role",
			roleName: RoleTenantAdmin,
			expected: true,
		},
		{
			name:     "does not have role",
			roleName: RoleTenantViewer,
			expected: false,
		},
		{
			name:     "empty role name",
			roleName: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := userContext.HasRole(tt.roleName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUserContext_HasTenantRole(t *testing.T) {
	userContext := &UserContext{
		UserID: "user123",
		TenantAccess: map[int64][]Role{
			1: {{Name: RoleTenantAdmin}},
			2: {{Name: RoleTenantEditor}, {Name: RoleTenantViewer}},
		},
	}

	tests := []struct {
		name     string
		tenantID int64
		roleName string
		expected bool
	}{
		{
			name:     "has admin role in tenant 1",
			tenantID: 1,
			roleName: RoleTenantAdmin,
			expected: true,
		},
		{
			name:     "has editor role in tenant 2",
			tenantID: 2,
			roleName: RoleTenantEditor,
			expected: true,
		},
		{
			name:     "has viewer role in tenant 2",
			tenantID: 2,
			roleName: RoleTenantViewer,
			expected: true,
		},
		{
			name:     "does not have admin role in tenant 2",
			tenantID: 2,
			roleName: RoleTenantAdmin,
			expected: false,
		},
		{
			name:     "no access to tenant 3",
			tenantID: 3,
			roleName: RoleTenantViewer,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := userContext.HasTenantRole(tt.tenantID, tt.roleName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUserContext_HasTenantAccess(t *testing.T) {
	serviceProviderContext := &UserContext{
		UserID:            "sp-admin",
		IsServiceProvider: true,
		GlobalRoles:       []Role{{Name: RoleServiceProviderAdmin}},
	}

	tenantUserContext := &UserContext{
		UserID: "tenant-user",
		TenantAccess: map[int64][]Role{
			1: {{Name: RoleTenantViewer}},
		},
	}

	tests := []struct {
		name        string
		userContext *UserContext
		tenantID    int64
		expected    bool
	}{
		{
			name:        "service provider has access to any tenant",
			userContext: serviceProviderContext,
			tenantID:    999,
			expected:    true,
		},
		{
			name:        "tenant user has access to their tenant",
			userContext: tenantUserContext,
			tenantID:    1,
			expected:    true,
		},
		{
			name:        "tenant user does not have access to other tenant",
			userContext: tenantUserContext,
			tenantID:    2,
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.userContext.HasTenantAccess(tt.tenantID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUserContext_HasGlobalRole(t *testing.T) {
	userContext := &UserContext{
		UserID: "user123",
		GlobalRoles: []Role{
			{Name: RoleServiceProviderAdmin},
			{Name: RoleServiceProviderSupport},
		},
		TenantAccess: map[int64][]Role{
			1: {{Name: RoleTenantAdmin}},
		},
	}

	tests := []struct {
		name     string
		roleName string
		expected bool
	}{
		{
			name:     "has global admin role",
			roleName: RoleServiceProviderAdmin,
			expected: true,
		},
		{
			name:     "has global support role",
			roleName: RoleServiceProviderSupport,
			expected: true,
		},
		{
			name:     "does not have tenant role as global",
			roleName: RoleTenantAdmin,
			expected: false,
		},
		{
			name:     "does not have non-existent role",
			roleName: RoleTenantViewer,
			expected: false,
		},
		{
			name:     "empty role name",
			roleName: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := userContext.HasGlobalRole(tt.roleName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUserRole_IsActive(t *testing.T) {
	now := time.Now()
	future := now.Add(24 * time.Hour)
	past := now.Add(-24 * time.Hour)

	tests := []struct {
		name     string
		userRole *UserRole
		expected bool
	}{
		{
			name: "active role without expiration",
			userRole: &UserRole{
				IsActive:  true,
				ExpiresAt: nil,
			},
			expected: true,
		},
		{
			name: "active role with future expiration",
			userRole: &UserRole{
				IsActive:  true,
				ExpiresAt: &future,
			},
			expected: true,
		},
		{
			name: "inactive role",
			userRole: &UserRole{
				IsActive:  false,
				ExpiresAt: nil,
			},
			expected: false,
		},
		{
			name: "expired role",
			userRole: &UserRole{
				IsActive:  true,
				ExpiresAt: &past,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.userRole.IsRoleActive()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPermissionCache_IsExpired(t *testing.T) {
	now := time.Now()
	future := now.Add(1 * time.Hour)
	past := now.Add(-1 * time.Hour)

	tests := []struct {
		name     string
		cache    *PermissionCache
		expected bool
	}{
		{
			name: "not expired cache",
			cache: &PermissionCache{
				ExpiresAt: future,
			},
			expected: false,
		},
		{
			name: "expired cache",
			cache: &PermissionCache{
				ExpiresAt: past,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.cache.IsExpired()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidTenantName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid name with letters",
			input:    "acme",
			expected: true,
		},
		{
			name:     "valid name with letters and numbers",
			input:    "acme123",
			expected: true,
		},
		{
			name:     "valid name with hyphens",
			input:    "acme-corp",
			expected: true,
		},
		{
			name:     "valid complex name",
			input:    "acme-corp-123",
			expected: true,
		},
		{
			name:     "too short",
			input:    "ab",
			expected: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "contains uppercase",
			input:    "Acme",
			expected: false,
		},
		{
			name:     "contains special characters",
			input:    "acme_corp",
			expected: false,
		},
		{
			name:     "contains spaces",
			input:    "acme corp",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidTenantName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidOktaGroupPrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid prefix",
			input:    "setagaya-acme",
			expected: true,
		},
		{
			name:     "valid prefix with numbers",
			input:    "setagaya-acme123",
			expected: true,
		},
		{
			name:     "valid prefix with hyphens",
			input:    "setagaya-acme-corp",
			expected: true,
		},
		{
			name:     "wrong prefix",
			input:    "wrong-acme",
			expected: false,
		},
		{
			name:     "too short",
			input:    "setagaya-",
			expected: false,
		},
		{
			name:     "missing prefix",
			input:    "acme-corp",
			expected: false,
		},
		{
			name:     "invalid suffix",
			input:    "setagaya-Acme",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidOktaGroupPrefix(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test constants and role definitions
func TestRoleConstants(t *testing.T) {
	// Verify all role constants are properly defined
	expectedRoles := []string{
		RoleServiceProviderAdmin,
		RoleServiceProviderSupport,
		RolePJMLoadTest,
		RoleTenantAdmin,
		RoleTenantEditor,
		RoleTenantViewer,
	}

	for _, role := range expectedRoles {
		assert.NotEmpty(t, role, "Role constant should not be empty")
		assert.True(t, isValidRoleName(role), "Role name should follow naming convention")
	}
}

func TestTenantStatusConstants(t *testing.T) {
	// Verify tenant status constants
	statuses := []string{TenantStatusActive, TenantStatusSuspended, TenantStatusDeleted}

	for _, status := range statuses {
		assert.NotEmpty(t, status, "Status constant should not be empty")
	}
}

func TestResourceTypeConstants(t *testing.T) {
	// Verify resource type constants
	resourceTypes := []string{
		ResourceTypeTenant,
		ResourceTypeProject,
		ResourceTypeCollection,
		ResourceTypePlan,
		ResourceTypeExecution,
		ResourceTypeSystem,
	}

	for _, resourceType := range resourceTypes {
		assert.NotEmpty(t, resourceType, "Resource type constant should not be empty")
	}
}

// Helper function for role name validation
func isValidRoleName(name string) bool {
	if len(name) < 3 {
		return false
	}

	for _, char := range name {
		if (char < 'a' || char > 'z') && char != '_' {
			return false
		}
	}

	return true
}
