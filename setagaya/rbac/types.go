package rbac

import (
	"time"
)

// Permission represents a specific permission on a resource
type Permission struct {
	Resource string   `json:"resource" db:"resource"`       // Resource type (project, collection, plan, etc.)
	Actions  []string `json:"actions" db:"actions"`         // Allowed actions (create, read, update, delete)
	Scope    string   `json:"scope" db:"scope"`             // Scope (global, tenant, project, resource)
	Filter   string   `json:"filter,omitempty" db:"filter"` // Additional filtering conditions
}

// Role represents a user role with permissions and hierarchy
type Role struct {
	ID             int64        `json:"id" db:"id"`
	Name           string       `json:"name" db:"name"`
	DisplayName    string       `json:"display_name" db:"display_name"`
	Description    string       `json:"description" db:"description"`
	ParentRoleID   *int64       `json:"parent_role_id,omitempty" db:"parent_role_id"`
	IsSystemRole   bool         `json:"is_system_role" db:"is_system_role"`
	IsTenantScoped bool         `json:"is_tenant_scoped" db:"is_tenant_scoped"`
	Permissions    []Permission `json:"permissions" db:"permissions"`
	CreatedAt      time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at" db:"updated_at"`
}

// Tenant represents a tenant organization in the multi-tenant system
type Tenant struct {
	ID              int64                  `json:"id" db:"id"`
	Name            string                 `json:"name" db:"name"`
	DisplayName     string                 `json:"display_name" db:"display_name"`
	Description     string                 `json:"description" db:"description"`
	OktaGroupPrefix string                 `json:"okta_group_prefix" db:"okta_group_prefix"`
	Status          string                 `json:"status" db:"status"` // ACTIVE, SUSPENDED, DELETED
	QuotaConfig     map[string]interface{} `json:"quota_config" db:"quota_config"`
	BillingConfig   map[string]interface{} `json:"billing_config" db:"billing_config"`
	Metadata        map[string]interface{} `json:"metadata" db:"metadata"`
	CreatedAt       time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at" db:"updated_at"`
}

// UserRole represents a user's role assignment
type UserRole struct {
	ID        int64      `json:"id" db:"id"`
	UserID    string     `json:"user_id" db:"user_id"`               // Okta User ID
	UserEmail string     `json:"user_email" db:"user_email"`         // User email for display
	RoleID    int64      `json:"role_id" db:"role_id"`               // Reference to Role
	TenantID  *int64     `json:"tenant_id,omitempty" db:"tenant_id"` // NULL for global roles
	GrantedAt time.Time  `json:"granted_at" db:"granted_at"`
	GrantedBy string     `json:"granted_by" db:"granted_by"`           // Who granted this role
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"` // NULL for permanent
	IsActive  bool       `json:"is_active" db:"is_active"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`

	// Populated via joins
	Role   *Role   `json:"role,omitempty"`
	Tenant *Tenant `json:"tenant,omitempty"`
}

// SimpleUserContext represents the basic authenticated user's context for integration
type SimpleUserContext struct {
	UserID   string   `json:"user_id"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	TenantID *int64   `json:"tenant_id,omitempty"`
}

// UserContext represents the complete user authorization context
type UserContext struct {
	UserID              string                  `json:"user_id"`
	Email               string                  `json:"email"`
	Name                string                  `json:"name"`
	SessionID           string                  `json:"session_id"`
	GlobalRoles         []Role                  `json:"global_roles"`         // Roles not scoped to tenant
	TenantAccess        map[int64][]Role        `json:"tenant_access"`        // Tenant -> Roles mapping
	IsServiceProvider   bool                    `json:"is_service_provider"`  // Quick check for SP access
	ComputedPermissions map[string][]Permission `json:"computed_permissions"` // Cached permissions
	LastUpdated         time.Time               `json:"last_updated"`
}

// AuthorizationRequest represents a permission check request
type AuthorizationRequest struct {
	UserContext       *UserContext           `json:"user_context"`
	Action            string                 `json:"action"`        // create, read, update, delete
	ResourceType      string                 `json:"resource_type"` // project, collection, plan, etc.
	ResourceID        string                 `json:"resource_id,omitempty"`
	TenantID          *int64                 `json:"tenant_id,omitempty"`
	AdditionalContext map[string]interface{} `json:"additional_context,omitempty"`
}

// AuthorizationResult represents the result of a permission check
type AuthorizationResult struct {
	Allowed     bool      `json:"allowed"`
	Reason      string    `json:"reason"`
	AppliedRule string    `json:"applied_rule,omitempty"` // Which rule granted/denied access
	Timestamp   time.Time `json:"timestamp"`
}

// AuditLogEntry represents an audit log entry
type AuditLogEntry struct {
	ID             int64                  `json:"id" db:"id"`
	UserID         string                 `json:"user_id" db:"user_id"`
	UserEmail      string                 `json:"user_email" db:"user_email"`
	SessionID      string                 `json:"session_id" db:"session_id"`
	Action         string                 `json:"action" db:"action"`
	ResourceType   string                 `json:"resource_type" db:"resource_type"`
	ResourceID     string                 `json:"resource_id" db:"resource_id"`
	TenantID       *int64                 `json:"tenant_id,omitempty" db:"tenant_id"`
	Result         string                 `json:"result" db:"result"` // ALLOWED, DENIED
	Reason         string                 `json:"reason" db:"reason"`
	RequestDetails map[string]interface{} `json:"request_details" db:"request_details"`
	IPAddress      string                 `json:"ip_address" db:"ip_address"`
	UserAgent      string                 `json:"user_agent" db:"user_agent"`
	Timestamp      time.Time              `json:"timestamp" db:"timestamp"`
}

// TenantUserAssignment represents a user's assignment to a tenant with a role
type TenantUserAssignment struct {
	UserID     string    `json:"user_id"`
	UserEmail  string    `json:"user_email"`
	RoleName   string    `json:"role_name"`
	AssignedAt time.Time `json:"assigned_at"`
	AssignedBy string    `json:"assigned_by"`
}

// PermissionCache represents cached permission data
type PermissionCache struct {
	ID           int64                  `json:"id" db:"id"`
	UserID       string                 `json:"user_id" db:"user_id"`
	TenantID     *int64                 `json:"tenant_id,omitempty" db:"tenant_id"`
	ResourceType string                 `json:"resource_type" db:"resource_type"`
	ResourceID   string                 `json:"resource_id" db:"resource_id"`
	Permissions  map[string]interface{} `json:"permissions" db:"permissions"`
	ComputedAt   time.Time              `json:"computed_at" db:"computed_at"`
	ExpiresAt    time.Time              `json:"expires_at" db:"expires_at"`
}

// Standard role names (constants for consistency)
const (
	RoleServiceProviderAdmin   = "service_provider_admin"
	RoleServiceProviderSupport = "service_provider_support"
	RolePJMLoadTest            = "pjm_loadtest"
	RoleTenantAdmin            = "tenant_admin"
	RoleTenantEditor           = "tenant_editor"
	RoleTenantViewer           = "tenant_viewer"
)

// Tenant statuses
const (
	TenantStatusActive    = "ACTIVE"
	TenantStatusSuspended = "SUSPENDED"
	TenantStatusDeleted   = "DELETED"
)

// Resource types
const (
	ResourceTypeTenant     = "tenant"
	ResourceTypeProject    = "project"
	ResourceTypeCollection = "collection"
	ResourceTypePlan       = "plan"
	ResourceTypeExecution  = "execution"
	ResourceTypeSystem     = "system"
)

// Actions
const (
	ActionCreate = "create"
	ActionRead   = "read"
	ActionUpdate = "update"
	ActionDelete = "delete"
	ActionAdmin  = "admin"
	ActionList   = "list"
)

// Permission scopes
const (
	ScopeGlobal   = "global"
	ScopeTenant   = "tenant"
	ScopeProject  = "project"
	ScopeResource = "resource"
)

// Audit results
const (
	AuditResultAllowed = "ALLOWED"
	AuditResultDenied  = "DENIED"
)

// HasRole checks if user context has a specific role
func (uc *UserContext) HasRole(roleName string) bool {
	// Check global roles
	for _, role := range uc.GlobalRoles {
		if role.Name == roleName {
			return true
		}
	}

	// Check tenant roles
	for _, roles := range uc.TenantAccess {
		for _, role := range roles {
			if role.Name == roleName {
				return true
			}
		}
	}

	return false
}

// HasTenantRole checks if user has a specific role in a specific tenant
func (uc *UserContext) HasTenantRole(tenantID int64, roleName string) bool {
	if roles, exists := uc.TenantAccess[tenantID]; exists {
		for _, role := range roles {
			if role.Name == roleName {
				return true
			}
		}
	}
	return false
}

// HasTenantAccess checks if user has any access to a specific tenant
func (uc *UserContext) HasTenantAccess(tenantID int64) bool {
	// Service providers have access to all tenants
	if uc.IsServiceProvider {
		return true
	}

	// Check if user has any roles in this tenant
	_, exists := uc.TenantAccess[tenantID]
	return exists
}

// HasGlobalRole checks if user has a specific global role
func (uc *UserContext) HasGlobalRole(roleName string) bool {
	for _, role := range uc.GlobalRoles {
		if role.Name == roleName {
			return true
		}
	}
	return false
}

// IsRoleActive checks if a user role assignment is currently active
func (ur *UserRole) IsRoleActive() bool {
	if !ur.IsActive {
		return false
	}

	if ur.ExpiresAt != nil && ur.ExpiresAt.Before(time.Now()) {
		return false
	}

	return true
}

// IsExpired checks if a permission cache entry has expired
func (pc *PermissionCache) IsExpired() bool {
	return time.Now().After(pc.ExpiresAt)
}

// Validate checks if a tenant has valid configuration
func (t *Tenant) Validate() error {
	if t.Name == "" {
		return NewValidationError("tenant name is required")
	}

	if t.DisplayName == "" {
		return NewValidationError("tenant display name is required")
	}

	if t.OktaGroupPrefix == "" {
		return NewValidationError("okta group prefix is required")
	}

	// Validate name format
	if !isValidTenantName(t.Name) {
		return NewValidationError("tenant name must contain only lowercase letters, numbers, and hyphens")
	}

	// Validate Okta group prefix format
	if !isValidOktaGroupPrefix(t.OktaGroupPrefix) {
		return NewValidationError("okta group prefix must start with 'setagaya-' and contain only lowercase letters, numbers, and hyphens")
	}

	return nil
}

// Helper functions for validation
func isValidTenantName(name string) bool {
	// Implement regex validation for tenant names
	// Should match: ^[a-z0-9-]+$ with minimum length 3
	if len(name) < 3 {
		return false
	}

	for _, char := range name {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}

	return true
}

func isValidOktaGroupPrefix(prefix string) bool {
	// Should match: ^setagaya-[a-z0-9-]+$
	if len(prefix) < 10 { // "setagaya-" + at least 1 char
		return false
	}

	if prefix[:9] != "setagaya-" {
		return false
	}

	suffix := prefix[9:]
	return isValidTenantName(suffix)
}
