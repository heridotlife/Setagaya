package rbac

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// RBACEngine defines the core authorization engine interface
type RBACEngine interface {
	// User and Role Management
	CreateRole(ctx context.Context, role *Role) error
	UpdateRole(ctx context.Context, roleID int64, updates *Role) error
	DeleteRole(ctx context.Context, roleID int64) error
	GetRole(ctx context.Context, roleID int64) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	ListRoles(ctx context.Context, tenantScoped bool) ([]Role, error)

	// User Role Assignment
	AssignUserRole(ctx context.Context, userID string, roleID int64, tenantID *int64, grantedBy string) error
	RevokeUserRole(ctx context.Context, userID string, roleID int64, tenantID *int64) error
	GetUserRoles(ctx context.Context, userID string) ([]UserRole, error)
	GetUsersWithRole(ctx context.Context, roleID int64, tenantID *int64) ([]UserRole, error)

	// Tenant Management
	CreateTenant(ctx context.Context, tenant *Tenant) (*Tenant, error)
	UpdateTenant(ctx context.Context, updates *Tenant) (*Tenant, error)
	GetTenant(ctx context.Context, tenantID int64) (*Tenant, error)
	GetTenantByName(ctx context.Context, name string) (*Tenant, error)
	ListTenants(ctx context.Context, status string) ([]Tenant, error)
	DeleteTenant(ctx context.Context, tenantID int64) error
	GetAccessibleTenants(ctx context.Context, userContext *UserContext) ([]*Tenant, error)

	// Authorization
	CheckPermission(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResult, error)
	HasPermission(ctx context.Context, userContext *UserContext, action, resourceType string, tenantID *int64, resourceID string) bool
	GetUserContext(ctx context.Context, userID string) (*UserContext, error)
	RefreshUserContext(ctx context.Context, userID string) (*UserContext, error)
	ClearUserCache(ctx context.Context, userID string) error

	// Audit
	LogAccess(ctx context.Context, userContext *UserContext, action string, resource string, result string, details map[string]interface{}) error
	GetAuditLogs(ctx context.Context, filters map[string]interface{}, limit int, offset int) ([]AuditLogEntry, error)
}

// ResourceAuthorizer defines resource-specific authorization logic
type ResourceAuthorizer interface {
	CanCreate(ctx context.Context, userContext *UserContext, tenantID *int64) bool
	CanRead(ctx context.Context, userContext *UserContext, resourceID string) bool
	CanUpdate(ctx context.Context, userContext *UserContext, resourceID string) bool
	CanDelete(ctx context.Context, userContext *UserContext, resourceID string) bool
	CanList(ctx context.Context, userContext *UserContext, tenantID *int64) bool
}

// TenantRepository defines tenant data access operations
type TenantRepository interface {
	Create(ctx context.Context, tenant *Tenant) error
	GetByID(ctx context.Context, id int64) (*Tenant, error)
	GetByName(ctx context.Context, name string) (*Tenant, error)
	Update(ctx context.Context, id int64, updates *Tenant) error
	Delete(ctx context.Context, id int64) error
	List(ctx context.Context, status string, limit, offset int) ([]Tenant, error)
	Count(ctx context.Context, status string) (int64, error)
}

// RoleRepository defines role data access operations
type RoleRepository interface {
	Create(ctx context.Context, role *Role) error
	GetByID(ctx context.Context, id int64) (*Role, error)
	GetByName(ctx context.Context, name string) (*Role, error)
	Update(ctx context.Context, id int64, updates *Role) error
	Delete(ctx context.Context, id int64) error
	List(ctx context.Context, tenantScoped bool, limit, offset int) ([]Role, error)
	ListSystemRoles(ctx context.Context) ([]Role, error)
}

// UserRoleRepository defines user role assignment data access operations
type UserRoleRepository interface {
	Assign(ctx context.Context, userRole *UserRole) error
	Revoke(ctx context.Context, userID string, roleID int64, tenantID *int64) error
	GetUserRoles(ctx context.Context, userID string) ([]UserRole, error)
	GetUsersWithRole(ctx context.Context, roleID int64, tenantID *int64) ([]UserRole, error)
	GetTenantUsers(ctx context.Context, tenantID int64, roleFilter string) ([]UserRole, error)
	IsAssigned(ctx context.Context, userID string, roleID int64, tenantID *int64) (bool, error)
}

// AuditRepository defines audit log data access operations
type AuditRepository interface {
	Log(ctx context.Context, entry *AuditLogEntry) error
	GetLogs(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]AuditLogEntry, error)
	CountLogs(ctx context.Context, filters map[string]interface{}) (int64, error)
	Cleanup(ctx context.Context, retentionPeriod int) error
}

// PermissionCacheRepository defines permission cache data access operations
type PermissionCacheRepository interface {
	Get(ctx context.Context, userID string, tenantID *int64, resourceType, resourceID string) (*PermissionCache, error)
	Set(ctx context.Context, cache *PermissionCache) error
	Delete(ctx context.Context, userID string, tenantID *int64, resourceType, resourceID string) error
	DeleteUserCache(ctx context.Context, userID string) error
	DeleteTenantCache(ctx context.Context, tenantID int64) error
	Cleanup(ctx context.Context) error
}

// OktaProvider defines Okta integration interface
type OktaProvider interface {
	ValidateToken(ctx context.Context, token string) (*OktaClaims, error)
	GetUserGroups(ctx context.Context, userID string) ([]string, error)
	GetGroupMembers(ctx context.Context, groupID string) ([]string, error)
	CreateUser(ctx context.Context, user *OktaUser) error
	UpdateUser(ctx context.Context, userID string, updates *OktaUser) error
	GetUser(ctx context.Context, userID string) (*OktaUser, error)
}

// OktaClaims represents JWT token claims from Okta
type OktaClaims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
	SetagayaRoles     []string `json:"setagaya_roles"`
	TenantMemberships []string `json:"tenant_memberships"`
	ServiceProvider   bool     `json:"service_provider"`
	IssuedAt          int64    `json:"iat"`
	ExpiresAt         int64    `json:"exp"`
	Audience          string   `json:"aud"`
	Issuer            string   `json:"iss"`
}

// GetExpirationTime implements jwt.Claims interface
func (c *OktaClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

// GetIssuedAt implements jwt.Claims interface
func (c *OktaClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

// GetNotBefore implements jwt.Claims interface
func (c *OktaClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

// GetIssuer implements jwt.Claims interface
func (c *OktaClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetSubject implements jwt.Claims interface
func (c *OktaClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

// GetAudience implements jwt.Claims interface
func (c *OktaClaims) GetAudience() (jwt.ClaimStrings, error) {
	if c.Audience == "" {
		return nil, nil
	}
	return jwt.ClaimStrings{c.Audience}, nil
}

// OktaUser represents a user in Okta
type OktaUser struct {
	ID     string   `json:"id"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Status string   `json:"status"`
	Groups []string `json:"groups"`
}

// Config represents RBAC configuration
type Config struct {
	DatabaseURL        string      `json:"database_url"`
	EnableRBAC         bool        `json:"enable_rbac"`
	DefaultTenantRole  string      `json:"default_tenant_role"`
	SessionTimeoutMins int         `json:"session_timeout_minutes"`
	AuditEnabled       bool        `json:"audit_enabled"`
	PermissionCacheTTL int         `json:"permission_cache_ttl_minutes"`
	OktaConfig         *OktaConfig `json:"okta"`
}

// OktaConfig represents Okta integration configuration
type OktaConfig struct {
	Domain       string   `json:"domain"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURI  string   `json:"redirect_uri"`
	Scopes       []string `json:"scopes"`
	GroupClaims  string   `json:"group_claims"`
}

// PermissionChecker defines the core permission checking interface
type PermissionChecker interface {
	HasPermission(ctx context.Context, userContext *UserContext, action, resourceType string, tenantID *int64, resourceID string) bool
	HasGlobalPermission(ctx context.Context, userContext *UserContext, action, resourceType string) bool
	HasTenantPermission(ctx context.Context, userContext *UserContext, action, resourceType string, tenantID int64) bool
	GetResourcePermissions(ctx context.Context, userContext *UserContext, resourceType string, tenantID *int64) ([]Permission, error)
}

// TenantScopeFilter defines interface for filtering queries by tenant scope
type TenantScopeFilter interface {
	GetUserTenants(ctx context.Context, userContext *UserContext) ([]int64, error)
	FilterByTenantAccess(ctx context.Context, userContext *UserContext, query string, args []interface{}) (string, []interface{}, error)
	ValidateTenantAccess(ctx context.Context, userContext *UserContext, tenantID int64) error
}

// RateLimiter defines interface for API rate limiting
type RateLimiter interface {
	CheckLimit(ctx context.Context, userID string, action string) (bool, error)
	GetLimitInfo(ctx context.Context, userID string) (*RateLimitInfo, error)
}

// RateLimitInfo represents rate limiting information
type RateLimitInfo struct {
	Limit     int   `json:"limit"`
	Remaining int   `json:"remaining"`
	ResetTime int64 `json:"reset_time"`
}

// NotificationService defines interface for sending notifications
type NotificationService interface {
	SendRoleAssignmentNotification(ctx context.Context, userEmail, roleName, tenantName string) error
	SendPermissionDeniedAlert(ctx context.Context, userID, action, resource string) error
	SendSecurityAlert(ctx context.Context, userID, action, reason string) error
}

// MetricsCollector defines interface for collecting RBAC metrics
type MetricsCollector interface {
	IncrementAuthorizationChecks(result string)
	IncrementRoleAssignments(roleName string)
	RecordAuthorizationLatency(duration float64)
	RecordPermissionCacheHits(hitType string)
	IncrementAuditLogEntries()
}
