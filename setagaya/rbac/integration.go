package rbac

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/julienschmidt/httprouter"
)

// Integration provides the main RBAC integration for the API
type Integration struct {
	engine        RBACEngine
	config        *Config
	permissionTTL time.Duration
	enableAudit   bool
	defaultTenant *Tenant
	oktaProvider  *OktaAuthProvider
	jwtMiddleware *JWTMiddleware
	oidcHandler   *OIDCHandler
	sessionStore  SessionStore
	logger        Logger
}

// NewIntegration creates a new RBAC integration instance
func NewIntegration() (*Integration, error) {
	// Load configuration from global config
	rbacConfig := &Config{
		EnableRBAC:         true,
		DefaultTenantRole:  RoleTenantViewer,
		SessionTimeoutMins: 120,
		AuditEnabled:       true,
		PermissionCacheTTL: 30,
		OktaConfig: &OktaConfig{
			Domain:       "REPLACE_WITH_OKTA_DOMAIN",
			ClientID:     "REPLACE_WITH_CLIENT_ID",
			ClientSecret: "REPLACE_WITH_CLIENT_SECRET", // WARNING: Use environment variables in production
			RedirectURI:  "http://localhost:8080/api/auth/callback",
			Scopes:       []string{"openid", "profile", "email", "groups"},
			GroupClaims:  "groups",
		},
	}

	// Create logger
	logger := NewSimpleLogger("RBAC", true)

	// Create a basic in-memory implementation for now
	engine := &MemoryRBACEngine{
		roles:       make(map[int64]*Role),
		userRoles:   make(map[string][]UserRole),
		tenants:     make(map[int64]*Tenant),
		permissions: make(map[string]*PermissionCache),
		auditLogs:   make([]AuditLogEntry, 0),
		nextID:      1,
	}

	// Initialize with default roles and tenant
	if err := initializeDefaultData(engine); err != nil {
		return nil, NewConfigurationError("failed to initialize default RBAC data: " + err.Error())
	}

	// Create session store
	sessionStore := NewMemorySessionStore(logger)

	// Create Okta provider if configuration is available
	var oktaProvider *OktaAuthProvider
	var jwtMiddleware *JWTMiddleware
	var oidcHandler *OIDCHandler

	if rbacConfig.OktaConfig != nil {
		oktaProviderInstance, err := NewOktaAuthProvider(rbacConfig.OktaConfig, logger)
		if err != nil {
			logger.Warn("Failed to initialize Okta provider", map[string]interface{}{
				"error": err.Error(),
			})
		} else {
			oktaProvider = oktaProviderInstance
			jwtMiddleware = NewJWTMiddleware(oktaProvider, engine, logger)
			oidcHandler = NewOIDCHandler(oktaProvider, engine, logger, sessionStore, "http://localhost:8080")
			logger.Info("Okta integration initialized successfully", nil)
		}
	}

	integration := &Integration{
		engine:        engine,
		config:        rbacConfig,
		permissionTTL: time.Duration(rbacConfig.PermissionCacheTTL) * time.Minute,
		enableAudit:   rbacConfig.AuditEnabled,
		oktaProvider:  oktaProvider,
		jwtMiddleware: jwtMiddleware,
		oidcHandler:   oidcHandler,
		sessionStore:  sessionStore,
		logger:        logger,
	}

	return integration, nil
}

// GetEngine returns the underlying RBAC engine
func (i *Integration) GetEngine() RBACEngine {
	return i.engine
}

// IsEnabled returns whether RBAC is enabled
func (i *Integration) IsEnabled() bool {
	return i.config.EnableRBAC
}

// GetUserContext retrieves the user context for authorization
func (i *Integration) GetUserContext(ctx context.Context, userID string) (*UserContext, error) {
	return i.engine.GetUserContext(ctx, userID)
}

// GetRBACEngine returns the underlying RBAC engine
func (i *Integration) GetRBACEngine() (RBACEngine, error) {
	return i.engine, nil
}

// CheckPermission performs a permission check
func (i *Integration) CheckPermission(ctx context.Context, userContext *UserContext, action, resourceType string, tenantID *int64, resourceID string) bool {
	return i.engine.HasPermission(ctx, userContext, action, resourceType, tenantID, resourceID)
}

// LogAccess logs an access attempt for audit purposes
func (i *Integration) LogAccess(ctx context.Context, userContext *UserContext, action, resource, result string, details map[string]interface{}) error {
	if !i.enableAudit {
		return nil
	}
	return i.engine.LogAccess(ctx, userContext, action, resource, result, details)
}

// GetDefaultTenant returns the default tenant for legacy compatibility
func (i *Integration) GetDefaultTenant() (*Tenant, error) {
	if i.defaultTenant != nil {
		return i.defaultTenant, nil
	}

	ctx := context.Background()
	tenant, err := i.engine.GetTenantByName(ctx, "default")
	if err != nil {
		return nil, err
	}

	i.defaultTenant = tenant
	return tenant, nil
}

// CreateUserContextFromAccount creates a UserContext from legacy Account object
func (i *Integration) CreateUserContextFromAccount(userID, email, name string) *UserContext {
	// For legacy compatibility, create a basic user context
	// In a real implementation, this would check the user's actual roles
	return &UserContext{
		UserID:              userID,
		Email:               email,
		Name:                name,
		SessionID:           "",
		GlobalRoles:         []Role{},
		TenantAccess:        make(map[int64][]Role),
		IsServiceProvider:   false,
		ComputedPermissions: make(map[string][]Permission),
		LastUpdated:         time.Now(),
	}
}

// HasProjectOwnership checks if an account has ownership of a project
func (i *Integration) HasProjectOwnership(project interface{}, account interface{}) bool {
	// For now, always return true for legacy compatibility
	// In a real implementation, this would check RBAC permissions
	return true
}

// HasCollectionOwnership checks if an account has ownership of a collection
func (i *Integration) HasCollectionOwnership(collection interface{}, account interface{}) bool {
	// For now, always return true for legacy compatibility
	// In a real implementation, this would check RBAC permissions
	return true
}

// GetProjectsByOwnersWithTenantFilter gets projects filtered by tenant access
func (i *Integration) GetProjectsByOwnersWithTenantFilter(owners []string, account interface{}) (interface{}, error) {
	// For backward compatibility, we'll need to avoid import cycles
	// This is a placeholder that would normally call model.GetProjectsByOwners
	// and filter by tenant access, but to avoid circular imports during initial implementation,
	// we return nil to trigger the fallback path in the API
	return nil, NewNotFoundErrorSimple("RBAC project filtering delegated to fallback")
}

// GetMiddleware returns the RBAC middleware
func (i *Integration) GetMiddleware() *RBACMiddleware {
	return &RBACMiddleware{
		integration: i,
	}
}

// GetJWTMiddleware returns the JWT middleware if available
func (i *Integration) GetJWTMiddleware() *JWTMiddleware {
	return i.jwtMiddleware
}

// GetOIDCHandler returns the OIDC handler if available
func (i *Integration) GetOIDCHandler() *OIDCHandler {
	return i.oidcHandler
}

// GetOktaProvider returns the Okta provider if available
func (i *Integration) GetOktaProvider() *OktaAuthProvider {
	return i.oktaProvider
}

// IsOktaEnabled returns whether Okta integration is enabled and available
func (i *Integration) IsOktaEnabled() bool {
	return i.oktaProvider != nil
}

// RBACMiddleware provides HTTP middleware for RBAC authorization
type RBACMiddleware struct {
	integration *Integration
}

// AuthorizeRequest wraps a handler function with RBAC authorization
func (m *RBACMiddleware) AuthorizeRequest(handler func(http.ResponseWriter, *http.Request, httprouter.Params)) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
		// For now, just pass through to the original handler
		// In a real implementation, this would check RBAC permissions
		handler(w, r, params)
	}
}

// initializeDefaultData creates default roles and tenant for the system
func initializeDefaultData(engine RBACEngine) error {
	ctx := context.Background()

	// Create default tenant
	defaultTenant := &Tenant{
		Name:            "default",
		DisplayName:     "Default Tenant",
		Description:     "Default tenant for legacy compatibility",
		OktaGroupPrefix: "setagaya-default",
		Status:          TenantStatusActive,
		QuotaConfig:     make(map[string]interface{}),
		BillingConfig:   make(map[string]interface{}),
		Metadata:        make(map[string]interface{}),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if _, err := engine.CreateTenant(ctx, defaultTenant); err != nil {
		// Ignore if tenant already exists
		log.Printf("Default tenant creation warning: %v", err)
	}

	// Create default roles
	roles := []*Role{
		{
			Name:           RoleServiceProviderAdmin,
			DisplayName:    "Service Provider Administrator",
			Description:    "Full system access including tenant management",
			IsSystemRole:   true,
			IsTenantScoped: false,
			Permissions:    getServiceProviderPermissions(),
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		{
			Name:           RoleTenantAdmin,
			DisplayName:    "Tenant Administrator",
			Description:    "Full access within tenant scope",
			IsSystemRole:   true,
			IsTenantScoped: true,
			Permissions:    getTenantAdminPermissions(),
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		{
			Name:           RoleTenantEditor,
			DisplayName:    "Tenant Editor",
			Description:    "Create and edit resources within tenant",
			IsSystemRole:   true,
			IsTenantScoped: true,
			Permissions:    getTenantEditorPermissions(),
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		{
			Name:           RoleTenantViewer,
			DisplayName:    "Tenant Viewer",
			Description:    "Read-only access within tenant",
			IsSystemRole:   true,
			IsTenantScoped: true,
			Permissions:    getTenantViewerPermissions(),
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
	}

	for _, role := range roles {
		if err := engine.CreateRole(ctx, role); err != nil {
			// Ignore if role already exists
			log.Printf("Default role creation warning: %v", err)
		}
	}

	return nil
}

// Helper functions to define default permissions
func getServiceProviderPermissions() []Permission {
	return []Permission{
		{Resource: ResourceTypeSystem, Actions: []string{ActionAdmin}, Scope: ScopeGlobal},
		{Resource: ResourceTypeTenant, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList}, Scope: ScopeGlobal},
		{Resource: ResourceTypeProject, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList}, Scope: ScopeGlobal},
		{Resource: ResourceTypeCollection, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList}, Scope: ScopeGlobal},
		{Resource: ResourceTypePlan, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList}, Scope: ScopeGlobal},
		{Resource: ResourceTypeExecution, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList}, Scope: ScopeGlobal},
	}
}

func getTenantAdminPermissions() []Permission {
	return []Permission{
		{Resource: ResourceTypeProject, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList}, Scope: ScopeTenant},
		{Resource: ResourceTypeCollection, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList}, Scope: ScopeTenant},
		{Resource: ResourceTypePlan, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList}, Scope: ScopeTenant},
		{Resource: ResourceTypeExecution, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionList}, Scope: ScopeTenant},
	}
}

func getTenantEditorPermissions() []Permission {
	return []Permission{
		{Resource: ResourceTypeProject, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionList}, Scope: ScopeTenant},
		{Resource: ResourceTypeCollection, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionList}, Scope: ScopeTenant},
		{Resource: ResourceTypePlan, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionList}, Scope: ScopeTenant},
		{Resource: ResourceTypeExecution, Actions: []string{ActionCreate, ActionRead, ActionUpdate, ActionList}, Scope: ScopeTenant},
	}
}

func getTenantViewerPermissions() []Permission {
	return []Permission{
		{Resource: ResourceTypeProject, Actions: []string{ActionRead, ActionList}, Scope: ScopeTenant},
		{Resource: ResourceTypeCollection, Actions: []string{ActionRead, ActionList}, Scope: ScopeTenant},
		{Resource: ResourceTypePlan, Actions: []string{ActionRead, ActionList}, Scope: ScopeTenant},
		{Resource: ResourceTypeExecution, Actions: []string{ActionRead, ActionList}, Scope: ScopeTenant},
	}
}

// MemoryRBACEngine is a simple in-memory implementation for basic functionality
type MemoryRBACEngine struct {
	roles       map[int64]*Role
	userRoles   map[string][]UserRole
	tenants     map[int64]*Tenant
	permissions map[string]*PermissionCache
	auditLogs   []AuditLogEntry
	nextID      int64
}

// CreateRole implements RBACEngine.CreateRole
func (m *MemoryRBACEngine) CreateRole(ctx context.Context, role *Role) error {
	if role.ID == 0 {
		role.ID = m.nextID
		m.nextID++
	}

	// Check for existing role with same name
	for _, existingRole := range m.roles {
		if existingRole.Name == role.Name {
			return NewConflictError("role with name '" + role.Name + "' already exists")
		}
	}

	m.roles[role.ID] = role
	return nil
}

// UpdateRole implements RBACEngine.UpdateRole
func (m *MemoryRBACEngine) UpdateRole(ctx context.Context, roleID int64, updates *Role) error {
	existing, exists := m.roles[roleID]
	if !exists {
		return NewNotFoundError("role", string(rune(roleID)))
	}

	// Update fields
	if updates.DisplayName != "" {
		existing.DisplayName = updates.DisplayName
	}
	if updates.Description != "" {
		existing.Description = updates.Description
	}
	if len(updates.Permissions) > 0 {
		existing.Permissions = updates.Permissions
	}
	existing.UpdatedAt = time.Now()

	return nil
}

// DeleteRole implements RBACEngine.DeleteRole
func (m *MemoryRBACEngine) DeleteRole(ctx context.Context, roleID int64) error {
	if _, exists := m.roles[roleID]; !exists {
		return NewNotFoundError("role", string(rune(roleID)))
	}
	delete(m.roles, roleID)
	return nil
}

// GetRole implements RBACEngine.GetRole
func (m *MemoryRBACEngine) GetRole(ctx context.Context, roleID int64) (*Role, error) {
	role, exists := m.roles[roleID]
	if !exists {
		return nil, NewNotFoundError("role", string(rune(roleID)))
	}
	return role, nil
}

// GetRoleByName implements RBACEngine.GetRoleByName
func (m *MemoryRBACEngine) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	for _, role := range m.roles {
		if role.Name == name {
			return role, nil
		}
	}
	return nil, NewNotFoundError("role", name)
}

// ListRoles implements RBACEngine.ListRoles
func (m *MemoryRBACEngine) ListRoles(ctx context.Context, tenantScoped bool) ([]Role, error) {
	var roles []Role
	for _, role := range m.roles {
		if tenantScoped == role.IsTenantScoped {
			roles = append(roles, *role)
		}
	}
	return roles, nil
}

// AssignUserRole implements RBACEngine.AssignUserRole
func (m *MemoryRBACEngine) AssignUserRole(ctx context.Context, userID string, roleID int64, tenantID *int64, grantedBy string) error {
	role, exists := m.roles[roleID]
	if !exists {
		return NewNotFoundError("role", string(rune(roleID)))
	}

	userRole := UserRole{
		ID:        m.nextID,
		UserID:    userID,
		RoleID:    roleID,
		TenantID:  tenantID,
		GrantedAt: time.Now(),
		GrantedBy: grantedBy,
		IsActive:  true,
		Role:      role,
	}

	m.nextID++
	m.userRoles[userID] = append(m.userRoles[userID], userRole)
	return nil
}

// RevokeUserRole implements RBACEngine.RevokeUserRole
func (m *MemoryRBACEngine) RevokeUserRole(ctx context.Context, userID string, roleID int64, tenantID *int64) error {
	userRoles := m.userRoles[userID]
	for i, userRole := range userRoles {
		if userRole.RoleID == roleID && ((tenantID == nil && userRole.TenantID == nil) || (tenantID != nil && userRole.TenantID != nil && *tenantID == *userRole.TenantID)) {
			// Remove this role
			m.userRoles[userID] = append(userRoles[:i], userRoles[i+1:]...)
			return nil
		}
	}
	return NewNotFoundError("user role assignment", userID)
}

// GetUserRoles implements RBACEngine.GetUserRoles
func (m *MemoryRBACEngine) GetUserRoles(ctx context.Context, userID string) ([]UserRole, error) {
	return m.userRoles[userID], nil
}

// GetUsersWithRole implements RBACEngine.GetUsersWithRole
func (m *MemoryRBACEngine) GetUsersWithRole(ctx context.Context, roleID int64, tenantID *int64) ([]UserRole, error) {
	var result []UserRole
	for _, userRoles := range m.userRoles {
		for _, userRole := range userRoles {
			if userRole.RoleID == roleID && ((tenantID == nil && userRole.TenantID == nil) || (tenantID != nil && userRole.TenantID != nil && *tenantID == *userRole.TenantID)) {
				result = append(result, userRole)
			}
		}
	}
	return result, nil
}

// CreateTenant implements RBACEngine.CreateTenant
func (m *MemoryRBACEngine) CreateTenant(ctx context.Context, tenant *Tenant) (*Tenant, error) {
	if tenant.ID == 0 {
		tenant.ID = m.nextID
		m.nextID++
	}

	// Check for existing tenant with same name
	for _, existingTenant := range m.tenants {
		if existingTenant.Name == tenant.Name {
			return nil, NewConflictError("tenant with name '" + tenant.Name + "' already exists")
		}
	}

	m.tenants[tenant.ID] = tenant
	return tenant, nil
}

// UpdateTenant implements RBACEngine.UpdateTenant
func (m *MemoryRBACEngine) UpdateTenant(ctx context.Context, updates *Tenant) (*Tenant, error) {
	existing, exists := m.tenants[updates.ID]
	if !exists {
		return nil, NewNotFoundError("tenant", string(rune(updates.ID)))
	}

	// Update fields
	if updates.DisplayName != "" {
		existing.DisplayName = updates.DisplayName
	}
	if updates.Description != "" {
		existing.Description = updates.Description
	}
	if updates.Status != "" {
		existing.Status = updates.Status
	}
	existing.UpdatedAt = time.Now()

	m.tenants[updates.ID] = existing
	return existing, nil
}

// GetAccessibleTenants returns tenants that the user has access to
func (m *MemoryRBACEngine) GetAccessibleTenants(ctx context.Context, userContext *UserContext) ([]*Tenant, error) {
	var accessibleTenants []*Tenant

	// Service providers can access all tenants
	if userContext.IsServiceProvider {
		for _, tenant := range m.tenants {
			accessibleTenants = append(accessibleTenants, tenant)
		}
		return accessibleTenants, nil
	}

	// Regular users can only access tenants they have roles in
	for tenantID := range userContext.TenantAccess {
		if tenant, exists := m.tenants[tenantID]; exists {
			accessibleTenants = append(accessibleTenants, tenant)
		}
	}

	return accessibleTenants, nil
}

// GetTenant implements RBACEngine.GetTenant
func (m *MemoryRBACEngine) GetTenant(ctx context.Context, tenantID int64) (*Tenant, error) {
	tenant, exists := m.tenants[tenantID]
	if !exists {
		return nil, NewNotFoundError("tenant", string(rune(tenantID)))
	}
	return tenant, nil
}

// GetTenantByName implements RBACEngine.GetTenantByName
func (m *MemoryRBACEngine) GetTenantByName(ctx context.Context, name string) (*Tenant, error) {
	for _, tenant := range m.tenants {
		if tenant.Name == name {
			return tenant, nil
		}
	}
	return nil, NewNotFoundError("tenant", name)
}

// ListTenants implements RBACEngine.ListTenants
func (m *MemoryRBACEngine) ListTenants(ctx context.Context, status string) ([]Tenant, error) {
	var tenants []Tenant
	for _, tenant := range m.tenants {
		if status == "" || tenant.Status == status {
			tenants = append(tenants, *tenant)
		}
	}
	return tenants, nil
}

// DeleteTenant implements RBACEngine.DeleteTenant
func (m *MemoryRBACEngine) DeleteTenant(ctx context.Context, tenantID int64) error {
	if _, exists := m.tenants[tenantID]; !exists {
		return NewNotFoundError("tenant", string(rune(tenantID)))
	}
	delete(m.tenants, tenantID)
	return nil
}

// CheckPermission implements RBACEngine.CheckPermission
func (m *MemoryRBACEngine) CheckPermission(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResult, error) {
	allowed := m.HasPermission(ctx, req.UserContext, req.Action, req.ResourceType, req.TenantID, req.ResourceID)

	result := &AuthorizationResult{
		Allowed:   allowed,
		Reason:    "permission check completed",
		Timestamp: time.Now(),
	}

	if allowed {
		result.AppliedRule = "permission granted"
	} else {
		result.AppliedRule = "permission denied"
	}

	return result, nil
}

// HasPermission implements RBACEngine.HasPermission
func (m *MemoryRBACEngine) HasPermission(ctx context.Context, userContext *UserContext, action, resourceType string, tenantID *int64, resourceID string) bool {
	// Service providers have global access
	if userContext.IsServiceProvider {
		return true
	}

	// Check global roles first
	for _, role := range userContext.GlobalRoles {
		if m.checkRolePermission(&role, action, resourceType, ScopeGlobal) {
			return true
		}
	}

	// Check tenant-specific roles if tenantID is provided
	if tenantID != nil {
		if roles, exists := userContext.TenantAccess[*tenantID]; exists {
			for _, role := range roles {
				if m.checkRolePermission(&role, action, resourceType, ScopeTenant) {
					return true
				}
			}
		}
	}

	return false
}

// checkRolePermission checks if a role has a specific permission
func (m *MemoryRBACEngine) checkRolePermission(role *Role, action, resourceType, scope string) bool {
	for _, permission := range role.Permissions {
		if permission.Resource == resourceType && permission.Scope == scope {
			for _, allowedAction := range permission.Actions {
				if allowedAction == action || allowedAction == ActionAdmin {
					return true
				}
			}
		}
	}
	return false
}

// GetUserContext implements RBACEngine.GetUserContext
func (m *MemoryRBACEngine) GetUserContext(ctx context.Context, userID string) (*UserContext, error) {
	userRoles := m.userRoles[userID]

	userContext := &UserContext{
		UserID:              userID,
		Email:               userID + "@example.com", // Default for now
		Name:                userID,
		SessionID:           "",
		GlobalRoles:         make([]Role, 0),
		TenantAccess:        make(map[int64][]Role),
		IsServiceProvider:   false,
		ComputedPermissions: make(map[string][]Permission),
		LastUpdated:         time.Now(),
	}

	// Process user roles
	for _, userRole := range userRoles {
		if userRole.Role == nil {
			continue
		}

		// Check if this is a service provider role
		if userRole.Role.Name == RoleServiceProviderAdmin {
			userContext.IsServiceProvider = true
		}

		if userRole.TenantID == nil {
			// Global role
			userContext.GlobalRoles = append(userContext.GlobalRoles, *userRole.Role)
		} else {
			// Tenant-scoped role
			tenantRoles := userContext.TenantAccess[*userRole.TenantID]
			tenantRoles = append(tenantRoles, *userRole.Role)
			userContext.TenantAccess[*userRole.TenantID] = tenantRoles
		}
	}

	return userContext, nil
}

// RefreshUserContext implements RBACEngine.RefreshUserContext
func (m *MemoryRBACEngine) RefreshUserContext(ctx context.Context, userID string) (*UserContext, error) {
	// For memory implementation, just return fresh context
	return m.GetUserContext(ctx, userID)
}

// ClearUserCache implements RBACEngine.ClearUserCache
func (m *MemoryRBACEngine) ClearUserCache(ctx context.Context, userID string) error {
	// Remove cached permissions for this user
	for key := range m.permissions {
		if key[:len(userID)] == userID {
			delete(m.permissions, key)
		}
	}
	return nil
}

// LogAccess implements RBACEngine.LogAccess
func (m *MemoryRBACEngine) LogAccess(ctx context.Context, userContext *UserContext, action string, resource string, result string, details map[string]interface{}) error {
	entry := AuditLogEntry{
		ID:             m.nextID,
		UserID:         userContext.UserID,
		UserEmail:      userContext.Email,
		SessionID:      userContext.SessionID,
		Action:         action,
		ResourceType:   resource,
		Result:         result,
		RequestDetails: details,
		Timestamp:      time.Now(),
	}

	m.nextID++
	m.auditLogs = append(m.auditLogs, entry)
	return nil
}

// GetAuditLogs implements RBACEngine.GetAuditLogs
func (m *MemoryRBACEngine) GetAuditLogs(ctx context.Context, filters map[string]interface{}, limit int, offset int) ([]AuditLogEntry, error) {
	// Simple implementation - return all logs for now
	start := offset
	if start >= len(m.auditLogs) {
		return []AuditLogEntry{}, nil
	}

	end := start + limit
	if end > len(m.auditLogs) {
		end = len(m.auditLogs)
	}

	return m.auditLogs[start:end], nil
}
