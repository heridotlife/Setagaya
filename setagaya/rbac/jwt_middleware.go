package rbac

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
)

// JWTMiddleware provides JWT-based authentication middleware
type JWTMiddleware struct {
	authProvider *OktaAuthProvider
	rbacEngine   RBACEngine
	logger       Logger
}

// NewJWTMiddleware creates a new JWT middleware instance
func NewJWTMiddleware(authProvider *OktaAuthProvider, rbacEngine RBACEngine, logger Logger) *JWTMiddleware {
	return &JWTMiddleware{
		authProvider: authProvider,
		rbacEngine:   rbacEngine,
		logger:       logger,
	}
}

// RequireAuthentication returns a middleware that requires valid JWT authentication
func (m *JWTMiddleware) RequireAuthentication() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Extract JWT token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.logger.Warn("Missing Authorization header", "path", r.URL.Path, "method", r.Method)
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		// Check for Bearer token format
		if !strings.HasPrefix(authHeader, "Bearer ") {
			m.logger.Warn("Invalid Authorization header format", "path", r.URL.Path, "method", r.Method)
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate JWT token
		claims, err := m.authProvider.ValidateJWT(tokenString)
		if err != nil {
			m.logger.Error("JWT validation failed", "error", err, "path", r.URL.Path, "method", r.Method)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Create user context from claims
		userContext := m.authProvider.CreateUserContext(claims)

		// Add user context to request context
		ctx := context.WithValue(r.Context(), "userContext", userContext)
		*r = *r.WithContext(ctx)

		m.logger.Debug("JWT authentication successful", 
			"userID", userContext.UserID, 
			"email", userContext.Email,
			"path", r.URL.Path)

		// Continue to next handler (this would be the actual API handler)
		// For now, we'll just return success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "authenticated", "user": "` + userContext.Email + `"}`))
	}
}

// RequirePermission returns a middleware that requires specific permissions
func (m *JWTMiddleware) RequirePermission(resource, action string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// First, require authentication
		m.RequireAuthentication()(w, r, ps)
		if w.Header().Get("Authorization-Error") != "" {
			return // Authentication failed, error already sent
		}

		// Get user context from request
		userContext, ok := r.Context().Value("userContext").(*UserContext)
		if !ok {
			m.logger.Error("User context not found in request", "path", r.URL.Path, "method", r.Method)
			http.Error(w, "Authentication context missing", http.StatusInternalServerError)
			return
		}

		// Check permission
		hasPermission := m.checkPermission(userContext, resource, action)
		if !hasPermission {
			m.logger.Warn("Permission denied", 
				"userID", userContext.UserID,
				"resource", resource,
				"action", action,
				"path", r.URL.Path)

			// Log audit entry
			m.logAuditEvent(userContext, resource, action, "DENIED", r)

			http.Error(w, "Insufficient permissions", http.StatusForbidden)
			return
		}

		// Log successful permission check
		m.logAuditEvent(userContext, resource, action, "GRANTED", r)

		m.logger.Debug("Permission check passed", 
			"userID", userContext.UserID,
			"resource", resource,
			"action", action)

		// Continue to next handler
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "authorized", "resource": "` + resource + `", "action": "` + action + `"}`))
	}
}

// RequireTenantPermission returns a middleware that requires tenant-specific permissions
func (m *JWTMiddleware) RequireTenantPermission(resource, action string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// First, require authentication
		m.RequireAuthentication()(w, r, ps)
		if w.Header().Get("Authorization-Error") != "" {
			return // Authentication failed
		}

		// Get user context
		userContext, ok := r.Context().Value("userContext").(*UserContext)
		if !ok {
			http.Error(w, "Authentication context missing", http.StatusInternalServerError)
			return
		}

		// Extract tenant ID from URL params or query
		tenantIDStr := ps.ByName("tenantId")
		if tenantIDStr == "" {
			tenantIDStr = r.URL.Query().Get("tenantId")
		}

		if tenantIDStr == "" {
			m.logger.Warn("Tenant ID not provided for tenant-scoped request", 
				"userID", userContext.UserID,
				"path", r.URL.Path)
			http.Error(w, "Tenant ID required", http.StatusBadRequest)
			return
		}

		// For now, we'll use a fixed tenant ID for demonstration
		// In production, this would parse the tenant ID from the URL
		tenantID := int64(1)

		// Check tenant-specific permission
		hasPermission := m.checkTenantPermission(userContext, tenantID, resource, action)
		if !hasPermission {
			m.logger.Warn("Tenant permission denied", 
				"userID", userContext.UserID,
				"tenantID", tenantID,
				"resource", resource,
				"action", action)

			// Log audit entry
			m.logTenantAuditEvent(userContext, tenantID, resource, action, "DENIED", r)

			http.Error(w, "Insufficient tenant permissions", http.StatusForbidden)
			return
		}

		// Log successful permission check
		m.logTenantAuditEvent(userContext, tenantID, resource, action, "GRANTED", r)

		m.logger.Debug("Tenant permission check passed", 
			"userID", userContext.UserID,
			"tenantID", tenantID,
			"resource", resource,
			"action", action)

		// Continue to next handler
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "authorized", "tenantId": "` + tenantIDStr + `"}`))
	}
}

// checkPermission checks if user has global permission for resource/action
func (m *JWTMiddleware) checkPermission(userContext *UserContext, resource, action string) bool {
	// Check global roles first
	for _, role := range userContext.GlobalRoles {
		for _, permission := range role.Permissions {
			if m.matchesPermission(permission, resource, action) {
				return true
			}
		}
	}

	// Check computed permissions cache
	if permissions, exists := userContext.ComputedPermissions[resource]; exists {
		for _, permission := range permissions {
			if m.matchesPermissionWithActions(permission, resource, action) {
				return true
			}
		}
	}

	return false
}

// checkTenantPermission checks if user has tenant-specific permission
func (m *JWTMiddleware) checkTenantPermission(userContext *UserContext, tenantID int64, resource, action string) bool {
	// Check global admin permissions first
	if m.checkPermission(userContext, resource, action) {
		return true
	}

	// Check tenant-specific roles
	if tenantRoles, exists := userContext.TenantAccess[tenantID]; exists {
		for _, role := range tenantRoles {
			for _, permission := range role.Permissions {
				if m.matchesPermission(permission, resource, action) {
					return true
				}
			}
		}
	}

	return false
}

// matchesPermission checks if a permission matches the requested resource/action
func (m *JWTMiddleware) matchesPermission(permission Permission, resource, action string) bool {
	// Check for wildcard permissions
	if permission.Resource == "*" {
		return true
	}

	// Check resource match
	if permission.Resource != resource {
		return false
	}

	// Check actions
	for _, allowedAction := range permission.Actions {
		if allowedAction == "*" || allowedAction == action {
			return true
		}
	}

	return false
}

// matchesPermissionWithActions checks permission from computed permissions cache
func (m *JWTMiddleware) matchesPermissionWithActions(permission Permission, resource, action string) bool {
	if permission.Resource == resource || permission.Resource == "*" {
		for _, allowedAction := range permission.Actions {
			if allowedAction == action || allowedAction == "*" {
				return true
			}
		}
	}
	return false
}

// logAuditEvent logs an audit event for permission checks
func (m *JWTMiddleware) logAuditEvent(userContext *UserContext, resource, action, result string, r *http.Request) {
	auditEntry := &AuditLogEntry{
		UserID:       userContext.UserID,
		UserEmail:    userContext.Email,
		SessionID:    userContext.SessionID,
		Action:       action,
		ResourceType: resource,
		Result:       result,
		Timestamp:    time.Now(),
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		RequestDetails: map[string]interface{}{
			"method": r.Method,
			"path":   r.URL.Path,
		},
	}

	// In a production system, this would be sent to an audit log system
	m.logger.Info("Audit event", 
		"userID", auditEntry.UserID,
		"action", auditEntry.Action,
		"resourceType", auditEntry.ResourceType,
		"result", auditEntry.Result,
		"ip", auditEntry.IPAddress)
}

// logTenantAuditEvent logs a tenant-specific audit event
func (m *JWTMiddleware) logTenantAuditEvent(userContext *UserContext, tenantID int64, resource, action, result string, r *http.Request) {
	auditEntry := &AuditLogEntry{
		UserID:       userContext.UserID,
		UserEmail:    userContext.Email,
		SessionID:    userContext.SessionID,
		TenantID:     &tenantID,
		Action:       action,
		ResourceType: resource,
		Result:       result,
		Timestamp:    time.Now(),
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		RequestDetails: map[string]interface{}{
			"method":   r.Method,
			"path":     r.URL.Path,
			"tenantId": tenantID,
		},
	}

	m.logger.Info("Tenant audit event", 
		"userID", auditEntry.UserID,
		"tenantID", tenantID,
		"action", auditEntry.Action,
		"resourceType", auditEntry.ResourceType,
		"result", auditEntry.Result,
		"ip", auditEntry.IPAddress)
}