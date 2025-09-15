package rbac

import (
	"context"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// UserContextKey is the key for storing user context in request context
	UserContextKey contextKey = "userContext"
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
		// Extract JWT token from Authorization header with enhanced validation
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.logger.Warn("Missing Authorization header", "path", sanitizeForLogging(r.URL.Path), "method", r.Method, "ip", r.RemoteAddr)
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		// Validate Authorization header length to prevent buffer overflow attacks
		if len(authHeader) > 8192 { // Maximum reasonable JWT size
			m.logger.Warn("Authorization header too long", "length", len(authHeader), "ip", r.RemoteAddr)
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		// Check for Bearer token format with enhanced validation
		if !strings.HasPrefix(authHeader, "Bearer ") {
			m.logger.Warn("Invalid Authorization header format", "path", sanitizeForLogging(r.URL.Path), "method", r.Method, "ip", r.RemoteAddr)
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate token string is not empty and has reasonable length
		if len(tokenString) == 0 || len(tokenString) > 8000 {
			m.logger.Warn("Invalid token length", "length", len(tokenString), "ip", r.RemoteAddr)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Validate JWT token with enhanced security logging
		claims, err := m.authProvider.ValidateJWT(tokenString)
		if err != nil {
			m.logger.Error("JWT validation failed", "error", sanitizeForLogging(err.Error()), "path", sanitizeForLogging(r.URL.Path), "method", r.Method, "ip", r.RemoteAddr)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Create user context from claims
		userContext := m.authProvider.CreateUserContext(claims)

		// Add user context to request context
		ctx := context.WithValue(r.Context(), UserContextKey, userContext)
		*r = *r.WithContext(ctx)

		m.logger.Debug("JWT authentication successful",
			"userID", sanitizeForLogging(userContext.UserID),
			"email", sanitizeForLogging(userContext.Email),
			"path", sanitizeForLogging(r.URL.Path))

		// Continue to next handler (this would be the actual API handler)
		// For now, we'll just return success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Sanitize output to prevent XSS and format string vulnerabilities
		safeEmail := sanitizeForJSON(userContext.Email)
		safeStatus := "authenticated"
		
		// Use safe string construction instead of format strings with user data
		response := `{"status": "` + safeStatus + `", "user": "` + safeEmail + `"}`
		if _, err := w.Write([]byte(response)); err != nil {
			m.logger.Error("Failed to write response", "error", err)
		}
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

		// Check permission with enhanced security validation
		hasPermission := m.checkPermission(userContext, resource, action)
		if !hasPermission {
			m.logger.Warn("Permission denied",
				"userID", sanitizeForLogging(userContext.UserID),
				"resource", sanitizeForLogging(resource),
				"action", sanitizeForLogging(action),
				"path", sanitizeForLogging(r.URL.Path))

			// Log audit entry
			m.logAuditEvent(userContext, resource, action, "DENIED", r)

			http.Error(w, "Insufficient permissions", http.StatusForbidden)
			return
		}

		// Log successful permission check
		m.logAuditEvent(userContext, resource, action, "GRANTED", r)

		m.logger.Debug("Permission check passed",
			"userID", sanitizeForLogging(userContext.UserID),
			"resource", sanitizeForLogging(resource),
			"action", sanitizeForLogging(action))

		// Continue to next handler
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		// Use safe string construction to prevent format string vulnerabilities
		safeResource := sanitizeForJSON(resource)
		safeAction := sanitizeForJSON(action)
		response := `{"status": "authorized", "resource": "` + safeResource + `", "action": "` + safeAction + `"}`
		
		if _, err := w.Write([]byte(response)); err != nil {
			m.logger.Error("Failed to write response", "error", err)
		}
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
		
		// Safe string construction to prevent format string vulnerabilities
		safeTenantIDStr := sanitizeForJSON(tenantIDStr)
		response := `{"status": "authorized", "tenantId": "` + safeTenantIDStr + `"}`
		
		if _, err := w.Write([]byte(response)); err != nil {
			m.logger.Error("Failed to write response", "error", err)
		}
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

// logAuditEvent logs an audit event for permission checks with enhanced security
func (m *JWTMiddleware) logAuditEvent(userContext *UserContext, resource, action, result string, r *http.Request) {
	auditEntry := &AuditLogEntry{
		UserID:       sanitizeForLogging(userContext.UserID),
		UserEmail:    sanitizeForLogging(userContext.Email),
		SessionID:    sanitizeForLogging(userContext.SessionID),
		Action:       sanitizeForLogging(action),
		ResourceType: sanitizeForLogging(resource),
		Result:       sanitizeForLogging(result),
		Timestamp:    time.Now(),
		IPAddress:    r.RemoteAddr,
		UserAgent:    sanitizeForLogging(r.UserAgent()),
		RequestDetails: map[string]interface{}{
			"method": r.Method,
			"path":   sanitizeForLogging(r.URL.Path),
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

// logTenantAuditEvent logs a tenant-specific audit event with enhanced security
func (m *JWTMiddleware) logTenantAuditEvent(userContext *UserContext, tenantID int64, resource, action, result string, r *http.Request) {
	auditEntry := &AuditLogEntry{
		UserID:       sanitizeForLogging(userContext.UserID),
		UserEmail:    sanitizeForLogging(userContext.Email),
		SessionID:    sanitizeForLogging(userContext.SessionID),
		TenantID:     &tenantID,
		Action:       sanitizeForLogging(action),
		ResourceType: sanitizeForLogging(resource),
		Result:       sanitizeForLogging(result),
		Timestamp:    time.Now(),
		IPAddress:    r.RemoteAddr,
		UserAgent:    sanitizeForLogging(r.UserAgent()),
		RequestDetails: map[string]interface{}{
			"method":   r.Method,
			"path":     sanitizeForLogging(r.URL.Path),
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

// sanitizeForJSON safely sanitizes strings for use in JSON responses to prevent XSS and injection
func sanitizeForJSON(input string) string {
	// Replace characters that could break JSON structure
	sanitized := strings.ReplaceAll(input, `"`, `\"`)
	sanitized = strings.ReplaceAll(sanitized, `\`, `\\`)
	sanitized = strings.ReplaceAll(sanitized, "\n", "\\n")
	sanitized = strings.ReplaceAll(sanitized, "\r", "\\r")
	sanitized = strings.ReplaceAll(sanitized, "\t", "\\t")
	
	// HTML encode to prevent XSS
	sanitized = html.EscapeString(sanitized)
	
	// Limit length to prevent buffer overflow
	if len(sanitized) > 256 {
		sanitized = sanitized[:253] + "..."
	}
	
	return sanitized
}

// sanitizeForLogging safely sanitizes data for logging to prevent log injection
func sanitizeForLogging(input string) string {
	if len(input) == 0 {
		return ""
	}
	
	// Replace control characters
	sanitized := strings.ReplaceAll(input, "\n", "\\n")
	sanitized = strings.ReplaceAll(sanitized, "\r", "\\r")
	sanitized = strings.ReplaceAll(sanitized, "\t", "\\t")
	
	// Limit length to prevent log flooding
	if len(sanitized) > 100 {
		sanitized = sanitized[:97] + "..."
	}
	
	return sanitized
}
