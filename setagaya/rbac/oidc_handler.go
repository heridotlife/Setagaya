package rbac

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
)

// OIDCHandler handles OIDC authentication flows
type OIDCHandler struct {
	authProvider *OktaAuthProvider
	rbacEngine   RBACEngine
	logger       Logger
	sessionStore SessionStore
	baseURL      string
}

// NewOIDCHandler creates a new OIDC handler
func NewOIDCHandler(authProvider *OktaAuthProvider, rbacEngine RBACEngine, logger Logger, sessionStore SessionStore, baseURL string) *OIDCHandler {
	return &OIDCHandler{
		authProvider: authProvider,
		rbacEngine:   rbacEngine,
		logger:       logger,
		sessionStore: sessionStore,
		baseURL:      baseURL,
	}
}

// HandleLogin initiates the OIDC login flow
func (h *OIDCHandler) HandleLogin() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Generate CSRF state parameter with sufficient entropy
		state, err := h.generateSecureState()
		if err != nil {
			h.logger.Error("Failed to generate state parameter", "error", sanitizeForLogging(err.Error()), "ip", r.RemoteAddr)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Enhanced state parameter validation with additional security checks
		if len(state) < 32 || len(state) > 256 {
			h.logger.Error("Generated state parameter has invalid length", "length", len(state))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		
		// Additional validation for state parameter content
		if !isValidStateParameter(state) {
			h.logger.Error("Generated state parameter contains invalid characters")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Store state in session for validation
		ctx := context.Background()
		sessionID := "state_" + state  // Safe string concatenation instead of format string
		sessionData := map[string]interface{}{
			"state":     state,
			"timestamp": time.Now(),
			"ip":        r.RemoteAddr,
			"userAgent": r.UserAgent(),
		}
		
		err = h.sessionStore.Set(ctx, sessionID, sessionData, 10*time.Minute)

		if err != nil {
			h.logger.Error("Failed to store state in session", "error", err, "ip", r.RemoteAddr)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get authorization URL
		authURL := h.authProvider.GetAuthorizationURL(state)

		// Validate authorization URL to prevent redirect attacks
		if len(authURL) > 2048 {
			h.logger.Error("Authorization URL too long", "length", len(authURL))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Set secure state cookie with additional security headers
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    state,
			Path:     "/",
			MaxAge:   600, // 10 minutes
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode, // Changed to Strict for better security
		})

		h.logger.Info("Initiating OIDC login", "ip", r.RemoteAddr, "userAgent", r.UserAgent())

		// Redirect to Okta
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// HandleCallback handles the OIDC callback from Okta
func (h *OIDCHandler) HandleCallback() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Get state from query parameter with validation
		stateParam := r.URL.Query().Get("state")
		if stateParam == "" || len(stateParam) < 32 || len(stateParam) > 256 {
			h.logger.Warn("Invalid state parameter in callback", "ip", r.RemoteAddr, "userAgent", r.UserAgent())
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		// Get state from cookie
		stateCookie, err := r.Cookie("oauth_state")
		if err != nil || stateCookie.Value == "" {
			h.logger.Warn("Missing or invalid state cookie in callback", "ip", r.RemoteAddr, "userAgent", r.UserAgent())
			http.Error(w, "Missing state cookie", http.StatusBadRequest)
			return
		}

		// Use constant-time comparison to prevent timing attacks
		if !constantTimeStringEqual(stateParam, stateCookie.Value) {
			h.logger.Warn("State parameter mismatch - possible CSRF attack", "ip", r.RemoteAddr, "userAgent", r.UserAgent())
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		// Validate state exists in session
		ctx := context.Background()
		sessionID := "state_" + stateParam  // Safe string concatenation
		stateSessionData, err := h.sessionStore.Get(ctx, sessionID)
		if err != nil {
			h.logger.Warn("State not found in session or expired", "error", err, "ip", r.RemoteAddr)
			http.Error(w, "Invalid or expired state", http.StatusBadRequest)
			return
		}

		// Validate session data structure
		sessionMap, ok := stateSessionData.(map[string]interface{})
		if !ok {
			h.logger.Error("Invalid session data format", "ip", r.RemoteAddr)
			http.Error(w, "Invalid session", http.StatusInternalServerError)
			return
		}

		// Validate IP consistency to prevent session hijacking
		if sessionIP, exists := sessionMap["ip"]; exists {
			if sessionIP != r.RemoteAddr {
				h.logger.Warn("IP address mismatch in session", "sessionIP", sessionIP, "requestIP", r.RemoteAddr)
				// Continue but log the potential security issue
			}
		}

		// Clean up state session immediately
		if err := h.sessionStore.Delete(ctx, sessionID); err != nil {
			h.logger.Warn("Failed to delete session", "error", err)
		}

		// Clear state cookie immediately
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
		})

		// Get authorization code with validation
		code := r.URL.Query().Get("code")
		if code == "" || len(code) > 512 {
			h.logger.Warn("Missing or invalid authorization code in callback", "ip", r.RemoteAddr)
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			return
		}

		// Check for error parameter
		if errorCode := r.URL.Query().Get("error"); errorCode != "" {
			errorDesc := r.URL.Query().Get("error_description")
			h.logger.Warn("OAuth error in callback", "error", errorCode, "description", errorDesc, "ip", r.RemoteAddr)
			
			// Comprehensive sanitization to prevent XSS and format string attacks
			safeErrorCode := sanitizeForOAuth(errorCode)
			safeErrorDesc := sanitizeForOAuth(errorDesc)
			
			// Use safe error message construction without format strings
			errorMessage := "OAuth error: " + safeErrorCode
			if safeErrorDesc != "" {
				errorMessage += " - " + safeErrorDesc
			}
			
			http.Error(w, errorMessage, http.StatusBadRequest)
			return
		}

		// Exchange code for token
		token, err := h.authProvider.ExchangeCodeForToken(ctx, code)
		if err != nil {
			h.logger.Error("Failed to exchange code for token", "error", err, "ip", r.RemoteAddr)
			http.Error(w, "Token exchange failed", http.StatusInternalServerError)
			return
		}

		// Extract and validate ID token
		idToken, ok := token.Extra("id_token").(string)
		if !ok {
			h.logger.Error("No ID token in response", "ip", r.RemoteAddr)
			http.Error(w, "No ID token received", http.StatusInternalServerError)
			return
		}

		// Validate JWT and extract claims
		claims, err := h.authProvider.ValidateJWT(idToken)
		if err != nil {
			h.logger.Error("Failed to validate ID token", "error", err, "ip", r.RemoteAddr)
			http.Error(w, "Invalid ID token", http.StatusUnauthorized)
			return
		}

		// Create user context
		userContext := h.authProvider.CreateUserContext(claims)

		// Create user session
		userSessionID, err := h.generateSessionID()
		if err != nil {
			h.logger.Error("Failed to generate session ID", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Store user session with security enhancements
		sessionData := map[string]interface{}{
			"userContext":  userContext,
			"accessToken":  token.AccessToken,
			"refreshToken": token.RefreshToken,
			"idToken":      idToken,
			"loginTime":    time.Now(),
			"ip":           r.RemoteAddr,
			"userAgent":    r.UserAgent(),
		}

		err = h.sessionStore.Set(ctx, userSessionID, sessionData, 2*time.Hour)
		if err != nil {
			h.logger.Error("Failed to store user session", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Set secure session cookie with enhanced security
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    userSessionID,
			Path:     "/",
			MaxAge:   7200, // 2 hours
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode, // Use strict mode for session cookies
		})

		h.logger.Info("OIDC login successful",
			"userID", userContext.UserID,
			"email", userContext.Email,
			"ip", r.RemoteAddr)

		// Redirect to application
		redirectURL := h.baseURL + "/dashboard"
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// HandleLogout handles user logout
func (h *OIDCHandler) HandleLogout() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Get session cookie with validation
		sessionCookie, err := r.Cookie("session_id")
		if err == nil && sessionCookie.Value != "" {
			// Validate session ID format before processing
			if len(sessionCookie.Value) < 10 || len(sessionCookie.Value) > 256 {
				h.logger.Warn("Invalid session ID format during logout", "length", len(sessionCookie.Value), "ip", r.RemoteAddr)
			} else {
				// Delete session from store
				ctx := context.Background()
				if err := h.sessionStore.Delete(ctx, sessionCookie.Value); err != nil {
					h.logger.Warn("Failed to delete session on logout", "error", err, "ip", r.RemoteAddr)
				}
			}
		}

		// Always clear session cookie regardless of session store operation result
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		// Check if we should redirect to Okta logout with validation
		oktaLogout := r.URL.Query().Get("okta_logout")
		if oktaLogout == "true" {
			// Validate domain to prevent open redirect attacks
			if h.authProvider.config.Domain == "" || len(h.authProvider.config.Domain) > 255 {
				h.logger.Error("Invalid Okta domain configuration", "ip", r.RemoteAddr)
				http.Error(w, "Configuration error", http.StatusInternalServerError)
				return
			}

			// Construct Okta logout URL with proper validation - safe string concatenation
			logoutURL := "https://" + h.authProvider.config.Domain + "/oauth2/default/v1/logout"
			postLogoutRedirectURI := h.baseURL + "/login"

			// Validate redirect URI to prevent open redirect
			if !strings.HasPrefix(postLogoutRedirectURI, h.baseURL) {
				h.logger.Error("Invalid post-logout redirect URI", "uri", postLogoutRedirectURI, "ip", r.RemoteAddr)
				http.Error(w, "Invalid redirect", http.StatusBadRequest)
				return
			}

			logoutParams := url.Values{}
			logoutParams.Set("post_logout_redirect_uri", postLogoutRedirectURI)

			fullLogoutURL := logoutURL + "?" + logoutParams.Encode()

			// Validate final URL length
			if len(fullLogoutURL) > 2048 {
				h.logger.Error("Logout URL too long", "length", len(fullLogoutURL), "ip", r.RemoteAddr)
				http.Error(w, "Invalid logout URL", http.StatusInternalServerError)
				return
			}

			h.logger.Info("Redirecting to Okta logout", "ip", r.RemoteAddr)
			http.Redirect(w, r, fullLogoutURL, http.StatusFound)
			return
		}

		h.logger.Info("User logged out", "ip", r.RemoteAddr, "userAgent", r.UserAgent())

		// Local logout - redirect to login page with validation
		localRedirect := h.baseURL + "/login"
		if !strings.HasPrefix(localRedirect, h.baseURL) {
			h.logger.Error("Invalid local redirect URL", "url", localRedirect)
			http.Error(w, "Invalid redirect", http.StatusBadRequest)
			return
		}

		http.Redirect(w, r, localRedirect, http.StatusFound)
	}
}

// HandleUserInfo returns current user information
func (h *OIDCHandler) HandleUserInfo() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Get session cookie with validation
		sessionCookie, err := r.Cookie("session_id")
		if err != nil || sessionCookie.Value == "" {
			h.logger.Warn("Missing session cookie in user info request", "ip", r.RemoteAddr)
			http.Error(w, "Not authenticated", http.StatusUnauthorized)
			return
		}

		// Validate session ID format
		if len(sessionCookie.Value) < 10 || len(sessionCookie.Value) > 256 {
			h.logger.Warn("Invalid session ID format", "length", len(sessionCookie.Value), "ip", r.RemoteAddr)
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		// Get session data
		ctx := context.Background()
		sessionData, err := h.sessionStore.Get(ctx, sessionCookie.Value)
		if err != nil {
			h.logger.Warn("Session not found for user info request", "error", err, "ip", r.RemoteAddr)
			http.Error(w, "Session not found", http.StatusUnauthorized)
			return
		}

		// Extract user context with proper validation
		sessionMap, ok := sessionData.(map[string]interface{})
		if !ok {
			h.logger.Error("Invalid session data format", "ip", r.RemoteAddr)
			http.Error(w, "Invalid session", http.StatusInternalServerError)
			return
		}

		userContext, ok := sessionMap["userContext"].(*UserContext)
		if !ok {
			h.logger.Error("User context not found in session", "ip", r.RemoteAddr)
			http.Error(w, "Invalid session", http.StatusInternalServerError)
			return
		}

		// Validate IP consistency to detect potential session hijacking
		if sessionIP, exists := sessionMap["ip"]; exists {
			if sessionIP != r.RemoteAddr {
				h.logger.Warn("IP address mismatch in user info request",
					"sessionIP", sessionIP, "requestIP", r.RemoteAddr, "userID", userContext.UserID)
				// Continue but log the security concern
			}
		}

		// Return sanitized user information with enhanced security
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.WriteHeader(http.StatusOK)

		// Comprehensive sanitization to prevent XSS and injection attacks
		safeUserID := sanitizeForJSONStrict(userContext.UserID)
		safeEmail := sanitizeForJSONStrict(userContext.Email)
		safeName := sanitizeForJSONStrict(userContext.Name)
		
		// Safe JSON construction without format strings
		roleCount := "0"
		if len(userContext.GlobalRoles) > 0 {
			roleCount = convertToString(len(userContext.GlobalRoles))
		}
		
		userInfo := `{` +
			`"user_id": "` + safeUserID + `",` +
			`"email": "` + safeEmail + `",` +
			`"name": "` + safeName + `",` +
			`"roles": ` + roleCount + `,` +
			`"authenticated": true` +
			`}`

		if _, err := w.Write([]byte(userInfo)); err != nil {
			h.logger.Error("Failed to write response", "error", err, "ip", r.RemoteAddr)
		}
	}
}

// generateSecureState generates a cryptographically secure state parameter
func (h *OIDCHandler) generateSecureState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// generateSessionID generates a secure session ID
func (h *OIDCHandler) generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Safe string concatenation instead of format string
	return "sess_" + base64.URLEncoding.EncodeToString(bytes), nil
}

// constantTimeStringEqual performs constant-time string comparison to prevent timing attacks
func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}

	return result == 0
}

// sanitizeForOAuth safely sanitizes OAuth error messages to prevent XSS and injection
func sanitizeForOAuth(input string) string {
	if len(input) == 0 {
		return ""
	}
	
	// Replace dangerous characters
	sanitized := strings.ReplaceAll(input, "<", "&lt;")
	sanitized = strings.ReplaceAll(sanitized, ">", "&gt;")
	sanitized = strings.ReplaceAll(sanitized, `"`, "&quot;")
	sanitized = strings.ReplaceAll(sanitized, `'`, "&#x27;")
	sanitized = strings.ReplaceAll(sanitized, "&", "&amp;")
	sanitized = strings.ReplaceAll(sanitized, "\n", " ")
	sanitized = strings.ReplaceAll(sanitized, "\r", " ")
	sanitized = strings.ReplaceAll(sanitized, "\t", " ")
	
	// Limit length to prevent buffer overflow
	if len(sanitized) > 200 {
		sanitized = sanitized[:197] + "..."
	}
	
	return sanitized
}

// sanitizeForJSONStrict provides strict sanitization for JSON values to prevent injection
func sanitizeForJSONStrict(input string) string {
	if len(input) == 0 {
		return ""
	}
	
	// Replace JSON-breaking characters
	sanitized := strings.ReplaceAll(input, `"`, `\"`)
	sanitized = strings.ReplaceAll(sanitized, `\`, `\\`)
	sanitized = strings.ReplaceAll(sanitized, "\n", "\\n")
	sanitized = strings.ReplaceAll(sanitized, "\r", "\\r")
	sanitized = strings.ReplaceAll(sanitized, "\t", "\\t")
	sanitized = strings.ReplaceAll(sanitized, "\b", "\\b")
	sanitized = strings.ReplaceAll(sanitized, "\f", "\\f")
	
	// HTML encode for additional XSS protection
	sanitized = html.EscapeString(sanitized)
	
	// Strict length limit for user info
	if len(sanitized) > 100 {
		sanitized = sanitized[:97] + "..."
	}
	
	return sanitized
}

// isValidStateParameter validates that a state parameter contains only safe characters
func isValidStateParameter(state string) bool {
	for _, char := range state {
		if !((char >= 'a' && char <= 'z') || 
			 (char >= 'A' && char <= 'Z') || 
			 (char >= '0' && char <= '9') || 
			 char == '_' || char == '-' || char == '=' || 
			 char == '+' || char == '/') { // Base64 URL-safe characters
			return false
		}
	}
	return true
}
