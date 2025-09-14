package rbac

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/julienschmidt/httprouter"
)

// OIDCHandler handles OIDC authentication flows
type OIDCHandler struct {
	authProvider   *OktaAuthProvider
	rbacEngine     RBACEngine
	logger         Logger
	sessionStore   SessionStore
	baseURL        string
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
		// Generate CSRF state parameter
		state, err := h.generateSecureState()
		if err != nil {
			h.logger.Error("Failed to generate state parameter", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Store state in session for validation
		ctx := context.Background()
		sessionID := fmt.Sprintf("state_%s", state)
		err = h.sessionStore.Set(ctx, sessionID, map[string]interface{}{
			"state":     state,
			"timestamp": time.Now(),
			"ip":        r.RemoteAddr,
		}, 10*time.Minute)

		if err != nil {
			h.logger.Error("Failed to store state in session", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get authorization URL
		authURL := h.authProvider.GetAuthorizationURL(state)

		// Set secure state cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    state,
			Path:     "/",
			MaxAge:   600, // 10 minutes
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		h.logger.Info("Initiating OIDC login", "state", state, "ip", r.RemoteAddr)

		// Redirect to Okta
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// HandleCallback handles the OIDC callback from Okta
func (h *OIDCHandler) HandleCallback() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Get state from query parameter
		stateParam := r.URL.Query().Get("state")
		if stateParam == "" {
			h.logger.Warn("Missing state parameter in callback", "ip", r.RemoteAddr)
			http.Error(w, "Missing state parameter", http.StatusBadRequest)
			return
		}

		// Get state from cookie
		stateCookie, err := r.Cookie("oauth_state")
		if err != nil {
			h.logger.Warn("Missing state cookie in callback", "ip", r.RemoteAddr)
			http.Error(w, "Missing state cookie", http.StatusBadRequest)
			return
		}

		// Validate state parameter
		if stateParam != stateCookie.Value {
			h.logger.Warn("State parameter mismatch", "expected", stateCookie.Value, "received", stateParam, "ip", r.RemoteAddr)
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		// Validate state exists in session
		ctx := context.Background()
		sessionID := fmt.Sprintf("state_%s", stateParam)
		_, err = h.sessionStore.Get(ctx, sessionID)
		if err != nil {
			h.logger.Warn("State not found in session", "state", stateParam, "error", err, "ip", r.RemoteAddr)
			http.Error(w, "Invalid or expired state", http.StatusBadRequest)
			return
		}

		// Declare sessionData variable for later use
		var sessionData map[string]interface{}

		// Clean up state session
		if err := h.sessionStore.Delete(ctx, sessionID); err != nil {
			h.logger.Warn("Failed to delete session", "error", err)
		}

		// Clear state cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
		})

		// Get authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			h.logger.Warn("Missing authorization code in callback", "ip", r.RemoteAddr)
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			return
		}

		// Check for error parameter
		if errorCode := r.URL.Query().Get("error"); errorCode != "" {
			errorDesc := r.URL.Query().Get("error_description")
			h.logger.Warn("OAuth error in callback", "error", errorCode, "description", errorDesc, "ip", r.RemoteAddr)
			http.Error(w, fmt.Sprintf("OAuth error: %s", errorDesc), http.StatusBadRequest)
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

		// Store user session
		sessionData = map[string]interface{}{
			"userContext":  userContext,
			"accessToken":  token.AccessToken,
			"refreshToken": token.RefreshToken,
			"idToken":      idToken,
			"loginTime":    time.Now(),
			"ip":           r.RemoteAddr,
		}

		err = h.sessionStore.Set(ctx, userSessionID, sessionData, 2*time.Hour)
		if err != nil {
			h.logger.Error("Failed to store user session", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    userSessionID,
			Path:     "/",
			MaxAge:   7200, // 2 hours
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
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
		// Get session cookie
		sessionCookie, err := r.Cookie("session_id")
		if err == nil {
			// Delete session from store
			ctx := context.Background()
			if err := h.sessionStore.Delete(ctx, sessionCookie.Value); err != nil {
				h.logger.Warn("Failed to delete session on logout", "error", err)
			}
		}

		// Clear session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
		})

		// Check if we should redirect to Okta logout
		oktaLogout := r.URL.Query().Get("okta_logout")
		if oktaLogout == "true" {
			// Construct Okta logout URL
			logoutURL := fmt.Sprintf("https://%s/oauth2/default/v1/logout", h.authProvider.config.Domain)
			postLogoutRedirectURI := h.baseURL + "/login"
			
			logoutParams := url.Values{}
			logoutParams.Set("post_logout_redirect_uri", postLogoutRedirectURI)
			
			fullLogoutURL := logoutURL + "?" + logoutParams.Encode()
			
			h.logger.Info("Redirecting to Okta logout", "url", fullLogoutURL)
			http.Redirect(w, r, fullLogoutURL, http.StatusFound)
			return
		}

		h.logger.Info("User logged out", "ip", r.RemoteAddr)

		// Local logout - redirect to login page
		http.Redirect(w, r, h.baseURL+"/login", http.StatusFound)
	}
}

// HandleUserInfo returns current user information
func (h *OIDCHandler) HandleUserInfo() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Get session cookie
		sessionCookie, err := r.Cookie("session_id")
		if err != nil {
			http.Error(w, "Not authenticated", http.StatusUnauthorized)
			return
		}

		// Get session data
		ctx := context.Background()
		sessionData, err := h.sessionStore.Get(ctx, sessionCookie.Value)
		if err != nil {
			h.logger.Warn("Session not found for user info request", "error", err)
			http.Error(w, "Session not found", http.StatusUnauthorized)
			return
		}

		// Extract user context
		sessionMap, ok := sessionData.(map[string]interface{})
		if !ok {
			h.logger.Error("Invalid session data format")
			http.Error(w, "Invalid session", http.StatusInternalServerError)
			return
		}

		userContext, ok := sessionMap["userContext"].(*UserContext)
		if !ok {
			h.logger.Error("User context not found in session")
			http.Error(w, "Invalid session", http.StatusInternalServerError)
			return
		}

		// Return user information
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		// Simplified user info response
		userInfo := fmt.Sprintf(`{
			"user_id": "%s",
			"email": "%s", 
			"name": "%s",
			"roles": %d,
			"authenticated": true
		}`, userContext.UserID, userContext.Email, userContext.Name, len(userContext.GlobalRoles))
		
		if _, err := w.Write([]byte(userInfo)); err != nil {
			h.logger.Error("Failed to write response", "error", err)
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
	return fmt.Sprintf("sess_%s", base64.URLEncoding.EncodeToString(bytes)), nil
}