package rbac

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// OktaAuthProvider handles Okta authentication and JWT validation
type OktaAuthProvider struct {
	config       *OktaConfig
	logger       Logger
	publicKey    *rsa.PublicKey
	oauth2Config *oauth2.Config
}

// NewOktaAuthProvider creates a new Okta authentication provider
func NewOktaAuthProvider(config *OktaConfig, logger Logger) (*OktaAuthProvider, error) {
	if config == nil {
		return nil, NewRBACError(ErrCodeInvalidConfig, "Okta config is required", nil)
	}

	provider := &OktaAuthProvider{
		config: config,
		logger: logger,
	}

	// Setup OAuth2 configuration
	provider.oauth2Config = &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURI,
		Scopes:       config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://%s/oauth2/default/v1/authorize", config.Domain),
			TokenURL: fmt.Sprintf("https://%s/oauth2/default/v1/token", config.Domain),
		},
	}

	// Initialize with a mock RSA public key for testing
	if err := provider.initMockPublicKey(); err != nil {
		return nil, fmt.Errorf("failed to initialize mock public key: %w", err)
	}

	logger.Info("Okta auth provider initialized", "domain", config.Domain, "clientID", config.ClientID)
	return provider, nil
}

// initMockPublicKey creates a mock RSA public key for testing
func (p *OktaAuthProvider) initMockPublicKey() error {
	// WARNING: This is a mock key for testing only. In production,
	// public keys must be fetched from Okta's JWKS endpoint
	// and validated against the issuer's certificate chain.
	mockPubKeyPEM := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2btf02uSG5fxmQE7D4LF5wqGMz1Wsp1qZF3cT2sYRW
iR4dPF76VsqxlLV1+fYPj8T2yAg9Qz1PdX5fL3Hm0FG9c5+4q2qV0+K5U5J+d2Y+
2A9a2KzG2e1zJ5g+3Mj5c5X3PQ8G9JGJHzO6Qbg+7mh+ZGR2SdE8bKz3CXR8eD8k
mJkWXvOzF/B4Q2bk7S5B5CrA9d+zP+4H7G5GzF9B5FzQzF/J8B4A2N5G+A4MzP+
LzJ+Q4J5G5Bz6Z5QzDzL9M5YzGJF8+2C5JzF/8+gJzGzS4K+F/T+5r5Yz8VZPF+
wIDAQAB
-----END PUBLIC KEY-----`

	block, rest := pem.Decode([]byte(mockPubKeyPEM))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block: invalid PEM format")
	}

	// Ensure no trailing data exists after PEM block
	if len(rest) > 0 {
		p.logger.Warn("Unexpected data after PEM block", "length", len(rest))
	}

	if block.Type != "PUBLIC KEY" {
		return fmt.Errorf("invalid PEM block type: expected 'PUBLIC KEY', got '%s'", block.Type)
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	p.publicKey = rsaPubKey
	return nil
}

// GetAuthorizationURL generates the OAuth2 authorization URL
func (p *OktaAuthProvider) GetAuthorizationURL(state string) string {
	return p.oauth2Config.AuthCodeURL(state)
}

// ExchangeCodeForToken exchanges an authorization code for tokens
func (p *OktaAuthProvider) ExchangeCodeForToken(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		p.logger.Error("Failed to exchange code for token", "error", err)
		return nil, NewRBACError(ErrCodeTokenExchangeFailed, "Failed to exchange authorization code", map[string]interface{}{
			"error": err.Error(),
		})
	}

	p.logger.Debug("Successfully exchanged code for token")
	return token, nil
}

// ValidateJWT validates a JWT token and returns the claims
func (p *OktaAuthProvider) ValidateJWT(tokenString string) (*OktaClaims, error) {
	// Parse and validate the JWT token
	token, err := jwt.ParseWithClaims(tokenString, &OktaClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.publicKey, nil
	})

	if err != nil {
		p.logger.Error("JWT validation failed", "error", err)
		return nil, NewRBACError(ErrCodeInvalidToken, "Invalid JWT token", map[string]interface{}{
			"error": err.Error(),
		})
	}

	if !token.Valid {
		return nil, NewRBACError(ErrCodeInvalidToken, "JWT token is not valid", nil)
	}

	claims, ok := token.Claims.(*OktaClaims)
	if !ok {
		return nil, NewRBACError(ErrCodeInvalidToken, "Invalid JWT claims", nil)
	}

	p.logger.Debug("JWT validation successful", "subject", claims.Subject, "email", claims.Email)
	return claims, nil
}

// MapGroupsToRoles maps Okta groups to Setagaya roles
func (p *OktaAuthProvider) MapGroupsToRoles(groups []string) []Role {
	var roles []Role

	// Simple mapping for demonstration - in production this would be configurable
	for _, group := range groups {
		switch {
		case strings.Contains(strings.ToLower(group), "admin"):
			roles = append(roles, Role{
				ID:             1,
				Name:           RoleTenantAdmin,
				DisplayName:    "Tenant Admin",
				Description:    "Full administrative access to tenant",
				IsTenantScoped: true,
				Permissions: []Permission{
					{Resource: "tenant", Actions: []string{"admin"}},
					{Resource: "*", Actions: []string{"*"}},
				},
			})
		case strings.Contains(strings.ToLower(group), "editor"):
			roles = append(roles, Role{
				ID:             2,
				Name:           RoleTenantEditor,
				DisplayName:    "Tenant Editor",
				Description:    "Edit access to tenant resources",
				IsTenantScoped: true,
				Permissions: []Permission{
					{Resource: "collection", Actions: []string{"create", "update", "read"}},
					{Resource: "plan", Actions: []string{"*"}},
				},
			})
		case strings.Contains(strings.ToLower(group), "viewer"):
			roles = append(roles, Role{
				ID:             3,
				Name:           RoleTenantViewer,
				DisplayName:    "Tenant Viewer",
				Description:    "Read-only access to tenant resources",
				IsTenantScoped: true,
				Permissions: []Permission{
					{Resource: "collection", Actions: []string{"read"}},
					{Resource: "plan", Actions: []string{"read"}},
				},
			})
		case strings.Contains(strings.ToLower(group), "support"):
			roles = append(roles, Role{
				ID:           4,
				Name:         RoleServiceProviderSupport,
				DisplayName:  "Service Support",
				Description:  "Support access across all tenants",
				IsSystemRole: true,
				Permissions: []Permission{
					{Resource: "*", Actions: []string{"read"}},
					{Resource: "tenant", Actions: []string{"read"}},
				},
			})
		}
	}

	// Default to viewer if no roles mapped
	if len(roles) == 0 {
		roles = append(roles, Role{
			ID:             3,
			Name:           RoleTenantViewer,
			DisplayName:    "Tenant Viewer",
			Description:    "Read-only access to tenant resources",
			IsTenantScoped: true,
			Permissions: []Permission{
				{Resource: "collection", Actions: []string{"read"}},
				{Resource: "plan", Actions: []string{"read"}},
			},
		})
	}

	p.logger.Debug("Mapped groups to roles", "groups", groups, "roleCount", len(roles))
	return roles
}

// CreateUserContext creates a user context from Okta claims
func (p *OktaAuthProvider) CreateUserContext(claims *OktaClaims) *UserContext {
	// Extract groups from claims
	groups := make([]string, 0)
	if claims.Groups != nil {
		groups = claims.Groups
	}

	// Map groups to roles
	roles := p.MapGroupsToRoles(groups)

	return &UserContext{
		UserID:              claims.Subject,
		Email:               claims.Email,
		Name:                claims.Name,
		SessionID:           "",
		GlobalRoles:         roles,
		TenantAccess:        make(map[int64][]Role),
		IsServiceProvider:   false,
		ComputedPermissions: make(map[string][]Permission),
		LastUpdated:         time.Now(),
	}
}
