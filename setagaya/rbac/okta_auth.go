package rbac

import (
	"context"
	"crypto/rand"
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

// initMockPublicKey creates a properly generated RSA public key for testing
func (p *OktaAuthProvider) initMockPublicKey() error {
	// WARNING: This is a mock key for testing only. In production,
	// public keys must be fetched from Okta's JWKS endpoint
	// and validated against the issuer's certificate chain.
	//
	// SECURITY: Use properly generated cryptographic material instead of static strings
	
	// Generate a proper RSA key pair for testing instead of using hardcoded material
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Use the public key from the generated pair
	p.publicKey = &privKey.PublicKey

	// For compatibility with PEM operations, also validate PEM handling
	// Generate a PEM representation and validate it
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	}

	pemData := pem.EncodeToMemory(pemBlock)
	if pemData == nil {
		return fmt.Errorf("failed to encode PEM data")
	}

	// Validate PEM decoding with comprehensive error handling
	decodedBlock, rest := pem.Decode(pemData)
	if decodedBlock == nil {
		return fmt.Errorf("failed to decode generated PEM block: invalid PEM format")
	}

	// Ensure no trailing data exists after PEM block
	if len(rest) > 0 {
		p.logger.Warn("Unexpected data after PEM block during validation", "length", len(rest))
		return fmt.Errorf("invalid PEM format: unexpected trailing data")
	}

	// Validate PEM block type strictly
	if decodedBlock.Type != "PUBLIC KEY" {
		return fmt.Errorf("invalid PEM block type: expected 'PUBLIC KEY', got '%s'", decodedBlock.Type)
	}

	// Re-parse the key to ensure validity
	parsedPubKey, err := x509.ParsePKIXPublicKey(decodedBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse generated public key: %w", err)
	}

	// Ensure it's an RSA key
	_, ok := parsedPubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("generated key is not an RSA public key")
	}

	p.logger.Info("Generated and validated mock RSA public key for testing",
		"keySize", privKey.N.BitLen(),
		"warning", "PRODUCTION DEPLOYMENT REQUIRES OKTA JWKS ENDPOINT")

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

// ValidateJWT validates a JWT token and returns the claims with enhanced security
func (p *OktaAuthProvider) ValidateJWT(tokenString string) (*OktaClaims, error) {
	// Enhanced input validation to prevent buffer overflow and injection attacks
	if len(tokenString) == 0 {
		return nil, NewRBACError(ErrCodeInvalidToken, "JWT token cannot be empty", nil)
	}

	// Limit JWT token size to prevent DoS attacks (8KB maximum)
	if len(tokenString) > 8192 {
		p.logger.Warn("JWT token exceeds maximum allowed size", "size", len(tokenString))
		return nil, NewRBACError(ErrCodeInvalidToken, "JWT token exceeds maximum allowed size", map[string]interface{}{
			"maxSize": 8192,
			"actualSize": len(tokenString),
		})
	}

	// Validate JWT format (basic structure check)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, NewRBACError(ErrCodeInvalidToken, "Invalid JWT format: must have 3 parts separated by dots", map[string]interface{}{
			"actualParts": len(parts),
		})
	}

	// Validate each part is not empty
	for i, part := range parts {
		if len(part) == 0 {
			return nil, NewRBACError(ErrCodeInvalidToken, fmt.Sprintf("JWT part %d is empty", i+1), nil)
		}
	}

	// Parse and validate the JWT token with proper error handling
	token, err := jwt.ParseWithClaims(tokenString, &OktaClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method - only allow RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			p.logger.Warn("Unexpected JWT signing method", "method", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		
		// Additional algorithm validation
		if alg, ok := token.Header["alg"].(string); ok {
			if alg != "RS256" && alg != "RS384" && alg != "RS512" {
				p.logger.Warn("Unsupported RSA algorithm", "algorithm", alg)
				return nil, fmt.Errorf("unsupported RSA algorithm: %s", alg)
			}
		}

		return p.publicKey, nil
	})

	if err != nil {
		// Sanitize error message to prevent information disclosure
		p.logger.Error("JWT validation failed", "error", err.Error())
		return nil, NewRBACError(ErrCodeInvalidToken, "JWT token validation failed", map[string]interface{}{
			"reason": "invalid_signature_or_format",
		})
	}

	if !token.Valid {
		p.logger.Warn("JWT token is invalid")
		return nil, NewRBACError(ErrCodeInvalidToken, "JWT token is not valid", nil)
	}

	claims, ok := token.Claims.(*OktaClaims)
	if !ok {
		p.logger.Error("Failed to extract JWT claims")
		return nil, NewRBACError(ErrCodeInvalidToken, "Invalid JWT claims structure", nil)
	}

	// Additional claims validation
	if claims.Subject == "" {
		return nil, NewRBACError(ErrCodeInvalidToken, "JWT claims missing required subject", nil)
	}

	if claims.Email == "" {
		return nil, NewRBACError(ErrCodeInvalidToken, "JWT claims missing required email", nil)
	}

	// Validate expiration time
	if claims.ExpiresAt != 0 && time.Unix(claims.ExpiresAt, 0).Before(time.Now()) {
		return nil, NewRBACError(ErrCodeInvalidToken, "JWT token has expired", map[string]interface{}{
			"expiredAt": time.Unix(claims.ExpiresAt, 0),
			"now": time.Now(),
		})
	}

	// Validate issued at time (not too far in the future)
	if claims.IssuedAt != 0 && time.Unix(claims.IssuedAt, 0).After(time.Now().Add(5*time.Minute)) {
		return nil, NewRBACError(ErrCodeInvalidToken, "JWT token issued too far in the future", map[string]interface{}{
			"issuedAt": time.Unix(claims.IssuedAt, 0),
			"now": time.Now(),
		})
	}

	p.logger.Debug("JWT validation successful", 
		"subject", claims.Subject, 
		"email", claims.Email,
		"issuer", claims.Issuer)
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
