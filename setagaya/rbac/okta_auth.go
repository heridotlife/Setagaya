package rbac

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
			// Validate domain to prevent injection attacks before URL construction
			AuthURL:  "https://" + sanitizeDomainForURL(config.Domain) + "/oauth2/default/v1/authorize",
			TokenURL: "https://" + sanitizeDomainForURL(config.Domain) + "/oauth2/default/v1/token",
		},
	}

	// Initialize with a mock RSA public key for testing
	if err := provider.initMockPublicKey(); err != nil {
		return nil, NewRBACError(ErrCodeInvalidConfig, "Failed to initialize mock public key", map[string]interface{}{
			"error": err.Error(),
		})
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
		return NewRBACError(ErrCodeCryptographicError, "Failed to generate RSA key", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Use the public key from the generated pair
	p.publicKey = &privKey.PublicKey

	// For compatibility with PEM operations, also validate PEM handling
	// Generate a PEM representation and validate it
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return NewRBACError(ErrCodeCryptographicError, "Failed to marshal public key", map[string]interface{}{
			"error": err.Error(),
		})
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	}

	pemData := pem.EncodeToMemory(pemBlock)
	if pemData == nil {
		return NewRBACError(ErrCodeCryptographicError, "Failed to encode PEM data", nil)
	}

	// Validate PEM decoding with comprehensive error handling
	decodedBlock, rest := pem.Decode(pemData)
	if decodedBlock == nil {
		return NewRBACError(ErrCodeCryptographicError, "Failed to decode generated PEM block: invalid PEM format", nil)
	}

	// Ensure no trailing data exists after PEM block
	if len(rest) > 0 {
		p.logger.Warn("Unexpected data after PEM block during validation", "length", len(rest))
		return NewRBACError(ErrCodeCryptographicError, "Invalid PEM format: unexpected trailing data", map[string]interface{}{
			"trailingDataLength": len(rest),
		})
	}

	// Validate PEM block type strictly
	if decodedBlock.Type != "PUBLIC KEY" {
		// Safe error construction to prevent format string vulnerabilities with user-controlled PEM data
		errorMsg := "invalid PEM block type: expected 'PUBLIC KEY', got '" + sanitizeErrorString(decodedBlock.Type) + "'"
		return &RBACError{
			Type:    "invalid_pem_block",
			Message: errorMsg,
		}
	}

	// Re-parse the key to ensure validity
	parsedPubKey, err := x509.ParsePKIXPublicKey(decodedBlock.Bytes)
	if err != nil {
		return NewRBACError(ErrCodeCryptographicError, "Failed to parse generated public key", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Ensure it's an RSA key
	_, ok := parsedPubKey.(*rsa.PublicKey)
	if !ok {
		return NewRBACError(ErrCodeCryptographicError, "Generated key is not an RSA public key", nil)
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

	p.logger.Debug("Successfully completed authorization code exchange")
	return token, nil
}

// ValidateJWT validates a JWT token and returns the claims with enhanced security
func (p *OktaAuthProvider) ValidateJWT(tokenString string) (*OktaClaims, error) {
	// Validate JWT input format and structure
	if err := p.validateJWTInput(tokenString); err != nil {
		return nil, err
	}

	// Parse and validate the JWT token with proper error handling
	token, err := p.parseJWTToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Extract and validate claims
	claims, err := p.extractAndValidateClaims(token)
	if err != nil {
		return nil, err
	}

	// Validate claims timing and content
	if err := p.validateClaimsContent(claims); err != nil {
		return nil, err
	}

	p.logger.Debug("JWT validation successful",
		"subject", sanitizeForLogging(claims.Subject),
		"email", sanitizeForLogging(claims.Email),
		"issuer", sanitizeForLogging(claims.Issuer))
	return claims, nil
}

// validateJWTInput validates JWT input format and basic structure
func (p *OktaAuthProvider) validateJWTInput(tokenString string) error {
	// Enhanced input validation to prevent buffer overflow and injection attacks
	if len(tokenString) == 0 {
		return NewRBACError(ErrCodeInvalidToken, "JWT token cannot be empty", nil)
	}

	// Limit JWT token size to prevent DoS attacks (8KB maximum)
	if len(tokenString) > 8192 {
		p.logger.Warn("JWT token exceeds maximum allowed size", "size", len(tokenString))
		return NewRBACError(ErrCodeInvalidToken, "JWT token exceeds maximum allowed size", map[string]interface{}{
			"maxSize":    8192,
			"actualSize": len(tokenString),
		})
	}

	return p.validateJWTStructure(tokenString)
}

// validateJWTStructure validates JWT token structure and format
func (p *OktaAuthProvider) validateJWTStructure(tokenString string) error {
	// Validate JWT format (basic structure check)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return NewRBACError(ErrCodeInvalidToken, "Invalid JWT format: must have 3 parts separated by dots", map[string]interface{}{
			"actualParts": len(parts),
		})
	}

	// Validate each part is not empty
	for i, part := range parts {
		if len(part) == 0 {
			// Use safe string construction to prevent format string vulnerabilities
			// Safe conversion to prevent G115 integer overflow (i+1 can't realistically overflow int64)
			partNumber := convertIntToString(int64(i + 1))
			return NewRBACError(ErrCodeInvalidToken, "JWT part "+partNumber+" is empty", nil)
		}
	}

	return nil
}

// parseJWTToken parses the JWT token with algorithm validation
func (p *OktaAuthProvider) parseJWTToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &OktaClaims{}, func(token *jwt.Token) (interface{}, error) {
		return p.validateSigningMethod(token)
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

	return token, nil
}

// validateSigningMethod validates JWT signing method and algorithm
func (p *OktaAuthProvider) validateSigningMethod(token *jwt.Token) (interface{}, error) {
	// Verify the signing method - only allow RSA
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		p.logger.Warn("Unexpected JWT signing method", "method", token.Header["alg"])
		return nil, NewRBACError(ErrCodeInvalidToken, "Unexpected signing method", map[string]interface{}{
			"method": token.Header["alg"],
		})
	}

	// Additional algorithm validation
	if alg, ok := token.Header["alg"].(string); ok {
		if alg != "RS256" && alg != "RS384" && alg != "RS512" {
			p.logger.Warn("Unsupported RSA algorithm", "algorithm", alg)
			// Safe error construction to prevent format string vulnerabilities
			errorMsg := "unsupported RSA algorithm: " + sanitizeErrorString(alg)
			return nil, &RBACError{
				Type:    "unsupported_algorithm",
				Message: errorMsg,
			}
		}
	}

	return p.publicKey, nil
}

// extractAndValidateClaims extracts and validates JWT claims structure
func (p *OktaAuthProvider) extractAndValidateClaims(token *jwt.Token) (*OktaClaims, error) {
	claims, ok := token.Claims.(*OktaClaims)
	if !ok {
		p.logger.Error("Failed to extract JWT claims")
		return nil, NewRBACError(ErrCodeInvalidToken, "Invalid JWT claims structure", nil)
	}

	// Basic claims validation
	if claims.Subject == "" {
		return nil, NewRBACError(ErrCodeInvalidToken, "JWT claims missing required subject", nil)
	}

	if claims.Email == "" {
		return nil, NewRBACError(ErrCodeInvalidToken, "JWT claims missing required email", nil)
	}

	return claims, nil
}

// validateClaimsContent validates claims timing and expiration
func (p *OktaAuthProvider) validateClaimsContent(claims *OktaClaims) error {
	// Validate expiration time
	if claims.ExpiresAt != 0 && time.Unix(claims.ExpiresAt, 0).Before(time.Now()) {
		return NewRBACError(ErrCodeInvalidToken, "JWT token has expired", map[string]interface{}{
			"expiredAt": time.Unix(claims.ExpiresAt, 0),
			"now":       time.Now(),
		})
	}

	// Validate issued at time (not too far in the future)
	if claims.IssuedAt != 0 && time.Unix(claims.IssuedAt, 0).After(time.Now().Add(5*time.Minute)) {
		return NewRBACError(ErrCodeInvalidToken, "JWT token issued too far in the future", map[string]interface{}{
			"issuedAt": time.Unix(claims.IssuedAt, 0),
			"now":      time.Now(),
		})
	}

	return nil
}

// sanitizeErrorString safely sanitizes strings for use in error messages
func sanitizeErrorString(input string) string {
	if len(input) == 0 {
		return "empty"
	}

	// Replace potentially dangerous characters
	sanitized := strings.ReplaceAll(input, "\n", "\\n")
	sanitized = strings.ReplaceAll(sanitized, "\r", "\\r")
	sanitized = strings.ReplaceAll(sanitized, "\t", "\\t")
	sanitized = strings.ReplaceAll(sanitized, "\"", "\\\"")
	sanitized = strings.ReplaceAll(sanitized, "'", "\\'")

	// Limit length to prevent buffer overflow
	if len(sanitized) > 50 {
		sanitized = sanitized[:47] + "..."
	}

	return sanitized
}

// sanitizeDomainForURL safely validates and sanitizes domain names for URL construction
func sanitizeDomainForURL(domain string) string {
	// Validate basic domain requirements
	if err := validateDomainBasics(domain); err != "" {
		return err
	}

	// Validate domain character set
	if err := validateDomainCharacters(domain); err != "" {
		return err
	}

	// Validate domain format and security
	if err := validateDomainSecurity(domain); err != "" {
		return err
	}

	return domain
}

// validateDomainBasics validates basic domain requirements
func validateDomainBasics(domain string) string {
	if len(domain) == 0 {
		return "invalid-domain"
	}

	// Validate domain length
	if len(domain) > 253 {
		return "invalid-domain-too-long"
	}

	return ""
}

// validateDomainCharacters validates domain character set
func validateDomainCharacters(domain string) string {
	// Basic domain validation - only allow alphanumeric, dots, and hyphens
	for _, char := range domain {
		if !isValidDomainChar(char) {
			return "invalid-domain-chars"
		}
	}
	return ""
}

// isValidDomainChar checks if a character is valid for domain names
func isValidDomainChar(char rune) bool {
	return (char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') ||
		char == '.' || char == '-'
}

// validateDomainSecurity validates domain format for security
func validateDomainSecurity(domain string) string {
	// Additional security: prevent obvious injection attempts
	if strings.Contains(domain, "..") ||
		strings.Contains(domain, "//") ||
		strings.Contains(domain, "@") ||
		strings.Contains(domain, ":") {
		return "invalid-domain-format"
	}

	return ""
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
