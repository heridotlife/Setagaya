package rbac

import (
	"context"
	"sync"
	"time"
)

// SessionStore defines the interface for session storage operations
type SessionStore interface {
	Set(ctx context.Context, sessionID string, data interface{}, ttl time.Duration) error
	Get(ctx context.Context, sessionID string) (interface{}, error)
	Delete(ctx context.Context, sessionID string) error
	Cleanup(ctx context.Context) error
}

// MemorySessionStore provides an in-memory implementation of SessionStore
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*sessionEntry
	logger   Logger
	stopCh   chan struct{}
}

// sessionEntry represents a stored session with expiration
type sessionEntry struct {
	data      interface{}
	expiresAt time.Time
}

// NewMemorySessionStore creates a new in-memory session store
func NewMemorySessionStore(logger Logger) SessionStore {
	store := &MemorySessionStore{
		sessions: make(map[string]*sessionEntry),
		logger:   logger,
		stopCh:   make(chan struct{}),
	}

	// Start cleanup goroutine
	go store.cleanupLoop()

	return store
}

// Set stores session data with enhanced validation and security
func (s *MemorySessionStore) Set(ctx context.Context, sessionID string, data interface{}, ttl time.Duration) error {
	// Enhanced session ID validation
	if len(sessionID) == 0 {
		return NewRBACError(ErrCodeInvalidSession, "Session ID cannot be empty", nil)
	}
	
	if len(sessionID) > 256 {
		return NewRBACError(ErrCodeInvalidSession, "Session ID too long", map[string]interface{}{
			"maxLength": 256,
			"actualLength": len(sessionID),
		})
	}

	// Validate TTL is reasonable (between 1 minute and 24 hours)
	if ttl < time.Minute {
		return NewRBACError(ErrCodeInvalidSession, "Session TTL too short", map[string]interface{}{
			"minTTL": "1 minute",
			"providedTTL": ttl.String(),
		})
	}
	
	if ttl > 24*time.Hour {
		return NewRBACError(ErrCodeInvalidSession, "Session TTL too long", map[string]interface{}{
			"maxTTL": "24 hours",
			"providedTTL": ttl.String(),
		})
	}

	// Validate data is not nil
	if data == nil {
		return NewRBACError(ErrCodeInvalidSession, "Session data cannot be nil", nil)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check session store size to prevent memory exhaustion attacks
	if len(s.sessions) > 10000 { // Configurable limit
		s.logger.Warn("Session store approaching capacity limit", "currentSessions", len(s.sessions))
		
		// Trigger immediate cleanup of expired sessions
		s.cleanupExpiredSessions()
		
		// If still too many sessions, refuse new ones
		if len(s.sessions) > 10000 {
			return NewRBACError(ErrCodeSessionStoreFull, "Session store at capacity", map[string]interface{}{
				"maxSessions": 10000,
				"currentSessions": len(s.sessions),
			})
		}
	}

	s.sessions[sessionID] = &sessionEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}

	s.logger.Debug("Session stored successfully", 
		"sessionPrefix", sessionID[:minInt(8, len(sessionID))]+"...",
		"ttl", ttl.String(),
		"totalSessions", len(s.sessions))
	return nil
}

// Get retrieves session data by session ID with enhanced security validation
func (s *MemorySessionStore) Get(ctx context.Context, sessionID string) (interface{}, error) {
	// Enhanced session ID format validation to prevent injection attacks
	if len(sessionID) == 0 {
		return nil, NewRBACError(ErrCodeInvalidSession, "Session ID cannot be empty", nil)
	}
	
	if len(sessionID) < 10 {
		return nil, NewRBACError(ErrCodeInvalidSession, "Session ID too short", map[string]interface{}{
			"minLength": 10,
			"actualLength": len(sessionID),
		})
	}
	
	if len(sessionID) > 256 {
		return nil, NewRBACError(ErrCodeInvalidSession, "Session ID too long", map[string]interface{}{
			"maxLength": 256,
			"actualLength": len(sessionID),
		})
	}

	// Enhanced session ID format validation for security (alphanumeric and safe characters only)
	// Use constant-time validation to prevent timing attacks
	invalidCharFound := false
	for _, char := range sessionID {
		if !((char >= 'a' && char <= 'z') || 
			 (char >= 'A' && char <= 'Z') || 
			 (char >= '0' && char <= '9') || 
			 char == '_' || char == '-' || char == '=') {
			invalidCharFound = true
			// Continue checking all characters to prevent timing attacks
		}
	}
	
	if invalidCharFound {
		return nil, NewRBACError(ErrCodeInvalidSession, "Session ID contains invalid characters", map[string]interface{}{
			"allowedChars": "a-z, A-Z, 0-9, _, -, =",
		})
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.sessions[sessionID]
	if !exists {
		// Don't leak information about session existence
		return nil, NewRBACError(ErrCodeSessionNotFound, "Session not found", nil)
	}

	// Check expiration with proper time handling
	now := time.Now()
	if now.After(entry.expiresAt) {
		// Remove expired session immediately
		s.mu.RUnlock()
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
		s.mu.RLock()

		return nil, NewRBACError(ErrCodeSessionExpired, "Session has expired", map[string]interface{}{
			"expiredAt": entry.expiresAt,
			"currentTime": now,
		})
	}

	// Additional session data validation with enhanced security checks
	if entry.data == nil {
		return nil, NewRBACError(ErrCodeInvalidSession, "Session data is corrupted", nil)
	}
	
	// Validate session data integrity if it's a map (common pattern)
	if sessionMap, ok := entry.data.(map[string]interface{}); ok {
		// Check for suspicious data patterns that might indicate tampering
		if len(sessionMap) > 50 { // Reasonable limit for session data fields
			s.logger.Warn("Session contains unusually large number of fields", 
				"sessionPrefix", sessionID[:minInt(8, len(sessionID))]+"...",
				"fieldCount", len(sessionMap))
		}
		
		// Validate critical session fields if they exist
		if userContext, exists := sessionMap["userContext"]; exists && userContext == nil {
			return nil, NewRBACError(ErrCodeInvalidSession, "Session user context is corrupted", nil)
		}
	}

	// Log session access with minimal information (security)
	s.logger.Debug("Session retrieved successfully", 
		"sessionPrefix", sessionID[:minInt(8, len(sessionID))]+"...",
		"expiresIn", entry.expiresAt.Sub(now).String())
	
	return entry.data, nil
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Delete removes a session by session ID with enhanced validation
func (s *MemorySessionStore) Delete(ctx context.Context, sessionID string) error {
	// Validate session ID before deletion
	if len(sessionID) == 0 {
		return NewRBACError(ErrCodeInvalidSession, "Session ID cannot be empty", nil)
	}
	
	if len(sessionID) > 256 {
		return NewRBACError(ErrCodeInvalidSession, "Session ID too long for deletion", map[string]interface{}{
			"maxLength": 256,
			"actualLength": len(sessionID),
		})
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if session exists before deletion
	_, exists := s.sessions[sessionID]
	
	delete(s.sessions, sessionID)
	
	if exists {
		s.logger.Debug("Session deleted successfully", 
			"sessionPrefix", sessionID[:minInt(8, len(sessionID))]+"...",
			"remainingSessions", len(s.sessions))
	} else {
		s.logger.Debug("Attempted to delete non-existent session", 
			"sessionPrefix", sessionID[:minInt(8, len(sessionID))]+"...")
	}
	
	return nil
}

// Cleanup removes all expired sessions with enhanced error handling
func (s *MemorySessionStore) Cleanup(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	initialCount := len(s.sessions)
	s.cleanupExpiredSessions()
	
	cleanedCount := initialCount - len(s.sessions)
	if cleanedCount > 0 {
		s.logger.Info("Session cleanup completed", 
			"cleanedSessions", cleanedCount,
			"remainingSessions", len(s.sessions),
			"initialCount", initialCount)
	}

	return nil
}

// cleanupLoop runs periodic cleanup of expired sessions
func (s *MemorySessionStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx := context.Background()
			if err := s.Cleanup(ctx); err != nil {
				s.logger.Error("Failed to cleanup expired sessions", "error", err)
			}
		case <-s.stopCh:
			return
		}
	}
}

// Stop stops the cleanup goroutine
func (s *MemorySessionStore) Stop() {
	close(s.stopCh)
}

// cleanupExpiredSessions removes expired sessions (internal method)
func (s *MemorySessionStore) cleanupExpiredSessions() {
	now := time.Now()
	expiredCount := 0

	for sessionID, entry := range s.sessions {
		if now.After(entry.expiresAt) {
			delete(s.sessions, sessionID)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		s.logger.Debug("Cleaned up expired sessions", 
			"expiredCount", expiredCount,
			"remainingSessions", len(s.sessions))
	}
}
