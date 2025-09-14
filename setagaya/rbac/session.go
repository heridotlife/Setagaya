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

// Set stores session data with the given TTL
func (s *MemorySessionStore) Set(ctx context.Context, sessionID string, data interface{}, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[sessionID] = &sessionEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}

	s.logger.Debug("Session stored", "sessionID", sessionID, "ttl", ttl)
	return nil
}

// Get retrieves session data by session ID
func (s *MemorySessionStore) Get(ctx context.Context, sessionID string) (interface{}, error) {
	// Validate session ID format to prevent injection attacks
	if len(sessionID) == 0 || len(sessionID) > 256 {
		return nil, NewRBACError(ErrCodeInvalidSession, "Invalid session ID format", map[string]interface{}{
			"sessionIDLength": len(sessionID),
		})
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.sessions[sessionID]
	if !exists {
		// Don't leak information about session existence
		return nil, NewRBACError(ErrCodeSessionNotFound, "Session not found", nil)
	}

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		s.mu.RUnlock()
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
		s.mu.RLock()

		return nil, NewRBACError(ErrCodeSessionExpired, "Session expired", nil)
	}

	s.logger.Debug("Session retrieved", "sessionID", sessionID[:minInt(8, len(sessionID))]+"...")
	return entry.data, nil
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Delete removes a session by session ID
func (s *MemorySessionStore) Delete(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, sessionID)
	s.logger.Debug("Session deleted", "sessionID", sessionID)
	return nil
}

// Cleanup removes all expired sessions
func (s *MemorySessionStore) Cleanup(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	expiredCount := 0

	for sessionID, entry := range s.sessions {
		if now.After(entry.expiresAt) {
			delete(s.sessions, sessionID)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		s.logger.Debug("Cleaned up expired sessions", "count", expiredCount)
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
