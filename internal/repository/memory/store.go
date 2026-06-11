// Package memory provides an in-memory implementation of repository.Store for use in tests.
package memory

import (
	"sync"

	"github.com/tinyauthapp/tinyauth/internal/repository"
)

// Store is a thread-safe in-memory implementation of repository.Store.
type Store struct {
	mu           sync.RWMutex
	sessions     map[string]repository.Session
	oidcSessions map[string]repository.OidcSession
	oidcConsent  map[string]repository.OidcConsent
}

// New returns a new empty in-memory Store.
func New() repository.Store {
	return &Store{
		sessions:     make(map[string]repository.Session),
		oidcSessions: make(map[string]repository.OidcSession),
		oidcConsent:  make(map[string]repository.OidcConsent),
	}
}
