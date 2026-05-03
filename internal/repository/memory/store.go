// Package memory provides an in-memory implementation of repository.Store for use in tests.
package memory

import (
	"sync"

	"github.com/tinyauthapp/tinyauth/internal/repository"
)

// Store is a thread-safe in-memory implementation of repository.Store.
type Store struct {
	mu         sync.RWMutex
	sessions   map[string]repository.Session
	oidcCodes  map[string]repository.OidcCode
	oidcTokens map[string]repository.OidcToken
	oidcUsers  map[string]repository.OidcUserinfo
}

// New returns a new empty in-memory Store.
func New() repository.Store {
	return &Store{
		sessions:   make(map[string]repository.Session),
		oidcCodes:  make(map[string]repository.OidcCode),
		oidcTokens: make(map[string]repository.OidcToken),
		oidcUsers:  make(map[string]repository.OidcUserinfo),
	}
}
