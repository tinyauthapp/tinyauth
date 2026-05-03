package memory

import (
	"context"
	"fmt"

	"github.com/tinyauthapp/tinyauth/internal/repository"
)

func (s *Store) CreateOidcCode(_ context.Context, arg repository.CreateOidcCodeParams) (repository.OidcCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Enforce sub UNIQUE constraint
	for _, c := range s.oidcCodes {
		if c.Sub == arg.Sub {
			return repository.OidcCode{}, fmt.Errorf("UNIQUE constraint failed: oidc_codes.sub")
		}
	}
	code := repository.OidcCode(arg)
	s.oidcCodes[arg.CodeHash] = code
	return code, nil
}

// GetOidcCode is a destructive read: it deletes and returns the code (mirrors SQLite's DELETE...RETURNING).
func (s *Store) GetOidcCode(_ context.Context, codeHash string) (repository.OidcCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.oidcCodes[codeHash]
	if !ok {
		return repository.OidcCode{}, repository.ErrNotFound
	}
	delete(s.oidcCodes, codeHash)
	return c, nil
}

// GetOidcCodeBySub is a destructive read: it deletes and returns the code (mirrors SQLite's DELETE...RETURNING).
func (s *Store) GetOidcCodeBySub(_ context.Context, sub string) (repository.OidcCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.oidcCodes {
		if c.Sub == sub {
			delete(s.oidcCodes, k)
			return c, nil
		}
	}
	return repository.OidcCode{}, repository.ErrNotFound
}

// GetOidcCodeUnsafe is a non-destructive read (mirrors SQLite's SELECT).
func (s *Store) GetOidcCodeUnsafe(_ context.Context, codeHash string) (repository.OidcCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.oidcCodes[codeHash]
	if !ok {
		return repository.OidcCode{}, repository.ErrNotFound
	}
	return c, nil
}

// GetOidcCodeBySubUnsafe is a non-destructive read (mirrors SQLite's SELECT).
func (s *Store) GetOidcCodeBySubUnsafe(_ context.Context, sub string) (repository.OidcCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.oidcCodes {
		if c.Sub == sub {
			return c, nil
		}
	}
	return repository.OidcCode{}, repository.ErrNotFound
}

func (s *Store) DeleteOidcCode(_ context.Context, codeHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.oidcCodes, codeHash)
	return nil
}

func (s *Store) DeleteOidcCodeBySub(_ context.Context, sub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.oidcCodes {
		if c.Sub == sub {
			delete(s.oidcCodes, k)
		}
	}
	return nil
}

func (s *Store) DeleteExpiredOidcCodes(_ context.Context, expiresAt int64) ([]repository.OidcCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var deleted []repository.OidcCode
	for k, c := range s.oidcCodes {
		if c.ExpiresAt < expiresAt {
			deleted = append(deleted, c)
			delete(s.oidcCodes, k)
		}
	}
	return deleted, nil
}

func (s *Store) CreateOidcToken(_ context.Context, arg repository.CreateOidcTokenParams) (repository.OidcToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Enforce sub UNIQUE constraint
	for _, t := range s.oidcTokens {
		if t.Sub == arg.Sub {
			return repository.OidcToken{}, fmt.Errorf("UNIQUE constraint failed: oidc_tokens.sub")
		}
	}
	tok := repository.OidcToken{
		Sub:                   arg.Sub,
		AccessTokenHash:       arg.AccessTokenHash,
		RefreshTokenHash:      arg.RefreshTokenHash,
		CodeHash:              arg.CodeHash,
		Scope:                 arg.Scope,
		ClientID:              arg.ClientID,
		TokenExpiresAt:        arg.TokenExpiresAt,
		RefreshTokenExpiresAt: arg.RefreshTokenExpiresAt,
		Nonce:                 arg.Nonce,
	}
	s.oidcTokens[arg.AccessTokenHash] = tok
	return tok, nil
}

func (s *Store) GetOidcToken(_ context.Context, accessTokenHash string) (repository.OidcToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.oidcTokens[accessTokenHash]
	if !ok {
		return repository.OidcToken{}, repository.ErrNotFound
	}
	return t, nil
}

func (s *Store) GetOidcTokenByRefreshToken(_ context.Context, refreshTokenHash string) (repository.OidcToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.oidcTokens {
		if t.RefreshTokenHash == refreshTokenHash {
			return t, nil
		}
	}
	return repository.OidcToken{}, repository.ErrNotFound
}

func (s *Store) GetOidcTokenBySub(_ context.Context, sub string) (repository.OidcToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.oidcTokens {
		if t.Sub == sub {
			return t, nil
		}
	}
	return repository.OidcToken{}, repository.ErrNotFound
}

func (s *Store) UpdateOidcTokenByRefreshToken(_ context.Context, arg repository.UpdateOidcTokenByRefreshTokenParams) (repository.OidcToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.oidcTokens {
		if t.RefreshTokenHash == arg.RefreshTokenHash_2 {
			delete(s.oidcTokens, k)
			t.AccessTokenHash = arg.AccessTokenHash
			t.RefreshTokenHash = arg.RefreshTokenHash
			t.TokenExpiresAt = arg.TokenExpiresAt
			t.RefreshTokenExpiresAt = arg.RefreshTokenExpiresAt
			s.oidcTokens[arg.AccessTokenHash] = t
			return t, nil
		}
	}
	return repository.OidcToken{}, repository.ErrNotFound
}

func (s *Store) DeleteOidcToken(_ context.Context, accessTokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.oidcTokens, accessTokenHash)
	return nil
}

func (s *Store) DeleteOidcTokenBySub(_ context.Context, sub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.oidcTokens {
		if t.Sub == sub {
			delete(s.oidcTokens, k)
		}
	}
	return nil
}

func (s *Store) DeleteOidcTokenByCodeHash(_ context.Context, codeHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.oidcTokens {
		if t.CodeHash == codeHash {
			delete(s.oidcTokens, k)
		}
	}
	return nil
}

func (s *Store) DeleteExpiredOidcTokens(_ context.Context, arg repository.DeleteExpiredOidcTokensParams) ([]repository.OidcToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var deleted []repository.OidcToken
	for k, t := range s.oidcTokens {
		if t.TokenExpiresAt < arg.TokenExpiresAt || t.RefreshTokenExpiresAt < arg.RefreshTokenExpiresAt {
			deleted = append(deleted, t)
			delete(s.oidcTokens, k)
		}
	}
	return deleted, nil
}

func (s *Store) CreateOidcUserInfo(_ context.Context, arg repository.CreateOidcUserInfoParams) (repository.OidcUserinfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := repository.OidcUserinfo(arg)
	s.oidcUsers[arg.Sub] = u
	return u, nil
}

func (s *Store) GetOidcUserInfo(_ context.Context, sub string) (repository.OidcUserinfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.oidcUsers[sub]
	if !ok {
		return repository.OidcUserinfo{}, repository.ErrNotFound
	}
	return u, nil
}

func (s *Store) DeleteOidcUserInfo(_ context.Context, sub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.oidcUsers, sub)
	return nil
}
