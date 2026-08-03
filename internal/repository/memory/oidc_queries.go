package memory

import (
	"context"
	"fmt"

	"github.com/tinyauthapp/tinyauth/internal/repository"
)

func (s *Store) CreateOIDCSession(_ context.Context, arg repository.CreateOIDCSessionParams) (repository.OidcSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Enforce UNIQUE constraints (sub is the primary key, access/refresh token hashes are unique).
	for _, sess := range s.oidcSessions {
		switch {
		case sess.Sub == arg.Sub:
			return repository.OidcSession{}, fmt.Errorf("UNIQUE constraint failed: oidc_sessions.sub")
		case sess.AccessTokenHash == arg.AccessTokenHash:
			return repository.OidcSession{}, fmt.Errorf("UNIQUE constraint failed: oidc_sessions.access_token_hash")
		case sess.RefreshTokenHash == arg.RefreshTokenHash:
			return repository.OidcSession{}, fmt.Errorf("UNIQUE constraint failed: oidc_sessions.refresh_token_hash")
		}
	}
	sess := repository.OidcSession(arg)
	s.oidcSessions[arg.Sub] = sess
	return sess, nil
}

func (s *Store) GetOIDCSessionBySub(_ context.Context, sub string) (repository.OidcSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.oidcSessions[sub]
	if !ok {
		return repository.OidcSession{}, repository.ErrNotFound
	}
	return sess, nil
}

func (s *Store) GetOIDCSessionByAccessTokenHash(_ context.Context, accessTokenHash string) (repository.OidcSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.oidcSessions {
		if sess.AccessTokenHash == accessTokenHash {
			return sess, nil
		}
	}
	return repository.OidcSession{}, repository.ErrNotFound
}

func (s *Store) GetOIDCSessionByRefreshTokenHash(_ context.Context, refreshTokenHash string) (repository.OidcSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.oidcSessions {
		if sess.RefreshTokenHash == refreshTokenHash {
			return sess, nil
		}
	}
	return repository.OidcSession{}, repository.ErrNotFound
}

func (s *Store) UpdateOIDCSession(_ context.Context, arg repository.UpdateOIDCSessionParams) (repository.OidcSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.oidcSessions[arg.Sub]
	if !ok {
		return repository.OidcSession{}, repository.ErrNotFound
	}
	sess.AccessTokenHash = arg.AccessTokenHash
	sess.RefreshTokenHash = arg.RefreshTokenHash
	sess.Scope = arg.Scope
	sess.ClientID = arg.ClientID
	sess.TokenExpiresAt = arg.TokenExpiresAt
	sess.RefreshTokenExpiresAt = arg.RefreshTokenExpiresAt
	sess.Nonce = arg.Nonce
	sess.UserinfoJson = arg.UserinfoJson
	s.oidcSessions[arg.Sub] = sess
	return sess, nil
}

func (s *Store) DeleteOIDCSessionBySub(_ context.Context, sub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.oidcSessions, sub)
	return nil
}

func (s *Store) DeleteExpiredOIDCSessions(_ context.Context, arg repository.DeleteExpiredOIDCSessionsParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, sess := range s.oidcSessions {
		if sess.TokenExpiresAt < arg.TokenExpiresAt && sess.RefreshTokenExpiresAt < arg.RefreshTokenExpiresAt {
			delete(s.oidcSessions, k)
		}
	}
	return nil
}
