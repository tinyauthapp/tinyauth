package repository

import (
	"context"
	"errors"
)

// ErrNotFound is returned by Store methods when the requested record does not exist.
var ErrNotFound = errors.New("not found")

// Store is the interface that all storage drivers must implement.
// The sqlc-generated *Queries struct satisfies this interface for SQLite.
// Future drivers (postgres, etc.) must return the shared types defined in this package.
type Store interface {
	// Sessions
	CreateSession(ctx context.Context, arg CreateSessionParams) (Session, error)
	GetSession(ctx context.Context, uuid string) (Session, error)
	UpdateSession(ctx context.Context, arg UpdateSessionParams) (Session, error)
	DeleteSession(ctx context.Context, uuid string) error
	DeleteExpiredSessions(ctx context.Context, expiry int64) error

	// OIDC sessions
	CreateOIDCSession(ctx context.Context, arg CreateOIDCSessionParams) (OidcSession, error)
	DeleteExpiredOIDCSessions(ctx context.Context, arg DeleteExpiredOIDCSessionsParams) error
	DeleteOIDCSessionBySub(ctx context.Context, sub string) error
	GetOIDCSessionByAccessTokenHash(ctx context.Context, accessTokenHash string) (OidcSession, error)
	GetOIDCSessionByRefreshTokenHash(ctx context.Context, refreshTokenHash string) (OidcSession, error)
	GetOIDCSessionBySub(ctx context.Context, sub string) (OidcSession, error)
	UpdateOIDCSession(ctx context.Context, arg UpdateOIDCSessionParams) (OidcSession, error)

	// OIDC consents
	CreateOIDCConsent(ctx context.Context, arg CreateOIDCConsentParams) (OidcConsent, error)
	DeleteOIDCConsentByUUID(ctx context.Context, uuid string) error
	GetOIDCConsentByUUID(ctx context.Context, uuid string) (OidcConsent, error)
	UpdateOIDCConsent(ctx context.Context, arg UpdateOIDCConsentParams) (OidcConsent, error)
}
