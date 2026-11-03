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
	// Users
	CreateUser(ctx context.Context, arg CreateUserParams) (User, error)
	GetUserByUUID(ctx context.Context, uuid string) (User, error)

	// Identities
	CreateIdentity(ctx context.Context, arg CreateIdentityParams) (Identity, error)
	GetIdentityByUUID(ctx context.Context, uuid string) (Identity, error)

	// Sessions
	CreateSession(ctx context.Context, arg CreateSessionParams) (Session, error)
	DeleteExpiredSessions(ctx context.Context, expiresAt int64) error
	DeleteSessionByUUID(ctx context.Context, uuid string) error
	GetSessionByUUID(ctx context.Context, uuid string) (Session, error)

	// OIDC
	CreateOIDCSession(ctx context.Context, arg CreateOIDCSessionParams) (OIDCSession, error)
	DeleteExpiredOIDCSessions(ctx context.Context, arg DeleteExpiredOIDCSessionsParams) error
	DeleteOIDCSessionBySub(ctx context.Context, sub string) error
	GetOIDCSessionByRefreshTokenHash(ctx context.Context, refreshTokenHash string) (OIDCSession, error)
	GetOIDCSessionBySub(ctx context.Context, sub string) (OIDCSession, error)
	UpdateOIDCSession(ctx context.Context, arg UpdateOIDCSessionParams) (OIDCSession, error)

	// OIDC Consent
	DeleteOIDCConsentByClientID(ctx context.Context, clientID string) error
	GetOIDCConsentByUsernameAndClientID(ctx context.Context, arg GetOIDCConsentByUsernameAndClientIDParams) (OIDCConsent, error)
	ListOIDCConsents(ctx context.Context) ([]OIDCConsent, error)
	UpsertOIDCConsent(ctx context.Context, arg UpsertOIDCConsentParams) (OIDCConsent, error)
}
