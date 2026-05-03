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

	// OIDC codes
	CreateOidcCode(ctx context.Context, arg CreateOidcCodeParams) (OidcCode, error)
	GetOidcCode(ctx context.Context, codeHash string) (OidcCode, error)
	GetOidcCodeBySub(ctx context.Context, sub string) (OidcCode, error)
	GetOidcCodeUnsafe(ctx context.Context, codeHash string) (OidcCode, error)
	GetOidcCodeBySubUnsafe(ctx context.Context, sub string) (OidcCode, error)
	DeleteOidcCode(ctx context.Context, codeHash string) error
	DeleteOidcCodeBySub(ctx context.Context, sub string) error
	DeleteExpiredOidcCodes(ctx context.Context, expiresAt int64) ([]OidcCode, error)

	// OIDC tokens
	CreateOidcToken(ctx context.Context, arg CreateOidcTokenParams) (OidcToken, error)
	GetOidcToken(ctx context.Context, accessTokenHash string) (OidcToken, error)
	GetOidcTokenByRefreshToken(ctx context.Context, refreshTokenHash string) (OidcToken, error)
	GetOidcTokenBySub(ctx context.Context, sub string) (OidcToken, error)
	UpdateOidcTokenByRefreshToken(ctx context.Context, arg UpdateOidcTokenByRefreshTokenParams) (OidcToken, error)
	DeleteOidcToken(ctx context.Context, accessTokenHash string) error
	DeleteOidcTokenBySub(ctx context.Context, sub string) error
	DeleteOidcTokenByCodeHash(ctx context.Context, codeHash string) error
	DeleteExpiredOidcTokens(ctx context.Context, arg DeleteExpiredOidcTokensParams) ([]OidcToken, error)

	// OIDC userinfo
	CreateOidcUserInfo(ctx context.Context, arg CreateOidcUserInfoParams) (OidcUserinfo, error)
	GetOidcUserInfo(ctx context.Context, sub string) (OidcUserinfo, error)
	DeleteOidcUserInfo(ctx context.Context, sub string) error
}
