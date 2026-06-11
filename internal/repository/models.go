package repository

import "time"

// Shared model and parameter types for all storage drivers.
// sqlc-generated driver packages use these via the conversion layer in their store.go.

type OidcConsent struct {
	UUID      string
	ClientID  string
	Scopes    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Session struct {
	UUID        string
	Username    string
	Email       string
	Name        string
	Provider    string
	TotpPending bool
	OAuthGroups string
	Expiry      int64
	CreatedAt   int64
	OAuthName   string
	OAuthSub    string
}

type OidcSession struct {
	Sub                   string
	AccessTokenHash       string
	RefreshTokenHash      string
	Scope                 string
	ClientID              string
	TokenExpiresAt        int64
	RefreshTokenExpiresAt int64
	Nonce                 string
	UserinfoJson          string
}

type CreateSessionParams struct {
	UUID        string
	Username    string
	Email       string
	Name        string
	Provider    string
	TotpPending bool
	OAuthGroups string
	Expiry      int64
	CreatedAt   int64
	OAuthName   string
	OAuthSub    string
}

type UpdateSessionParams struct {
	Username    string
	Email       string
	Name        string
	Provider    string
	TotpPending bool
	OAuthGroups string
	Expiry      int64
	OAuthName   string
	OAuthSub    string
	UUID        string
}

type CreateOIDCSessionParams struct {
	Sub                   string
	AccessTokenHash       string
	RefreshTokenHash      string
	Scope                 string
	ClientID              string
	TokenExpiresAt        int64
	RefreshTokenExpiresAt int64
	Nonce                 string
	UserinfoJson          string
}

type UpdateOIDCSessionParams struct {
	AccessTokenHash       string
	RefreshTokenHash      string
	Scope                 string
	ClientID              string
	TokenExpiresAt        int64
	RefreshTokenExpiresAt int64
	Nonce                 string
	UserinfoJson          string
	Sub                   string
}

type DeleteExpiredOIDCSessionsParams struct {
	TokenExpiresAt        int64
	RefreshTokenExpiresAt int64
}

type CreateOIDCConsentParams struct {
	UUID     string
	ClientID string
	Scopes   string
}

type UpdateOIDCConsentParams struct {
	Scopes string
	UUID   string
}
