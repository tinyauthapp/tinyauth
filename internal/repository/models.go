package repository

// Shared model and parameter types for all storage drivers.
// sqlc-generated driver packages use these via the conversion layer in their store.go.

// Users

type User struct {
	UUID     string
	Username string
	Email    string
	Name     string
}

type CreateUserParams struct {
	UUID     string
	Username string
	Email    string
	Name     string
}

type UpdateUserParams struct {
	Username string
	Email    string
	Name     string
	UUID     string
}

type GetUserByUsernameAndEmailParams struct {
	Username string
	Email    string
}

// Identities

type Identity struct {
	UUID           string
	UserUUID       string
	ProviderType   string
	Provider       string
	ProviderUserID string
	ContextJSON    string
}

type CreateIdentityParams struct {
	UUID           string
	UserUUID       string
	ProviderType   string
	Provider       string
	ProviderUserID string
	ContextJSON    string
}

// Sessions

type Session struct {
	UUID         string
	IdentityUUID string
	ExpiresAt    int64
	CreatedAt    int64
	ContextJSON  string
}

type CreateSessionParams struct {
	UUID         string
	IdentityUUID string
	ExpiresAt    int64
	CreatedAt    int64
	ContextJSON  string
}

type UpdateSessionByUUIDParams struct {
	ExpiresAt   int64
	ContextJSON string
	UUID        string
}

// OIDC

type OIDCSession struct {
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

// OIDC Consent

type OIDCConsent struct {
	Username  string
	ClientID  string
	Scope     string
	CreatedAt int64
}

type UpsertOIDCConsentParams struct {
	Username  string
	ClientID  string
	Scope     string
	CreatedAt int64
}

type GetOIDCConsentByUsernameAndClientIDParams struct {
	Username string
	ClientID string
}
