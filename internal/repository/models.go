package repository

// Shared model and parameter types for all storage drivers.
// sqlc-generated driver packages use these via the conversion layer in their store.go.

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

type OidcCode struct {
	Sub           string
	CodeHash      string
	Scope         string
	RedirectURI   string
	ClientID      string
	ExpiresAt     int64
	Nonce         string
	CodeChallenge string
}

type OidcToken struct {
	Sub                   string
	AccessTokenHash       string
	RefreshTokenHash      string
	CodeHash              string
	Scope                 string
	ClientID              string
	TokenExpiresAt        int64
	RefreshTokenExpiresAt int64
	Nonce                 string
}

type OidcUserinfo struct {
	Sub               string
	Name              string
	PreferredUsername string
	Email             string
	Groups            string
	UpdatedAt         int64
	GivenName         string
	FamilyName        string
	MiddleName        string
	Nickname          string
	Profile           string
	Picture           string
	Website           string
	Gender            string
	Birthdate         string
	Zoneinfo          string
	Locale            string
	PhoneNumber       string
	Address           string
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

type CreateOidcCodeParams struct {
	Sub           string
	CodeHash      string
	Scope         string
	RedirectURI   string
	ClientID      string
	ExpiresAt     int64
	Nonce         string
	CodeChallenge string
}

type CreateOidcTokenParams struct {
	Sub                   string
	AccessTokenHash       string
	RefreshTokenHash      string
	Scope                 string
	ClientID              string
	TokenExpiresAt        int64
	RefreshTokenExpiresAt int64
	CodeHash              string
	Nonce                 string
}

type UpdateOidcTokenByRefreshTokenParams struct {
	AccessTokenHash       string
	RefreshTokenHash      string
	TokenExpiresAt        int64
	RefreshTokenExpiresAt int64
	RefreshTokenHash_2    string
}

type DeleteExpiredOidcTokensParams struct {
	TokenExpiresAt        int64
	RefreshTokenExpiresAt int64
}

type CreateOidcUserInfoParams struct {
	Sub               string
	Name              string
	PreferredUsername string
	Email             string
	Groups            string
	UpdatedAt         int64
	GivenName         string
	FamilyName        string
	MiddleName        string
	Nickname          string
	Profile           string
	Picture           string
	Website           string
	Gender            string
	Birthdate         string
	Zoneinfo          string
	Locale            string
	PhoneNumber       string
	Address           string
}
