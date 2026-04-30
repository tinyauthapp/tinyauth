package repository

// This file is a stop-gap until more drivers are added. It re-exports the models from the sqlite package so that the rest
// of the codebase can import them from a single location without needing to know about the underlying database implementation.

import "github.com/tinyauthapp/tinyauth/internal/repository/sqlite"

type Session = sqlite.Session
type OidcCode = sqlite.OidcCode
type OidcToken = sqlite.OidcToken
type OidcUserinfo = sqlite.OidcUserinfo

type CreateSessionParams = sqlite.CreateSessionParams
type UpdateSessionParams = sqlite.UpdateSessionParams
type CreateOidcCodeParams = sqlite.CreateOidcCodeParams
type CreateOidcTokenParams = sqlite.CreateOidcTokenParams
type UpdateOidcTokenByRefreshTokenParams = sqlite.UpdateOidcTokenByRefreshTokenParams
type DeleteExpiredOidcTokensParams = sqlite.DeleteExpiredOidcTokensParams
type CreateOidcUserInfoParams = sqlite.CreateOidcUserInfoParams
