package model

import "context"

type RuntimeConfig struct {
	AppURL                 string
	UUID                   string
	CookieDomain           string
	SessionCookieName      string
	OAuthSessionCookieName string
	ConsentCookieName      string
	LocalUsers             []LocalUser
	OAuthProviders         map[string]OAuthServiceConfig
	OAuthWhitelist         []string
	ConfiguredProviders    []Provider
	OIDCClients            []OIDCClientConfig
	TrustedDomains         []string
}

type RuntimeHelpers struct {
	GetCookieDomain func(ctx context.Context, ip string) (string, error)
}

type Provider struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	OAuth bool   `json:"oauth"`
}
