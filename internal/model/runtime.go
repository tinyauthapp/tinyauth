package model

import (
	"fmt"

	"github.com/tinyauthapp/tinyauth/internal/repository"
)

type RuntimeConfig struct {
	AppURL                   string
	UUID                     string
	CookieDomain             string
	SessionCookieName        string
	OAuthFlowCookieName      string
	LocalUsers               []LocalUser
	OAuthProviders           map[string]OAuthServiceConfig
	OAuthWhitelist           []string
	ConfiguredProviders      []Provider
	TrustedProxiesConfigured bool
}

type Provider struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	OAuth bool   `json:"oauth"`
}

type LinkingMode string

const (
	LinkingModeEmail    LinkingMode = "email"
	LinkingModeUsername LinkingMode = "username"
	LinkingModeBoth     LinkingMode = "both"
)

func (l LinkingMode) String() string {
	return string(l)
}

func LinkingModeFromString(s string) (LinkingMode, error) {
	switch s {
	case "email":
		return LinkingModeEmail, nil
	case "username":
		return LinkingModeUsername, nil
	case "both":
		return LinkingModeBoth, nil
	default:
		return LinkingModeBoth, fmt.Errorf("invalid linking mode: %s", s)
	}
}

type IdentityResult struct {
	// User information
	Username string
	Email    string
	Name     string

	// Identity information
	Provider       string
	ProviderType   ProviderType
	ProviderUserID string

	// Context information
	IdentityContext IdentityContext
}

type IdentityLocalContext struct {
	Attributes UserAttributes `json:"attributes"`
}

type IdentityOAuthContext struct {
	Groups      string `json:"groups"`
	DisplayName string `json:"display_name"`
}

type IdentityLDAPContext struct {
	Groups []string `json:"groups"`
}

type IdentityTailscaleContext struct {
	NodeName string `json:"node_name"`
}

type IdentityContext struct {
	Local     IdentityLocalContext     `json:"local"`
	OAuth     IdentityOAuthContext     `json:"oauth"`
	LDAP      IdentityLDAPContext      `json:"ldap"`
	Tailscale IdentityTailscaleContext `json:"tailscale"`
}

type SessionLocalContext struct {
	TOTPPending bool `json:"totp_pending"`
}

type SessionContext struct {
	Local SessionLocalContext `json:"local"`
}

type SessionGetResult struct {
	Session        repository.Session
	SessionContext SessionContext
}
