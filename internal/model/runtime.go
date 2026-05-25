package model

type RuntimeConfig struct {
	AppURL                 string
	UUID                   string
	CookieDomain           string
	SessionCookieName      string
	CSRFCookieName         string
	RedirectCookieName     string
	OAuthSessionCookieName string
	LocalUsers             []LocalUser
	OAuthProviders         map[string]OAuthServiceConfig
	OAuthWhitelist         []string
	ConfiguredProviders    []Provider
	OIDCClients            []OIDCClientConfig
	TrustedDomains         []string
	Policy                 Policy
}

type Provider struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	OAuth bool   `json:"oauth"`
}

type Policy string

const (
	PolicyAllow Policy = "allow"
	PolicyDeny  Policy = "deny"
)
