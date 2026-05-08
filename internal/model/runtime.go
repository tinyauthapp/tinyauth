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
}

type Provider struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	OAuth bool   `json:"oauth"`
}
