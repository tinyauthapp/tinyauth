package model

const DefaultNamePrefix = "TINYAUTH_"

const APIServer = "https://api.tinyauth.app"

type Claims struct {
	Sub               string `json:"sub"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Groups            any    `json:"groups"`
}

var OverrideProviders = map[string]string{
	"google": "Google",
	"github": "GitHub",
}

const SessionCookieName = "tinyauth-session"
const OAuthSessionCookieName = "tinyauth-oauth"
const ConsentCookieName = "tinyauth-consent"

const GracefulShutdownTimeout = 5 // seconds
