package service

import (
	"github.com/tinyauthapp/tinyauth/internal/model"
	"golang.org/x/oauth2/endpoints"
)

func newGoogleOAuthService(config model.OAuthServiceConfig) *OAuthService {
	scopes := []string{"openid", "email", "profile"}
	config.Scopes = scopes
	config.AuthURL = endpoints.Google.AuthURL
	config.TokenURL = endpoints.Google.TokenURL
	config.UserinfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
	return NewOAuthService(config, "google")
}

func newGitHubOAuthService(config model.OAuthServiceConfig) *OAuthService {
	scopes := []string{"read:user", "user:email"}
	config.Scopes = scopes
	config.AuthURL = endpoints.GitHub.AuthURL
	config.TokenURL = endpoints.GitHub.TokenURL
	return NewOAuthService(config, "github").WithUserinfoExtractor(githubExtractor)
}
