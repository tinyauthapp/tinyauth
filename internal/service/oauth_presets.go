package service

import (
	"context"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"golang.org/x/oauth2/endpoints"
)

func newGoogleOAuthService(config model.OAuthServiceConfig, ctx context.Context) *OAuthService {
	scopes := []string{"openid", "email", "profile"}
	config.Scopes = scopes
	config.AuthURL = endpoints.Google.AuthURL
	config.TokenURL = endpoints.Google.TokenURL
	config.UserinfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
	return NewOAuthService(config, "google", ctx)
}

func newGitHubOAuthService(config model.OAuthServiceConfig, ctx context.Context) *OAuthService {
	scopes := []string{"read:user", "user:email"}
	config.Scopes = scopes
	config.AuthURL = endpoints.GitHub.AuthURL
	config.TokenURL = endpoints.GitHub.TokenURL
	return NewOAuthService(config, "github", ctx).WithUserinfoExtractor(githubExtractor)
}
