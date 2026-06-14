package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestIsEmailWhitelistedUsesProviderSpecificList(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	auth := &AuthService{
		log: log,
		runtime: &model.RuntimeConfig{
			OAuthWhitelist: []string{"global@example.com"},
			OAuthProviders: map[string]model.OAuthServiceConfig{
				"github": {
					Whitelist: []string{"github@example.com"},
				},
				"pocketid": {
					Whitelist: []string{"pocket@example.com"},
				},
				"gitlab": {
					Whitelist: []string{},
				},
			},
		},
	}

	assert.True(t, auth.IsEmailWhitelisted("github", "github@example.com"))
	assert.False(t, auth.IsEmailWhitelisted("github", "pocket@example.com"))
	assert.True(t, auth.IsEmailWhitelisted("pocketid", "pocket@example.com"))
	assert.True(t, auth.IsEmailWhitelisted("google", "global@example.com"))
	assert.True(t, auth.IsEmailWhitelisted("gitlab", "global@example.com"))
	assert.False(t, auth.IsEmailWhitelisted("gitlab", "unknown@example.com"))
}
