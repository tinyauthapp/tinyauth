package test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"golang.org/x/crypto/bcrypt"
)

var TestingTOTPSecret = "JPIEBDKJH6UGWJMX66RR3S55UFP2SGKK"

func CreateTestConfigs(t *testing.T) (model.Config, model.RuntimeConfig) {
	tempDir := t.TempDir()

	config := model.Config{
		UI: model.UIConfig{
			Title:                 "Tinyauth Test",
			ForgotPasswordMessage: "foo",
			BackgroundImage:       "/background.jpg",
			WarningsEnabled:       true,
		},
		OAuth: model.OAuthConfig{
			AutoRedirect: "none",
		},
		OIDC: model.OIDCConfig{
			Clients: map[string]model.OIDCClientConfig{
				"test": {
					ClientID:            "some-client-id",
					ClientSecret:        "some-client-secret",
					TrustedRedirectURIs: []string{"https://test.example.com/callback"},
					Name:                "Test Client",
				},
			},
			PrivateKeyPath: filepath.Join(tempDir, "key.pem"),
			PublicKeyPath:  filepath.Join(tempDir, "key.pub"),
		},
		Auth: model.AuthConfig{
			SessionExpiry:   10,
			LoginTimeout:    10,
			LoginMaxRetries: 3,
		},
		Database: model.DatabaseConfig{
			Path: filepath.Join(tempDir, "test.db"),
		},
		Resources: model.ResourcesConfig{
			Enabled: true,
			Path:    filepath.Join(tempDir, "resources"),
		},
	}

	passwd, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	require.NoError(t, err)

	runtime := model.RuntimeConfig{
		ConfiguredProviders: []model.Provider{
			{
				Name:  "Local",
				ID:    "local",
				OAuth: false,
			},
		},
		LocalUsers: []model.LocalUser{
			{
				Username: "testuser",
				Password: string(passwd),
			},
			{
				Username:   "totpuser",
				Password:   string(passwd),
				TOTPSecret: TestingTOTPSecret,
			},
			{
				Username: "attruser",
				Password: string(passwd),
				Attributes: model.UserAttributes{
					Name:  "Alice Smith",
					Email: "alice@example.com",
				},
			},
			{
				Username:   "attrtotpuser",
				Password:   string(passwd),
				TOTPSecret: TestingTOTPSecret,
				Attributes: model.UserAttributes{
					Name:  "Bob Jones",
					Email: "bob@example.com",
				},
			},
		},
		CookieDomain:      "example.com",
		AppURL:            "https://tinyauth.example.com",
		SessionCookieName: "tinyauth-session",
		OIDCClients: func() []model.OIDCClientConfig {
			var clients []model.OIDCClientConfig
			for id, client := range config.OIDC.Clients {
				client.ID = id
				clients = append(clients, client)
			}
			return clients
		}(),
	}

	return config, runtime
}
