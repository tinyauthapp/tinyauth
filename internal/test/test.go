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
			ACLs: model.ACLsConfig{
				Policy: "allow",
			},
			SubdomainsEnabled: true,
		},
		Database: model.DatabaseConfig{
			Path: filepath.Join(tempDir, "test.db"),
		},
		Resources: model.ResourcesConfig{
			Enabled: true,
			Path:    filepath.Join(tempDir, "resources"),
		},
		Apps: map[string]model.App{
			"app_path_allow": {
				Config: model.AppConfig{
					Domain: "path-allow.example.com",
				},
				Path: model.AppPath{
					Allow: "/allowed",
				},
			},
			"app_user_allow": {
				Config: model.AppConfig{
					Domain: "user-allow.example.com",
				},
				Users: model.AppUsers{
					Allow: "testuser",
				},
			},
			"ip_bypass": {
				Config: model.AppConfig{
					Domain: "ip-bypass.example.com",
				},
				IP: model.AppIP{
					Bypass: []string{"10.10.10.10"},
				},
			},
			"ip_block": {
				Config: model.AppConfig{
					Domain: "ip-block.example.com",
				},
				IP: model.AppIP{
					Block: []string{"10.10.10.10"},
				},
			},
			"oauth_group": {
				Config: model.AppConfig{
					Domain: "oauth-group.example.com",
				},
				OAuth: model.AppOAuth{
					Whitelist: "testuser@example.com",
					Groups:    "group1,group2",
				},
			},
			"ldap_group": {
				Config: model.AppConfig{
					Domain: "ldap-group.example.com",
				},
				LDAP: model.AppLDAP{
					Groups: "group1,group2",
				},
			},
			"basic_auth": {
				Config: model.AppConfig{
					Domain: "basic-auth.example.com",
				},
				Response: model.AppResponse{
					BasicAuth: model.AppBasicAuth{
						Username: "test",
						Password: "password",
					},
				},
			},
			"response_headers": {
				Config: model.AppConfig{
					Domain: "response-headers.example.com",
				},
				Response: model.AppResponse{
					Headers: []string{"x-foo=bar"},
				},
			},
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
	}

	return config, runtime
}
