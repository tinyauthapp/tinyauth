package controller

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestOAuthController_isRedirectSafe(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)

	type testCase struct {
		description       string
		appURL            string
		cookieDomain      string
		subdomainsEnabled bool
		redirectURI       string
		expected          bool
	}

	tests := []testCase{
		{
			description:       "Exact host match returns true",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "https://tinyauth.example.com",
			expected:          true,
		},
		{
			description:       "Exact host match is case insensitive",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "https://TinyAuth.Example.com",
			expected:          true,
		},
		{
			description:       "Exact host match with subdomains disabled returns true",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: false,
			redirectURI:       "https://tinyauth.example.com",
			expected:          true,
		},
		{
			description:       "Subdomain of cookie domain returns true when subdomains enabled",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "https://sub.example.com",
			expected:          true,
		},
		{
			description:       "Subdomain of cookie domain is case insensitive",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "Example.COM",
			subdomainsEnabled: true,
			redirectURI:       "https://SUB.example.com",
			expected:          true,
		},
		{
			description:       "Subdomain not matching cookie domain returns false",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "https://sub.evil.com",
			expected:          false,
		},
		{
			description:       "Subdomain returns false when subdomains disabled",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: false,
			redirectURI:       "https://sub.example.com",
			expected:          false,
		},
		{
			description:       "Cookie domain itself is not a subdomain match",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "https://example.com",
			expected:          false,
		},
		{
			description:       "Different scheme returns false",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "http://tinyauth.example.com",
			expected:          false,
		},
		{
			description:       "Different port returns false",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "https://tinyauth.example.com:8080",
			expected:          false,
		},
		{
			description:       "Empty redirect URI returns false",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "",
			expected:          false,
		},
		{
			description:       "Redirect URI without host returns false",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "https:/malicious",
			expected:          false,
		},
		{
			description:       "Redirect URI without scheme returns false",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "tinyauth.example.com",
			expected:          false,
		},
		{
			description:       "Relative redirect URI returns false",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "/some/path",
			expected:          false,
		},
		{
			description:       "Userinfo trick with malicious host returns false",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "https://malicious.example.com@evil.com",
			expected:          false,
		},
		{
			description:       "Unparseable redirect URI returns false",
			appURL:            "https://tinyauth.example.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "https://exa\x7fmple.com",
			expected:          false,
		},
		{
			description:       "Unparseable app URL returns false",
			appURL:            "https://tinyauth.\x7fexample.com",
			cookieDomain:      "example.com",
			subdomainsEnabled: true,
			redirectURI:       "https://tinyauth.example.com",
			expected:          false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			router := gin.Default()
			group := router.Group("/api")
			gin.SetMode(gin.TestMode)

			// Overwrite the app URL, cookie domain and subdomain setting for each test case
			runtime.AppURL = tc.appURL
			runtime.CookieDomain = tc.cookieDomain
			cfg.Auth.SubdomainsEnabled = tc.subdomainsEnabled

			ctrl := NewOAuthController(OAuthControllerInput{
				Log:           log,
				Config:        &cfg,
				RuntimeConfig: &runtime,
				RouterGroup:   group,
			})

			assert.Equal(t, tc.expected, ctrl.isRedirectSafe(tc.redirectURI))
		})
	}
}
