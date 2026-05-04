package model_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
)

func TestContext(t *testing.T) {
	tests := []struct {
		description string
		context     *model.UserContext
		run         func(*model.UserContext) any
		expected    any
	}{
		{
			description: "IsAuthenticated returns true when Authenticated is true",
			context:     &model.UserContext{Authenticated: true},
			run:         func(c *model.UserContext) any { return c.IsAuthenticated() },
			expected:    true,
		},
		{
			description: "IsAuthenticated returns false when Authenticated is false",
			context:     &model.UserContext{Authenticated: false},
			run:         func(c *model.UserContext) any { return c.IsAuthenticated() },
			expected:    false,
		},
		{
			description: "IsLocal returns true when Provider is ProviderLocal",
			context:     &model.UserContext{Provider: model.ProviderLocal},
			run:         func(c *model.UserContext) any { return c.IsLocal() },
			expected:    true,
		},
		{
			description: "IsLocal returns false when Provider is not ProviderLocal",
			context:     &model.UserContext{Provider: model.ProviderOAuth},
			run:         func(c *model.UserContext) any { return c.IsLocal() },
			expected:    false,
		},
		{
			description: "IsOAuth returns true when Provider is ProviderOAuth",
			context:     &model.UserContext{Provider: model.ProviderOAuth},
			run:         func(c *model.UserContext) any { return c.IsOAuth() },
			expected:    true,
		},
		{
			description: "IsOAuth returns false when Provider is ProviderLocal",
			context:     &model.UserContext{Provider: model.ProviderLocal},
			run:         func(c *model.UserContext) any { return c.IsOAuth() },
			expected:    false,
		},
		{
			description: "IsLDAP returns true when Provider is ProviderLDAP",
			context:     &model.UserContext{Provider: model.ProviderLDAP},
			run:         func(c *model.UserContext) any { return c.IsLDAP() },
			expected:    true,
		},
		{
			description: "IsLDAP returns false when Provider is ProviderOAuth",
			context:     &model.UserContext{Provider: model.ProviderOAuth},
			run:         func(c *model.UserContext) any { return c.IsLDAP() },
			expected:    false,
		},
		{
			description: "IsBasicAuth returns true when Provider is ProviderBasicAuth",
			context:     &model.UserContext{Provider: model.ProviderBasicAuth},
			run:         func(c *model.UserContext) any { return c.IsBasicAuth() },
			expected:    true,
		},
		{
			description: "IsBasicAuth returns false when Provider is ProviderLocal",
			context:     &model.UserContext{Provider: model.ProviderLocal},
			run:         func(c *model.UserContext) any { return c.IsBasicAuth() },
			expected:    false,
		},
		{
			description: "NewFromSession local session without TOTP sets ProviderLocal and is authenticated",
			context:     &model.UserContext{},
			run: func(c *model.UserContext) any {
				got, _ := c.NewFromSession(&repository.Session{
					Username: "alice", Email: "alice@example.com", Name: "Alice",
					Provider: "local", TotpPending: false,
				})
				return got.Provider == model.ProviderLocal && got.Authenticated
			},
			expected: true,
		},
		{
			description: "NewFromSession local session with TOTP pending is not authenticated",
			context:     &model.UserContext{},
			run: func(c *model.UserContext) any {
				got, _ := c.NewFromSession(&repository.Session{
					Username: "bob", Provider: "local", TotpPending: true,
				})
				return got.Authenticated
			},
			expected: false,
		},
		{
			description: "NewFromSession ldap session sets ProviderLDAP and is authenticated",
			context:     &model.UserContext{},
			run: func(c *model.UserContext) any {
				got, _ := c.NewFromSession(&repository.Session{
					Username: "carol", Email: "carol@example.com", Name: "Carol",
					Provider: "ldap",
				})
				return got.Provider == model.ProviderLDAP && got.Authenticated
			},
			expected: true,
		},
		{
			description: "NewFromSession unknown provider defaults to ProviderOAuth",
			context:     &model.UserContext{},
			run: func(c *model.UserContext) any {
				got, _ := c.NewFromSession(&repository.Session{
					Username: "dave", Provider: "github",
					OAuthGroups: "devs,admins", OAuthSub: "sub-123", OAuthName: "GitHub",
				})
				return got.Provider
			},
			expected: model.ProviderOAuth,
		},
		{
			description: "GetUsername returns local username for ProviderLocal",
			context: &model.UserContext{
				Provider: model.ProviderLocal,
				Local:    &model.LocalContext{BaseContext: model.BaseContext{Username: "alice"}},
			},
			run:      func(c *model.UserContext) any { return c.GetUsername() },
			expected: "alice",
		},
		{
			description: "GetUsername returns local username for ProviderBasicAuth",
			context: &model.UserContext{
				Provider: model.ProviderBasicAuth,
				Local:    &model.LocalContext{BaseContext: model.BaseContext{Username: "bob"}},
			},
			run:      func(c *model.UserContext) any { return c.GetUsername() },
			expected: "bob",
		},
		{
			description: "GetUsername returns LDAP username for ProviderLDAP",
			context: &model.UserContext{
				Provider: model.ProviderLDAP,
				LDAP:     &model.LDAPContext{BaseContext: model.BaseContext{Username: "carol"}},
			},
			run:      func(c *model.UserContext) any { return c.GetUsername() },
			expected: "carol",
		},
		{
			description: "GetUsername returns OAuth username for ProviderOAuth",
			context: &model.UserContext{
				Provider: model.ProviderOAuth,
				OAuth:    &model.OAuthContext{BaseContext: model.BaseContext{Username: "dave"}},
			},
			run:      func(c *model.UserContext) any { return c.GetUsername() },
			expected: "dave",
		},
		{
			description: "GetEmail returns local email for ProviderLocal",
			context: &model.UserContext{
				Provider: model.ProviderLocal,
				Local:    &model.LocalContext{BaseContext: model.BaseContext{Email: "alice@example.com"}},
			},
			run:      func(c *model.UserContext) any { return c.GetEmail() },
			expected: "alice@example.com",
		},
		{
			description: "GetEmail returns local email for ProviderBasicAuth",
			context: &model.UserContext{
				Provider: model.ProviderBasicAuth,
				Local:    &model.LocalContext{BaseContext: model.BaseContext{Email: "bob@example.com"}},
			},
			run:      func(c *model.UserContext) any { return c.GetEmail() },
			expected: "bob@example.com",
		},
		{
			description: "GetEmail returns LDAP email for ProviderLDAP",
			context: &model.UserContext{
				Provider: model.ProviderLDAP,
				LDAP:     &model.LDAPContext{BaseContext: model.BaseContext{Email: "carol@example.com"}},
			},
			run:      func(c *model.UserContext) any { return c.GetEmail() },
			expected: "carol@example.com",
		},
		{
			description: "GetEmail returns OAuth email for ProviderOAuth",
			context: &model.UserContext{
				Provider: model.ProviderOAuth,
				OAuth:    &model.OAuthContext{BaseContext: model.BaseContext{Email: "dave@example.com"}},
			},
			run:      func(c *model.UserContext) any { return c.GetEmail() },
			expected: "dave@example.com",
		},
		{
			description: "GetName returns local name for ProviderLocal",
			context: &model.UserContext{
				Provider: model.ProviderLocal,
				Local:    &model.LocalContext{BaseContext: model.BaseContext{Name: "Alice"}},
			},
			run:      func(c *model.UserContext) any { return c.GetName() },
			expected: "Alice",
		},
		{
			description: "GetName returns local name for ProviderBasicAuth",
			context: &model.UserContext{
				Provider: model.ProviderBasicAuth,
				Local:    &model.LocalContext{BaseContext: model.BaseContext{Name: "Bob"}},
			},
			run:      func(c *model.UserContext) any { return c.GetName() },
			expected: "Bob",
		},
		{
			description: "GetName returns LDAP name for ProviderLDAP",
			context: &model.UserContext{
				Provider: model.ProviderLDAP,
				LDAP:     &model.LDAPContext{BaseContext: model.BaseContext{Name: "Carol"}},
			},
			run:      func(c *model.UserContext) any { return c.GetName() },
			expected: "Carol",
		},
		{
			description: "GetName returns OAuth name for ProviderOAuth",
			context: &model.UserContext{
				Provider: model.ProviderOAuth,
				OAuth:    &model.OAuthContext{BaseContext: model.BaseContext{Name: "Dave"}},
			},
			run:      func(c *model.UserContext) any { return c.GetName() },
			expected: "Dave",
		},
		{
			description: "ProviderName returns 'local' for ProviderLocal",
			context:     &model.UserContext{Provider: model.ProviderLocal},
			run:         func(c *model.UserContext) any { return c.ProviderName() },
			expected:    "local",
		},
		{
			description: "ProviderName returns 'local' for ProviderBasicAuth",
			context:     &model.UserContext{Provider: model.ProviderBasicAuth},
			run:         func(c *model.UserContext) any { return c.ProviderName() },
			expected:    "local",
		},
		{
			description: "ProviderName returns 'ldap' for ProviderLDAP",
			context:     &model.UserContext{Provider: model.ProviderLDAP},
			run:         func(c *model.UserContext) any { return c.ProviderName() },
			expected:    "ldap",
		},
		{
			description: "ProviderName returns OAuth DisplayName for ProviderOAuth",
			context: &model.UserContext{
				Provider: model.ProviderOAuth,
				OAuth:    &model.OAuthContext{DisplayName: "GitHub"},
			},
			run:      func(c *model.UserContext) any { return c.ProviderName() },
			expected: "GitHub",
		},
		{
			description: "TOTPPending returns true for ProviderLocal when TOTPPending is true",
			context: &model.UserContext{
				Provider: model.ProviderLocal,
				Local:    &model.LocalContext{TOTPPending: true},
			},
			run:      func(c *model.UserContext) any { return c.TOTPPending() },
			expected: true,
		},
		{
			description: "TOTPPending returns false for ProviderLocal when TOTPPending is false",
			context: &model.UserContext{
				Provider: model.ProviderLocal,
				Local:    &model.LocalContext{TOTPPending: false},
			},
			run:      func(c *model.UserContext) any { return c.TOTPPending() },
			expected: false,
		},
		{
			description: "TOTPPending returns false for ProviderOAuth",
			context: &model.UserContext{
				Provider: model.ProviderOAuth,
				OAuth:    &model.OAuthContext{},
			},
			run:      func(c *model.UserContext) any { return c.TOTPPending() },
			expected: false,
		},
		{
			description: "TOTPPending returns false for ProviderLDAP",
			context: &model.UserContext{
				Provider: model.ProviderLDAP,
				LDAP:     &model.LDAPContext{},
			},
			run:      func(c *model.UserContext) any { return c.TOTPPending() },
			expected: false,
		},
		{
			description: "OAuthName returns DisplayName for ProviderOAuth",
			context: &model.UserContext{
				Provider: model.ProviderOAuth,
				OAuth:    &model.OAuthContext{DisplayName: "Google"},
			},
			run:      func(c *model.UserContext) any { return c.OAuthName() },
			expected: "Google",
		},
		{
			description: "OAuthName returns empty string for ProviderLocal",
			context: &model.UserContext{
				Provider: model.ProviderLocal,
				Local:    &model.LocalContext{},
			},
			run:      func(c *model.UserContext) any { return c.OAuthName() },
			expected: "",
		},
		{
			description: "OAuthName returns empty string for ProviderLDAP",
			context: &model.UserContext{
				Provider: model.ProviderLDAP,
				LDAP:     &model.LDAPContext{},
			},
			run:      func(c *model.UserContext) any { return c.OAuthName() },
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			assert.Equal(t, test.expected, test.run(test.context))
		})
	}
}
