package model_test

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
)

func TestContext(t *testing.T) {
	errMsg := func(err error) string {
		if err == nil {
			return ""
		}
		return err.Error()
	}

	newGinCtx := func(value any, set bool) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		if set {
			c.Set("context", value)
		}
		return c
	}

	tests := []struct {
		description string
		context     *model.UserContext
		run         func(*model.UserContext) any
		expected    any
	}{
		{
			description: "IsAuthenticated reflects Authenticated field",
			context:     &model.UserContext{Authenticated: true},
			run:         func(c *model.UserContext) any { return c.IsAuthenticated() },
			expected:    true,
		},
		{
			description: "IsLocal returns true for ProviderLocal",
			context:     &model.UserContext{Provider: model.ProviderLocal},
			run:         func(c *model.UserContext) any { return c.IsLocal() },
			expected:    true,
		},
		{
			description: "IsOAuth returns true for ProviderOAuth",
			context:     &model.UserContext{Provider: model.ProviderOAuth},
			run:         func(c *model.UserContext) any { return c.IsOAuth() },
			expected:    true,
		},
		{
			description: "IsLDAP returns true for ProviderLDAP",
			context:     &model.UserContext{Provider: model.ProviderLDAP},
			run:         func(c *model.UserContext) any { return c.IsLDAP() },
			expected:    true,
		},
		{
			description: "IsBasicAuth returns true for ProviderBasicAuth",
			context:     &model.UserContext{Provider: model.ProviderBasicAuth},
			run:         func(c *model.UserContext) any { return c.IsBasicAuth() },
			expected:    true,
		},
		{
			description: "NewFromSession local session is authenticated and ProviderLocal",
			context:     &model.UserContext{},
			run: func(c *model.UserContext) any {
				got, _ := c.NewFromSession(&repository.Session{
					Username: "alice", Email: "alice@example.com", Name: "Alice",
					Provider: "local",
				})
				return [2]any{got.Provider, got.Authenticated}
			},
			expected: [2]any{model.ProviderLocal, true},
		},
		{
			description: "NewFromSession local session with TotpPending is not authenticated",
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
			description: "NewFromSession ldap session is ProviderLDAP",
			context:     &model.UserContext{},
			run: func(c *model.UserContext) any {
				got, _ := c.NewFromSession(&repository.Session{
					Username: "carol", Provider: "ldap",
				})
				return got.Provider
			},
			expected: model.ProviderLDAP,
		},
		{
			description: "NewFromSession unknown provider defaults to OAuth and populates oauth fields",
			context:     &model.UserContext{},
			run: func(c *model.UserContext) any {
				got, _ := c.NewFromSession(&repository.Session{
					Username: "dave", Provider: "github",
					OAuthGroups: "devs,admins", OAuthSub: "sub-123", OAuthName: "GitHub",
				})
				return [4]any{got.Provider, got.OAuth.ID, got.OAuth.Sub, got.OAuth.DisplayName}
			},
			expected: [4]any{model.ProviderOAuth, "github", "sub-123", "GitHub"},
		},
		{
			description: "Local getters return BaseContext fields",
			context: &model.UserContext{
				Provider: model.ProviderLocal,
				Local:    &model.LocalContext{BaseContext: model.BaseContext{Username: "alice", Email: "alice@example.com", Name: "Alice"}},
			},
			run: func(c *model.UserContext) any {
				return [3]string{c.GetUsername(), c.GetEmail(), c.GetName()}
			},
			expected: [3]string{"alice", "alice@example.com", "Alice"},
		},
		{
			description: "BasicAuth getters fall back to local fields",
			context: &model.UserContext{
				Provider: model.ProviderBasicAuth,
				Local:    &model.LocalContext{BaseContext: model.BaseContext{Username: "bob", Email: "bob@example.com", Name: "Bob"}},
			},
			run: func(c *model.UserContext) any {
				return [3]string{c.GetUsername(), c.GetEmail(), c.GetName()}
			},
			expected: [3]string{"bob", "bob@example.com", "Bob"},
		},
		{
			description: "LDAP getters return LDAP fields",
			context: &model.UserContext{
				Provider: model.ProviderLDAP,
				LDAP:     &model.LDAPContext{BaseContext: model.BaseContext{Username: "carol", Email: "carol@example.com", Name: "Carol"}},
			},
			run: func(c *model.UserContext) any {
				return [3]string{c.GetUsername(), c.GetEmail(), c.GetName()}
			},
			expected: [3]string{"carol", "carol@example.com", "Carol"},
		},
		{
			description: "OAuth getters return OAuth fields",
			context: &model.UserContext{
				Provider: model.ProviderOAuth,
				OAuth:    &model.OAuthContext{BaseContext: model.BaseContext{Username: "dave", Email: "dave@example.com", Name: "Dave"}},
			},
			run: func(c *model.UserContext) any {
				return [3]string{c.GetUsername(), c.GetEmail(), c.GetName()}
			},
			expected: [3]string{"dave", "dave@example.com", "Dave"},
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
			description: "TOTPPending returns true when local context is pending",
			context: &model.UserContext{
				Provider: model.ProviderLocal,
				Local:    &model.LocalContext{TOTPPending: true},
			},
			run:      func(c *model.UserContext) any { return c.TOTPPending() },
			expected: true,
		},
		{
			description: "TOTPPending returns false when local context is not pending",
			context: &model.UserContext{
				Provider: model.ProviderLocal,
				Local:    &model.LocalContext{TOTPPending: false},
			},
			run:      func(c *model.UserContext) any { return c.TOTPPending() },
			expected: false,
		},
		{
			description: "TOTPPending returns false for non-local providers",
			context:     &model.UserContext{Provider: model.ProviderOAuth, OAuth: &model.OAuthContext{}},
			run:         func(c *model.UserContext) any { return c.TOTPPending() },
			expected:    false,
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
			description: "OAuthName returns empty string for non-oauth providers",
			context:     &model.UserContext{Provider: model.ProviderLocal, Local: &model.LocalContext{}},
			run:         func(c *model.UserContext) any { return c.OAuthName() },
			expected:    "",
		},
		{
			description: "NewFromGin populates context from gin value",
			context:     &model.UserContext{},
			run: func(c *model.UserContext) any {
				stored := &model.UserContext{
					Authenticated: true,
					Provider:      model.ProviderLocal,
					Local:         &model.LocalContext{BaseContext: model.BaseContext{Username: "alice"}},
				}
				got, err := c.NewFromGin(newGinCtx(stored, true))
				if err != nil {
					return err.Error()
				}
				return [2]any{got.Authenticated, got.GetUsername()}
			},
			expected: [2]any{true, "alice"},
		},
		{
			description: "NewFromGin returns error when context value is missing",
			context:     &model.UserContext{},
			run: func(c *model.UserContext) any {
				_, err := c.NewFromGin(newGinCtx(nil, false))
				return errMsg(err)
			},
			expected: "failed to get user context",
		},
		{
			description: "NewFromGin returns error when context value has wrong type",
			context:     &model.UserContext{},
			run: func(c *model.UserContext) any {
				_, err := c.NewFromGin(newGinCtx("not a user context", true))
				return errMsg(err)
			},
			expected: "invalid user context type",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			assert.Equal(t, test.expected, test.run(test.context))
		})
	}
}
