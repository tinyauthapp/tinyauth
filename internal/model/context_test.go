package model_test

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
)

func TestContext(t *testing.T) {
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
		run         func(*testing.T, *model.UserContext) any
		expected    any
	}{
		{
			description: "IsAuthenticated reflects Authenticated field",
			context:     &model.UserContext{Authenticated: true},
			run:         func(t *testing.T, c *model.UserContext) any { return c.IsAuthenticated() },
			expected:    true,
		},
		{
			description: "IsLocal returns true for ProviderLocal",
			context:     &model.UserContext{Provider: model.ProviderLocal, Local: &model.LocalContext{}},
			run:         func(t *testing.T, c *model.UserContext) any { return c.IsLocal() },
			expected:    true,
		},
		{
			description: "IsOAuth returns true for ProviderOAuth",
			context:     &model.UserContext{Provider: model.ProviderOAuth, OAuth: &model.OAuthContext{}},
			run:         func(t *testing.T, c *model.UserContext) any { return c.IsOAuth() },
			expected:    true,
		},
		{
			description: "IsLDAP returns true for ProviderLDAP",
			context:     &model.UserContext{Provider: model.ProviderLDAP, LDAP: &model.LDAPContext{}},
			run:         func(t *testing.T, c *model.UserContext) any { return c.IsLDAP() },
			expected:    true,
		},
		{
			description: "IsBasicAuth returns true for ProviderBasicAuth",
			context:     &model.UserContext{Provider: model.ProviderBasicAuth, Local: &model.LocalContext{}},
			run:         func(t *testing.T, c *model.UserContext) any { return c.IsBasicAuth() },
			expected:    true,
		},
		{
			description: "NewFromSession local session is authenticated and ProviderLocal",
			context:     &model.UserContext{},
			run: func(t *testing.T, c *model.UserContext) any {
				got, err := c.NewFromSession(&repository.Session{
					Username: "alice", Email: "alice@example.com", Name: "Alice",
					Provider: "local",
				})
				require.NoError(t, err)
				return [2]any{got.Provider, got.Authenticated}
			},
			expected: [2]any{model.ProviderLocal, true},
		},
		{
			description: "NewFromSession local session with TotpPending is not authenticated",
			context:     &model.UserContext{},
			run: func(t *testing.T, c *model.UserContext) any {
				got, err := c.NewFromSession(&repository.Session{
					Username: "bob", Provider: "local", TotpPending: true,
				})
				require.NoError(t, err)
				return got.Authenticated
			},
			expected: false,
		},
		{
			description: "NewFromSession ldap session is ProviderLDAP",
			context:     &model.UserContext{},
			run: func(t *testing.T, c *model.UserContext) any {
				got, err := c.NewFromSession(&repository.Session{
					Username: "carol", Provider: "ldap",
				})
				require.NoError(t, err)
				return got.Provider
			},
			expected: model.ProviderLDAP,
		},
		{
			description: "NewFromSession unknown provider defaults to OAuth and populates oauth fields",
			context:     &model.UserContext{},
			run: func(t *testing.T, c *model.UserContext) any {
				got, err := c.NewFromSession(&repository.Session{
					Username: "dave", Provider: "github",
					OAuthGroups: "devs,admins", OAuthSub: "sub-123", OAuthName: "GitHub",
				})
				require.NoError(t, err)
				return [5]any{got.Provider, got.OAuth.ID, got.OAuth.Sub, got.OAuth.DisplayName, got.OAuth.Groups}
			},
			expected: [5]any{model.ProviderOAuth, "github", "sub-123", "GitHub", []string{"devs", "admins"}},
		},
		{
			description: "Local getters return BaseContext fields",
			context: &model.UserContext{
				Provider: model.ProviderLocal,
				Local:    &model.LocalContext{BaseContext: model.BaseContext{Username: "alice", Email: "alice@example.com", Name: "Alice"}},
			},
			run: func(t *testing.T, c *model.UserContext) any {
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
			run: func(t *testing.T, c *model.UserContext) any {
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
			run: func(t *testing.T, c *model.UserContext) any {
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
			run: func(t *testing.T, c *model.UserContext) any {
				return [3]string{c.GetUsername(), c.GetEmail(), c.GetName()}
			},
			expected: [3]string{"dave", "dave@example.com", "Dave"},
		},
		{
			description: "ProviderName returns 'local' for ProviderLocal",
			context:     &model.UserContext{Provider: model.ProviderLocal},
			run:         func(t *testing.T, c *model.UserContext) any { return c.GetProviderID() },
			expected:    "local",
		},
		{
			description: "ProviderName returns 'local' for ProviderBasicAuth",
			context:     &model.UserContext{Provider: model.ProviderBasicAuth},
			run:         func(t *testing.T, c *model.UserContext) any { return c.GetProviderID() },
			expected:    "local",
		},
		{
			description: "ProviderName returns 'ldap' for ProviderLDAP",
			context:     &model.UserContext{Provider: model.ProviderLDAP},
			run:         func(t *testing.T, c *model.UserContext) any { return c.GetProviderID() },
			expected:    "ldap",
		},
		{
			description: "ProviderName returns OAuth provider ID for ProviderOAuth",
			context: &model.UserContext{
				Provider: model.ProviderOAuth,
				OAuth:    &model.OAuthContext{ID: "github"},
			},
			run:      func(t *testing.T, c *model.UserContext) any { return c.GetProviderID() },
			expected: "github",
		},
		{
			description: "TOTPPending returns true when local context is pending",
			context: &model.UserContext{
				Provider: model.ProviderLocal,
				Local:    &model.LocalContext{TOTPPending: true},
			},
			run:      func(t *testing.T, c *model.UserContext) any { return c.TOTPPending() },
			expected: true,
		},
		{
			description: "TOTPPending returns false when local context is not pending",
			context: &model.UserContext{
				Provider: model.ProviderLocal,
				Local:    &model.LocalContext{TOTPPending: false},
			},
			run:      func(t *testing.T, c *model.UserContext) any { return c.TOTPPending() },
			expected: false,
		},
		{
			description: "TOTPPending returns false for non-local providers",
			context:     &model.UserContext{Provider: model.ProviderOAuth, OAuth: &model.OAuthContext{}},
			run:         func(t *testing.T, c *model.UserContext) any { return c.TOTPPending() },
			expected:    false,
		},
		{
			description: "OAuthName returns DisplayName for ProviderOAuth",
			context: &model.UserContext{
				Provider: model.ProviderOAuth,
				OAuth:    &model.OAuthContext{DisplayName: "Google"},
			},
			run:      func(t *testing.T, c *model.UserContext) any { return c.OAuthName() },
			expected: "Google",
		},
		{
			description: "OAuthName returns empty string for non-oauth providers",
			context:     &model.UserContext{Provider: model.ProviderLocal, Local: &model.LocalContext{}},
			run:         func(t *testing.T, c *model.UserContext) any { return c.OAuthName() },
			expected:    "",
		},
		{
			description: "NewFromGin populates context from gin value",
			context:     &model.UserContext{},
			run: func(t *testing.T, c *model.UserContext) any {
				stored := &model.UserContext{
					Authenticated: true,
					Provider:      model.ProviderLocal,
					Local:         &model.LocalContext{BaseContext: model.BaseContext{Username: "alice"}},
				}
				got, err := c.NewFromGin(newGinCtx(stored, true))
				require.NoError(t, err)
				return [2]any{got.Authenticated, got.GetUsername()}
			},
			expected: [2]any{true, "alice"},
		},
		{
			description: "NewFromGin returns error when context value is missing",
			context:     &model.UserContext{},
			run: func(t *testing.T, c *model.UserContext) any {
				_, err := c.NewFromGin(newGinCtx(nil, false))
				return err.Error()
			},
			expected: "failed to get user context",
		},
		{
			description: "NewFromGin returns error when context value has wrong type",
			context:     &model.UserContext{},
			run: func(t *testing.T, c *model.UserContext) any {
				_, err := c.NewFromGin(newGinCtx("not a user context", true))
				return err.Error()
			},
			expected: "invalid user context type",
		},
		{
			description: "NewFromGin returns an error when context doesn't include user information",
			context:     &model.UserContext{},
			run: func(t *testing.T, c *model.UserContext) any {
				_, err := c.NewFromGin(newGinCtx(&model.UserContext{Provider: model.ProviderLocal}, true))
				return err.Error()
			},
			expected: "incomplete user context",
		},
		{
			description: "Getters should not panic if provider context is empty",
			context:     &model.UserContext{Provider: model.ProviderLocal},
			run: func(t *testing.T, c *model.UserContext) any {
				return [3]string{c.GetUsername(), c.GetEmail(), c.GetName()}
			},
			expected: [3]string{"", "", ""},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			assert.Equal(t, test.expected, test.run(t, test.context))
		})
	}
}
