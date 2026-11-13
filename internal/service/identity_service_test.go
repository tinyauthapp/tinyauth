package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/test"
)

func TestIdentityService(t *testing.T) {
	user := repository.User{
		UUID: "user-id", Username: "testuser", Email: "test@example.com", Name: "Test User",
	}
	identity := repository.Identity{
		UUID: "identity-id", UserUUID: user.UUID, Provider: "github",
		ProviderType: "oauth", ProviderUserID: "provider-user-id",
	}
	params := StoreIdentityParams{
		Username: user.Username, Email: user.Email, Name: user.Name,
		ProviderID: identity.Provider, ProviderType: model.ProviderOAuth, ProviderUserID: identity.ProviderUserID,
		IdentityContext: model.IdentityContext{
			OAuth: model.IdentityOAuthContext{Groups: "admins,users", DisplayName: "GitHub"},
		},
	}

	tests := []struct {
		description string
		linkingMode string
		run         func(t *testing.T, svc *IdentityService, db *test.TestDatabase)
	}{
		{
			description: "rejects invalid linking mode",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				result, err := NewIdentityService(IdentityServiceInput{
					Config: &model.Config{Auth: model.AuthConfig{LinkingMode: "invalid"}},
				})
				require.ErrorContains(t, err, "failed to parse linking mode")
				assert.Nil(t, result)
			},
		},
		{
			description: "stores and loads a new user and identity",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				args := params
				args.Username, args.Email, args.Name = "newuser", "new@example.com", "New User"
				stored, err := svc.Store(t.Context(), args)
				require.NoError(t, err)
				assert.NotEmpty(t, stored.UUID)
				assert.NotEmpty(t, stored.UserUUID)
				assert.NotEqual(t, user.UUID, stored.UserUUID)
				assert.NotEqual(t, identity.UUID, stored.UUID)
				persisted, err := svc.store.GetIdentityByUUID(t.Context(), stored.UUID)
				require.NoError(t, err)
				assert.Equal(t, stored, persisted)

				loaded, err := svc.Load(t.Context(), stored.UUID)
				require.NoError(t, err)
				assert.Equal(t, model.IdentityResult{
					Username: args.Username, Email: args.Email, Name: args.Name,
					Provider: args.ProviderID, ProviderType: args.ProviderType,
					ProviderUserID: args.ProviderUserID, IdentityContext: args.IdentityContext,
				}, loaded)
			},
		},
		{
			description: "both mode reuses an unchanged user across providers",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				args := params
				args.ProviderID, args.ProviderType, args.ProviderUserID = "ldap", model.ProviderLDAP, "ldap-user"
				stored, err := svc.Store(t.Context(), args)
				require.NoError(t, err)
				assert.Equal(t, user.UUID, stored.UserUUID)
				assert.Equal(t, "ldap", stored.Provider)
				assert.Equal(t, "ldap", stored.ProviderType)
				assert.Equal(t, "ldap-user", stored.ProviderUserID)
				persisted, err := svc.store.GetUserByUUID(t.Context(), user.UUID)
				require.NoError(t, err)
				assert.Equal(t, user, persisted)
			},
		},
		{
			description: "both mode updates the name of a matching user",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				args := params
				args.Name = "Updated Name"
				stored, err := svc.Store(t.Context(), args)
				require.NoError(t, err)
				assert.Equal(t, user.UUID, stored.UserUUID)
				persisted, err := svc.store.GetUserByUUID(t.Context(), user.UUID)
				require.NoError(t, err)
				expected := user
				expected.Name = args.Name
				assert.Equal(t, expected, persisted)
			},
		},
		{
			description: "both mode requires both username and email to match",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				for _, args := range []StoreIdentityParams{
					{Username: user.Username, Email: "other@example.com"},
					{Username: "otheruser", Email: user.Email},
				} {
					stored, err := svc.Store(t.Context(), args)
					require.NoError(t, err)
					assert.NotEqual(t, user.UUID, stored.UserUUID)
				}
			},
		},
		{
			description: "email mode links and updates the username",
			linkingMode: "email",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				args := params
				args.Username = "renamed"
				stored, err := svc.Store(t.Context(), args)
				require.NoError(t, err)
				assert.Equal(t, user.UUID, stored.UserUUID)
				persisted, err := svc.store.GetUserByUUID(t.Context(), user.UUID)
				require.NoError(t, err)
				expected := user
				expected.Username = args.Username
				assert.Equal(t, expected, persisted)
			},
		},
		{
			description: "username mode links and updates the email",
			linkingMode: "username",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				args := params
				args.Email = "updated@example.com"
				stored, err := svc.Store(t.Context(), args)
				require.NoError(t, err)
				assert.Equal(t, user.UUID, stored.UserUUID)
				persisted, err := svc.store.GetUserByUUID(t.Context(), user.UUID)
				require.NoError(t, err)
				expected := user
				expected.Email = args.Email
				assert.Equal(t, expected, persisted)
			},
		},
		{
			description: "explicit user UUID takes precedence over linking mode",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				expected := repository.User{
					UUID: user.UUID, Username: "renamed", Email: "updated@example.com", Name: "Updated Name",
				}
				result, err := svc.ensureUser(t.Context(), repository.CreateUserParams(expected))
				require.NoError(t, err)
				assert.Equal(t, expected, result)
				persisted, err := svc.store.GetUserByUUID(t.Context(), user.UUID)
				require.NoError(t, err)
				assert.Equal(t, expected, persisted)
			},
		},
		{
			description: "rejects an unknown runtime linking mode",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				svc.linkingMode = "invalid"
				result, err := svc.Store(t.Context(), params)
				require.ErrorContains(t, err, "unknown linking mode")
				assert.Empty(t, result)
			},
		},
		{
			description: "reuses an existing identity without changing it",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				result, err := svc.ensureIdentity(t.Context(), repository.CreateIdentityParams{
					UUID: identity.UUID, Provider: "different-provider",
				})
				require.NoError(t, err)
				assert.Equal(t, identity, result)
				persisted, err := svc.store.GetIdentityByUUID(t.Context(), identity.UUID)
				require.NoError(t, err)
				assert.Equal(t, identity, persisted)
			},
		},
		{
			description: "rejects tailscale when it is not configured",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				args := params
				args.ProviderType = model.ProviderTailscale
				result, err := svc.Store(t.Context(), args)
				require.ErrorContains(t, err, "tailscale provider not configured")
				assert.Empty(t, result)
			},
		},
		{
			description: "stores a configured tailscale identity",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				svc.runtime.ConfiguredProviders = []model.Provider{{Name: "Tailscale", ID: "tailscale"}}
				args := params
				args.ProviderID, args.ProviderType = "tailscale", model.ProviderTailscale
				args.IdentityContext = model.IdentityContext{Tailscale: model.IdentityTailscaleContext{NodeName: "node"}}
				stored, err := svc.Store(t.Context(), args)
				require.NoError(t, err)
				loaded, err := svc.Load(t.Context(), stored.UUID)
				require.NoError(t, err)
				assert.Equal(t, model.ProviderTailscale, loaded.ProviderType)
				assert.Equal(t, args.IdentityContext, loaded.IdentityContext)
			},
		},
		{
			description: "loads an identity without context",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				result, err := svc.Load(t.Context(), identity.UUID)
				require.NoError(t, err)
				assert.Equal(t, model.IdentityResult{
					Username: user.Username, Email: user.Email, Name: user.Name,
					Provider: identity.Provider, ProviderType: model.ProviderOAuth, ProviderUserID: identity.ProviderUserID,
				}, result)
			},
		},
		{
			description: "loading a missing identity preserves not found",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				result, err := svc.Load(t.Context(), "missing")
				require.ErrorIs(t, err, repository.ErrNotFound)
				assert.Empty(t, result)
			},
		},
		{
			description: "loading propagates user lookup errors",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				_, err := db.DB().ExecContext(t.Context(), "DROP TABLE users")
				require.NoError(t, err)
				result, err := svc.Load(t.Context(), identity.UUID)
				require.ErrorContains(t, err, "failed to get user")
				assert.Empty(t, result)
			},
		},
		{
			description: "rejects malformed identity context",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				args := repository.CreateIdentityParams(identity)
				args.UUID, args.ContextJSON = "invalid-context", "{"
				_, err := svc.store.CreateIdentity(t.Context(), args)
				require.NoError(t, err)
				result, err := svc.Load(t.Context(), args.UUID)
				require.ErrorContains(t, err, "failed to unmarshal context")
				assert.Empty(t, result)
			},
		},
		{
			description: "rejects an unknown stored provider type",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				args := repository.CreateIdentityParams(identity)
				args.UUID, args.ProviderType = "invalid-provider", "invalid"
				_, err := svc.store.CreateIdentity(t.Context(), args)
				require.NoError(t, err)
				result, err := svc.Load(t.Context(), args.UUID)
				require.ErrorContains(t, err, "failed to parse provider")
				assert.Empty(t, result)
			},
		},
		{
			description: "propagates canceled repository reads",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				_, err := svc.Store(ctx, params)
				require.ErrorIs(t, err, context.Canceled)
				_, err = svc.ensureIdentity(ctx, repository.CreateIdentityParams(identity))
				require.ErrorIs(t, err, context.Canceled)
				_, err = svc.Load(ctx, identity.UUID)
				require.ErrorIs(t, err, context.Canceled)
			},
		},
		{
			description: "propagates repository write failures",
			run: func(t *testing.T, svc *IdentityService, db *test.TestDatabase) {
				_, err := db.DB().ExecContext(t.Context(), "PRAGMA query_only = ON")
				require.NoError(t, err)
				_, err = svc.ensureUser(t.Context(), repository.CreateUserParams{Username: "newuser"})
				require.ErrorContains(t, err, "failed to create user")
				args := repository.CreateUserParams(user)
				args.Name = "Updated Name"
				_, err = svc.ensureUser(t.Context(), args)
				require.ErrorContains(t, err, "failed to update user")
				_, err = svc.Store(t.Context(), params)
				require.ErrorContains(t, err, "failed to create identity")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			db, err := test.NewTestDatabase()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			store := db.Store()
			_, err = store.CreateUser(t.Context(), repository.CreateUserParams(user))
			require.NoError(t, err)
			_, err = store.CreateIdentity(t.Context(), repository.CreateIdentityParams(identity))
			require.NoError(t, err)

			mode := tc.linkingMode
			if mode == "" {
				mode = "both"
			}
			svc, err := NewIdentityService(IdentityServiceInput{
				Store: store, Config: &model.Config{Auth: model.AuthConfig{LinkingMode: mode}},
				Runtime: &model.RuntimeConfig{},
			})
			require.NoError(t, err)
			tc.run(t, svc, db)
		})
	}
}
