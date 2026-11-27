package service

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/test"
)

func TestIdentityService_Store(t *testing.T) {
	type testCase struct {
		description string
		provider    model.ProviderType
		providerID  string
		userID      string
		context     model.IdentityContext
		providers   []model.Provider
		errContains string
	}

	testCases := []testCase{
		{
			description: "local identity",
			provider:    model.ProviderLocal,
			providerID:  "local",
			userID:      "local:alice",
			context: model.IdentityContext{
				Local: model.IdentityLocalContext{
					Attributes: model.UserAttributes{Name: "Alice Smith"},
				},
			},
		},
		{
			description: "OAuth identity",
			provider:    model.ProviderOAuth,
			providerID:  "github",
			userID:      "github-alice",
			context: model.IdentityContext{
				OAuth: model.IdentityOAuthContext{Groups: "admins,users", DisplayName: "Alice"},
			},
		},
		{
			description: "LDAP identity",
			provider:    model.ProviderLDAP,
			providerID:  "ldap",
			userID:      "uid=alice,dc=example,dc=com",
			context: model.IdentityContext{
				LDAP: model.IdentityLDAPContext{Groups: []string{"admins", "users"}},
			},
		},
		{
			description: "Tailscale identity",
			provider:    model.ProviderTailscale,
			providerID:  "tailscale",
			userID:      "tailscale-alice",
			context: model.IdentityContext{
				Tailscale: model.IdentityTailscaleContext{NodeName: "alice-laptop"},
			},
			providers: []model.Provider{{Name: "Tailscale", ID: "tailscale"}},
		},
		{
			description: "Tailscale not configured",
			provider:    model.ProviderTailscale,
			providerID:  "tailscale",
			userID:      "tailscale-alice",
			errContains: "tailscale provider not configured",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg, runtime := test.CreateTestConfigs(t)
			runtime.ConfiguredProviders = append(runtime.ConfiguredProviders, tc.providers...)
			tdb, err := test.NewTestDatabase()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tdb.Close()) })

			factory := NewStoreFactory(StoreFactoryInput{
				Database: tdb.DB(), DatabaseType: model.DatabaseTypeSQLite,
			})
			svc, err := NewIdentityService(IdentityServiceInput{
				Config: &cfg, Runtime: &runtime, StoreFactory: factory,
			})
			require.NoError(t, err)

			identity, err := svc.Store(t.Context(), StoreIdentityParams{
				Username: "alice", Email: "alice@example.com", Name: "Alice",
				ProviderType: tc.provider, ProviderID: tc.providerID, ProviderUserID: tc.userID,
				IdentityContext: tc.context,
			})
			if tc.errContains != "" {
				require.ErrorContains(t, err, tc.errContains)
				assert.Empty(t, identity)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, identity.UUID)
			assert.NotEmpty(t, identity.UserUUID)
			assert.Equal(t, tc.provider.String(), identity.ProviderType)
			assert.Equal(t, tc.providerID, identity.Provider)
			assert.Equal(t, tc.userID, identity.ProviderUserID)

			var context model.IdentityContext
			require.NoError(t, json.Unmarshal([]byte(identity.ContextJSON), &context))
			assert.Equal(t, tc.context, context)

			store, err := factory.ProvideStore()
			require.NoError(t, err)
			stored, err := store.GetIdentityByUUID(t.Context(), identity.UUID)
			require.NoError(t, err)
			assert.Equal(t, identity, stored)
			user, err := store.GetUserByUUID(t.Context(), identity.UserUUID)
			require.NoError(t, err)
			assert.Equal(t, repository.User{
				UUID: identity.UserUUID, Username: "alice", Email: "alice@example.com", Name: "Alice",
			}, user)
		})
	}
}

func TestIdentityService_Linking(t *testing.T) {
	type testCase struct {
		description string
		mode        string
		username    string
		email       string
		linked      bool
		errContains string
	}

	testCases := []testCase{
		{
			description: "both match", mode: "both",
			username: "alice", email: "alice@example.com", linked: true,
		},
		{
			description: "both requires matching username", mode: "both",
			username: "alice-github", email: "alice@example.com",
		},
		{
			description: "both requires matching email", mode: "both",
			username: "alice", email: "other@example.com",
		},
		{
			description: "email ignores username", mode: "email",
			username: "alice-github", email: "alice@example.com", linked: true,
		},
		{
			description: "email requires matching email", mode: "email",
			username: "alice", email: "other@example.com",
		},
		{
			description: "username ignores email", mode: "username",
			username: "alice", email: "other@example.com", linked: true,
		},
		{
			description: "username requires matching username", mode: "username",
			username: "alice-github", email: "alice@example.com",
		},
		{
			description: "both rejects missing username", mode: "both",
			email: "alice@example.com", errContains: "email and username are required",
		},
		{
			description: "both rejects missing email", mode: "both",
			username: "alice", errContains: "email and username are required",
		},
		{
			description: "email rejects missing email", mode: "email",
			username: "alice", errContains: "email is required",
		},
		{
			description: "username rejects missing username", mode: "username",
			email: "alice@example.com", errContains: "username is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg, runtime := test.CreateTestConfigs(t)
			cfg.Auth.LinkingMode = tc.mode
			tdb, err := test.NewTestDatabase()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tdb.Close()) })

			factory := NewStoreFactory(StoreFactoryInput{
				Database: tdb.DB(), DatabaseType: model.DatabaseTypeSQLite,
			})
			svc, err := NewIdentityService(IdentityServiceInput{
				Config: &cfg, Runtime: &runtime, StoreFactory: factory,
			})
			require.NoError(t, err)

			local, err := svc.Store(t.Context(), StoreIdentityParams{
				Username: "alice", Email: "alice@example.com", Name: "Alice",
				ProviderType: model.ProviderLocal, ProviderID: "local", ProviderUserID: "local:alice",
			})
			require.NoError(t, err)

			identity, err := svc.Store(t.Context(), StoreIdentityParams{
				Username: tc.username, Email: tc.email, Name: "Alice Smith",
				ProviderType: model.ProviderOAuth, ProviderID: "github", ProviderUserID: "github-alice",
			})
			if tc.errContains != "" {
				require.ErrorContains(t, err, tc.errContains)
				assert.Empty(t, identity)
				return
			}
			require.NoError(t, err)
			assert.NotEqual(t, local.UUID, identity.UUID)
			if tc.linked {
				assert.Equal(t, local.UserUUID, identity.UserUUID)
			} else {
				assert.NotEqual(t, local.UserUUID, identity.UserUUID)
			}

			store, err := factory.ProvideStore()
			require.NoError(t, err)
			user, err := store.GetUserByUUID(t.Context(), identity.UserUUID)
			require.NoError(t, err)
			assert.Equal(t, repository.User{
				UUID: identity.UserUUID, Username: tc.username, Email: tc.email, Name: "Alice Smith",
			}, user)
			if !tc.linked {
				original, err := store.GetUserByUUID(t.Context(), local.UserUUID)
				require.NoError(t, err)
				assert.Equal(t, repository.User{
					UUID: local.UserUUID, Username: "alice", Email: "alice@example.com", Name: "Alice",
				}, original)
			}
			stored, err := store.GetIdentityByUUID(t.Context(), local.UUID)
			require.NoError(t, err)
			assert.Equal(t, local, stored)
		})
	}
}

func TestIdentityService_Update(t *testing.T) {
	type testCase struct {
		description string
		name        string
		context     model.IdentityContext
	}

	testCases := []testCase{
		{description: "unchanged login", name: "Alice"},
		{description: "updated profile", name: "Alice Smith"},
		{
			description: "updated identity context", name: "Alice",
			context: model.IdentityContext{
				OAuth: model.IdentityOAuthContext{Groups: "admins", DisplayName: "Alice Smith"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg, runtime := test.CreateTestConfigs(t)
			tdb, err := test.NewTestDatabase()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tdb.Close()) })

			factory := NewStoreFactory(StoreFactoryInput{
				Database: tdb.DB(), DatabaseType: model.DatabaseTypeSQLite,
			})
			svc, err := NewIdentityService(IdentityServiceInput{
				Config: &cfg, Runtime: &runtime, StoreFactory: factory,
			})
			require.NoError(t, err)

			params := StoreIdentityParams{
				Username: "alice", Email: "alice@example.com", Name: "Alice",
				ProviderType: model.ProviderOAuth, ProviderID: "github", ProviderUserID: "github-alice",
			}
			original, err := svc.Store(t.Context(), params)
			require.NoError(t, err)

			params.Name = tc.name
			params.IdentityContext = tc.context
			identity, err := svc.Store(t.Context(), params)
			require.NoError(t, err)
			assert.Equal(t, original.UUID, identity.UUID)
			assert.Equal(t, original.UserUUID, identity.UserUUID)

			store, err := factory.ProvideStore()
			require.NoError(t, err)
			stored, err := store.GetIdentityByUUID(t.Context(), original.UUID)
			require.NoError(t, err)
			assert.Equal(t, identity, stored)
			var context model.IdentityContext
			require.NoError(t, json.Unmarshal([]byte(stored.ContextJSON), &context))
			assert.Equal(t, tc.context, context)
			user, err := store.GetUserByUUID(t.Context(), original.UserUUID)
			require.NoError(t, err)
			assert.Equal(t, repository.User{
				UUID: original.UserUUID, Username: "alice", Email: "alice@example.com", Name: tc.name,
			}, user)
		})
	}
}

func TestIdentityService_Relinking(t *testing.T) {
	type testCase struct {
		description string
		existing    bool
	}

	testCases := []testCase{
		{description: "move to existing user", existing: true},
		{description: "move to new user"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg, runtime := test.CreateTestConfigs(t)
			cfg.Auth.LinkingMode = "email"
			tdb, err := test.NewTestDatabase()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tdb.Close()) })

			factory := NewStoreFactory(StoreFactoryInput{
				Database: tdb.DB(), DatabaseType: model.DatabaseTypeSQLite,
			})
			svc, err := NewIdentityService(IdentityServiceInput{
				Config: &cfg, Runtime: &runtime, StoreFactory: factory,
			})
			require.NoError(t, err)
			store, err := factory.ProvideStore()
			require.NoError(t, err)

			params := StoreIdentityParams{
				Username: "alice", Email: "alice@example.com", Name: "Alice",
				ProviderType: model.ProviderOAuth, ProviderID: "github", ProviderUserID: "github-alice",
			}
			original, err := svc.Store(t.Context(), params)
			require.NoError(t, err)
			if tc.existing {
				_, err = store.CreateUser(t.Context(), repository.CreateUserParams{
					UUID: "matched-user", Username: "alice", Email: "new@example.com", Name: "Alice",
				})
				require.NoError(t, err)
			}

			params.Email = "new@example.com"
			identity, err := svc.Store(t.Context(), params)
			require.NoError(t, err)
			assert.Equal(t, original.UUID, identity.UUID)
			assert.NotEqual(t, original.UserUUID, identity.UserUUID)

			user, err := store.GetUserByEmail(t.Context(), params.Email)
			require.NoError(t, err)
			assert.Equal(t, user.UUID, identity.UserUUID)
			if tc.existing {
				assert.Equal(t, "matched-user", user.UUID)
			}
			stored, err := store.GetIdentityByUUID(t.Context(), original.UUID)
			require.NoError(t, err)
			assert.Equal(t, identity, stored)
		})
	}
}

func TestIdentityService_Load(t *testing.T) {
	type testCase struct {
		description string
		contextJSON string
		expect      model.IdentityContext
		missing     bool
	}

	testCases := []testCase{
		{
			description: "identity with context",
			contextJSON: `{"oauth":{"groups":"admins,users","display_name":"Alice Smith"}}`,
			expect: model.IdentityContext{
				OAuth: model.IdentityOAuthContext{Groups: "admins,users", DisplayName: "Alice Smith"},
			},
		},
		{description: "identity without context"},
		{description: "missing identity", missing: true},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg, runtime := test.CreateTestConfigs(t)
			tdb, err := test.NewTestDatabase()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tdb.Close()) })

			factory := NewStoreFactory(StoreFactoryInput{
				Database: tdb.DB(), DatabaseType: model.DatabaseTypeSQLite,
			})
			svc, err := NewIdentityService(IdentityServiceInput{
				Config: &cfg, Runtime: &runtime, StoreFactory: factory,
			})
			require.NoError(t, err)
			store, err := factory.ProvideStore()
			require.NoError(t, err)

			if !tc.missing {
				_, err = store.CreateUser(t.Context(), repository.CreateUserParams{
					UUID: "user", Username: "alice", Email: "alice@example.com", Name: "Alice",
				})
				require.NoError(t, err)
				_, err = store.CreateIdentity(t.Context(), repository.CreateIdentityParams{
					UUID: "identity", UserUUID: "user", ProviderType: "oauth",
					Provider: "github", ProviderUserID: "github-alice", ContextJSON: tc.contextJSON,
				})
				require.NoError(t, err)
			}

			identity, err := svc.Load(t.Context(), "identity")
			if tc.missing {
				require.ErrorIs(t, err, repository.ErrNotFound)
				assert.Empty(t, identity)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, model.IdentityResult{
				Username: "alice", Email: "alice@example.com", Name: "Alice",
				Provider: "github", ProviderType: model.ProviderOAuth, ProviderUserID: "github-alice",
				IdentityContext: tc.expect,
			}, identity)
		})
	}
}

func TestIdentityService_StoreWithOwnTransaction(t *testing.T) {
	type testCase struct {
		description string
		rollback    bool
	}

	testCases := []testCase{
		{description: "commit stores user and identity"},
		{description: "rollback removes user and identity", rollback: true},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg, runtime := test.CreateTestConfigs(t)
			tdb, err := test.NewTestDatabase()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tdb.Close()) })

			factory := NewStoreFactory(StoreFactoryInput{
				Database: tdb.DB(), DatabaseType: model.DatabaseTypeSQLite,
			})
			svc, err := NewIdentityService(IdentityServiceInput{
				Config: &cfg, Runtime: &runtime, StoreFactory: factory,
			})
			require.NoError(t, err)

			var identity repository.Identity
			rollback := errors.New("cancel login")
			err = factory.ProvideTransaction(t.Context(), func(store repository.Store) error {
				var err error
				identity, err = svc.StoreWithOwnTransaction(t.Context(), store, StoreIdentityParams{
					Username: "alice", Email: "alice@example.com", Name: "Alice",
					ProviderType: model.ProviderLocal, ProviderID: "local", ProviderUserID: "local:alice",
				})
				if err != nil {
					return err
				}
				if tc.rollback {
					return rollback
				}
				return nil
			})
			if tc.rollback {
				require.ErrorIs(t, err, rollback)
			} else {
				require.NoError(t, err)
			}
			require.NotEmpty(t, identity.UUID)
			require.NotEmpty(t, identity.UserUUID)

			store, err := factory.ProvideStore()
			require.NoError(t, err)
			stored, err := store.GetIdentityByUUID(t.Context(), identity.UUID)
			if tc.rollback {
				require.ErrorIs(t, err, repository.ErrNotFound)
				_, err = store.GetUserByUUID(t.Context(), identity.UserUUID)
				require.ErrorIs(t, err, repository.ErrNotFound)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, identity, stored)
			user, err := store.GetUserByUUID(t.Context(), identity.UserUUID)
			require.NoError(t, err)
			assert.Equal(t, repository.User{
				UUID: identity.UserUUID, Username: "alice", Email: "alice@example.com", Name: "Alice",
			}, user)
		})
	}
}
