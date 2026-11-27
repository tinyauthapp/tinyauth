package service

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/test"
)

func TestSessionsService_Create(t *testing.T) {
	type testCase struct {
		description string
		context     model.SessionContext
		lifetime    time.Duration
		missing     bool
	}

	testCases := []testCase{
		{description: "configured expiry", lifetime: 2 * time.Hour},
		{
			description: "pending TOTP",
			context: model.SessionContext{
				Local: model.SessionLocalContext{TOTPPending: true},
			},
			lifetime: time.Hour,
		},
		{description: "missing identity", missing: true},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg, runtime := test.CreateTestConfigs(t)
			cfg.Auth.SessionExpiry = 7200
			tdb, err := test.NewTestDatabase()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tdb.Close()) })

			factory := NewStoreFactory(StoreFactoryInput{
				Database: tdb.DB(), DatabaseType: model.DatabaseTypeSQLite,
			})
			identityService, err := NewIdentityService(IdentityServiceInput{
				Config: &cfg, Runtime: &runtime, StoreFactory: factory,
			})
			require.NoError(t, err)
			svc := NewSessionsService(SessionsServiceInput{
				Config: &cfg, Runtime: &runtime, StoreFactory: factory, Identity: identityService,
			})

			identityUUID := "missing"
			if !tc.missing {
				identity, err := identityService.Store(t.Context(), StoreIdentityParams{
					Username: "alice", Email: "alice@example.com", Name: "Alice",
					ProviderType: model.ProviderLocal, ProviderID: "local", ProviderUserID: "local:alice",
				})
				require.NoError(t, err)
				identityUUID = identity.UUID
			}

			before := time.Now().Unix()
			session, err := svc.Create(t.Context(), identityUUID, tc.context)
			if tc.missing {
				require.ErrorIs(t, err, repository.ErrNotFound)
				assert.Empty(t, session)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, session.UUID)
			assert.Equal(t, identityUUID, session.IdentityUUID)
			assert.GreaterOrEqual(t, session.CreatedAt, before)
			assert.LessOrEqual(t, session.CreatedAt, time.Now().Unix())
			assert.Equal(t, int64(tc.lifetime/time.Second), session.ExpiresAt-session.CreatedAt)

			var context model.SessionContext
			require.NoError(t, json.Unmarshal([]byte(session.ContextJSON), &context))
			assert.Equal(t, tc.context, context)

			store, err := factory.ProvideStore()
			require.NoError(t, err)
			stored, err := store.GetSessionByUUID(t.Context(), session.UUID)
			require.NoError(t, err)
			assert.Equal(t, session, stored)
		})
	}
}

func TestSessionsService_Get(t *testing.T) {
	type testCase struct {
		description string
		expiresIn   time.Duration
		contextJSON string
		context     model.SessionContext
		missing     bool
		expectErr   error
	}

	testCases := []testCase{
		{description: "active session", expiresIn: time.Hour, contextJSON: `{}`},
		{
			description: "pending TOTP", expiresIn: 30 * time.Minute,
			contextJSON: `{"local":{"totp_pending":true}}`,
			context: model.SessionContext{
				Local: model.SessionLocalContext{TOTPPending: true},
			},
		},
		{
			description: "expired session", expiresIn: -time.Minute,
			contextJSON: `{}`, expectErr: ErrSessionNotFound,
		},
		{description: "missing session", missing: true, expectErr: ErrSessionNotFound},
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
			svc := NewSessionsService(SessionsServiceInput{
				Config: &cfg, Runtime: &runtime, StoreFactory: factory,
			})
			store, err := factory.ProvideStore()
			require.NoError(t, err)

			var original repository.Session
			if !tc.missing {
				_, err = store.CreateUser(t.Context(), repository.CreateUserParams{
					UUID: "user", Username: "alice", Email: "alice@example.com", Name: "Alice",
				})
				require.NoError(t, err)
				_, err = store.CreateIdentity(t.Context(), repository.CreateIdentityParams{
					UUID: "identity", UserUUID: "user", ProviderType: "local",
					Provider: "local", ProviderUserID: "local:alice", ContextJSON: `{}`,
				})
				require.NoError(t, err)
				now := time.Now()
				original, err = store.CreateSession(t.Context(), repository.CreateSessionParams{
					UUID: "session", IdentityUUID: "identity", ContextJSON: tc.contextJSON,
					CreatedAt: now.Add(-2 * time.Hour).Unix(), ExpiresAt: now.Add(tc.expiresIn).Unix(),
				})
				require.NoError(t, err)
			}

			session, err := svc.Get(t.Context(), "session")
			if tc.expectErr != nil {
				require.ErrorIs(t, err, tc.expectErr)
				assert.Empty(t, session)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, model.SessionGetResult{
				Session: original, SessionContext: tc.context,
			}, session)
		})
	}
}

func TestSessionsService_Refresh(t *testing.T) {
	type testCase struct {
		description string
		expiry      time.Duration
		maxLifetime time.Duration
		age         time.Duration
		remaining   time.Duration
		extension   time.Duration
		missing     bool
	}

	testCases := []testCase{
		{
			description: "outside hourly window", expiry: 24 * time.Hour,
			age: 22 * time.Hour, remaining: 2 * time.Hour,
		},
		{
			description: "unlimited lifetime", expiry: 24 * time.Hour,
			age: 7 * 24 * time.Hour, remaining: 30 * time.Minute, extension: time.Hour,
		},
		{
			description: "outside short window", expiry: 30 * time.Minute,
			age: 10 * time.Minute, remaining: 20 * time.Minute,
		},
		{
			description: "within short window", expiry: 30 * time.Minute,
			age: 20 * time.Minute, remaining: 10 * time.Minute, extension: 15 * time.Minute,
		},
		{
			description: "one-hour expiry", expiry: time.Hour,
			age: 40 * time.Minute, remaining: 20 * time.Minute, extension: 30 * time.Minute,
		},
		{
			description: "below lifetime cap", expiry: 2 * time.Hour, maxLifetime: 4 * time.Hour,
			age: 2 * time.Hour, remaining: 30 * time.Minute, extension: time.Hour,
		},
		{
			description: "capped at lifetime", expiry: 2 * time.Hour, maxLifetime: 3 * time.Hour,
			age: 150 * time.Minute, remaining: 20 * time.Minute, extension: 10 * time.Minute,
		},
		{
			description: "already at lifetime cap", expiry: 2 * time.Hour, maxLifetime: 3 * time.Hour,
			age: 160 * time.Minute, remaining: 20 * time.Minute,
		},
		{description: "missing session", expiry: 2 * time.Hour, missing: true},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg, runtime := test.CreateTestConfigs(t)
			cfg.Auth.SessionExpiry = int(tc.expiry / time.Second)
			cfg.Auth.SessionMaxLifetime = int(tc.maxLifetime / time.Second)
			tdb, err := test.NewTestDatabase()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tdb.Close()) })

			factory := NewStoreFactory(StoreFactoryInput{
				Database: tdb.DB(), DatabaseType: model.DatabaseTypeSQLite,
			})
			svc := NewSessionsService(SessionsServiceInput{
				Config: &cfg, Runtime: &runtime, StoreFactory: factory,
			})
			store, err := factory.ProvideStore()
			require.NoError(t, err)

			var original repository.Session
			if !tc.missing {
				_, err = store.CreateUser(t.Context(), repository.CreateUserParams{
					UUID: "user", Username: "alice", Email: "alice@example.com", Name: "Alice",
				})
				require.NoError(t, err)
				_, err = store.CreateIdentity(t.Context(), repository.CreateIdentityParams{
					UUID: "identity", UserUUID: "user", ProviderType: "local",
					Provider: "local", ProviderUserID: "local:alice", ContextJSON: `{}`,
				})
				require.NoError(t, err)
				now := time.Now()
				original, err = store.CreateSession(t.Context(), repository.CreateSessionParams{
					UUID: "session", IdentityUUID: "identity", ContextJSON: `{"local":{"totp_pending":false}}`,
					CreatedAt: now.Add(-tc.age).Unix(), ExpiresAt: now.Add(tc.remaining).Unix(),
				})
				require.NoError(t, err)
			}

			session, err := svc.Refresh(t.Context(), "session")
			if tc.missing {
				require.ErrorIs(t, err, ErrSessionNotFound)
				assert.Empty(t, session)
				return
			}
			require.NoError(t, err)
			expect := original
			expect.ExpiresAt += int64(tc.extension / time.Second)
			assert.Equal(t, expect, session)

			stored, err := store.GetSessionByUUID(t.Context(), original.UUID)
			require.NoError(t, err)
			assert.Equal(t, expect, stored)
		})
	}
}

func TestSessionsService_Update(t *testing.T) {
	type testCase struct {
		description string
		pending     bool
		context     model.SessionContext
		resetExpiry bool
		missing     bool
		expired     bool
		expectErr   error
	}

	testCases := []testCase{
		{description: "expiry preserved"},
		{
			description: "TOTP still pending", pending: true,
			context: model.SessionContext{
				Local: model.SessionLocalContext{TOTPPending: true},
			},
		},
		{description: "TOTP completed", pending: true, resetExpiry: true},
		{description: "missing session", missing: true, expectErr: ErrSessionNotFound},
		{
			description: "expired TOTP session", pending: true,
			expired: true, expectErr: ErrSessionNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg, runtime := test.CreateTestConfigs(t)
			cfg.Auth.SessionExpiry = 7200
			tdb, err := test.NewTestDatabase()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tdb.Close()) })

			factory := NewStoreFactory(StoreFactoryInput{
				Database: tdb.DB(), DatabaseType: model.DatabaseTypeSQLite,
			})
			svc := NewSessionsService(SessionsServiceInput{
				Config: &cfg, Runtime: &runtime, StoreFactory: factory,
			})
			store, err := factory.ProvideStore()
			require.NoError(t, err)

			var original repository.Session
			if !tc.missing {
				_, err = store.CreateUser(t.Context(), repository.CreateUserParams{
					UUID: "user", Username: "alice", Email: "alice@example.com", Name: "Alice",
				})
				require.NoError(t, err)
				_, err = store.CreateIdentity(t.Context(), repository.CreateIdentityParams{
					UUID: "identity", UserUUID: "user", ProviderType: "local",
					Provider: "local", ProviderUserID: "local:alice", ContextJSON: `{}`,
				})
				require.NoError(t, err)
				contextJSON, err := json.Marshal(model.SessionContext{
					Local: model.SessionLocalContext{TOTPPending: tc.pending},
				})
				require.NoError(t, err)
				now := time.Now()
				expiresAt := now.Add(30 * time.Minute).Unix()
				if tc.expired {
					expiresAt = now.Add(-time.Minute).Unix()
				}
				original, err = store.CreateSession(t.Context(), repository.CreateSessionParams{
					UUID: "session", IdentityUUID: "identity", ContextJSON: string(contextJSON),
					CreatedAt: now.Add(-30 * time.Minute).Unix(), ExpiresAt: expiresAt,
				})
				require.NoError(t, err)
			}

			before := time.Now().Unix()
			session, err := svc.Update(t.Context(), "session", tc.context)
			if tc.expectErr != nil {
				require.ErrorIs(t, err, tc.expectErr)
				assert.Empty(t, session)
				if !tc.missing {
					stored, err := store.GetSessionByUUID(t.Context(), original.UUID)
					require.NoError(t, err)
					assert.Equal(t, original, stored)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, original.UUID, session.UUID)
			assert.Equal(t, original.IdentityUUID, session.IdentityUUID)
			assert.Equal(t, original.CreatedAt, session.CreatedAt)
			if tc.resetExpiry {
				assert.GreaterOrEqual(t, session.ExpiresAt, before+int64(cfg.Auth.SessionExpiry))
				assert.LessOrEqual(t, session.ExpiresAt, time.Now().Unix()+int64(cfg.Auth.SessionExpiry))
			} else {
				assert.Equal(t, original.ExpiresAt, session.ExpiresAt)
			}

			var context model.SessionContext
			require.NoError(t, json.Unmarshal([]byte(session.ContextJSON), &context))
			assert.Equal(t, tc.context, context)

			stored, err := store.GetSessionByUUID(t.Context(), original.UUID)
			require.NoError(t, err)
			assert.Equal(t, session, stored)
		})
	}
}

func TestSessionsService_Delete(t *testing.T) {
	type testCase struct {
		description string
		missing     bool
		expired     bool
	}

	testCases := []testCase{
		{description: "active session"},
		{description: "expired session", expired: true},
		{description: "missing session", missing: true},
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
			svc := NewSessionsService(SessionsServiceInput{
				Config: &cfg, Runtime: &runtime, StoreFactory: factory,
			})
			store, err := factory.ProvideStore()
			require.NoError(t, err)

			_, err = store.CreateUser(t.Context(), repository.CreateUserParams{
				UUID: "user", Username: "alice", Email: "alice@example.com", Name: "Alice",
			})
			require.NoError(t, err)
			_, err = store.CreateIdentity(t.Context(), repository.CreateIdentityParams{
				UUID: "identity", UserUUID: "user", ProviderType: "local",
				Provider: "local", ProviderUserID: "local:alice", ContextJSON: `{}`,
			})
			require.NoError(t, err)
			now := time.Now()
			other, err := store.CreateSession(t.Context(), repository.CreateSessionParams{
				UUID: "other-session", IdentityUUID: "identity", ContextJSON: `{}`,
				CreatedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
			})
			require.NoError(t, err)
			if !tc.missing {
				expiresAt := now.Add(time.Hour).Unix()
				if tc.expired {
					expiresAt = now.Add(-time.Minute).Unix()
				}
				_, err = store.CreateSession(t.Context(), repository.CreateSessionParams{
					UUID: "session", IdentityUUID: "identity", ContextJSON: `{}`,
					CreatedAt: now.Add(-time.Hour).Unix(), ExpiresAt: expiresAt,
				})
				require.NoError(t, err)
			}

			require.NoError(t, svc.Delete(t.Context(), "session"))
			_, err = store.GetSessionByUUID(t.Context(), "session")
			require.ErrorIs(t, err, repository.ErrNotFound)
			stored, err := store.GetSessionByUUID(t.Context(), other.UUID)
			require.NoError(t, err)
			assert.Equal(t, other, stored)
		})
	}
}
