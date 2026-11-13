package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/test"
)

func TestSessionsService(t *testing.T) {
	pending := model.SessionContext{Local: model.SessionLocalContext{TOTPPending: true}}

	tests := []struct {
		description string
		run         func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session)
	}{
		{
			description: "creates and gets a session with the configured expiry",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				before := time.Now().Unix()
				created, err := svc.Create(t.Context(), session.IdentityUUID, model.SessionContext{})
				require.NoError(t, err)
				assert.NotEmpty(t, created.UUID)
				assert.NotEqual(t, session.UUID, created.UUID)
				assert.Equal(t, session.IdentityUUID, created.IdentityUUID)
				assert.GreaterOrEqual(t, created.CreatedAt, before)
				assert.LessOrEqual(t, created.CreatedAt, time.Now().Unix())
				assert.Equal(t, int64(svc.config.Auth.SessionExpiry), created.ExpiresAt-created.CreatedAt)
				loaded, err := svc.Get(t.Context(), created.UUID)
				require.NoError(t, err)
				assert.Equal(t, model.SessionGetResult{Session: created}, loaded)
			},
		},
		{
			description: "pending TOTP sessions expire in one hour",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				created, err := svc.Create(t.Context(), session.IdentityUUID, pending)
				require.NoError(t, err)
				assert.Equal(t, int64(3600), created.ExpiresAt-created.CreatedAt)
				loaded, err := svc.Get(t.Context(), created.UUID)
				require.NoError(t, err)
				assert.Equal(t, model.SessionGetResult{Session: created, SessionContext: pending}, loaded)
			},
		},
		{
			description: "cannot create a session for a missing identity",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				result, err := svc.Create(t.Context(), "missing", model.SessionContext{})
				require.ErrorIs(t, err, repository.ErrNotFound)
				assert.Empty(t, result)
			},
		},
		{
			description: "refresh extends near-expiry sessions by the refresh threshold",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				for _, tc := range []struct {
					expiry    int
					threshold int64
				}{
					{expiry: 7200, threshold: 3600},
					{expiry: 3600, threshold: 1800},
					{expiry: 1200, threshold: 600},
				} {
					svc.config.Auth.SessionExpiry = tc.expiry
					_, err := svc.store.UpdateSessionByUUID(t.Context(), repository.UpdateSessionByUUIDParams{
						UUID: session.UUID, ExpiresAt: session.ExpiresAt, ContextJSON: session.ContextJSON,
					})
					require.NoError(t, err)
					refreshed, err := svc.Refresh(t.Context(), session.UUID)
					require.NoError(t, err)
					expected := session
					expected.ExpiresAt += tc.threshold
					assert.Equal(t, expected, refreshed, "session expiry %d", tc.expiry)
					persisted, err := svc.store.GetSessionByUUID(t.Context(), session.UUID)
					require.NoError(t, err)
					assert.Equal(t, expected, persisted)
				}
			},
		},
		{
			description: "refresh leaves sessions outside the threshold unchanged",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				created, err := svc.Create(t.Context(), session.IdentityUUID, model.SessionContext{})
				require.NoError(t, err)
				result, err := svc.Refresh(t.Context(), created.UUID)
				require.NoError(t, err)
				assert.Empty(t, result)
				persisted, err := svc.store.GetSessionByUUID(t.Context(), created.UUID)
				require.NoError(t, err)
				assert.Equal(t, created, persisted)
			},
		},
		{
			description: "missing sessions return the service not found error",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				loaded, err := svc.Get(t.Context(), "missing")
				require.ErrorIs(t, err, ErrSessionNotFound)
				assert.Empty(t, loaded)
				refreshed, err := svc.Refresh(t.Context(), "missing")
				require.ErrorIs(t, err, ErrSessionNotFound)
				assert.Empty(t, refreshed)
				updated, err := svc.Update(t.Context(), "missing", pending)
				require.ErrorIs(t, err, ErrSessionNotFound)
				assert.Empty(t, updated)
			},
		},
		{
			description: "expired sessions cannot be read or updated",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				session.ExpiresAt = time.Now().Add(-time.Hour).Unix()
				_, err := svc.store.UpdateSessionByUUID(t.Context(), repository.UpdateSessionByUUIDParams{
					UUID: session.UUID, ExpiresAt: session.ExpiresAt, ContextJSON: session.ContextJSON,
				})
				require.NoError(t, err)
				_, err = svc.Get(t.Context(), session.UUID)
				require.ErrorIs(t, err, ErrSessionNotFound)
				_, err = svc.Update(t.Context(), session.UUID, pending)
				require.ErrorIs(t, err, ErrSessionNotFound)
				persisted, err := svc.store.GetSessionByUUID(t.Context(), session.UUID)
				require.NoError(t, err)
				assert.Equal(t, session, persisted)
			},
		},
		{
			description: "rejects malformed session context",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				_, err := svc.store.UpdateSessionByUUID(t.Context(), repository.UpdateSessionByUUIDParams{
					UUID: session.UUID, ExpiresAt: session.ExpiresAt, ContextJSON: "{",
				})
				require.NoError(t, err)
				result, err := svc.Get(t.Context(), session.UUID)
				require.ErrorContains(t, err, "failed to unmarshal session context")
				assert.Empty(t, result)
			},
		},
		{
			description: "updating context preserves expiry and creation time",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				updated, err := svc.Update(t.Context(), session.UUID, pending)
				require.NoError(t, err)
				encoded, err := json.Marshal(pending)
				require.NoError(t, err)
				expected := session
				expected.ContextJSON = string(encoded)
				assert.Equal(t, expected, updated)
				loaded, err := svc.Get(t.Context(), session.UUID)
				require.NoError(t, err)
				assert.Equal(t, model.SessionGetResult{Session: expected, SessionContext: pending}, loaded)
			},
		},
		{
			description: "completing TOTP starts the configured session lifetime",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				created, err := svc.Create(t.Context(), session.IdentityUUID, pending)
				require.NoError(t, err)
				before := time.Now().Unix()
				updated, err := svc.Update(t.Context(), created.UUID, model.SessionContext{})
				require.NoError(t, err)
				assert.GreaterOrEqual(t, updated.ExpiresAt, before+int64(svc.config.Auth.SessionExpiry))
				assert.LessOrEqual(t, updated.ExpiresAt, time.Now().Unix()+int64(svc.config.Auth.SessionExpiry))
				assert.Greater(t, updated.ExpiresAt, created.ExpiresAt)
				assert.Equal(t, created.CreatedAt, updated.CreatedAt)
				assert.Equal(t, created.IdentityUUID, updated.IdentityUUID)
				loaded, err := svc.Get(t.Context(), created.UUID)
				require.NoError(t, err)
				assert.Equal(t, model.SessionGetResult{Session: updated}, loaded)
			},
		},
		{
			description: "repeated pending updates do not extend TOTP expiry",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				created, err := svc.Create(t.Context(), session.IdentityUUID, pending)
				require.NoError(t, err)
				updated, err := svc.Update(t.Context(), created.UUID, pending)
				require.NoError(t, err)
				assert.Equal(t, created, updated)
			},
		},
		{
			description: "deletion removes sessions and is idempotent",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				require.NoError(t, svc.Delete(t.Context(), session.UUID))
				_, err := svc.store.GetSessionByUUID(t.Context(), session.UUID)
				require.ErrorIs(t, err, repository.ErrNotFound)
				require.NoError(t, svc.Delete(t.Context(), session.UUID))
			},
		},
		{
			description: "propagates canceled repository operations",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				_, err := svc.Get(ctx, session.UUID)
				require.ErrorIs(t, err, context.Canceled)
				_, err = svc.Refresh(ctx, session.UUID)
				require.ErrorIs(t, err, context.Canceled)
				require.ErrorIs(t, svc.Delete(ctx, session.UUID), context.Canceled)
			},
		},
		{
			description: "propagates repository write failures without changing the session",
			run: func(t *testing.T, svc *SessionsService, db *test.TestDatabase, session repository.Session) {
				_, err := db.DB().ExecContext(t.Context(), "PRAGMA query_only = ON")
				require.NoError(t, err)
				_, err = svc.Create(t.Context(), session.IdentityUUID, pending)
				require.ErrorContains(t, err, "failed to create session")
				_, err = svc.Refresh(t.Context(), session.UUID)
				require.ErrorContains(t, err, "failed to update session expiry")
				_, err = svc.Update(t.Context(), session.UUID, pending)
				require.ErrorContains(t, err, "failed to update session")
				require.ErrorContains(t, svc.Delete(t.Context(), session.UUID), "failed to delete session")
				persisted, err := svc.store.GetSessionByUUID(t.Context(), session.UUID)
				require.NoError(t, err)
				assert.Equal(t, session, persisted)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			db, err := test.NewTestDatabase()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			store := db.Store()
			cfg := &model.Config{Auth: model.AuthConfig{LinkingMode: "both", SessionExpiry: 7200}}
			identity, err := NewIdentityService(IdentityServiceInput{Store: store, Config: cfg})
			require.NoError(t, err)
			stored, err := identity.Store(t.Context(), StoreIdentityParams{
				Username: "testuser", Email: "test@example.com", ProviderID: "local", ProviderType: model.ProviderLocal,
			})
			require.NoError(t, err)
			session, err := store.CreateSession(t.Context(), repository.CreateSessionParams{
				UUID: "session-id", IdentityUUID: stored.UUID,
				CreatedAt: time.Now().Add(-time.Hour).Unix(), ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
				ContextJSON: `{"local":{"totp_pending":false}}`,
			})
			require.NoError(t, err)
			svc := NewSessionsService(SessionsServiceInput{Store: store, Identity: identity, Config: cfg})
			tc.run(t, svc, db, session)
		})
	}
}
