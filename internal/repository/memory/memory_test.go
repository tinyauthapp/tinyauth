package memory_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/repository/memory"
)

var ctx = context.Background()

func TestMemoryStore(t *testing.T) {
	type testCase struct {
		description string
		run         func(t *testing.T, s repository.Store)
	}

	tests := []testCase{
		{
			description: "Create and get session",
			run: func(t *testing.T, s repository.Store) {
				sess, err := s.CreateSession(ctx, repository.CreateSessionParams{
					UUID:     "uuid-1",
					Username: "alice",
					Expiry:   9999,
				})
				require.NoError(t, err)
				assert.Equal(t, "uuid-1", sess.UUID)
				assert.Equal(t, "alice", sess.Username)

				got, err := s.GetSession(ctx, "uuid-1")
				require.NoError(t, err)
				assert.Equal(t, sess, got)
			},
		},
		{
			description: "Get session not found",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.GetSession(ctx, "missing")
				assert.ErrorIs(t, err, repository.ErrNotFound)
			},
		},
		{
			description: "Update session",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.CreateSession(ctx, repository.CreateSessionParams{UUID: "uuid-1", Username: "alice"})
				require.NoError(t, err)

				updated, err := s.UpdateSession(ctx, repository.UpdateSessionParams{
					UUID:     "uuid-1",
					Username: "bob",
					Email:    "bob@example.com",
				})
				require.NoError(t, err)
				assert.Equal(t, "bob", updated.Username)
				assert.Equal(t, "bob@example.com", updated.Email)

				got, err := s.GetSession(ctx, "uuid-1")
				require.NoError(t, err)
				assert.Equal(t, updated, got)
			},
		},
		{
			description: "Update session not found",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.UpdateSession(ctx, repository.UpdateSessionParams{UUID: "missing"})
				assert.ErrorIs(t, err, repository.ErrNotFound)
			},
		},
		{
			description: "Delete session",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.CreateSession(ctx, repository.CreateSessionParams{UUID: "uuid-1"})
				require.NoError(t, err)

				require.NoError(t, s.DeleteSession(ctx, "uuid-1"))

				_, err = s.GetSession(ctx, "uuid-1")
				assert.ErrorIs(t, err, repository.ErrNotFound)
			},
		},
		{
			description: "Delete expired sessions",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.CreateSession(ctx, repository.CreateSessionParams{UUID: "expired", Expiry: 10})
				require.NoError(t, err)
				_, err = s.CreateSession(ctx, repository.CreateSessionParams{UUID: "valid", Expiry: 100})
				require.NoError(t, err)

				require.NoError(t, s.DeleteExpiredSessions(ctx, 50))

				_, err = s.GetSession(ctx, "expired")
				assert.ErrorIs(t, err, repository.ErrNotFound)

				_, err = s.GetSession(ctx, "valid")
				assert.NoError(t, err)
			},
		},
		{
			description: "Create and get OIDC session",
			run: func(t *testing.T, s repository.Store) {
				sess, err := s.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
					Sub:              "sub-1",
					AccessTokenHash:  "at-1",
					RefreshTokenHash: "rt-1",
					Scope:            "openid",
				})
				require.NoError(t, err)
				assert.Equal(t, "sub-1", sess.Sub)

				got, err := s.GetOIDCSessionBySub(ctx, "sub-1")
				require.NoError(t, err)
				assert.Equal(t, sess, got)
			},
		},
		{
			description: "Get OIDC session by sub not found",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.GetOIDCSessionBySub(ctx, "missing")
				assert.ErrorIs(t, err, repository.ErrNotFound)
			},
		},
		{
			description: "Get OIDC session by access token hash",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
					Sub:              "sub-1",
					AccessTokenHash:  "at-1",
					RefreshTokenHash: "rt-1",
				})
				require.NoError(t, err)

				got, err := s.GetOIDCSessionByAccessTokenHash(ctx, "at-1")
				require.NoError(t, err)
				assert.Equal(t, "sub-1", got.Sub)
			},
		},
		{
			description: "Get OIDC session by access token hash not found",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.GetOIDCSessionByAccessTokenHash(ctx, "missing")
				assert.ErrorIs(t, err, repository.ErrNotFound)
			},
		},
		{
			description: "Get OIDC session by refresh token hash",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
					Sub:              "sub-1",
					AccessTokenHash:  "at-1",
					RefreshTokenHash: "rt-1",
				})
				require.NoError(t, err)

				got, err := s.GetOIDCSessionByRefreshTokenHash(ctx, "rt-1")
				require.NoError(t, err)
				assert.Equal(t, "sub-1", got.Sub)
			},
		},
		{
			description: "Get OIDC session by refresh token hash not found",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.GetOIDCSessionByRefreshTokenHash(ctx, "missing")
				assert.ErrorIs(t, err, repository.ErrNotFound)
			},
		},
		{
			description: "Create OIDC session unique sub constraint",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{Sub: "sub-1", AccessTokenHash: "at-1", RefreshTokenHash: "rt-1"})
				require.NoError(t, err)

				_, err = s.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{Sub: "sub-1", AccessTokenHash: "at-2", RefreshTokenHash: "rt-2"})
				assert.ErrorContains(t, err, "UNIQUE constraint failed: oidc_sessions.sub")
			},
		},
		{
			description: "Create OIDC session unique access token hash constraint",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{Sub: "sub-1", AccessTokenHash: "at-1", RefreshTokenHash: "rt-1"})
				require.NoError(t, err)

				_, err = s.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{Sub: "sub-2", AccessTokenHash: "at-1", RefreshTokenHash: "rt-2"})
				assert.ErrorContains(t, err, "UNIQUE constraint failed: oidc_sessions.access_token_hash")
			},
		},
		{
			description: "Create OIDC session unique refresh token hash constraint",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{Sub: "sub-1", AccessTokenHash: "at-1", RefreshTokenHash: "rt-1"})
				require.NoError(t, err)

				_, err = s.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{Sub: "sub-2", AccessTokenHash: "at-2", RefreshTokenHash: "rt-1"})
				assert.ErrorContains(t, err, "UNIQUE constraint failed: oidc_sessions.refresh_token_hash")
			},
		},
		{
			description: "Update OIDC session",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
					Sub:              "sub-1",
					AccessTokenHash:  "at-1",
					RefreshTokenHash: "rt-1",
				})
				require.NoError(t, err)

				updated, err := s.UpdateOIDCSession(ctx, repository.UpdateOIDCSessionParams{
					Sub:                   "sub-1",
					AccessTokenHash:       "at-2",
					RefreshTokenHash:      "rt-2",
					Scope:                 "openid profile",
					TokenExpiresAt:        200,
					RefreshTokenExpiresAt: 400,
				})
				require.NoError(t, err)
				assert.Equal(t, "at-2", updated.AccessTokenHash)
				assert.Equal(t, "rt-2", updated.RefreshTokenHash)
				assert.Equal(t, "openid profile", updated.Scope)

				// updated token hashes are now queryable, old ones are gone
				got, err := s.GetOIDCSessionByAccessTokenHash(ctx, "at-2")
				require.NoError(t, err)
				assert.Equal(t, "sub-1", got.Sub)

				_, err = s.GetOIDCSessionByAccessTokenHash(ctx, "at-1")
				assert.ErrorIs(t, err, repository.ErrNotFound)
			},
		},
		{
			description: "Update OIDC session not found",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.UpdateOIDCSession(ctx, repository.UpdateOIDCSessionParams{Sub: "missing"})
				assert.ErrorIs(t, err, repository.ErrNotFound)
			},
		},
		{
			description: "Delete OIDC session by sub",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{Sub: "sub-1", AccessTokenHash: "at-1", RefreshTokenHash: "rt-1"})
				require.NoError(t, err)

				require.NoError(t, s.DeleteOIDCSessionBySub(ctx, "sub-1"))

				_, err = s.GetOIDCSessionBySub(ctx, "sub-1")
				assert.ErrorIs(t, err, repository.ErrNotFound)
			},
		},
		{
			description: "Delete expired OIDC sessions",
			run: func(t *testing.T, s repository.Store) {
				// both expiries past
				_, err := s.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
					Sub: "sub-1", AccessTokenHash: "at-1", RefreshTokenHash: "rt-1",
					TokenExpiresAt: 10, RefreshTokenExpiresAt: 10,
				})
				require.NoError(t, err)
				// valid
				_, err = s.CreateOIDCSession(ctx, repository.CreateOIDCSessionParams{
					Sub: "sub-2", AccessTokenHash: "at-2", RefreshTokenHash: "rt-2",
					TokenExpiresAt: 100, RefreshTokenExpiresAt: 100,
				})
				require.NoError(t, err)

				require.NoError(t, s.DeleteExpiredOIDCSessions(ctx, repository.DeleteExpiredOIDCSessionsParams{
					TokenExpiresAt:        50,
					RefreshTokenExpiresAt: 50,
				}))

				_, err = s.GetOIDCSessionBySub(ctx, "sub-1")
				assert.ErrorIs(t, err, repository.ErrNotFound)

				_, err = s.GetOIDCSessionBySub(ctx, "sub-2")
				assert.NoError(t, err)
			},
		},
		{
			description: "Upsert creates a consent for each user+client pair",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.UpsertOIDCConsent(ctx, repository.UpsertOIDCConsentParams{
					Username: "alice", ClientID: "client-a", Scope: "openid profile", CreatedAt: 1,
				})
				require.NoError(t, err)
				_, err = s.UpsertOIDCConsent(ctx, repository.UpsertOIDCConsentParams{
					Username: "alice", ClientID: "client-b", Scope: "openid email", CreatedAt: 2,
				})
				require.NoError(t, err)

				consents, err := s.ListOIDCConsents(ctx)
				require.NoError(t, err)
				assert.Len(t, consents, 2)

				gotA, err := s.GetOIDCConsentByUsernameAndClientID(ctx, repository.GetOIDCConsentByUsernameAndClientIDParams{Username: "alice", ClientID: "client-a"})
				require.NoError(t, err)
				assert.Equal(t, "openid profile", gotA.Scope)

				gotB, err := s.GetOIDCConsentByUsernameAndClientID(ctx, repository.GetOIDCConsentByUsernameAndClientIDParams{Username: "alice", ClientID: "client-b"})
				require.NoError(t, err)
				assert.Equal(t, "openid email", gotB.Scope)
			},
		},
		{
			description: "Upsert overwrites the same consent row",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.UpsertOIDCConsent(ctx, repository.UpsertOIDCConsentParams{
					Username: "alice", ClientID: "client-a", Scope: "openid", CreatedAt: 1,
				})
				require.NoError(t, err)

				_, err = s.UpsertOIDCConsent(ctx, repository.UpsertOIDCConsentParams{
					Username: "alice", ClientID: "client-a", Scope: "openid email", CreatedAt: 2,
				})
				require.NoError(t, err)

				consents, err := s.ListOIDCConsents(ctx)
				require.NoError(t, err)
				assert.Len(t, consents, 1)

				got, err := s.GetOIDCConsentByUsernameAndClientID(ctx, repository.GetOIDCConsentByUsernameAndClientIDParams{Username: "alice", ClientID: "client-a"})
				require.NoError(t, err)
				assert.Equal(t, "openid email", got.Scope)
			},
		},
		{
			description: "Get consent by username and client not found",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.GetOIDCConsentByUsernameAndClientID(ctx, repository.GetOIDCConsentByUsernameAndClientIDParams{Username: "alice", ClientID: "client-a"})
				assert.ErrorIs(t, err, repository.ErrNotFound)
			},
		},
		{
			description: "Delete consent by client id",
			run: func(t *testing.T, s repository.Store) {
				_, err := s.UpsertOIDCConsent(ctx, repository.UpsertOIDCConsentParams{
					Username: "alice", ClientID: "client-a", Scope: "openid", CreatedAt: 1,
				})
				require.NoError(t, err)
				_, err = s.UpsertOIDCConsent(ctx, repository.UpsertOIDCConsentParams{
					Username: "alice", ClientID: "client-b", Scope: "openid", CreatedAt: 2,
				})
				require.NoError(t, err)

				require.NoError(t, s.DeleteOIDCConsentByClientID(ctx, "client-a"))

				consents, err := s.ListOIDCConsents(ctx)
				require.NoError(t, err)
				assert.Len(t, consents, 1)
				assert.Equal(t, "client-b", consents[0].ClientID)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			s := memory.New()
			test.run(t, s)
		})
	}
}
