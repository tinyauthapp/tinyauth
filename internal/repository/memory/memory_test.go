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

func TestCreateAndGetSession(t *testing.T) {
	s := memory.New()
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
}

func TestGetSession_NotFound(t *testing.T) {
	s := memory.New()
	_, err := s.GetSession(ctx, "missing")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestUpdateSession(t *testing.T) {
	s := memory.New()
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
}

func TestUpdateSession_NotFound(t *testing.T) {
	s := memory.New()
	_, err := s.UpdateSession(ctx, repository.UpdateSessionParams{UUID: "missing"})
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestDeleteSession(t *testing.T) {
	s := memory.New()
	_, err := s.CreateSession(ctx, repository.CreateSessionParams{UUID: "uuid-1"})
	require.NoError(t, err)

	require.NoError(t, s.DeleteSession(ctx, "uuid-1"))

	_, err = s.GetSession(ctx, "uuid-1")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestDeleteExpiredSessions(t *testing.T) {
	s := memory.New()
	_, err := s.CreateSession(ctx, repository.CreateSessionParams{UUID: "expired", Expiry: 10})
	require.NoError(t, err)
	_, err = s.CreateSession(ctx, repository.CreateSessionParams{UUID: "valid", Expiry: 100})
	require.NoError(t, err)

	require.NoError(t, s.DeleteExpiredSessions(ctx, 50))

	_, err = s.GetSession(ctx, "expired")
	assert.ErrorIs(t, err, repository.ErrNotFound)

	_, err = s.GetSession(ctx, "valid")
	assert.NoError(t, err)
}

func TestCreateAndGetOidcCode(t *testing.T) {
	s := memory.New()
	code, err := s.CreateOidcCode(ctx, repository.CreateOidcCodeParams{
		Sub:      "sub-1",
		CodeHash: "hash-1",
		Scope:    "openid",
	})
	require.NoError(t, err)
	assert.Equal(t, "sub-1", code.Sub)

	// destructive read removes the record
	got, err := s.GetOidcCode(ctx, "hash-1")
	require.NoError(t, err)
	assert.Equal(t, code, got)

	_, err = s.GetOidcCode(ctx, "hash-1")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestGetOidcCode_NotFound(t *testing.T) {
	s := memory.New()
	_, err := s.GetOidcCode(ctx, "missing")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestGetOidcCodeBySub(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcCode(ctx, repository.CreateOidcCodeParams{Sub: "sub-1", CodeHash: "hash-1"})
	require.NoError(t, err)

	got, err := s.GetOidcCodeBySub(ctx, "sub-1")
	require.NoError(t, err)
	assert.Equal(t, "sub-1", got.Sub)

	// destructive — gone after read
	_, err = s.GetOidcCodeBySub(ctx, "sub-1")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestGetOidcCodeBySub_NotFound(t *testing.T) {
	s := memory.New()
	_, err := s.GetOidcCodeBySub(ctx, "missing")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestGetOidcCodeUnsafe(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcCode(ctx, repository.CreateOidcCodeParams{Sub: "sub-1", CodeHash: "hash-1"})
	require.NoError(t, err)

	got, err := s.GetOidcCodeUnsafe(ctx, "hash-1")
	require.NoError(t, err)
	assert.Equal(t, "sub-1", got.Sub)

	// non-destructive — still present
	_, err = s.GetOidcCodeUnsafe(ctx, "hash-1")
	assert.NoError(t, err)
}

func TestGetOidcCodeUnsafe_NotFound(t *testing.T) {
	s := memory.New()
	_, err := s.GetOidcCodeUnsafe(ctx, "missing")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestGetOidcCodeBySubUnsafe(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcCode(ctx, repository.CreateOidcCodeParams{Sub: "sub-1", CodeHash: "hash-1"})
	require.NoError(t, err)

	got, err := s.GetOidcCodeBySubUnsafe(ctx, "sub-1")
	require.NoError(t, err)
	assert.Equal(t, "hash-1", got.CodeHash)

	// non-destructive — still present
	_, err = s.GetOidcCodeBySubUnsafe(ctx, "sub-1")
	assert.NoError(t, err)
}

func TestGetOidcCodeBySubUnsafe_NotFound(t *testing.T) {
	s := memory.New()
	_, err := s.GetOidcCodeBySubUnsafe(ctx, "missing")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestCreateOidcCode_UniqueSubConstraint(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcCode(ctx, repository.CreateOidcCodeParams{Sub: "sub-1", CodeHash: "hash-1"})
	require.NoError(t, err)

	_, err = s.CreateOidcCode(ctx, repository.CreateOidcCodeParams{Sub: "sub-1", CodeHash: "hash-2"})
	assert.ErrorContains(t, err, "UNIQUE constraint failed: oidc_codes.sub")
}

func TestDeleteOidcCode(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcCode(ctx, repository.CreateOidcCodeParams{Sub: "sub-1", CodeHash: "hash-1"})
	require.NoError(t, err)

	require.NoError(t, s.DeleteOidcCode(ctx, "hash-1"))

	_, err = s.GetOidcCodeUnsafe(ctx, "hash-1")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestDeleteOidcCodeBySub(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcCode(ctx, repository.CreateOidcCodeParams{Sub: "sub-1", CodeHash: "hash-1"})
	require.NoError(t, err)

	require.NoError(t, s.DeleteOidcCodeBySub(ctx, "sub-1"))

	_, err = s.GetOidcCodeUnsafe(ctx, "hash-1")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestDeleteExpiredOidcCodes(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcCode(ctx, repository.CreateOidcCodeParams{Sub: "sub-1", CodeHash: "hash-1", ExpiresAt: 10})
	require.NoError(t, err)
	_, err = s.CreateOidcCode(ctx, repository.CreateOidcCodeParams{Sub: "sub-2", CodeHash: "hash-2", ExpiresAt: 100})
	require.NoError(t, err)

	deleted, err := s.DeleteExpiredOidcCodes(ctx, 50)
	require.NoError(t, err)
	require.Len(t, deleted, 1)
	assert.Equal(t, "hash-1", deleted[0].CodeHash)

	_, err = s.GetOidcCodeUnsafe(ctx, "hash-2")
	assert.NoError(t, err)
}

func TestCreateAndGetOidcToken(t *testing.T) {
	s := memory.New()
	tok, err := s.CreateOidcToken(ctx, repository.CreateOidcTokenParams{
		Sub:             "sub-1",
		AccessTokenHash: "at-hash-1",
		CodeHash:        "code-hash-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "sub-1", tok.Sub)

	got, err := s.GetOidcToken(ctx, "at-hash-1")
	require.NoError(t, err)
	assert.Equal(t, tok, got)
}

func TestGetOidcToken_NotFound(t *testing.T) {
	s := memory.New()
	_, err := s.GetOidcToken(ctx, "missing")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestCreateOidcToken_UniqueSubConstraint(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcToken(ctx, repository.CreateOidcTokenParams{Sub: "sub-1", AccessTokenHash: "at-1"})
	require.NoError(t, err)

	_, err = s.CreateOidcToken(ctx, repository.CreateOidcTokenParams{Sub: "sub-1", AccessTokenHash: "at-2"})
	assert.ErrorContains(t, err, "UNIQUE constraint failed: oidc_tokens.sub")
}

func TestGetOidcTokenByRefreshToken(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcToken(ctx, repository.CreateOidcTokenParams{
		Sub:              "sub-1",
		AccessTokenHash:  "at-1",
		RefreshTokenHash: "rt-1",
	})
	require.NoError(t, err)

	got, err := s.GetOidcTokenByRefreshToken(ctx, "rt-1")
	require.NoError(t, err)
	assert.Equal(t, "sub-1", got.Sub)
}

func TestGetOidcTokenByRefreshToken_NotFound(t *testing.T) {
	s := memory.New()
	_, err := s.GetOidcTokenByRefreshToken(ctx, "missing")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestGetOidcTokenBySub(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcToken(ctx, repository.CreateOidcTokenParams{
		Sub:             "sub-1",
		AccessTokenHash: "at-1",
	})
	require.NoError(t, err)

	got, err := s.GetOidcTokenBySub(ctx, "sub-1")
	require.NoError(t, err)
	assert.Equal(t, "at-1", got.AccessTokenHash)
}

func TestGetOidcTokenBySub_NotFound(t *testing.T) {
	s := memory.New()
	_, err := s.GetOidcTokenBySub(ctx, "missing")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestUpdateOidcTokenByRefreshToken(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcToken(ctx, repository.CreateOidcTokenParams{
		Sub:              "sub-1",
		AccessTokenHash:  "at-1",
		RefreshTokenHash: "rt-1",
	})
	require.NoError(t, err)

	updated, err := s.UpdateOidcTokenByRefreshToken(ctx, repository.UpdateOidcTokenByRefreshTokenParams{
		RefreshTokenHash_2:    "rt-1",
		AccessTokenHash:       "at-2",
		RefreshTokenHash:      "rt-2",
		TokenExpiresAt:        200,
		RefreshTokenExpiresAt: 400,
	})
	require.NoError(t, err)
	assert.Equal(t, "at-2", updated.AccessTokenHash)
	assert.Equal(t, "rt-2", updated.RefreshTokenHash)

	// old key gone, new key present
	_, err = s.GetOidcToken(ctx, "at-1")
	assert.ErrorIs(t, err, repository.ErrNotFound)

	got, err := s.GetOidcToken(ctx, "at-2")
	require.NoError(t, err)
	assert.Equal(t, "sub-1", got.Sub)
}

func TestUpdateOidcTokenByRefreshToken_NotFound(t *testing.T) {
	s := memory.New()
	_, err := s.UpdateOidcTokenByRefreshToken(ctx, repository.UpdateOidcTokenByRefreshTokenParams{
		RefreshTokenHash_2: "missing",
	})
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestDeleteOidcToken(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcToken(ctx, repository.CreateOidcTokenParams{Sub: "sub-1", AccessTokenHash: "at-1"})
	require.NoError(t, err)

	require.NoError(t, s.DeleteOidcToken(ctx, "at-1"))

	_, err = s.GetOidcToken(ctx, "at-1")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestDeleteOidcTokenBySub(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcToken(ctx, repository.CreateOidcTokenParams{Sub: "sub-1", AccessTokenHash: "at-1"})
	require.NoError(t, err)

	require.NoError(t, s.DeleteOidcTokenBySub(ctx, "sub-1"))

	_, err = s.GetOidcToken(ctx, "at-1")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestDeleteOidcTokenByCodeHash(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcToken(ctx, repository.CreateOidcTokenParams{
		Sub:             "sub-1",
		AccessTokenHash: "at-1",
		CodeHash:        "code-1",
	})
	require.NoError(t, err)

	require.NoError(t, s.DeleteOidcTokenByCodeHash(ctx, "code-1"))

	_, err = s.GetOidcToken(ctx, "at-1")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestDeleteExpiredOidcTokens(t *testing.T) {
	s := memory.New()
	// expired by TokenExpiresAt
	_, err := s.CreateOidcToken(ctx, repository.CreateOidcTokenParams{
		Sub: "sub-1", AccessTokenHash: "at-1",
		TokenExpiresAt: 10, RefreshTokenExpiresAt: 100,
	})
	require.NoError(t, err)
	// expired by RefreshTokenExpiresAt
	_, err = s.CreateOidcToken(ctx, repository.CreateOidcTokenParams{
		Sub: "sub-2", AccessTokenHash: "at-2",
		TokenExpiresAt: 100, RefreshTokenExpiresAt: 10,
	})
	require.NoError(t, err)
	// valid
	_, err = s.CreateOidcToken(ctx, repository.CreateOidcTokenParams{
		Sub: "sub-3", AccessTokenHash: "at-3",
		TokenExpiresAt: 100, RefreshTokenExpiresAt: 100,
	})
	require.NoError(t, err)

	deleted, err := s.DeleteExpiredOidcTokens(ctx, repository.DeleteExpiredOidcTokensParams{
		TokenExpiresAt:        50,
		RefreshTokenExpiresAt: 50,
	})
	require.NoError(t, err)
	assert.Len(t, deleted, 2)

	_, err = s.GetOidcToken(ctx, "at-3")
	assert.NoError(t, err)
}

func TestCreateAndGetOidcUserInfo(t *testing.T) {
	s := memory.New()
	u, err := s.CreateOidcUserInfo(ctx, repository.CreateOidcUserInfoParams{
		Sub:   "sub-1",
		Name:  "Alice",
		Email: "alice@example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "sub-1", u.Sub)

	got, err := s.GetOidcUserInfo(ctx, "sub-1")
	require.NoError(t, err)
	assert.Equal(t, u, got)
}

func TestGetOidcUserInfo_NotFound(t *testing.T) {
	s := memory.New()
	_, err := s.GetOidcUserInfo(ctx, "missing")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestDeleteOidcUserInfo(t *testing.T) {
	s := memory.New()
	_, err := s.CreateOidcUserInfo(ctx, repository.CreateOidcUserInfoParams{Sub: "sub-1"})
	require.NoError(t, err)

	require.NoError(t, s.DeleteOidcUserInfo(ctx, "sub-1"))

	_, err = s.GetOidcUserInfo(ctx, "sub-1")
	assert.ErrorIs(t, err, repository.ErrNotFound)
}
