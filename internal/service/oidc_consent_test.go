package service

import (
	"context"
	"strings"
	"testing"

	"github.com/steveiliop56/ding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/repository/memory"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func newTestOIDCService(t *testing.T, cfg *model.Config, runtime *model.RuntimeConfig, store repository.Store) *OIDCService {
	t.Helper()

	log := logger.NewLogger().WithTestConfig()
	log.Init()

	ctx := context.Background()
	dg := ding.New(ctx)

	svc, err := NewOIDCService(OIDCServiceInput{
		Log:     log,
		Config:  cfg,
		Runtime: runtime,
		Queries: store,
		Ding:    dg,
	})
	require.NoError(t, err)
	require.NotNil(t, svc)

	return svc
}

func TestOIDCConsentPerClient(t *testing.T) {
	cfg, runtime := test.CreateTestConfigs(t)

	store := memory.New()
	svc := newTestOIDCService(t, &cfg, &runtime, store)

	// Consent for client A
	_, err := svc.UpsertOIDCConsent(context.Background(), "testuser", "openid profile", "some-client-id")
	require.NoError(t, err)

	// Consent for client B
	_, err = svc.UpsertOIDCConsent(context.Background(), "testuser", "openid email", "other-client-id")
	require.NoError(t, err)

	// Two separate rows, one per client
	consents, err := store.ListOIDCConsents(context.Background())
	require.NoError(t, err)
	assert.Len(t, consents, 2)

	// Each lookup returns the consent for that specific client
	gotA, err := svc.GetOIDCConsent(context.Background(), "testuser", "some-client-id")
	require.NoError(t, err)
	require.NotNil(t, gotA)
	assert.Equal(t, "openid profile", gotA.Scope)

	gotB, err := svc.GetOIDCConsent(context.Background(), "testuser", "other-client-id")
	require.NoError(t, err)
	require.NotNil(t, gotB)
	assert.Equal(t, "openid email", gotB.Scope)
}

func TestOIDCConsentUnionKeepsOneRow(t *testing.T) {
	cfg, runtime := test.CreateTestConfigs(t)

	store := memory.New()
	svc := newTestOIDCService(t, &cfg, &runtime, store)

	_, err := svc.UpsertOIDCConsent(context.Background(), "testuser", "openid profile", "some-client-id")
	require.NoError(t, err)

	// Second authorize with an additional scope
	_, err = svc.UpsertOIDCConsent(context.Background(), "testuser", "openid email", "some-client-id")
	require.NoError(t, err)

	// Still exactly one row
	consents, err := store.ListOIDCConsents(context.Background())
	require.NoError(t, err)
	assert.Len(t, consents, 1)

	// Stored scope is the union of both requests
	got, err := svc.GetOIDCConsent(context.Background(), "testuser", "some-client-id")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, []string{"email", "openid", "profile"}, splitScopes(got.Scope))
}

func TestOIDCConsentSubsetDoesNotShrink(t *testing.T) {
	cfg, runtime := test.CreateTestConfigs(t)

	store := memory.New()
	svc := newTestOIDCService(t, &cfg, &runtime, store)

	_, err := svc.UpsertOIDCConsent(context.Background(), "testuser", "openid profile email", "some-client-id")
	require.NoError(t, err)

	// Authorize with a subset of already-granted scopes
	_, err = svc.UpsertOIDCConsent(context.Background(), "testuser", "openid profile", "some-client-id")
	require.NoError(t, err)

	// Stored scope is unchanged
	got, err := svc.GetOIDCConsent(context.Background(), "testuser", "some-client-id")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, []string{"email", "openid", "profile"}, splitScopes(got.Scope))
}

func TestOIDCConsentNotFound(t *testing.T) {
	cfg, runtime := test.CreateTestConfigs(t)

	store := memory.New()
	svc := newTestOIDCService(t, &cfg, &runtime, store)

	got, err := svc.GetOIDCConsent(context.Background(), "testuser", "some-client-id")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestOIDCConsentReconcileRemovesDeletedClients(t *testing.T) {
	cfg, runtime := test.CreateTestConfigs(t)

	cfg.OIDC.Clients["client-a"] = model.OIDCClientConfig{
		ClientID:            "client-a",
		ClientSecret:        "secret-a",
		TrustedRedirectURIs: []string{"https://a.example.com/callback"},
	}
	cfg.OIDC.Clients["client-b"] = model.OIDCClientConfig{
		ClientID:            "client-b",
		ClientSecret:        "secret-b",
		TrustedRedirectURIs: []string{"https://b.example.com/callback"},
	}

	// First startup: both clients configured
	store := memory.New()
	svc := newTestOIDCService(t, &cfg, &runtime, store)

	_, err := svc.UpsertOIDCConsent(context.Background(), "testuser", "openid profile", "client-a")
	require.NoError(t, err)
	_, err = svc.UpsertOIDCConsent(context.Background(), "testuser", "openid email", "client-b")
	require.NoError(t, err)
	// Stale consent for a client that was never configured
	_, err = svc.UpsertOIDCConsent(context.Background(), "testuser", "openid", "stale-client")
	require.NoError(t, err)

	// Second startup: client-b removed from configuration
	delete(cfg.OIDC.Clients, "client-b")

	svc2 := newTestOIDCService(t, &cfg, &runtime, store)

	// Consents for the removed and unknown clients are gone
	_, err = store.GetOIDCConsentByUsernameAndClientID(context.Background(), repository.GetOIDCConsentByUsernameAndClientIDParams{
		Username: "testuser", ClientID: "client-a",
	})
	require.NoError(t, err)

	_, err = store.GetOIDCConsentByUsernameAndClientID(context.Background(), repository.GetOIDCConsentByUsernameAndClientIDParams{
		Username: "testuser", ClientID: "client-b",
	})
	assert.ErrorIs(t, err, repository.ErrNotFound)

	_, err = store.GetOIDCConsentByUsernameAndClientID(context.Background(), repository.GetOIDCConsentByUsernameAndClientIDParams{
		Username: "testuser", ClientID: "stale-client",
	})
	assert.ErrorIs(t, err, repository.ErrNotFound)

	require.NotNil(t, svc2)
}

func splitScopes(scope string) []string {
	return strings.Fields(scope)
}
