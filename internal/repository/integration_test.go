package repository_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	pgxmigrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/tinyauthapp/tinyauth/internal/assets"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/repository/postgres"
	"github.com/tinyauthapp/tinyauth/internal/repository/sqlite"
)

func setupSQLiteStore(t *testing.T) repository.Store {
	t.Helper()

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)

	migrations, err := iofs.New(assets.Migrations, "migrations/sqlite")
	require.NoError(t, err)

	target, err := sqlite3.WithInstance(db, &sqlite3.Config{})
	require.NoError(t, err)

	migrator, err := migrate.NewWithInstance("iofs", migrations, "sqlite3", target)
	require.NoError(t, err)

	err = migrator.Up()
	require.NoError(t, err)

	t.Cleanup(func() { db.Close() })

	return sqlite.NewStore(sqlite.New(db))
}

func setupPostgresStore(t *testing.T) repository.Store {
	t.Helper()

	url := os.Getenv("INTEGRATION_POSTGRES_URL")
	if url == "" {
		t.Skip("INTEGRATION_POSTGRES_URL not set, skipping postgres integration test")
	}

	db, err := sql.Open("pgx", url)
	require.NoError(t, err)

	migrations, err := iofs.New(assets.Migrations, "migrations/postgres")
	require.NoError(t, err)

	target, err := pgxmigrate.WithInstance(db, &pgxmigrate.Config{})
	require.NoError(t, err)

	migrator, err := migrate.NewWithInstance("iofs", migrations, "pgx", target)
	require.NoError(t, err)

	err = migrator.Up()
	require.NoError(t, err)

	t.Cleanup(func() { db.Close() })

	return postgres.NewStore(postgres.New(db))
}

func TestConsentIntegration(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		runConsentScenarios(t, setupSQLiteStore(t))
	})
	t.Run("postgres", func(t *testing.T) {
		runConsentScenarios(t, setupPostgresStore(t))
	})
}

func runConsentScenarios(t *testing.T, store repository.Store) {
	t.Helper()

	ctx := context.Background()

	// User consents to client A with openid profile, then client B with openid email
	_, err := store.UpsertOIDCConsent(ctx, repository.UpsertOIDCConsentParams{
		Username: "alice", ClientID: "client-a", Scope: "openid profile", CreatedAt: 100,
	})
	require.NoError(t, err)
	_, err = store.UpsertOIDCConsent(ctx, repository.UpsertOIDCConsentParams{
		Username: "alice", ClientID: "client-b", Scope: "openid email", CreatedAt: 101,
	})
	require.NoError(t, err)

	consents, err := store.ListOIDCConsents(ctx)
	require.NoError(t, err)
	assert.Len(t, consents, 2)

	gotA, err := store.GetOIDCConsentByUsernameAndClientID(ctx, repository.GetOIDCConsentByUsernameAndClientIDParams{Username: "alice", ClientID: "client-a"})
	require.NoError(t, err)
	assert.Equal(t, "openid profile", gotA.Scope)

	gotB, err := store.GetOIDCConsentByUsernameAndClientID(ctx, repository.GetOIDCConsentByUsernameAndClientIDParams{Username: "alice", ClientID: "client-b"})
	require.NoError(t, err)
	assert.Equal(t, "openid email", gotB.Scope)

	// Same user+client upsert keeps exactly one row
	_, err = store.UpsertOIDCConsent(ctx, repository.UpsertOIDCConsentParams{
		Username: "alice", ClientID: "client-a", Scope: "openid profile email", CreatedAt: 102,
	})
	require.NoError(t, err)

	consents, err = store.ListOIDCConsents(ctx)
	require.NoError(t, err)
	assert.Len(t, consents, 2)

	gotA, err = store.GetOIDCConsentByUsernameAndClientID(ctx, repository.GetOIDCConsentByUsernameAndClientIDParams{Username: "alice", ClientID: "client-a"})
	require.NoError(t, err)
	assert.Equal(t, "openid profile email", gotA.Scope)

	// Removing a client deletes its consent rows
	require.NoError(t, store.DeleteOIDCConsentByClientID(ctx, "client-a"))

	consents, err = store.ListOIDCConsents(ctx)
	require.NoError(t, err)
	assert.Len(t, consents, 1)
	assert.Equal(t, "client-b", consents[0].ClientID)

	_, err = store.GetOIDCConsentByUsernameAndClientID(ctx, repository.GetOIDCConsentByUsernameAndClientIDParams{Username: "alice", ClientID: "client-a"})
	assert.ErrorIs(t, err, repository.ErrNotFound)
}
