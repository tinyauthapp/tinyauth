package bootstrap

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tinyauthapp/tinyauth/internal/assets"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/repository/sqlite"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "modernc.org/sqlite"
)

func (app *BootstrapApp) SetupStore() (repository.Store, error) {
	return app.setupSQLite(app.config.Database.Path)
}

// NewSQLiteStore opens a SQLite database at the given path, runs migrations, and returns a Store.
// Useful for testing or when constructing a store outside of a BootstrapApp.
func NewSQLiteStore(databasePath string) (repository.Store, error) {
	app := &BootstrapApp{}
	return app.setupSQLite(databasePath)
}

func (app *BootstrapApp) setupSQLite(databasePath string) (repository.Store, error) {
	dir := filepath.Dir(databasePath)

	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create database directory %s: %w", dir, err)
	}

	db, err := sql.Open("sqlite", databasePath)

	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Limit to 1 connection to sequence writes, this may need to be revisited in the future
	// if the sqlite connection starts being a bottleneck
	db.SetMaxOpenConns(1)

	migrations, err := iofs.New(assets.Migrations, "migrations/sqlite")

	if err != nil {
		return nil, fmt.Errorf("failed to create migrations: %w", err)
	}

	target, err := sqlite3.WithInstance(db, &sqlite3.Config{})

	if err != nil {
		return nil, fmt.Errorf("failed to create sqlite3 instance: %w", err)
	}

	migrator, err := migrate.NewWithInstance("iofs", migrations, "sqlite3", target)

	if err != nil {
		return nil, fmt.Errorf("failed to create migrator: %w", err)
	}

	if err := migrator.Up(); err != nil && err != migrate.ErrNoChange {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return sqlite.NewStore(sqlite.New(db)), nil
}
