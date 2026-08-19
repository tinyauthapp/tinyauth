package bootstrap

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	pgxmigrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/tinyauthapp/tinyauth/internal/assets"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/repository/memory"
	"github.com/tinyauthapp/tinyauth/internal/repository/postgres"
	"github.com/tinyauthapp/tinyauth/internal/repository/sqlite"
)

func (app *BootstrapApp) SetupStore() (repository.Store, error) {
	switch app.config.Database.Driver {
	case "memory":
		return memory.New(), nil
	case "sqlite", "":
		return app.setupSQLite(app.config.Database.Path)
	case "postgres":
		return app.setupPostgres(app.config.Database.Path)
	default:
		return nil, fmt.Errorf("unknown database driver %q: valid values are sqlite, postgres, memory", app.config.Database.Driver)
	}
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

	cleanup := true
	defer func() {
		if cleanup {
			db.Close()
		}
	}()

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

	if err = migrator.Up(); err != nil && err != migrate.ErrNoChange {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	cleanup = false
	app.db = db

	return sqlite.NewStore(sqlite.New(db)), nil
}

func (app *BootstrapApp) setupPostgres(databaseURL string) (repository.Store, error) {
	db, err := sql.Open("pgx", databaseURL)

	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	cleanup := true
	defer func() {
		if cleanup {
			db.Close()
		}
	}()

	migrations, err := iofs.New(assets.Migrations, "migrations/postgres")

	if err != nil {
		return nil, fmt.Errorf("failed to create migrations: %w", err)
	}

	target, err := pgxmigrate.WithInstance(db, &pgxmigrate.Config{})

	if err != nil {
		return nil, fmt.Errorf("failed to create postgres instance: %w", err)
	}

	migrator, err := migrate.NewWithInstance("iofs", migrations, "pgx", target)

	if err != nil {
		return nil, fmt.Errorf("failed to create migrator: %w", err)
	}

	if err = migrator.Up(); err != nil && err != migrate.ErrNoChange {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	cleanup = false
	app.db = db

	return postgres.NewStore(postgres.New(db)), nil
}
