package bootstrap

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tinyauthapp/tinyauth/internal/assets"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "modernc.org/sqlite"
)

func (app *BootstrapApp) SetupDatabase() error {
	dir := filepath.Dir(app.config.Database.Path)

	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create database directory %s: %w", dir, err)
	}

	db, err := sql.Open("sqlite", app.config.Database.Path)

	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Close the database if there is an error during migration
	defer func() {
		if err != nil {
			db.Close()
		}
	}()

	// Limit to 1 connection to sequence writes, this may need to be revisited in the future
	// if the sqlite connection starts being a bottleneck
	db.SetMaxOpenConns(1)

	migrations, err := iofs.New(assets.Migrations, "migrations")

	if err != nil {
		return fmt.Errorf("failed to create migrations: %w", err)
	}

	target, err := sqlite3.WithInstance(db, &sqlite3.Config{})

	if err != nil {
		return fmt.Errorf("failed to create sqlite3 instance: %w", err)
	}

	migrator, err := migrate.NewWithInstance("iofs", migrations, "sqlite3", target)

	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}

	if err := migrator.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	app.db = db
	return nil
}

func (app *BootstrapApp) GetDB() *sql.DB {
	return app.db
}
