package repository

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	pgxmigrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/tinyauthapp/tinyauth/internal/assets"
	_ "modernc.org/sqlite"
)

func SetupSQLite(databasePath string) (*sql.DB, error) {
	dir := filepath.Dir(databasePath)

	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create database directory %s: %w", dir, err)
	}

	dsn := databasePath

	if databasePath != ":memory:" {
		separator := "?"
		if strings.Contains(dsn, "?") {
			separator = "&"
		}
		dsn += separator + "_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	}

	if databasePath == ":memory:" {
		dsn = "file::memory:?cache=shared"
	}

	dsn += "&_pragma=foreign_keys(1)"

	db, err := sql.Open("sqlite", dsn)

	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	cleanup := true
	defer func() {
		if cleanup {
			db.Close()
		}
	}()

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

	if err = migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	cleanup = false
	return db, nil
}

func SetupPostgres(databaseURL string) (*sql.DB, error) {
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

	if err = migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	cleanup = false
	return db, nil
}
