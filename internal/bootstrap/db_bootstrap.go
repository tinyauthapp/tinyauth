package bootstrap

import (
	"fmt"

	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/repository/postgres"
	"github.com/tinyauthapp/tinyauth/internal/repository/sqlite"
)

func (app *BootstrapApp) setupStore() (repository.Store, error) {
	driver := app.config.Database.Driver

	switch driver {
	case "memory", "sqlite", "":
		path := app.config.Database.Path
		if driver == "memory" {
			path = ":memory:"
		}

		db, err := repository.SetupSQLite(path)
		if err != nil {
			return nil, fmt.Errorf("failed to setup SQLite: %w", err)
		}

		app.db = db

		return sqlite.NewStore(sqlite.New(db)), nil

	case "postgres":
		db, err := repository.SetupPostgres(app.config.Database.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to setup PostgreSQL: %w", err)
		}

		app.db = db

		return postgres.NewStore(postgres.New(db)), nil

	default:
		return nil, fmt.Errorf("unknown database driver %q", driver)
	}
}
