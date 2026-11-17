package bootstrap

import (
	"fmt"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
)

func (app *BootstrapApp) setupDatabase() error {
	driver := app.config.Database.Driver

	switch driver {
	case "memory", "sqlite", "":
		path := app.config.Database.Path
		if driver == "memory" {
			path = ":memory:"
		}

		db, err := repository.SetupSQLite(path)
		if err != nil {
			return fmt.Errorf("failed to setup sqlite: %w", err)
		}

		app.db = db
		app.dbtyp = model.DatabaseTypeSQLite

		return nil
	case "postgres":
		db, err := repository.SetupPostgres(app.config.Database.Path)
		if err != nil {
			return fmt.Errorf("failed to setup postgresql: %w", err)
		}

		app.db = db
		app.dbtyp = model.DatabaseTypePostgres

		return nil
	default:
		return fmt.Errorf("unknown database driver: %q", driver)
	}
}
