package test

import (
	"database/sql"

	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/repository/sqlite"
)

type TestDatabase struct {
	db    *sql.DB
	store repository.Store
}

func NewTestDatabase() (*TestDatabase, error) {
	db, err := repository.SetupSQLite(":memory:")
	if err != nil {
		return nil, err
	}

	store := sqlite.NewStore(sqlite.New(db))
	return &TestDatabase{
		db:    db,
		store: store,
	}, nil
}

func (tdb *TestDatabase) Close() error {
	return tdb.db.Close()
}

func (tdb *TestDatabase) Store() repository.Store {
	return tdb.store
}

func (tdb *TestDatabase) DB() *sql.DB {
	return tdb.db
}
