package test

import (
	"database/sql"

	"github.com/tinyauthapp/tinyauth/internal/repository"
)

type TestDatabase struct {
	db *sql.DB
}

func NewTestDatabase() (*TestDatabase, error) {
	db, err := repository.SetupSQLite(":memory:")
	if err != nil {
		return nil, err
	}
	return &TestDatabase{
		db: db,
	}, nil
}

func (tdb *TestDatabase) Close() error {
	return tdb.db.Close()
}

func (tdb *TestDatabase) DB() *sql.DB {
	return tdb.db
}
