package test

import (
	"database/sql"
	"sync/atomic"

	"github.com/tinyauthapp/tinyauth/internal/repository"
)

var openDBs atomic.Uint64

type TestDatabase struct {
	db *sql.DB
}

func NewTestDatabase() (*TestDatabase, error) {
	db, err := repository.SetupSQLite(":memory:")
	if err != nil {
		return nil, err
	}
	openDBs.Add(1)
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
