package test

import (
	"database/sql"
	"fmt"
	"sync/atomic"

	"github.com/tinyauthapp/tinyauth/internal/repository"
)

var databaseID atomic.Uint64

type TestDatabase struct {
	db *sql.DB
}

func NewTestDatabase() (*TestDatabase, error) {
	path := fmt.Sprintf("file:tinyauth-test-%d?mode=memory&cache=shared", databaseID.Add(1))
	db, err := repository.SetupSQLite(path)
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
