package service

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/repository/postgres"
	"github.com/tinyauthapp/tinyauth/internal/repository/sqlite"
	"go.uber.org/dig"
)

type StoreFactoryDBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

type StoreFactory struct {
	db  *sql.DB
	typ model.DatabaseType
}

type StoreFactoryInput struct {
	dig.In

	Database     *sql.DB
	DatabaseType model.DatabaseType
}

func NewStoreFactory(i StoreFactoryInput) *StoreFactory {
	return &StoreFactory{
		typ: i.DatabaseType,
		db:  i.Database,
	}
}

func (f *StoreFactory) createStore(dbtx StoreFactoryDBTX) (repository.Store, error) {
	switch f.typ {
	case model.DatabaseTypeSQLite:
		return sqlite.NewStore(sqlite.New(dbtx)), nil
	case model.DatabaseTypePostgres:
		return postgres.NewStore(postgres.New(dbtx)), nil
	default:
		return nil, fmt.Errorf("unknown database type %q", f.typ)
	}
}

func (f *StoreFactory) ProvideStore() (repository.Store, error) {
	return f.createStore(f.db)
}

func (f *StoreFactory) ProvideTransaction(ctx context.Context, cb func(store repository.Store) error) error {
	// Isolation level serializable ensures that a transaction does
	// not insert a user at the same time as another transaction,
	// ensuring no duplicate users
	tx, err := f.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	store, err := f.createStore(tx)
	if err != nil {
		return fmt.Errorf("failed to create store: %w", err)
	}

	if err := cb(store); err != nil {
		// escalate the error without modifying it
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit: %w", err)
	}

	return nil
}
