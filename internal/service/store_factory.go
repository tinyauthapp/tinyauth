package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// The callback may run more than once, each time in a new serializable transaction.
func (f *StoreFactory) ProvideTransaction(ctx context.Context, cb func(store repository.Store) error) error {
	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = time.Second
	exp.RandomizationFactor = 0.1
	exp.Multiplier = 1.5
	exp.Reset()

	attempt := func() error {
		tx, err := f.db.BeginTx(ctx, &sql.TxOptions{
			Isolation: sql.LevelSerializable,
		})
		if err != nil {
			return err
		}
		defer tx.Rollback()

		store, err := f.createStore(tx)
		if err != nil {
			return err
		}

		err = cb(store)
		if err != nil {
			return err
		}
		return tx.Commit()
	}

	_, err := backoff.Retry(ctx, func() (any, error) {
		err := attempt()
		var pgErr *pgconn.PgError
		if err != nil && (!errors.As(err, &pgErr) || pgErr.Code != "40001") {
			return nil, backoff.Permanent(fmt.Errorf("failed to execute transaction: %w", err))
		}
		return nil, err
	}, backoff.WithBackOff(exp), backoff.WithMaxElapsedTime(5*time.Second))
	return err
}
