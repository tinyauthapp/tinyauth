package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/test"
)

func TestStoreFactory_ProvideTransaction(t *testing.T) {
	serialization := &pgconn.PgError{Code: "40001"}
	wrapped := fmt.Errorf("failed to create user: %w", serialization)
	other := errors.New("login failed")
	unique := &pgconn.PgError{Code: "23505"}

	type testCase struct {
		description string
		failures    int
		err         error
		calls       int
		expectErr   error
	}

	testCases := []testCase{
		{description: "commit succeeds", calls: 1},
		{
			description: "retry serialization failure",
			failures:    1, err: serialization, calls: 2,
		},
		{
			description: "retry wrapped serialization failure",
			failures:    1, err: wrapped, calls: 2,
		},
		{
			description: "stop after retry budget",
			failures:    100, err: wrapped, expectErr: wrapped,
		},
		{
			description: "other errors are not retried",
			failures:    1, err: other, calls: 1, expectErr: other,
		},
		{
			description: "other SQL states are not retried",
			failures:    1, err: unique, calls: 1, expectErr: unique,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			tdb, err := test.NewTestDatabase()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tdb.Close()) })
			factory := NewStoreFactory(StoreFactoryInput{
				Database: tdb.DB(), DatabaseType: model.DatabaseTypeSQLite,
			})

			ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
			defer cancel()
			calls := 0
			err = factory.ProvideTransaction(ctx, func(store repository.Store) error {
				calls++
				// Reusing the UUID verifies that failed attempts were rolled back.
				_, err := store.CreateUser(ctx, repository.CreateUserParams{
					UUID: "user", Username: "alice", Email: "alice@example.com", Name: "Alice",
				})
				if err != nil {
					return err
				}
				if calls <= tc.failures {
					return tc.err
				}
				return nil
			})
			if tc.calls != 0 {
				assert.Equal(t, tc.calls, calls)
			} else {
				assert.Greater(t, calls, 1)
				assert.Less(t, calls, tc.failures)
			}
			if tc.expectErr != nil {
				require.ErrorContains(t, err, tc.expectErr.Error())
			} else {
				require.NoError(t, err)
			}

			store, err := factory.ProvideStore()
			require.NoError(t, err)
			user, err := store.GetUserByUUID(t.Context(), "user")
			if tc.expectErr != nil {
				require.ErrorIs(t, err, repository.ErrNotFound)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, repository.User{
				UUID: "user", Username: "alice", Email: "alice@example.com", Name: "Alice",
			}, user)
		})
	}
}

func TestStoreFactory_Cancellation(t *testing.T) {
	type testCase struct {
		description  string
		cancelBefore bool
		calls        int
		expectErr    error
	}

	testCases := []testCase{
		{description: "cancel before begin", cancelBefore: true, expectErr: context.Canceled},
		{description: "cancel during backoff", calls: 1, expectErr: context.DeadlineExceeded},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			tdb, err := test.NewTestDatabase()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tdb.Close()) })
			factory := NewStoreFactory(StoreFactoryInput{
				Database: tdb.DB(), DatabaseType: model.DatabaseTypeSQLite,
			})

			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			if tc.cancelBefore {
				cancel()
			}
			calls := 0
			err = factory.ProvideTransaction(ctx, func(store repository.Store) error {
				calls++
				return &pgconn.PgError{Code: "40001"}
			})
			require.ErrorIs(t, err, tc.expectErr)
			assert.Equal(t, tc.calls, calls)
		})
	}
}
