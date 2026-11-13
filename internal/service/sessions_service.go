package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"go.uber.org/dig"
)

var (
	ErrSessionNotFound = fmt.Errorf("session not found")
)

type SessionsService struct {
	identity *IdentityService

	store   repository.Store
	config  *model.Config
	runtime *model.RuntimeConfig
}

type SessionsServiceInput struct {
	dig.In

	Store    repository.Store
	Identity *IdentityService
	Config   *model.Config
	Runtime  *model.RuntimeConfig
}

func NewSessionsService(i SessionsServiceInput) *SessionsService {
	return &SessionsService{
		store:    i.Store,
		identity: i.Identity,
		config:   i.Config,
		runtime:  i.Runtime,
	}
}

func (s *SessionsService) Create(ctx context.Context, identityUUID string, sessionContext model.SessionContext) (repository.Session, error) {
	// validate that the identity exists
	_, err := s.identity.Load(ctx, identityUUID)

	if err != nil {
		return repository.Session{}, err
	}

	u := uuid.New()
	createdAt := time.Now()

	expiresAt := createdAt.Add(time.Duration(s.config.Auth.SessionExpiry) * time.Second)

	if sessionContext.Local.TOTPPending {
		expiresAt = createdAt.Add(time.Duration(3600) * time.Second)
	}

	contextJSON, err := json.Marshal(sessionContext)

	if err != nil {
		return repository.Session{}, fmt.Errorf("failed to marshal session context: %w", err)
	}

	session, err := s.store.CreateSession(ctx, repository.CreateSessionParams{
		UUID:         u.String(),
		IdentityUUID: identityUUID,
		ExpiresAt:    expiresAt.Unix(),
		CreatedAt:    createdAt.Unix(),
		ContextJSON:  string(contextJSON),
	})

	if err != nil {
		return repository.Session{}, fmt.Errorf("failed to create session: %w", err)
	}

	return session, nil
}

func (s *SessionsService) Refresh(ctx context.Context, uuid string) (repository.Session, error) {
	session, err := s.store.GetSessionByUUID(ctx, uuid)

	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.Session{}, ErrSessionNotFound
		}
		return repository.Session{}, fmt.Errorf("failed to get session: %w", err)
	}

	t := time.Now()

	refreshThreshold := int64(time.Hour.Seconds())

	if s.config.Auth.SessionExpiry <= int(time.Hour.Seconds()) {
		refreshThreshold = int64(s.config.Auth.SessionExpiry / 2)
	}

	if int64(time.Unix(session.ExpiresAt, 0).Sub(t).Seconds()) > refreshThreshold {
		return repository.Session{}, nil
	}

	expiresAt := time.Unix(session.ExpiresAt, 0).Add(time.Duration(refreshThreshold) * time.Second)

	session, err = s.store.UpdateSessionByUUID(ctx, repository.UpdateSessionByUUIDParams{
		UUID:        session.UUID,
		ExpiresAt:   expiresAt.Unix(),
		ContextJSON: session.ContextJSON,
	})

	if err != nil {
		return repository.Session{}, fmt.Errorf("failed to update session expiry: %w", err)
	}

	return session, nil
}

func (s *SessionsService) Delete(ctx context.Context, uuid string) error {
	err := s.store.DeleteSessionByUUID(ctx, uuid)

	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}
func (s *SessionsService) Get(ctx context.Context, uuid string) (model.SessionGetResult, error) {
	session, err := s.store.GetSessionByUUID(ctx, uuid)

	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return model.SessionGetResult{}, ErrSessionNotFound
		}
		return model.SessionGetResult{}, fmt.Errorf("failed to get session: %w", err)
	}

	var sessionContext model.SessionContext

	err = json.Unmarshal([]byte(session.ContextJSON), &sessionContext)

	if err != nil {
		return model.SessionGetResult{}, fmt.Errorf("failed to unmarshal session context: %w", err)
	}

	return model.SessionGetResult{
		Session:        session,
		SessionContext: sessionContext,
	}, nil
}

func (s *SessionsService) Update(ctx context.Context, uuid string, sessionContext model.SessionContext) (repository.Session, error) {
	current, err := s.Get(ctx, uuid)
	if err != nil {
		return repository.Session{}, err
	}

	expiresAt := current.Session.ExpiresAt
	if current.SessionContext.Local.TOTPPending && !sessionContext.Local.TOTPPending {
		expiresAt = time.Now().Add(time.Duration(s.config.Auth.SessionExpiry) * time.Second).Unix()
	}

	contextJSON, err := json.Marshal(sessionContext)

	if err != nil {
		return repository.Session{}, fmt.Errorf("failed to marshal session context: %w", err)
	}

	session, err := s.store.UpdateSessionByUUID(ctx, repository.UpdateSessionByUUIDParams{
		UUID:        current.Session.UUID,
		ExpiresAt:   expiresAt,
		ContextJSON: string(contextJSON),
	})

	if err != nil {
		return repository.Session{}, fmt.Errorf("failed to update session: %w", err)
	}

	return session, nil
}
