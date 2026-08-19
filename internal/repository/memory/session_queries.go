package memory

import (
	"context"

	"github.com/tinyauthapp/tinyauth/internal/repository"
)

func (s *Store) CreateSession(_ context.Context, arg repository.CreateSessionParams) (repository.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := repository.Session(arg)
	s.sessions[arg.UUID] = sess
	return sess, nil
}

func (s *Store) GetSession(_ context.Context, uuid string) (repository.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[uuid]
	if !ok {
		return repository.Session{}, repository.ErrNotFound
	}
	return sess, nil
}

func (s *Store) UpdateSession(_ context.Context, arg repository.UpdateSessionParams) (repository.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[arg.UUID]
	if !ok {
		return repository.Session{}, repository.ErrNotFound
	}
	sess.Username = arg.Username
	sess.Email = arg.Email
	sess.Name = arg.Name
	sess.Provider = arg.Provider
	sess.TotpPending = arg.TotpPending
	sess.OAuthGroups = arg.OAuthGroups
	sess.Expiry = arg.Expiry
	sess.OAuthName = arg.OAuthName
	sess.OAuthSub = arg.OAuthSub
	s.sessions[arg.UUID] = sess
	return sess, nil
}

func (s *Store) DeleteSession(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, uuid)
	return nil
}

func (s *Store) DeleteExpiredSessions(_ context.Context, expiry int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.sessions {
		if v.Expiry < expiry {
			delete(s.sessions, k)
		}
	}
	return nil
}
