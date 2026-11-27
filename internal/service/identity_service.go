package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"uuid"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"go.uber.org/dig"
)

type IdentityServiceInput struct {
	dig.In

	StoreFactory *StoreFactory
	Config       *model.Config
	Runtime      *model.RuntimeConfig
}

type IdentityService struct {
	storeFactory *StoreFactory
	runtime      *model.RuntimeConfig

	linkingMode model.LinkingMode
}

func NewIdentityService(i IdentityServiceInput) (*IdentityService, error) {
	linkingMode, err := model.LinkingModeFromString(i.Config.Auth.LinkingMode)

	if err != nil {
		return nil, fmt.Errorf("failed to parse linking mode: %w", err)
	}

	return &IdentityService{
		storeFactory: i.StoreFactory,
		runtime:      i.Runtime,
		linkingMode:  linkingMode,
	}, nil
}

func (s *IdentityService) getUserFunc(store repository.Store, args repository.CreateUserParams) func(ctx context.Context) (user repository.User, err error) {
	if args.UUID != "" {
		return func(ctx context.Context) (user repository.User, err error) {
			return store.GetUserByUUID(ctx, args.UUID)
		}
	}

	switch s.linkingMode {
	case model.LinkingModeBoth:
		if args.Email == "" || args.Username == "" {
			return func(ctx context.Context) (user repository.User, err error) {
				return repository.User{}, fmt.Errorf("email and username are required for linking mode 'both'")
			}
		}
		return func(ctx context.Context) (user repository.User, err error) {
			return store.GetUserByUsernameAndEmail(ctx, repository.GetUserByUsernameAndEmailParams{
				Username: args.Username,
				Email:    args.Email,
			})
		}
	case model.LinkingModeEmail:
		if args.Email == "" {
			return func(ctx context.Context) (user repository.User, err error) {
				return repository.User{}, fmt.Errorf("email is required for linking mode 'email'")
			}
		}
		return func(ctx context.Context) (user repository.User, err error) {
			return store.GetUserByEmail(ctx, args.Email)
		}
	case model.LinkingModeUsername:
		if args.Username == "" {
			return func(ctx context.Context) (user repository.User, err error) {
				return repository.User{}, fmt.Errorf("username is required for linking mode 'username'")
			}
		}
		return func(ctx context.Context) (user repository.User, err error) {
			return store.GetUserByUsername(ctx, args.Username)
		}
	}

	return func(ctx context.Context) (user repository.User, err error) {
		return repository.User{}, fmt.Errorf("unknown linking mode: %s", s.linkingMode.String())
	}
}

func (s *IdentityService) ensureUser(ctx context.Context, store repository.Store, args repository.CreateUserParams) (user repository.User, err error) {
	user, err = s.getUserFunc(store, args)(ctx)

	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return repository.User{}, fmt.Errorf("failed to get user: %w", err)
	}

	if err == nil {
		exp := repository.User{
			UUID:     user.UUID,
			Username: args.Username,
			Email:    args.Email,
			Name:     args.Name,
		}
		if user.Username != exp.Username ||
			user.Email != exp.Email ||
			user.Name != exp.Name {
			err = store.UpdateUser(ctx, repository.UpdateUserParams{
				UUID:     user.UUID,
				Username: args.Username,
				Email:    args.Email,
				Name:     args.Name,
			})
			if err != nil {
				return repository.User{}, fmt.Errorf("failed to update user: %w", err)
			}
		}
		return repository.User{
			UUID:     user.UUID,
			Username: args.Username,
			Email:    args.Email,
			Name:     args.Name,
		}, nil
	}

	u := uuid.New()
	args.UUID = u.String()

	user, err = store.CreateUser(ctx, args)

	if err != nil {
		return repository.User{}, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

func (s *IdentityService) ensureIdentity(ctx context.Context, store repository.Store, args repository.CreateIdentityParams) (identity repository.Identity, err error) {
	identity, err = store.GetIdentityByProviderIDs(ctx, repository.GetIdentityByProviderIDsParams{
		ProviderType:   args.ProviderType,
		ProviderUserID: args.ProviderUserID,
		Provider:       args.Provider,
	})

	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			return repository.Identity{}, fmt.Errorf("failed to get identity: %w", err)
		}

		u := uuid.New()
		args.UUID = u.String()

		identity, err = store.CreateIdentity(ctx, args)

		if err != nil {
			return repository.Identity{}, fmt.Errorf("failed to create identity: %w", err)
		}

		return identity, nil
	}

	identity, err = store.UpdateIdentityByUUID(ctx, repository.UpdateIdentityByUUIDParams{
		ContextJSON: args.ContextJSON,
		UserUUID:    args.UserUUID,
		UUID:        identity.UUID,
	})

	if err != nil {
		return repository.Identity{}, fmt.Errorf("failed to update identity: %w", err)
	}

	return identity, nil
}

type StoreIdentityParams struct {
	// User information
	Username string
	Email    string
	Name     string

	// Identity information
	ProviderID     string
	ProviderType   model.ProviderType
	ProviderUserID string

	// Context information
	IdentityContext model.IdentityContext
}

func (s *IdentityService) Store(ctx context.Context, params StoreIdentityParams) (identity repository.Identity, err error) {
	err = s.storeFactory.ProvideTransaction(ctx, func(store repository.Store) error {
		identity, err = s.store(ctx, store, params)
		return err
	})
	if err != nil {
		return repository.Identity{}, err
	}
	return
}

func (s *IdentityService) StoreWithOwnTransaction(ctx context.Context, store repository.Store, params StoreIdentityParams) (identity repository.Identity, err error) {
	identity, err = s.store(ctx, store, params)
	return
}

func (s *IdentityService) store(ctx context.Context, store repository.Store, params StoreIdentityParams) (identity repository.Identity, err error) {
	if params.ProviderType == model.ProviderTailscale &&
		!slices.Contains(s.runtime.ConfiguredProviders, model.Provider{
			Name: "Tailscale",
			ID:   "tailscale",
		}) {
		return repository.Identity{}, fmt.Errorf("tailscale provider not configured, cannot create identity")
	}

	encoded, err := json.Marshal(params.IdentityContext)

	if err != nil {
		return repository.Identity{}, fmt.Errorf("failed to marshal context: %w", err)
	}

	user, err := s.ensureUser(ctx, store, repository.CreateUserParams{
		Username: params.Username,
		Email:    params.Email,
		Name:     params.Name,
	})

	if err != nil {
		return repository.Identity{}, err
	}

	identity, err = s.ensureIdentity(ctx, store, repository.CreateIdentityParams{
		UserUUID:       user.UUID,
		Provider:       params.ProviderID,
		ProviderType:   params.ProviderType.String(),
		ProviderUserID: params.ProviderUserID,
		ContextJSON:    string(encoded),
	})

	if err != nil {
		return repository.Identity{}, fmt.Errorf("failed to create identity: %w", err)
	}

	return identity, nil
}

func (s *IdentityService) Load(ctx context.Context, uuid string) (result model.IdentityResult, err error) {
	store, err := s.storeFactory.ProvideStore()

	if err != nil {
		return model.IdentityResult{}, fmt.Errorf("failed to get store: %w", err)
	}

	identity, err := store.GetIdentityByUUID(ctx, uuid)

	if err != nil {
		return model.IdentityResult{}, fmt.Errorf("failed to get identity: %w", err)
	}

	user, err := store.GetUserByUUID(ctx, identity.UserUUID)

	if err != nil {
		return model.IdentityResult{}, fmt.Errorf("failed to get user: %w", err)
	}

	var identityContext model.IdentityContext

	if identity.ContextJSON != "" {
		err = json.Unmarshal([]byte(identity.ContextJSON), &identityContext)

		if err != nil {
			return model.IdentityResult{}, fmt.Errorf("failed to unmarshal context: %w", err)
		}
	}

	provider, err := model.ProviderFromString(identity.ProviderType)

	if err != nil {
		return model.IdentityResult{}, fmt.Errorf("failed to parse provider: %w", err)
	}

	return model.IdentityResult{
		Username:        user.Username,
		Email:           user.Email,
		Name:            user.Name,
		Provider:        identity.Provider,
		ProviderType:    provider,
		ProviderUserID:  identity.ProviderUserID,
		IdentityContext: identityContext,
	}, nil
}
