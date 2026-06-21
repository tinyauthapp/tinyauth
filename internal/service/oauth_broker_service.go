package service

import (
	"context"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"go.uber.org/dig"

	"slices"

	"golang.org/x/oauth2"
)

type IOAuthService interface {
	Name() string
	ID() string
	NewRandom() string
	GetAuthURL(state, verifier string) string
	GetToken(code, verifier string) (*oauth2.Token, error)
	GetUserinfo(token *oauth2.Token) (*model.Claims, error)
	GetConfig() model.OAuthServiceConfig
	UpdateConfig(config model.OAuthServiceConfig)
}

type OAuthBrokerService struct {
	log *logger.Logger

	services map[string]IOAuthService
	configs  map[string]model.OAuthServiceConfig
}

var presets = map[string]func(config model.OAuthServiceConfig, ctx context.Context) *OAuthService{
	"github": newGitHubOAuthService,
	"google": newGoogleOAuthService,
}

type OAuthBrokerServiceInput struct {
	dig.In

	Log     *logger.Logger
	Runtime *model.RuntimeConfig
	Ctx     context.Context
}

func NewOAuthBrokerService(i OAuthBrokerServiceInput) *OAuthBrokerService {
	service := &OAuthBrokerService{
		log:      i.Log,
		services: make(map[string]IOAuthService),
		configs:  i.Runtime.OAuthProviders,
	}

	for name, cfg := range service.configs {
		if presetFunc, exists := presets[name]; exists {
			service.services[name] = presetFunc(cfg, i.Ctx)
			service.log.App.Debug().Str("service", name).Msg("Loaded OAuth service from preset")
		} else {
			service.services[name] = NewOAuthService(cfg, name, i.Ctx)
			service.log.App.Debug().Str("service", name).Msg("Loaded OAuth service from custom config")
		}
	}

	return service
}

func (broker *OAuthBrokerService) GetConfiguredServices() []string {
	services := make([]string, 0, len(broker.services))
	for name := range broker.services {
		services = append(services, name)
	}
	slices.Sort(services)
	return services
}

func (broker *OAuthBrokerService) GetService(name string) (IOAuthService, bool) {
	service, exists := broker.services[name]
	return service, exists
}
