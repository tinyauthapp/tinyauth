package service

import (
	"context"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"

	"slices"

	"golang.org/x/oauth2"
)

type OAuthServiceImpl interface {
	Name() string
	ID() string
	NewRandom() string
	GetAuthURL(state string, verifier string) string
	GetToken(code string, verifier string) (*oauth2.Token, error)
	GetUserinfo(token *oauth2.Token) (*model.Claims, error)
}

type OAuthBrokerService struct {
	log *logger.Logger

	services map[string]OAuthServiceImpl
	configs  map[string]model.OAuthServiceConfig
}

var presets = map[string]func(config model.OAuthServiceConfig, ctx context.Context) *OAuthService{
	"github": newGitHubOAuthService,
	"google": newGoogleOAuthService,
}

func NewOAuthBrokerService(
	log *logger.Logger,
	configs map[string]model.OAuthServiceConfig,
	ctx context.Context,
) *OAuthBrokerService {
	service := &OAuthBrokerService{
		log:      log,
		services: make(map[string]OAuthServiceImpl),
		configs:  configs,
	}

	for name, cfg := range configs {
		if presetFunc, exists := presets[name]; exists {
			service.services[name] = presetFunc(cfg, ctx)
			service.log.App.Debug().Str("service", name).Msg("Loaded OAuth service from preset")
		} else {
			service.services[name] = NewOAuthService(cfg, name, ctx)
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

func (broker *OAuthBrokerService) GetService(name string) (OAuthServiceImpl, bool) {
	service, exists := broker.services[name]
	return service, exists
}
