package service

import (
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"

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
	services map[string]OAuthServiceImpl
	configs  map[string]model.OAuthServiceConfig
}

var presets = map[string]func(config model.OAuthServiceConfig) *OAuthService{
	"github": newGitHubOAuthService,
	"google": newGoogleOAuthService,
}

func NewOAuthBrokerService(configs map[string]model.OAuthServiceConfig) *OAuthBrokerService {
	return &OAuthBrokerService{
		services: make(map[string]OAuthServiceImpl),
		configs:  configs,
	}
}

func (broker *OAuthBrokerService) Init() error {
	for name, cfg := range broker.configs {
		if presetFunc, exists := presets[name]; exists {
			broker.services[name] = presetFunc(cfg)
			tlog.App.Debug().Str("service", name).Msg("Loaded OAuth service from preset")
		} else {
			broker.services[name] = NewOAuthService(cfg, name)
			tlog.App.Debug().Str("service", name).Msg("Loaded OAuth service from config")
		}
	}
	return nil
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
