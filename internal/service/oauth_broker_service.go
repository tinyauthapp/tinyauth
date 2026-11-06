package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/cache"
	"go.uber.org/dig"

	"slices"

	"golang.org/x/oauth2"
)

// OAuthCallbackParams are the parameters that are passed to the callback URL
// after the user has logged in with OAuth
type OAuthCallbackParams struct {
	LoginFor    string `form:"login_for" url:"login_for"`
	OIDCTicket  string `form:"oidc_ticket" url:"oidc_ticket"`
	OIDCScope   string `form:"oidc_scope" url:"oidc_scope"`
	OIDCName    string `form:"oidc_name" url:"oidc_name"`
	RedirectURI string `form:"redirect_uri" url:"redirect_uri"`
}

// OAuthFlow represents the state of an OAuth flow
type OAuthFlow struct {
	State          string
	Verifier       string
	Token          *oauth2.Token
	Service        IOAuthService
	ExpiresAt      time.Time
	CallbackParams OAuthCallbackParams
}

type IOAuthService interface {
	Name() string
	ID() string
	NewRandom() string
	GetAuthURL(state, verifier string) string
	GetToken(code, verifier string) (*oauth2.Token, error)
	GetUserinfo(token *oauth2.Token) (*model.Claims, error)
	GetConfig() model.OAuthServiceConfig
}

type OAuthBrokerService struct {
	log *logger.Logger

	services map[string]IOAuthService
	configs  map[string]model.OAuthServiceConfig

	caches struct {
		flows *cache.CacheStore[OAuthFlow]
	}
}

var presets = map[string]func(config model.OAuthServiceConfig, ctx context.Context) *OAuthService{
	"github": newGitHubOAuthService,
	"google": newGoogleOAuthService,
}

type OAuthBrokerServiceInput struct {
	dig.In

	Log     *logger.Logger
	Runtime *model.RuntimeConfig
	Ding    *ding.Ding
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

	service.caches.flows = cache.NewCacheStore[OAuthFlow](256)

	i.Ding.Go(func(ctx context.Context) {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				service.caches.flows.Sweep()
			case <-ctx.Done():
				return
			}
		}
	}, ding.RingMinor)

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

func (broker *OAuthBrokerService) BeginOAuthFlow(serviceName string, params OAuthCallbackParams) (string, error) {
	service, exists := broker.services[serviceName]

	if !exists {
		return "", fmt.Errorf("oauth service not found: %s", serviceName)
	}

	u := uuid.New()
	state := service.NewRandom()
	verifier := service.NewRandom()

	session := OAuthFlow{
		State:          state,
		Verifier:       verifier,
		Service:        service,
		ExpiresAt:      time.Now().Add(1 * time.Hour),
		CallbackParams: params,
	}

	broker.caches.flows.Set(u.String(), session, time.Minute*10)

	return u.String(), nil
}

func (broker *OAuthBrokerService) FlowAuthURL(flowId string) (string, bool) {
	flow, ok := broker.caches.flows.Get(flowId)

	if !ok {
		return "", false
	}

	return flow.Service.GetAuthURL(flow.State, flow.Verifier), true
}

func (broker *OAuthBrokerService) FlowOAuthToken(flowId string, code string) (*oauth2.Token, error) {
	flow, ok := broker.caches.flows.Get(flowId)

	if !ok {
		return nil, fmt.Errorf("oauth flow not found: %s", flowId)
	}

	token, err := flow.Service.GetToken(code, flow.Verifier)

	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	flow.Token = token

	ok = broker.caches.flows.Update(flowId, flow, 0)

	if !ok {
		return nil, fmt.Errorf("failed to update oauth flow in cache")
	}

	return token, nil
}

func (broker *OAuthBrokerService) FlowOAuthUserinfo(flowId string) (*model.Claims, error) {
	flow, ok := broker.caches.flows.Get(flowId)

	if !ok {
		return nil, fmt.Errorf("oauth flow not found: %s", flowId)
	}

	if flow.Token == nil {
		return nil, fmt.Errorf("oauth token not found for flow: %s", flowId)
	}

	userinfo, err := flow.Service.GetUserinfo(flow.Token)

	if err != nil {
		return nil, fmt.Errorf("failed to get userinfo: %w", err)
	}

	return userinfo, nil
}

func (broker *OAuthBrokerService) GetFlow(flowId string) (OAuthFlow, bool) {
	return broker.caches.flows.Get(flowId)
}

func (broker *OAuthBrokerService) EndFlow(flowId string) {
	broker.caches.flows.Delete(flowId)
}
