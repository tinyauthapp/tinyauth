package bootstrap

import (
	"context"
	"fmt"
	"os"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"go.uber.org/dig"
)

func (app *BootstrapApp) setupServices() error {
	c := dig.New()
	app.dig = c

	c.Provide(func() *logger.Logger {
		return app.log
	})

	c.Provide(func() *model.Config {
		return &app.config
	})

	c.Provide(func() *model.RuntimeConfig {
		return &app.runtime
	})

	c.Provide(func() *ding.Ding {
		return app.ding
	})

	c.Provide(func() context.Context {
		return app.ctx
	})

	c.Provide(func() repository.Store {
		return app.queries
	})

	c.Provide(service.NewLdapService)
	c.Provide(app.getLabelProvider)
	c.Provide(service.NewTailscaleService)
	c.Provide(service.NewAccessControlsService)
	c.Provide(app.setupPolicyEngine)
	c.Provide(service.NewOAuthBrokerService)
	c.Provide(service.NewAuthService)
	c.Provide(service.NewOIDCService)

	type svcInput struct {
		dig.In

		AccessControlService *service.AccessControlsService
		AuthService          *service.AuthService
		LDAPService          *service.LdapService
		OAuthBrokerService   *service.OAuthBrokerService
		OIDCService          *service.OIDCService
		TailscaleService     *service.TailscaleService
		PolicyEngine         *service.PolicyEngine
	}

	err := c.Invoke(func(i svcInput) error {
		app.services = Services{
			accessControlService: i.AccessControlService,
			authService:          i.AuthService,
			ldapService:          i.LDAPService,
			oauthBrokerService:   i.OAuthBrokerService,
			tailscaleService:     i.TailscaleService,
			policyEngine:         i.PolicyEngine,
		}
		return nil
	})

	return err
}

func (app *BootstrapApp) getLabelProvider() (service.LabelProvider, error) {
	switch app.config.LabelProvider {
	case "none", "docker", "kubernetes", "auto":
		if app.config.LabelProvider == "none" {
			return nil, nil
		}

		useKubernetes := app.config.LabelProvider == "kubernetes" ||
			(app.config.LabelProvider == "auto" && os.Getenv("KUBERNETES_SERVICE_HOST") != "")

		if useKubernetes {
			app.log.App.Debug().Msg("Using Kubernetes label provider")

			kubernetesService, err := service.NewKubernetesService(service.KubernetesServiceInput{
				Log:  app.log,
				Ctx:  app.ctx,
				Ding: app.ding,
			})

			if err != nil {
				return nil, fmt.Errorf("failed to initialize kubernetes service: %w", err)
			}

			app.services.kubernetesService = kubernetesService
			return kubernetesService, nil
		}

		app.log.App.Debug().Msg("Using Docker label provider")

		dockerService, err := service.NewDockerService(service.DockerServiceInput{
			Log:  app.log,
			Ctx:  app.ctx,
			Ding: app.ding,
		})

		if err != nil {
			return nil, fmt.Errorf("failed to initialize docker service: %w", err)
		}

		if dockerService == nil {
			if app.config.LabelProvider == "docker" {
				app.log.App.Warn().Msg("Docker label provider selected but Docker is not available, will continue without it")
			}
			return nil, nil
		}

		app.services.dockerService = dockerService
		return dockerService, nil
	default:
		return nil, fmt.Errorf("invalid label provider: %s", app.config.LabelProvider)
	}
}

func (app *BootstrapApp) setupPolicyEngine() (*service.PolicyEngine, error) {
	policyEngine, err := service.NewPolicyEngine(service.PolicyEngineInput{
		Log:    app.log,
		Config: &app.config,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to initialize policy engine: %w", err)
	}

	policyEngine.RegisterRule(service.RuleUserAllowed, &service.UserAllowedRule{
		Log: app.log,
	})
	policyEngine.RegisterRule(service.RuleOAuthGroup, &service.OAuthGroupRule{
		Log: app.log,
	})
	policyEngine.RegisterRule(service.RuleLDAPGroup, &service.LDAPGroupRule{
		Log: app.log,
	})
	policyEngine.RegisterRule(service.RuleAuthEnabled, &service.AuthEnabledRule{
		Log: app.log,
	})
	policyEngine.RegisterRule(service.RuleIPAllowed, &service.IPAllowedRule{
		Log:    app.log,
		Config: app.config,
	})
	policyEngine.RegisterRule(service.RuleIPBypassed, &service.IPBypassedRule{
		Log:    app.log,
		Config: app.config,
	})

	return policyEngine, nil
}
