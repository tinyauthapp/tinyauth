package bootstrap

import (
	"fmt"
	"os"

	"github.com/tinyauthapp/tinyauth/internal/service"
	"go.uber.org/dig"
)

func (app *BootstrapApp) setupServices() error {
	app.setupPolicyEngine()

	app.dig.Provide(func() *service.PolicyEngine {
		return app.services.policyEngine
	})

	app.dig.Provide(app.getLabelProvider)
	app.dig.Provide(service.NewLdapService)
	app.dig.Provide(service.NewTailscaleService)
	app.dig.Provide(service.NewAccessControlsService)
	app.dig.Provide(service.NewOAuthBrokerService)
	app.dig.Provide(service.NewAuthService)
	app.dig.Provide(service.NewOIDCService)

	type svcInput struct {
		dig.In

		AccessControlService *service.AccessControlsService
		AuthService          *service.AuthService
		LDAPService          *service.LdapService
		OAuthBrokerService   *service.OAuthBrokerService
		OIDCService          *service.OIDCService
		TailscaleService     *service.TailscaleService
	}

	err := app.dig.Invoke(func(i svcInput) error {
		app.services = Services{
			accessControlService: i.AccessControlService,
			authService:          i.AuthService,
			ldapService:          i.LDAPService,
			oauthBrokerService:   i.OAuthBrokerService,
			tailscaleService:     i.TailscaleService,
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

			app.dig.Provide(service.NewKubernetesService)

			app.dig.Invoke(func(k *service.KubernetesService) error {
				app.services.kubernetesService = k
				return nil
			})

			return app.services.kubernetesService, nil
		}

		app.log.App.Debug().Msg("Using Docker label provider")

		app.dig.Provide(service.NewDockerService)

		app.dig.Invoke(func(d *service.DockerService) error {
			app.services.dockerService = d
			return nil
		})

		if app.services.dockerService == nil {
			if app.config.LabelProvider == "docker" {
				app.log.App.Warn().Msg("Docker label provider selected but Docker is not available, will continue without it")
			}
			return nil, nil
		}

		return app.services.dockerService, nil
	default:
		return nil, fmt.Errorf("invalid label provider: %s", app.config.LabelProvider)
	}
}

func (app *BootstrapApp) setupPolicyEngine() {
	app.dig.Provide(service.NewPolicyEngine)

	app.dig.Invoke(func(policyEngine *service.PolicyEngine) error {
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
		return nil
	})
}
