package bootstrap

import (
	"fmt"
	"os"

	"github.com/tinyauthapp/tinyauth/internal/service"
	"go.uber.org/dig"
)

func (app *BootstrapApp) setupServices() error {
	err := app.setupPolicyEngine()

	if err != nil {
		return fmt.Errorf("failed to setup policy engine: %w", err)
	}

	err = app.dig.Provide(app.getLabelProvider)
	if err != nil {
		return fmt.Errorf("failed to provide label provider: %w", err)
	}

	err = app.dig.Provide(service.NewLdapService)
	if err != nil {
		return fmt.Errorf("failed to provide ldap service: %w", err)
	}

	err = app.dig.Provide(service.NewTailscaleService)
	if err != nil {
		return fmt.Errorf("failed to provide tailscale service: %w", err)
	}

	err = app.dig.Provide(service.NewAccessControlsService)
	if err != nil {
		return fmt.Errorf("failed to provide access controls service: %w", err)
	}

	err = app.dig.Provide(service.NewOAuthBrokerService)
	if err != nil {
		return fmt.Errorf("failed to provide oauth broker service: %w", err)
	}

	err = app.dig.Provide(service.NewAuthService)
	if err != nil {
		return fmt.Errorf("failed to provide auth service: %w", err)
	}

	err = app.dig.Provide(service.NewOIDCService)
	if err != nil {
		return fmt.Errorf("failed to provide oidc service: %w", err)
	}

	type svcInput struct {
		dig.In

		AccessControlService *service.AccessControlsService
		AuthService          *service.AuthService
		LDAPService          *service.LdapService
		OAuthBrokerService   *service.OAuthBrokerService
		OIDCService          *service.OIDCService
		TailscaleService     *service.TailscaleService
	}

	err = app.dig.Invoke(func(i svcInput) error {
		app.services = Services{
			accessControlService: i.AccessControlService,
			authService:          i.AuthService,
			ldapService:          i.LDAPService,
			oauthBrokerService:   i.OAuthBrokerService,
			tailscaleService:     i.TailscaleService,
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to invoke services: %w", err)
	}

	return nil
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

			err := app.dig.Provide(service.NewKubernetesService)

			if err != nil {
				return nil, fmt.Errorf("failed to provide kubernetes service: %w", err)
			}

			err = app.dig.Invoke(func(k *service.KubernetesService) error {
				app.services.kubernetesService = k
				return nil
			})

			if err != nil {
				return nil, fmt.Errorf("failed to invoke kubernetes service: %w", err)
			}

			return app.services.kubernetesService, nil
		}

		app.log.App.Debug().Msg("Using Docker label provider")

		err := app.dig.Provide(service.NewDockerService)

		if err != nil {
			return nil, fmt.Errorf("failed to provide docker service: %w", err)
		}

		err = app.dig.Invoke(func(d *service.DockerService) error {
			app.services.dockerService = d
			return nil
		})

		if err != nil {
			return nil, fmt.Errorf("failed to invoke docker service: %w", err)
		}

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

func (app *BootstrapApp) setupPolicyEngine() error {
	err := app.dig.Provide(service.NewPolicyEngine)

	if err != nil {
		return fmt.Errorf("failed to create policy engine: %w", err)
	}

	err = app.dig.Invoke(func(policyEngine *service.PolicyEngine) error {
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

	return err
}
