package bootstrap

import (
	"fmt"
	"os"

	"github.com/tinyauthapp/tinyauth/internal/service"
)

func (app *BootstrapApp) setupServices() error {
	ldapService, err := service.NewLdapService(app.log, app.config, app.ding)

	if err != nil {
		app.log.App.Warn().Err(err).Msg("Failed to initialize LDAP connection, will continue without it")
	}

	app.services.ldapService = ldapService

	labelProvider, err := app.getLabelProvider()

	if err != nil {
		return fmt.Errorf("failed to initialize label provider: %w", err)
	}

	tailscaleService, err := service.NewTailscaleService(app.log, app.config, app.ctx, app.ding)

	if err != nil {
		app.log.App.Warn().Err(err).Msg("Failed to initialize Tailscale connection, will continue without it")
	}

	app.services.tailscaleService = tailscaleService

	accessControlsService := service.NewAccessControlsService(app.log, app.config, &labelProvider)
	app.services.accessControlService = accessControlsService

	err = app.setupPolicyEngine()

	if err != nil {
		return fmt.Errorf("failed to initialize policy engine: %w", err)
	}

	oauthBrokerService := service.NewOAuthBrokerService(app.log, app.runtime.OAuthProviders, app.ctx)
	app.services.oauthBrokerService = oauthBrokerService

	authService := service.NewAuthService(app.log, app.config, app.runtime, app.ctx, app.ding, app.services.ldapService, app.queries, app.services.oauthBrokerService, app.services.tailscaleService, app.services.policyEngine)
	app.services.authService = authService

	oidcService, err := service.NewOIDCService(app.log, app.config, app.runtime, app.queries, app.ding)

	if err != nil {
		return fmt.Errorf("failed to initialize oidc service: %w", err)
	}

	app.services.oidcService = oidcService

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

			kubernetesService, err := service.NewKubernetesService(app.log, app.ctx, app.ding)

			if err != nil {
				return nil, fmt.Errorf("failed to initialize kubernetes service: %w", err)
			}

			app.services.kubernetesService = kubernetesService
			return kubernetesService, nil
		}

		app.log.App.Debug().Msg("Using Docker label provider")

		dockerService, err := service.NewDockerService(app.log, app.ctx, app.ding)

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

func (app *BootstrapApp) setupPolicyEngine() error {
	policyEngine, err := service.NewPolicyEngine(app.config, app.log)

	if err != nil {
		return fmt.Errorf("failed to initialize policy engine: %w", err)
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

	app.services.policyEngine = policyEngine
	return nil
}
