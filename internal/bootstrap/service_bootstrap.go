package bootstrap

import (
	"fmt"
	"os"

	"github.com/tinyauthapp/tinyauth/internal/service"
)

func (app *BootstrapApp) setupServices() error {
	ldapService := service.NewLdapService(app.log, app.config, app.ctx)

	err := ldapService.Init()

	if err != nil {
		app.log.App.Warn().Err(err).Msg("Failed to initialize LDAP connection, will continue without it")
		ldapService.Unconfigure()
	}

	app.services.ldapService = ldapService

	useKubernetes := app.config.LabelProvider == "kubernetes" ||
		(app.config.LabelProvider == "auto" && os.Getenv("KUBERNETES_SERVICE_HOST") != "")

	var labelProvider service.LabelProviderImpl

	if useKubernetes {
		app.log.App.Debug().Msg("Using Kubernetes label provider")

		kubernetesService := service.NewKubernetesService(app.log, app.ctx)

		err = kubernetesService.Init()

		if err != nil {
			return fmt.Errorf("failed to initialize kubernetes service: %w", err)
		}

		app.services.kubernetesService = kubernetesService
		labelProvider = kubernetesService
	} else {
		app.log.App.Debug().Msg("Using Docker label provider")

		dockerService := service.NewDockerService(app.log, app.ctx)

		err = dockerService.Init()

		if err != nil {
			return fmt.Errorf("failed to initialize docker service: %w", err)
		}

		app.services.dockerService = dockerService
		labelProvider = dockerService
	}

	accessControlsService := service.NewAccessControlsService(app.log, labelProvider, app.config.Apps)

	err = accessControlsService.Init()

	if err != nil {
		return fmt.Errorf("failed to initialize access controls service: %w", err)
	}

	app.services.accessControlService = accessControlsService

	oauthBrokerService := service.NewOAuthBrokerService(app.log, app.runtime.OAuthProviders)

	err = oauthBrokerService.Init()

	if err != nil {
		return fmt.Errorf("failed to initialize oauth broker service: %w", err)
	}

	app.services.oauthBrokerService = oauthBrokerService

	authService := service.NewAuthService(app.log, app.config, app.runtime, app.ctx, app.services.ldapService, app.queries, app.services.oauthBrokerService)

	err = authService.Init()

	if err != nil {
		return fmt.Errorf("failed to initialize auth service: %w", err)
	}

	app.services.authService = authService

	oidcService := service.NewOIDCService(app.log, app.config, app.runtime, app.queries, app.ctx)

	err = oidcService.Init()

	if err != nil {
		return fmt.Errorf("failed to initialize oidc service: %w", err)
	}

	app.services.oidcService = oidcService

	return nil
}
