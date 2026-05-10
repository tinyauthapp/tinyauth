package bootstrap

import (
	"fmt"
	"os"

	"github.com/tinyauthapp/tinyauth/internal/service"
)

func (app *BootstrapApp) setupServices() error {
	ldapService, err := service.NewLdapService(app.log, app.config, app.ctx, &app.wg)

	if err != nil {
		app.log.App.Warn().Err(err).Msg("Failed to initialize LDAP connection, will continue without it")
	}

	app.services.ldapService = ldapService

	useKubernetes := app.config.LabelProvider == "kubernetes" ||
		(app.config.LabelProvider == "auto" && os.Getenv("KUBERNETES_SERVICE_HOST") != "")

	var labelProvider service.LabelProvider

	if useKubernetes {
		app.log.App.Debug().Msg("Using Kubernetes label provider")

		kubernetesService, err := service.NewKubernetesService(app.log, app.ctx, &app.wg)

		if err != nil {
			return fmt.Errorf("failed to initialize kubernetes service: %w", err)
		}

		app.services.kubernetesService = kubernetesService
		labelProvider = kubernetesService
	} else {
		app.log.App.Debug().Msg("Using Docker label provider")

		dockerService, err := service.NewDockerService(app.log, app.ctx, &app.wg)

		if err != nil {
			return fmt.Errorf("failed to initialize docker service: %w", err)
		}

		app.services.dockerService = dockerService
		labelProvider = dockerService
	}

	accessControlsService := service.NewAccessControlsService(app.log, &labelProvider, app.config.Apps)
	app.services.accessControlService = accessControlsService

	oauthBrokerService := service.NewOAuthBrokerService(app.log, app.runtime.OAuthProviders, app.ctx)
	app.services.oauthBrokerService = oauthBrokerService

	authService := service.NewAuthService(app.log, app.config, app.runtime, app.ctx, &app.wg, app.services.ldapService, app.queries, app.services.oauthBrokerService)
	app.services.authService = authService

	oidcService, err := service.NewOIDCService(app.log, app.config, app.runtime, app.queries, app.ctx, &app.wg)

	if err != nil {
		return fmt.Errorf("failed to initialize oidc service: %w", err)
	}

	app.services.oidcService = oidcService

	return nil
}
