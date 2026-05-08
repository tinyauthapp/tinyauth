package bootstrap

import (
	"fmt"
	"os"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/service"
)

func (app *BootstrapApp) setupServices() error {
	ldapService := service.NewLdapService(service.LdapServiceConfig{
		Address:      app.config.LDAP.Address,
		BindDN:       app.config.LDAP.BindDN,
		BindPassword: app.config.LDAP.BindPassword,
		BaseDN:       app.config.LDAP.BaseDN,
		Insecure:     app.config.LDAP.Insecure,
		SearchFilter: app.config.LDAP.SearchFilter,
		AuthCert:     app.config.LDAP.AuthCert,
		AuthKey:      app.config.LDAP.AuthKey,
	})

	err := ldapService.Init()

	if err != nil {
		app.log.App.Warn().Err(err).Msg("Failed to initialize LDAP connection, will continue without it")
		ldapService.Unconfigure()
	}

	app.services.ldapService = ldapService

	useKubernetes := app.config.LabelProvider == "kubernetes" ||
		(app.config.LabelProvider == "auto" && os.Getenv("KUBERNETES_SERVICE_HOST") != "")

	if useKubernetes {
		app.log.App.Debug().Msg("Using Kubernetes label provider")

		kubernetesService := service.NewKubernetesService()

		err = kubernetesService.Init()

		if err != nil {
			return fmt.Errorf("failed to initialize kubernetes service: %w", err)
		}

		app.services.kubernetesService = kubernetesService
		app.runtime.LabelProvider = model.LabelProviderKubernetes
	} else {
		app.log.App.Debug().Msg("Using Docker label provider")

		dockerService := service.NewDockerService()

		err = dockerService.Init()

		if err != nil {
			return fmt.Errorf("failed to initialize docker service: %w", err)
		}

		app.services.dockerService = dockerService
		app.runtime.LabelProvider = model.LabelProviderDocker
	}

	accessControlsService := service.NewAccessControlsService(app.runtime.LabelProvider, app.config.Apps)

	err = accessControlsService.Init()

	if err != nil {
		return fmt.Errorf("failed to initialize access controls service: %w", err)
	}

	app.services.accessControlService = accessControlsService

	oauthBrokerService := service.NewOAuthBrokerService(app.runtime.OAuthProviders)

	err = oauthBrokerService.Init()

	if err != nil {
		return fmt.Errorf("failed to initialize oauth broker service: %w", err)
	}

	app.services.oauthBrokerService = oauthBrokerService

	authService := service.NewAuthService(service.AuthServiceConfig{
		LocalUsers:         &app.runtime.LocalUsers,
		OauthWhitelist:     app.runtime.OAuthWhitelist,
		SessionExpiry:      app.config.Auth.SessionExpiry,
		SessionMaxLifetime: app.config.Auth.SessionMaxLifetime,
		SecureCookie:       app.config.Auth.SecureCookie,
		CookieDomain:       app.runtime.CookieDomain,
		LoginTimeout:       app.config.Auth.LoginTimeout,
		LoginMaxRetries:    app.config.Auth.LoginMaxRetries,
		SessionCookieName:  app.runtime.SessionCookieName,
		IP:                 app.config.Auth.IP,
		LDAPGroupsCacheTTL: app.config.LDAP.GroupCacheTTL,
		SubdomainsEnabled:  app.config.Auth.SubdomainsEnabled,
	}, app.services.ldapService, app.queries, app.services.oauthBrokerService)

	err = authService.Init()

	if err != nil {
		return fmt.Errorf("failed to initialize auth service: %w", err)
	}

	app.services.authService = authService

	oidcService := service.NewOIDCService(service.OIDCServiceConfig{
		Clients:        app.config.OIDC.Clients,
		PrivateKeyPath: app.config.OIDC.PrivateKeyPath,
		PublicKeyPath:  app.config.OIDC.PublicKeyPath,
		Issuer:         app.config.AppURL,
		SessionExpiry:  app.config.Auth.SessionExpiry,
	}, app.queries)

	err = oidcService.Init()

	if err != nil {
		return fmt.Errorf("failed to initialize oidc service: %w", err)
	}

	app.services.oidcService = oidcService

	return nil
}
