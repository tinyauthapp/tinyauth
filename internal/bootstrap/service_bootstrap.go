package bootstrap

import (
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
)

type Services struct {
	accessControlService *service.AccessControlsService
	authService          *service.AuthService
	dockerService        *service.DockerService
	ldapService          *service.LdapService
	oauthBrokerService   *service.OAuthBrokerService
	oidcService          *service.OIDCService
}

func (app *BootstrapApp) initServices(queries *repository.Queries) (Services, error) {
	services := Services{}

	ldapService := service.NewLdapService(service.LdapServiceConfig{
		Address:      app.config.Ldap.Address,
		BindDN:       app.config.Ldap.BindDN,
		BindPassword: app.config.Ldap.BindPassword,
		BaseDN:       app.config.Ldap.BaseDN,
		Insecure:     app.config.Ldap.Insecure,
		SearchFilter: app.config.Ldap.SearchFilter,
		AuthCert:     app.config.Ldap.AuthCert,
		AuthKey:      app.config.Ldap.AuthKey,
	})

	err := ldapService.Init()

	if err != nil {
		tlog.App.Warn().Err(err).Msg("Failed to setup LDAP service, starting without it")
		ldapService.Unconfigure()
	}

	services.ldapService = ldapService

	dockerService := service.NewDockerService()

	err = dockerService.Init()

	if err != nil {
		return Services{}, err
	}

	services.dockerService = dockerService

	accessControlsService := service.NewAccessControlsService(dockerService, app.config.Apps)

	err = accessControlsService.Init()

	if err != nil {
		return Services{}, err
	}

	services.accessControlService = accessControlsService

	oauthBrokerService := service.NewOAuthBrokerService(app.context.oauthProviders)

	err = oauthBrokerService.Init()

	if err != nil {
		return Services{}, err
	}

	services.oauthBrokerService = oauthBrokerService

	authService := service.NewAuthService(service.AuthServiceConfig{
		Users:              app.context.users,
		OauthWhitelist:     app.config.OAuth.Whitelist,
		SessionExpiry:      app.config.Auth.SessionExpiry,
		SessionMaxLifetime: app.config.Auth.SessionMaxLifetime,
		SecureCookie:       app.config.Auth.SecureCookie,
		CookieDomain:       app.context.cookieDomain,
		LoginTimeout:       app.config.Auth.LoginTimeout,
		LoginMaxRetries:    app.config.Auth.LoginMaxRetries,
		SessionCookieName:  app.context.sessionCookieName,
		IP:                 app.config.Auth.IP,
		LDAPGroupsCacheTTL: app.config.Ldap.GroupCacheTTL,
		SubdomainsEnabled:  app.config.Auth.SubdomainsEnabled,
	}, dockerService, services.ldapService, queries, services.oauthBrokerService)

	err = authService.Init()

	if err != nil {
		return Services{}, err
	}

	services.authService = authService

	oidcService := service.NewOIDCService(service.OIDCServiceConfig{
		Clients:        app.config.OIDC.Clients,
		PrivateKeyPath: app.config.OIDC.PrivateKeyPath,
		PublicKeyPath:  app.config.OIDC.PublicKeyPath,
		Issuer:         app.config.AppURL,
		SessionExpiry:  app.config.Auth.SessionExpiry,
	}, queries)

	err = oidcService.Init()

	if err != nil {
		return Services{}, err
	}

	services.oidcService = oidcService

	return services, nil
}
