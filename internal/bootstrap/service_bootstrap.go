package bootstrap

import (
	"os"

	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
)

type Services struct {
	accessControlService *service.AccessControlsService
	authService          *service.AuthService
	dockerService        *service.DockerService
	kubernetesService    *service.KubernetesService
	ldapService          *service.LdapService
	oauthBrokerService   *service.OAuthBrokerService
	oidcService          *service.OIDCService
}

func (app *BootstrapApp) initServices(queries *repository.Queries) (Services, error) {
	services := Services{}

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
		tlog.App.Warn().Err(err).Msg("Failed to setup LDAP service, starting without it")
		ldapService.Unconfigure()
	}

	services.ldapService = ldapService

	var labelProvider service.LabelProvider
	var dockerService *service.DockerService
	var kubernetesService *service.KubernetesService

	useKubernetes := app.config.LabelProvider == "kubernetes" ||
		(app.config.LabelProvider == "auto" && os.Getenv("KUBERNETES_SERVICE_HOST") != "")

	if useKubernetes {
		tlog.App.Debug().Msg("Using Kubernetes label provider")
		kubernetesService = service.NewKubernetesService()
		err = kubernetesService.Init()
		if err != nil {
			return Services{}, err
		}
		services.kubernetesService = kubernetesService
		labelProvider = kubernetesService
	} else {
		tlog.App.Debug().Msg("Using Docker label provider")
		dockerService = service.NewDockerService()
		err = dockerService.Init()
		if err != nil {
			return Services{}, err
		}
		services.dockerService = dockerService
		labelProvider = dockerService
	}

	accessControlsService := service.NewAccessControlsService(labelProvider, app.config.Apps)

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
		LocalUsers:         app.context.localUsers,
		OauthWhitelist:     app.config.OAuth.Whitelist,
		SessionExpiry:      app.config.Auth.SessionExpiry,
		SessionMaxLifetime: app.config.Auth.SessionMaxLifetime,
		SecureCookie:       app.config.Auth.SecureCookie,
		CookieDomain:       app.context.cookieDomain,
		LoginTimeout:       app.config.Auth.LoginTimeout,
		LoginMaxRetries:    app.config.Auth.LoginMaxRetries,
		SessionCookieName:  app.context.sessionCookieName,
		IP:                 app.config.Auth.IP,
		LDAPGroupsCacheTTL: app.config.LDAP.GroupCacheTTL,
	}, services.ldapService, queries, services.oauthBrokerService)

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
