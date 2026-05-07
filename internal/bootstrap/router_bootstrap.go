package bootstrap

import (
	"fmt"
	"slices"

	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/middleware"
	"github.com/tinyauthapp/tinyauth/internal/model"

	"github.com/gin-gonic/gin"
)

var DEV_MODES = []string{"main", "test", "development"}

func (app *BootstrapApp) setupRouter() (*gin.Engine, error) {
	if !slices.Contains(DEV_MODES, model.Version) {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.New()
	engine.Use(gin.Recovery())

	if len(app.config.Auth.TrustedProxies) > 0 {
		err := engine.SetTrustedProxies(app.config.Auth.TrustedProxies)

		if err != nil {
			return nil, fmt.Errorf("failed to set trusted proxies: %w", err)
		}
	}

	contextMiddleware := middleware.NewContextMiddleware(middleware.ContextMiddlewareConfig{
		CookieDomain:      app.context.cookieDomain,
		SessionCookieName: app.context.sessionCookieName,
	}, app.services.authService, app.services.oauthBrokerService)

	err := contextMiddleware.Init()

	if err != nil {
		return nil, fmt.Errorf("failed to initialize context middleware: %w", err)
	}

	engine.Use(contextMiddleware.Middleware())

	uiMiddleware := middleware.NewUIMiddleware()

	err = uiMiddleware.Init()

	if err != nil {
		return nil, fmt.Errorf("failed to initialize UI middleware: %w", err)
	}

	engine.Use(uiMiddleware.Middleware())

	zerologMiddleware := middleware.NewZerologMiddleware()

	err = zerologMiddleware.Init()

	if err != nil {
		return nil, fmt.Errorf("failed to initialize zerolog middleware: %w", err)
	}

	engine.Use(zerologMiddleware.Middleware())

	apiRouter := engine.Group("/api")

	contextController := controller.NewContextController(controller.ContextControllerConfig{
		Providers:             app.context.configuredProviders,
		Title:                 app.config.UI.Title,
		AppURL:                app.config.AppURL,
		CookieDomain:          app.context.cookieDomain,
		ForgotPasswordMessage: app.config.UI.ForgotPasswordMessage,
		BackgroundImage:       app.config.UI.BackgroundImage,
		OAuthAutoRedirect:     app.config.OAuth.AutoRedirect,
		WarningsEnabled:       app.config.UI.WarningsEnabled,
	}, apiRouter)

	contextController.SetupRoutes()

	oauthController := controller.NewOAuthController(controller.OAuthControllerConfig{
		AppURL:                 app.config.AppURL,
		SecureCookie:           app.config.Auth.SecureCookie,
		CSRFCookieName:         app.context.csrfCookieName,
		RedirectCookieName:     app.context.redirectCookieName,
		CookieDomain:           app.context.cookieDomain,
		OAuthSessionCookieName: app.context.oauthSessionCookieName,
		SubdomainsEnabled:      app.config.Auth.SubdomainsEnabled,
	}, apiRouter, app.services.authService)

	oauthController.SetupRoutes()

	oidcController := controller.NewOIDCController(controller.OIDCControllerConfig{}, app.services.oidcService, apiRouter)

	oidcController.SetupRoutes()

	proxyController := controller.NewProxyController(controller.ProxyControllerConfig{
		AppURL: app.config.AppURL,
	}, apiRouter, app.services.accessControlService, app.services.authService)

	proxyController.SetupRoutes()

	userController := controller.NewUserController(controller.UserControllerConfig{
		CookieDomain:      app.context.cookieDomain,
		SessionCookieName: app.context.sessionCookieName,
	}, apiRouter, app.services.authService)

	userController.SetupRoutes()

	resourcesController := controller.NewResourcesController(controller.ResourcesControllerConfig{
		Path:    app.config.Resources.Path,
		Enabled: app.config.Resources.Enabled,
	}, &engine.RouterGroup)

	resourcesController.SetupRoutes()

	healthController := controller.NewHealthController(apiRouter)

	healthController.SetupRoutes()

	wellknownController := controller.NewWellKnownController(controller.WellKnownControllerConfig{}, app.services.oidcService, engine)

	wellknownController.SetupRoutes()

	return engine, nil
}
