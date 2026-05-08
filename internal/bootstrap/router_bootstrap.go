package bootstrap

import (
	"fmt"

	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/middleware"

	"github.com/gin-gonic/gin"
)

func (app *BootstrapApp) setupRouter() error {
	// we don't want gin debug mode
	gin.SetMode(gin.ReleaseMode)

	engine := gin.New()
	engine.Use(gin.Recovery())

	if len(app.config.Auth.TrustedProxies) > 0 {
		err := engine.SetTrustedProxies(app.config.Auth.TrustedProxies)

		if err != nil {
			return fmt.Errorf("failed to set trusted proxies: %w", err)
		}
	}

	contextMiddleware := middleware.NewContextMiddleware(app.log, app.runtime, app.services.authService, app.services.oauthBrokerService)

	err := contextMiddleware.Init()

	if err != nil {
		return fmt.Errorf("failed to initialize context middleware: %w", err)
	}

	engine.Use(contextMiddleware.Middleware())

	uiMiddleware := middleware.NewUIMiddleware()

	err = uiMiddleware.Init()

	if err != nil {
		return fmt.Errorf("failed to initialize UI middleware: %w", err)
	}

	engine.Use(uiMiddleware.Middleware())

	zerologMiddleware := middleware.NewZerologMiddleware(app.log)

	err = zerologMiddleware.Init()

	if err != nil {
		return fmt.Errorf("failed to initialize zerolog middleware: %w", err)
	}

	engine.Use(zerologMiddleware.Middleware())

	apiRouter := engine.Group("/api")

	contextController := controller.NewContextController(app.log, app.config, app.runtime, apiRouter)

	contextController.SetupRoutes()

	oauthController := controller.NewOAuthController(app.log, app.config, app.runtime, apiRouter, app.services.authService)

	oauthController.SetupRoutes()

	oidcController := controller.NewOIDCController(app.log, app.services.oidcService, apiRouter)

	oidcController.SetupRoutes()

	proxyController := controller.NewProxyController(app.log, app.runtime, apiRouter, app.services.accessControlService, app.services.authService)

	proxyController.SetupRoutes()

	userController := controller.NewUserController(app.log, app.runtime, apiRouter, app.services.authService)

	userController.SetupRoutes()

	resourcesController := controller.NewResourcesController(app.config, &engine.RouterGroup)

	resourcesController.SetupRoutes()

	healthController := controller.NewHealthController(apiRouter)

	healthController.SetupRoutes()

	wellknownController := controller.NewWellKnownController(app.services.oidcService, &engine.RouterGroup)

	wellknownController.SetupRoutes()

	app.router = engine
	return nil
}
