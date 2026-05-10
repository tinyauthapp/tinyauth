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
	engine.Use(contextMiddleware.Middleware())

	uiMiddleware, err := middleware.NewUIMiddleware()

	if err != nil {
		return fmt.Errorf("failed to initialize UI middleware: %w", err)
	}

	engine.Use(uiMiddleware.Middleware())

	zerologMiddleware := middleware.NewZerologMiddleware(app.log)

	engine.Use(zerologMiddleware.Middleware())

	apiRouter := engine.Group("/api")

	controller.NewContextController(app.log, app.config, app.runtime, apiRouter)
	controller.NewOAuthController(app.log, app.config, app.runtime, apiRouter, app.services.authService)
	controller.NewOIDCController(app.log, app.services.oidcService, app.runtime, apiRouter)
	controller.NewProxyController(app.log, app.runtime, apiRouter, app.services.accessControlService, app.services.authService)
	controller.NewUserController(app.log, app.runtime, apiRouter, app.services.authService)
	controller.NewResourcesController(app.config, &engine.RouterGroup)
	controller.NewHealthController(apiRouter)
	controller.NewWellKnownController(app.services.oidcService, &engine.RouterGroup)

	app.router = engine
	return nil
}
