package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	ginScalar "github.com/tinyauthapp/gin-scalar"
	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/middleware"
	"github.com/tinyauthapp/tinyauth/internal/model"
	docs "github.com/tinyauthapp/tinyauth/internal/swagger"
	"go.uber.org/dig"

	"github.com/gin-gonic/gin"
)

// @title			Tinyauth API
// @version		development
// @description	Documentation for Tinyauth's API.
// @license.name	AGPL-3.0
// @license.url	https://github.com/tinyauthapp/tinyauth/blob/main/LICENSE
// @BasePath		/
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

	middlewareProvideFor := []any{
		middleware.NewContextMiddleware,
		middleware.NewUIMiddleware,
		middleware.NewZerologMiddleware,
	}

	for _, provider := range middlewareProvideFor {
		err := app.dig.Provide(provider)

		if err != nil {
			return fmt.Errorf("failed to provide middleware: %w", err)
		}
	}

	type middlewareInput struct {
		dig.In

		ContextMiddleware *middleware.ContextMiddleware
		UIMiddleware      *middleware.UIMiddleware
		ZerologMiddleware *middleware.ZerologMiddleware
	}

	err := app.dig.Invoke(func(mi middlewareInput) {
		engine.Use(mi.ContextMiddleware.Middleware())
		engine.Use(mi.UIMiddleware.Middleware())
		engine.Use(mi.ZerologMiddleware.Middleware())
	})

	if err != nil {
		return fmt.Errorf("failed to invoke middleware: %w", err)
	}

	err = app.dig.Provide(func() *gin.RouterGroup {
		return &engine.RouterGroup
	}, dig.Name("mainRouterGroup"))

	if err != nil {
		return fmt.Errorf("failed to provide main router group: %w", err)
	}

	err = app.dig.Provide(func() *gin.RouterGroup {
		return engine.Group("/api")
	}, dig.Name("apiRouterGroup"))

	if err != nil {
		return fmt.Errorf("failed to provide api router group: %w", err)
	}

	if app.config.Server.ScalarEnabled {
		err = app.setupScalar()

		if err != nil {
			return fmt.Errorf("failed to setup scalar: %w", err)
		}
	}

	controllerProvideFor := []any{
		controller.NewContextController,
		controller.NewOAuthController,
		controller.NewOIDCController,
		controller.NewProxyController,
		controller.NewUserController,
		controller.NewResourcesController,
		controller.NewHealthController,
		controller.NewWellKnownController,
	}

	for _, provider := range controllerProvideFor {
		err := app.dig.Provide(provider)

		if err != nil {
			return fmt.Errorf("failed to provide controller: %w", err)
		}
	}

	type controllerInput struct {
		dig.In

		ContextController   *controller.ContextController
		OAuthController     *controller.OAuthController
		OIDCController      *controller.OIDCController
		ProxyController     *controller.ProxyController
		UserController      *controller.UserController
		ResourcesController *controller.ResourcesController
		HealthController    *controller.HealthController
		WellKnownController *controller.WellKnownController
	}

	// force dig to build all controllers and register their routes
	err = app.dig.Invoke(func(ci controllerInput) error {
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to invoke controllers: %w", err)
	}

	app.router = engine
	return nil
}

func (app *BootstrapApp) setupScalar() error {
	appUrl, err := url.Parse(app.runtime.AppURL)

	if err != nil {
		return fmt.Errorf("failed to parse app url: %w", err)
	}

	docs.SwaggerInfo.Host = appUrl.Host
	docs.SwaggerInfo.Schemes = []string{appUrl.Scheme}
	docs.SwaggerInfo.Version = model.Version

	type scalarInput struct {
		dig.In

		RouterGroup *gin.RouterGroup `name:"mainRouterGroup"`
	}

	err = app.dig.Invoke(func(i scalarInput) {
		i.RouterGroup.GET("/scalar/*any", ginScalar.WrapHandler(nil))
	})

	if err != nil {
		return fmt.Errorf("failed to invoke scalar: %w", err)
	}

	return nil
}

// Top down
// 1. Tailscale (if tailscale.listen)
// 2. Unix socket (if server.socketPath)
// 3. HTTP - default
func (app *BootstrapApp) getListenerFunc() (func(ctx context.Context) error, error) {
	if app.config.Experimental.Tailscale.Listen {
		if app.services.tailscaleService == nil {
			return nil, fmt.Errorf("experimental.tailscale.listen is enabled but tailscale service is not initialized")
		}
		return app.serveTailscale, nil
	}

	if app.config.Server.SocketPath != "" {
		return app.serveUnix, nil
	}

	return app.serveHTTP, nil
}

func (app *BootstrapApp) serveHTTP(ctx context.Context) error {
	address := fmt.Sprintf("%s:%d", app.config.Server.Address, app.config.Server.Port)

	app.log.App.Info().Msgf("Starting server on http://%s", address)

	listener, err := net.Listen("tcp", address)

	if err != nil {
		return fmt.Errorf("failed to create tcp listener: %w", err)
	}

	server := &http.Server{
		Addr:    address,
		Handler: app.router.Handler(),
	}

	return app.serve(listener, server, ctx, "http")
}

func (app *BootstrapApp) serveUnix(ctx context.Context) error {
	_, err := os.Stat(app.config.Server.SocketPath)

	if err == nil {
		app.log.App.Info().Msgf("Removing existing socket file %s", app.config.Server.SocketPath)
		err := os.Remove(app.config.Server.SocketPath)

		if err != nil {
			return fmt.Errorf("failed to remove existing socket file: %w", err)
		}
	}

	app.log.App.Info().Msgf("Starting server on unix socket %s", app.config.Server.SocketPath)

	listener, err := net.Listen("unix", app.config.Server.SocketPath)

	if err != nil {
		return fmt.Errorf("failed to create unix socket listener: %w", err)
	}

	server := &http.Server{
		Handler: app.router.Handler(),
	}

	return app.serve(listener, server, ctx, "unix socket")
}

func (app *BootstrapApp) serveTailscale(ctx context.Context) error {
	app.log.App.Info().Msgf("Starting Tailscale server on %s", fmt.Sprintf("https://%s", app.services.tailscaleService.GetHostname()))

	listener, err := app.services.tailscaleService.CreateListener()

	if err != nil {
		return fmt.Errorf("failed to create tailscale listener: %w", err)
	}

	server := &http.Server{
		Handler: app.router.Handler(),
	}

	return app.serve(listener, server, ctx, "tailscale")
}

func (app *BootstrapApp) serve(listener net.Listener, server *http.Server, ctx context.Context, name string) error {
	shutdown := func() {
		// we use a new context for the shutdown since the main one is cancelled
		sctx, cancel := context.WithTimeout(context.Background(), model.GracefulShutdownTimeout*time.Second)
		defer cancel()
		err := server.Shutdown(sctx)
		if err != nil {
			app.log.App.Error().Err(err).Msgf("Failed to shutdown %s listener gracefully", name)
		}
		listener.Close()
	}

	go func() {
		<-ctx.Done()
		app.log.App.Debug().Msgf("Shutting down %s listener", name)
		shutdown()
	}()

	err := server.Serve(listener)

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to start %s listener: %w", name, err)
	}

	return nil
}
