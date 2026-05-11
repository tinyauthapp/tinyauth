package bootstrap

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/middleware"

	"github.com/gin-gonic/gin"
)

type Listener int

const (
	ListenerHTTP Listener = iota
	ListenerUnix
	ListenerTailscale
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

	contextMiddleware := middleware.NewContextMiddleware(app.log, app.runtime, app.services.authService, app.services.oauthBrokerService, app.services.tailscaleService)
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

func (app *BootstrapApp) runListeners() (chan error, error) {
	// lec -> listener error channel
	lec := make(chan error, len(app.listeners))

	for _, listenerType := range app.listeners {
		listenerFunc, err := app.listenerFromType(listenerType)

		if err != nil {
			return nil, fmt.Errorf("failed to get listener function: %w", err)
		}

		app.wg.Go(func() {
			lec <- listenerFunc()
		})
	}

	return lec, nil
}

func (app *BootstrapApp) listenerFromType(listenerType Listener) (func() error, error) {
	switch listenerType {
	case ListenerHTTP:
		return app.serveHTTP, nil
	case ListenerUnix:
		return app.serveUnix, nil
	case ListenerTailscale:
		return app.serveTailscale, nil
	default:
		return nil, fmt.Errorf("invalid listener type: %d", listenerType)
	}
}

func (app *BootstrapApp) serveHTTP() error {
	address := fmt.Sprintf("%s:%d", app.config.Server.Address, app.config.Server.Port)

	app.log.App.Info().Msgf("Starting server on %s", address)

	listener, err := net.Listen("tcp", address)

	if err != nil {
		return fmt.Errorf("failed to create tcp listener: %w", err)
	}

	server := &http.Server{
		Addr:    address,
		Handler: app.router.Handler(),
	}

	return app.serve(listener, server, "http")
}

func (app *BootstrapApp) serveUnix() error {
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

	return app.serve(listener, server, "unix socket")
}

func (app *BootstrapApp) serveTailscale() error {
	app.log.App.Info().Msgf("Starting Tailscale server on %s", fmt.Sprintf("https://%s", app.services.tailscaleService.GetHostname()))

	listener, err := app.services.tailscaleService.CreateListener()

	if err != nil {
		return fmt.Errorf("failed to create tailscale listener: %w", err)
	}

	server := &http.Server{
		Handler: app.router.Handler(),
	}

	return app.serve(listener, server, "tailscale")
}

func (app *BootstrapApp) serve(listener net.Listener, server *http.Server, name string) error {
	shutdown := func() {
		server.Shutdown(app.ctx)
		listener.Close()
	}

	go func() {
		<-app.ctx.Done()
		app.log.App.Debug().Msgf("Shutting down %s listener", name)
		shutdown()
	}()

	err := server.Serve(listener)

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		shutdown()
		return fmt.Errorf("failed to start %s listener: %w", name, err)
	}

	return nil
}
