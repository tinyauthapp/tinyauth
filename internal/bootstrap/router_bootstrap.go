package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/middleware"
	"github.com/tinyauthapp/tinyauth/internal/model"

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

	contextMiddleware := middleware.NewContextMiddleware(app.log, app.runtime, app.services.AuthService, app.services.OAuthBrokerService, app.services.TailscaleService)
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
	controller.NewOAuthController(app.log, app.config, app.runtime, apiRouter, app.services.AuthService)
	controller.NewOIDCController(app.log, app.services.OIDCService, app.runtime, apiRouter, &engine.RouterGroup)
	controller.NewProxyController(app.log, app.runtime, apiRouter, app.services.AccessControlService, app.services.AuthService, app.services.PolicyEngine)
	controller.NewUserController(app.log, app.runtime, apiRouter, app.services.AuthService)
	controller.NewResourcesController(app.config, &engine.RouterGroup)
	controller.NewHealthController(apiRouter)
	controller.NewWellKnownController(app.services.OIDCService, &engine.RouterGroup)

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

		app.ding.Go(func(ctx context.Context) {
			lec <- listenerFunc(ctx)
		}, ding.RingNormal)
	}

	return lec, nil
}

// The way we calculate listeners is as follows:
// If concurrent listeners are disabled, we pick the first available listener, so:
// 1. If tailscale is enabled, we use tailscale
// 2. If socket path is configured, we use unix socket
// 3. Finally if none is configured we use http
// If concurrent listeners are enabled, we add all available listeners in the following order
func (app *BootstrapApp) calculateListenerPolicy() []Listener {
	l := []Listener{}

	if !app.config.Server.ConcurrentListenersEnabled {
		if app.services.TailscaleService != nil {
			l = append(l, ListenerTailscale)
			return l
		}

		if app.config.Server.SocketPath != "" {
			l = append(l, ListenerUnix)
			return l
		}

		l = append(l, ListenerHTTP)
		return l
	}

	if app.config.Server.SocketPath != "" {
		l = append(l, ListenerUnix)
	}

	if app.services.TailscaleService != nil {
		l = append(l, ListenerTailscale)
	}

	l = append(l, ListenerHTTP)

	return l
}

func (app *BootstrapApp) listenerFromType(listenerType Listener) (func(ctx context.Context) error, error) {
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

func (app *BootstrapApp) serveHTTP(ctx context.Context) error {
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
	app.log.App.Info().Msgf("Starting Tailscale server on %s", fmt.Sprintf("https://%s", app.services.TailscaleService.GetHostname()))

	listener, err := app.services.TailscaleService.CreateListener()

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
		shutdown()
		return fmt.Errorf("failed to start %s listener: %w", name, err)
	}

	return nil
}
