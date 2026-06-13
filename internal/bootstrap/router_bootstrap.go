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
	"go.uber.org/dig"

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

	err := app.dig.Provide(middleware.NewContextMiddleware)

	if err != nil {
		return fmt.Errorf("failed to provide context middleware: %w", err)
	}

	err = app.dig.Provide(middleware.NewUIMiddleware)

	if err != nil {
		return fmt.Errorf("failed to provide ui middleware: %w", err)
	}

	err = app.dig.Provide(middleware.NewZerologMiddleware)

	if err != nil {
		return fmt.Errorf("failed to provide zerolog middleware: %w", err)
	}

	type middlewareInput struct {
		dig.In

		ContextMiddleware *middleware.ContextMiddleware
		UIMiddleware      *middleware.UIMiddleware
		ZerologMiddleware *middleware.ZerologMiddleware
	}

	err = app.dig.Invoke(func(mi middlewareInput) {
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

	err = app.dig.Provide(controller.NewContextController)
	if err != nil {
		return fmt.Errorf("failed to provide context controller: %w", err)
	}

	err = app.dig.Provide(controller.NewOAuthController)
	if err != nil {
		return fmt.Errorf("failed to provide oauth controller: %w", err)
	}

	err = app.dig.Provide(controller.NewOIDCController)
	if err != nil {
		return fmt.Errorf("failed to provide oidc controller: %w", err)
	}

	err = app.dig.Provide(controller.NewProxyController)
	if err != nil {
		return fmt.Errorf("failed to provide proxy controller: %w", err)
	}

	err = app.dig.Provide(controller.NewUserController)
	if err != nil {
		return fmt.Errorf("failed to provide user controller: %w", err)
	}

	err = app.dig.Provide(controller.NewResourcesController)
	if err != nil {
		return fmt.Errorf("failed to provide resources controller: %w", err)
	}

	err = app.dig.Provide(controller.NewHealthController)
	if err != nil {
		return fmt.Errorf("failed to provide health controller: %w", err)
	}

	err = app.dig.Provide(controller.NewWellKnownController)
	if err != nil {
		return fmt.Errorf("failed to provide well-known controller: %w", err)
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
		if app.services.tailscaleService != nil {
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

	if app.services.tailscaleService != nil {
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
		shutdown()
		return fmt.Errorf("failed to start %s listener: %w", name, err)
	}

	return nil
}
