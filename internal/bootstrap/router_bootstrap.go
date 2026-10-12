package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/middleware"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"go.uber.org/dig"

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

		app.runtime.TrustedProxiesConfigured = true
	} else {
		err := engine.SetTrustedProxies(nil)

		if err != nil {
			return fmt.Errorf("failed to set trusted proxies: %w", err)
		}

		app.log.App.Warn().Msg("Trusted proxies are not configured, IP access controls will NOT work")
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

// Top down
// 1. Unix socket (if server.socketPath)
// 2. HTTP - default
func (app *BootstrapApp) getListenerFunc() (func(ctx context.Context) error, error) {
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

// parseSocketMode parses an octal permission string such as "0660" into an os.FileMode.
func parseSocketMode(s string) (os.FileMode, error) {
	v, err := strconv.ParseUint(s, 8, 32)

	if err != nil || v > 0o777 {
		return 0, fmt.Errorf("expected an octal mode such as 0660")
	}

	return os.FileMode(v), nil
}

func (app *BootstrapApp) serveUnix(ctx context.Context) error {
	// Validate socketMode up front, before removing any existing socket, so a configuration error does
	// not delete the current socket and then fail to start.
	hasMode := app.config.Server.SocketMode != ""

	var mode os.FileMode

	if hasMode {
		if runtime.GOOS == "windows" {
			return errors.New("server.socketMode is not supported on Windows, where socket permissions cannot be enforced")
		}

		var perr error

		if mode, perr = parseSocketMode(app.config.Server.SocketMode); perr != nil {
			return fmt.Errorf("invalid server.socketMode %q: %w", app.config.Server.SocketMode, perr)
		}
	}

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

	if hasMode {
		// net.Listen creates the socket with the process umask's mode; chmod tightens it immediately.
		// serve() has not started accepting connections yet, and connecting to the socket is not itself
		// an auth bypass, so this is the standard Listen+Chmod pattern for Go unix sockets. It is
		// preferred over changing the process-wide umask, which would race with any other file created
		// during startup. Operators wanting a hard guarantee should also restrict the socket's directory.
		if err := os.Chmod(app.config.Server.SocketPath, mode); err != nil {
			listener.Close()
			return fmt.Errorf("failed to set unix socket mode: %w", err)
		}
	}

	server := &http.Server{
		Handler: app.router.Handler(),
	}

	return app.serve(listener, server, ctx, "unix socket")
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
