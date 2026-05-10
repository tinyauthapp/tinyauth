package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
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

type BootstrapApp struct {
	config   model.Config
	runtime  model.RuntimeConfig
	services Services
	log      *logger.Logger
	ctx      context.Context
	cancel   context.CancelFunc
	queries  *repository.Queries
	router   *gin.Engine
	db       *sql.DB
	wg       sync.WaitGroup
}

func NewBootstrapApp(config model.Config) *BootstrapApp {
	return &BootstrapApp{
		config: config,
	}
}

func (app *BootstrapApp) Setup() error {
	// create context
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	app.ctx = ctx
	app.cancel = cancel

	// setup logger
	log := logger.NewLogger().WithConfig(app.config.Log)
	log.Init()
	app.log = log

	// get app url
	if app.config.AppURL == "" {
		return errors.New("app url cannot be empty, perhaps config loading failed")
	}

	appUrl, err := url.Parse(app.config.AppURL)

	if err != nil {
		return fmt.Errorf("failed to parse app url: %w", err)
	}

	app.runtime.AppURL = appUrl.Scheme + "://" + appUrl.Host

	// validate session config
	if app.config.Auth.SessionMaxLifetime != 0 && app.config.Auth.SessionMaxLifetime < app.config.Auth.SessionExpiry {
		return errors.New("session max lifetime cannot be less than session expiry")
	}

	// parse users
	users, err := utils.GetUsers(app.config.Auth.Users, app.config.Auth.UsersFile, app.config.Auth.UserAttributes)

	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	app.runtime.LocalUsers = *users

	// load oauth whitelist
	oauthWhitelist, err := utils.GetStringList(app.config.OAuth.Whitelist, app.config.OAuth.WhitelistFile)

	if err != nil {
		return fmt.Errorf("failed to load oauth whitelist: %w", err)
	}

	app.runtime.OAuthWhitelist = oauthWhitelist

	// setup oauth providers
	app.runtime.OAuthProviders = app.config.OAuth.Providers

	for id, provider := range app.runtime.OAuthProviders {
		secret := utils.GetSecret(provider.ClientSecret, provider.ClientSecretFile)
		provider.ClientSecret = secret
		provider.ClientSecretFile = ""

		if provider.RedirectURL == "" {
			provider.RedirectURL = app.runtime.AppURL + "/api/oauth/callback/" + id
		}

		app.runtime.OAuthProviders[id] = provider
	}

	// set presets for built-in providers
	for id, provider := range app.runtime.OAuthProviders {
		if provider.Name == "" {
			if name, ok := model.OverrideProviders[id]; ok {
				provider.Name = name
			} else {
				provider.Name = utils.Capitalize(id)
			}
		}
		app.runtime.OAuthProviders[id] = provider
	}

	// setup oidc clients
	for id, client := range app.config.OIDC.Clients {
		client.ID = id
		app.runtime.OIDCClients = append(app.runtime.OIDCClients, client)
	}

	// cookie domain
	cookieDomainResolver := utils.GetCookieDomain

	if !app.config.Auth.SubdomainsEnabled {
		app.log.App.Warn().Msg("Subdomains are disabled, using standalone cookie domain resolver which will not work with subdomains")
		cookieDomainResolver = utils.GetStandaloneCookieDomain
	}

	cookieDomain, err := cookieDomainResolver(app.runtime.AppURL)

	if err != nil {
		return fmt.Errorf("failed to get cookie domain: %w", err)
	}

	app.runtime.CookieDomain = cookieDomain

	// cookie names
	app.runtime.UUID = utils.GenerateUUID(appUrl.Hostname())

	cookieId := strings.Split(app.runtime.UUID, "-")[0] // first 8 characters of the uuid should be good enough

	app.runtime.SessionCookieName = fmt.Sprintf("%s-%s", model.SessionCookieName, cookieId)
	app.runtime.CSRFCookieName = fmt.Sprintf("%s-%s", model.CSRFCookieName, cookieId)
	app.runtime.RedirectCookieName = fmt.Sprintf("%s-%s", model.RedirectCookieName, cookieId)
	app.runtime.OAuthSessionCookieName = fmt.Sprintf("%s-%s", model.OAuthSessionCookieName, cookieId)

	// database
	err = app.SetupDatabase()

	if err != nil {
		return fmt.Errorf("failed to setup database: %w", err)
	}

	// after this point, we start initializing dependencies so it's a good time to setup a defer
	// to ensure that resources are cleaned up properly in case of an error during initialization
	defer func() {
		app.cancel()
		app.wg.Wait()
		app.db.Close()
	}()

	// queries
	queries := repository.New(app.db)
	app.queries = queries

	// services
	err = app.setupServices()

	if err != nil {
		return fmt.Errorf("failed to initialize services: %w", err)
	}

	// configured providers
	configuredProviders := make([]model.Provider, 0)

	for id, provider := range app.runtime.OAuthProviders {
		configuredProviders = append(configuredProviders, model.Provider{
			Name:  provider.Name,
			ID:    id,
			OAuth: true,
		})
	}

	sort.Slice(configuredProviders, func(i, j int) bool {
		return configuredProviders[i].Name < configuredProviders[j].Name
	})

	if app.services.authService.LocalAuthConfigured() {
		configuredProviders = append(configuredProviders, model.Provider{
			Name:  "Local",
			ID:    "local",
			OAuth: false,
		})
	}

	if app.services.authService.LDAPAuthConfigured() {
		configuredProviders = append(configuredProviders, model.Provider{
			Name:  "LDAP",
			ID:    "ldap",
			OAuth: false,
		})
	}

	if len(configuredProviders) == 0 {
		return errors.New("no authentication providers configured")
	}

	for _, provider := range configuredProviders {
		app.log.App.Debug().Str("provider", provider.Name).Msg("Configured authentication provider")
	}

	app.runtime.ConfiguredProviders = configuredProviders

	// setup router
	err = app.setupRouter()

	if err != nil {
		return fmt.Errorf("failed to setup routes: %w", err)
	}

	// start db cleanup routine
	app.log.App.Debug().Msg("Starting database cleanup routine")
	app.wg.Go(app.dbCleanupRoutine)

	// if analytics are not disabled, start heartbeat
	if app.config.Analytics.Enabled {
		app.log.App.Debug().Msg("Starting heartbeat routine")
		app.wg.Go(app.heartbeatRoutine)
	}

	// create err channel to listen for server errors
	errChanLen := 0

	runUnix := app.config.Server.SocketPath != ""
	runHTTP := app.config.Server.SocketPath == "" || app.config.Server.ConcurrentListenersEnabled

	if runUnix {
		errChanLen++
	}

	if runHTTP {
		errChanLen++
	}

	errChan := make(chan error, errChanLen)

	if app.config.Server.ConcurrentListenersEnabled {
		app.log.App.Info().Msg("Concurrent listeners enabled, will run on all available listeners")
	}

	// serve unix
	if runUnix {
		app.wg.Go(func() {
			if err := app.serveUnix(); err != nil {
				errChan <- err
			}
		})
	}

	// serve to http
	if runHTTP {
		app.wg.Go(func() {
			if err := app.serveHTTP(); err != nil {
				errChan <- err
			}
		})
	}

	// monitor cancellation and server errors
	for {
		select {
		case <-app.ctx.Done():
			app.log.App.Info().Msg("Oh, it's time for me to go, bye!")
			return nil
		case err := <-errChan:
			if err != nil {
				return fmt.Errorf("server error: %w", err)
			}
		}
	}
}

func (app *BootstrapApp) serveHTTP() error {
	address := fmt.Sprintf("%s:%d", app.config.Server.Address, app.config.Server.Port)

	app.log.App.Info().Msgf("Starting server on %s", address)

	server := &http.Server{
		Addr:    address,
		Handler: app.router.Handler(),
	}

	go func() {
		<-app.ctx.Done()
		app.log.App.Debug().Msg("Shutting down http listener")
		server.Shutdown(app.ctx)
	}()

	err := server.ListenAndServe()

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to start http listener: %w", err)
	}

	return nil
}

func (app *BootstrapApp) serveUnix() error {
	if app.config.Server.SocketPath == "" {
		return nil
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

	server := &http.Server{
		Handler: app.router.Handler(),
	}

	shutdown := func() {
		server.Shutdown(app.ctx)
		listener.Close()
		os.Remove(app.config.Server.SocketPath)
	}

	go func() {
		<-app.ctx.Done()
		app.log.App.Debug().Msg("Shutting down unix socket listener")
		shutdown()
	}()

	err = server.Serve(listener)

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		shutdown()
		return fmt.Errorf("failed to start unix socket listener: %w", err)
	}

	return nil
}

func (app *BootstrapApp) heartbeatRoutine() {
	ticker := time.NewTicker(time.Duration(12) * time.Hour)
	defer ticker.Stop()

	type Heartbeat struct {
		UUID    string `json:"uuid"`
		Version string `json:"version"`
	}

	var body Heartbeat

	body.UUID = app.runtime.UUID
	body.Version = model.Version

	bodyJson, err := json.Marshal(body)

	if err != nil {
		app.log.App.Error().Err(err).Msg("Failed to marshal heartbeat body, heartbeat routine will not start")
		return
	}

	client := &http.Client{
		Timeout: 30 * time.Second, // The server should never take more than 30 seconds to respond
	}

	heartbeatURL := model.APIServer + "/v1/instances/heartbeat"

	for {
		select {
		case <-ticker.C:
			app.log.App.Debug().Msg("Sending heartbeat")

			req, err := http.NewRequest(http.MethodPost, heartbeatURL, bytes.NewReader(bodyJson))

			if err != nil {
				app.log.App.Error().Err(err).Msg("Failed to create heartbeat request")
				continue
			}

			req.Header.Add("Content-Type", "application/json")

			res, err := client.Do(req)

			if err != nil {
				app.log.App.Error().Err(err).Msg("Failed to send heartbeat")
				continue
			}

			res.Body.Close()

			if res.StatusCode != 200 && res.StatusCode != 201 {
				app.log.App.Debug().Str("status", res.Status).Msg("Heartbeat returned non-200/201 status")
			}
		case <-app.ctx.Done():
			app.log.App.Debug().Msg("Stopping heartbeat routine")
			ticker.Stop()
			return
		}
	}
}

func (app *BootstrapApp) dbCleanupRoutine() {
	ticker := time.NewTicker(time.Duration(30) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			app.log.App.Debug().Msg("Running database cleanup")

			err := app.queries.DeleteExpiredSessions(app.ctx, time.Now().Unix())

			if err != nil {
				app.log.App.Error().Err(err).Msg("Failed to delete expired sessions")
			}

			app.log.App.Debug().Msg("Database cleanup completed")
		case <-app.ctx.Done():
			app.log.App.Debug().Msg("Stopping database cleanup routine")
			ticker.Stop()
			return
		}
	}
}
