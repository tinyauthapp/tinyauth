package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/ding"
	"go.uber.org/dig"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

// Shutdown order for go routines
// 1. Janitor routines (e.g. database cleanup, heartbeat) - ding.RingMinor
// 2. HTTP server listeners - ding.RingNormal
// 3. Networking layers, user and label providers (e.g. ailscale service, kubernetes service) - ding.RingMajor
// 4. Database connection - ding.RingCritical

type Services struct {
	accessControlService *service.AccessControlsService
	authService          *service.AuthService
	dockerService        *service.DockerService
	kubernetesService    *service.KubernetesService
	ldapService          *service.LdapService
	oauthBrokerService   *service.OAuthBrokerService
	oidcService          *service.OIDCService
	tailscaleService     *service.TailscaleService
	policyEngine         *service.PolicyEngine
}

type BootstrapApp struct {
	config    model.Config
	runtime   model.RuntimeConfig
	services  Services
	log       *logger.Logger
	ctx       context.Context
	cancel    context.CancelFunc
	queries   repository.Store
	router    *gin.Engine
	db        *sql.DB
	ding      *ding.Ding
	listeners []Listener
	dig       *dig.Container
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

	// create the dig container
	c := dig.New()
	app.dig = c

	// create a ding instance
	dg := ding.New(ctx)
	app.ding = dg

	// setup logger
	log := logger.NewLogger().WithConfig(app.config.Log)
	log.Init()
	app.log = log

	app.log.App.Info().Msgf("Starting Tinyauth version: %s", model.Version)

	// get app url
	if app.config.AppURL == "" {
		return errors.New("app url cannot be empty, perhaps config loading failed")
	}

	appUrl, err := url.Parse(app.config.AppURL)

	if err != nil {
		return fmt.Errorf("failed to parse app url: %w", err)
	}

	app.runtime.AppURL = appUrl.Scheme + "://" + appUrl.Host
	app.runtime.TrustedDomains = append(app.runtime.TrustedDomains, app.runtime.AppURL)

	// validate session config
	if app.config.Auth.SessionMaxLifetime != 0 && app.config.Auth.SessionMaxLifetime < app.config.Auth.SessionExpiry {
		return errors.New("session max lifetime cannot be less than session expiry")
	}

	// parse users
	users, err := utils.GetUsers(app.config.Auth.Users, app.config.Auth.UsersFile, app.config.Auth.UserAttributes)

	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	if users != nil {
		app.runtime.LocalUsers = *users
	} else {
		log.App.Debug().Msg("No local users found, local authentication will not be available")
		app.runtime.LocalUsers = []model.LocalUser{}
	}

	// load oauth whitelist
	oauthWhitelist, err := utils.GetStringList(app.config.OAuth.Whitelist, app.config.OAuth.WhitelistFile)

	if err != nil {
		return fmt.Errorf("failed to load oauth whitelist: %w", err)
	}

	app.runtime.OAuthWhitelist = oauthWhitelist

	// setup oauth providers
	app.runtime.OAuthProviders = app.config.OAuth.Providers

	for id, provider := range app.runtime.OAuthProviders {
		providerWhitelist, err := utils.GetStringList(provider.Whitelist, provider.WhitelistFile)
		if err != nil {
			return fmt.Errorf("failed to load oauth whitelist for provider %s: %w", id, err)
		}

		provider.Whitelist = providerWhitelist

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
	store, err := app.SetupStore()

	if err != nil {
		return fmt.Errorf("failed to setup database: %w", err)
	}

	app.ding.Go(func(ctx context.Context) {
		<-ctx.Done()
		app.log.App.Debug().Msg("Shutting down database connection")
		if app.db == nil {
			// using memory store, no db instance
			return
		}
		if err := app.db.Close(); err != nil {
			app.log.App.Error().Err(err).Msg("Failed to close database connection")
		}
	}, ding.RingCritical)

	// store
	app.queries = store

	// provide basic utilities to container
	type utilityProvider struct {
		dig.Out

		Log     *logger.Logger
		Config  *model.Config
		Runtime *model.RuntimeConfig
		Ding    *ding.Ding
		Ctx     context.Context
		Queries repository.Store
	}

	app.dig.Provide(func() utilityProvider {
		return utilityProvider{
			Log:     app.log,
			Config:  &app.config,
			Runtime: &app.runtime,
			Ding:    app.ding,
			Ctx:     app.ctx,
			Queries: app.queries,
		}
	})

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

	// throw in tailscale if it's configured just before setting up the controllers
	if app.services.tailscaleService != nil {
		app.runtime.TrustedDomains = append(app.runtime.TrustedDomains, "https://"+app.services.tailscaleService.GetHostname())
	}

	// setup router
	err = app.setupRouter()

	if err != nil {
		return fmt.Errorf("failed to setup routes: %w", err)
	}

	// start db cleanup routine
	app.log.App.Debug().Msg("Starting database cleanup routine")
	app.ding.Go(app.dbCleanupRoutine, ding.RingMinor)

	// if analytics are not disabled, start heartbeat
	if app.config.Analytics.Enabled {
		app.log.App.Debug().Msg("Starting heartbeat routine")
		app.ding.Go(app.heartbeatRoutine, ding.RingMinor)
	}

	// setup listeners
	app.listeners = app.calculateListenerPolicy()

	if app.config.Server.ConcurrentListenersEnabled {
		app.log.App.Info().Msg("Concurrent listeners enabled, will run on all available listeners")
	}

	// run listeners
	lec, err := app.runListeners()

	if err != nil {
		return fmt.Errorf("failed to run listeners: %w", err)
	}

	// monitor cancellation and server errors
	for {
		select {
		case <-app.ctx.Done():
			app.ding.Wait()
			app.log.App.Info().Msg("Oh, it's time for me to go, bye!")
			return nil
		case err := <-lec:
			if err != nil {
				return fmt.Errorf("listener error: %w", err)
			}
		}
	}
}

func (app *BootstrapApp) heartbeatRoutine(ctx context.Context) {
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
		case <-ctx.Done():
			app.log.App.Debug().Msg("Stopping heartbeat routine")
			ticker.Stop()
			return
		}
	}
}

func (app *BootstrapApp) dbCleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(30) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			app.log.App.Debug().Msg("Running database cleanup")

			err := app.queries.DeleteExpiredSessions(ctx, time.Now().Unix())

			if err != nil {
				app.log.App.Error().Err(err).Msg("Failed to delete expired sessions")
			}

			app.log.App.Debug().Msg("Database cleanup completed")
		case <-ctx.Done():
			app.log.App.Debug().Msg("Stopping database cleanup routine")
			ticker.Stop()
			return
		}
	}
}
