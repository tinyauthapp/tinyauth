package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"

	"slices"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

// hard-defaults, may make configurable in the future if needed,
// but for now these are just safety limits to prevent unbounded memory usage
const MaxOAuthPendingSessions = 256
const OAuthCleanupCount = 16
const MaxLoginAttemptRecords = 256

var (
	ErrUserNotFound = errors.New("user not found")
)

// slightly modified version of the AuthorizeRequest from the OIDC service to basically accept all
// parameters and pass them to the authorize page if needed
type OAuthURLParams struct {
	Scope               string `form:"scope" url:"scope"`
	ResponseType        string `form:"response_type" url:"response_type"`
	ClientID            string `form:"client_id" url:"client_id"`
	RedirectURI         string `form:"redirect_uri" url:"redirect_uri"`
	State               string `form:"state" url:"state"`
	Nonce               string `form:"nonce" url:"nonce"`
	CodeChallenge       string `form:"code_challenge" url:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method" url:"code_challenge_method"`
}

type OAuthPendingSession struct {
	State          string
	Verifier       string
	Token          *oauth2.Token
	Service        *OAuthServiceImpl
	ExpiresAt      time.Time
	CallbackParams OAuthURLParams
}

type LdapGroupsCache struct {
	Groups  []string
	Expires time.Time
}

type LoginAttempt struct {
	FailedAttempts int
	LastAttempt    time.Time
	LockedUntil    time.Time
}

type Lockdown struct {
	Active      bool
	ActiveUntil time.Time
}

type AuthService struct {
	log     *logger.Logger
	config  model.Config
	runtime model.RuntimeConfig
	context context.Context

	ldap        *LdapService
	queries     repository.Store
	oauthBroker *OAuthBrokerService
	tailscale   *TailscaleService

	loginAttempts        map[string]*LoginAttempt
	ldapGroupsCache      map[string]*LdapGroupsCache
	oauthPendingSessions map[string]*OAuthPendingSession
	oauthMutex           sync.RWMutex
	loginMutex           sync.RWMutex
	ldapGroupsMutex      sync.RWMutex
	lockdown             *Lockdown
	lockdownCtx          context.Context
	lockdownCancelFunc   context.CancelFunc
}

func NewAuthService(
	log *logger.Logger,
	config model.Config,
	runtime model.RuntimeConfig,
	ctx context.Context,
	wg *sync.WaitGroup,
	ldap *LdapService,
	queries repository.Store,
	oauthBroker *OAuthBrokerService,
	tailscale *TailscaleService,
) *AuthService {
	service := &AuthService{
		log:                  log,
		runtime:              runtime,
		context:              ctx,
		config:               config,
		loginAttempts:        make(map[string]*LoginAttempt),
		ldapGroupsCache:      make(map[string]*LdapGroupsCache),
		oauthPendingSessions: make(map[string]*OAuthPendingSession),
		ldap:                 ldap,
		queries:              queries,
		oauthBroker:          oauthBroker,
		tailscale:            tailscale,
	}

	wg.Go(service.CleanupOAuthSessionsRoutine)

	return service
}

func (auth *AuthService) SearchUser(username string) (*model.UserSearch, error) {
	if auth.GetLocalUser(username) != nil {
		return &model.UserSearch{
			Username: username,
			Type:     model.UserLocal,
		}, nil
	}

	if auth.ldap != nil {
		userDN, email, err := auth.ldap.GetUserInfo(username)

		if err != nil {
			return nil, fmt.Errorf("failed to get ldap user: %w", err)
		}

		return &model.UserSearch{
			Username: userDN,
			Email:    email,
			Type:     model.UserLDAP,
		}, nil
	}

	return nil, ErrUserNotFound
}

func (auth *AuthService) CheckUserPassword(search model.UserSearch, password string) error {
	switch search.Type {
	case model.UserLocal:
		user := auth.GetLocalUser(search.Username)
		if user == nil {
			return ErrUserNotFound
		}
		return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	case model.UserLDAP:
		if auth.ldap != nil {
			err := auth.ldap.Bind(search.Username, password)
			if err != nil {
				return fmt.Errorf("failed to bind to ldap user: %w", err)
			}

			err = auth.ldap.BindService(true)
			if err != nil {
				return fmt.Errorf("failed to bind to ldap service account: %w", err)
			}

			return nil
		}
	default:
		return errors.New("unknown user search type")
	}
	return errors.New("user authentication failed")
}

func (auth *AuthService) GetLocalUser(username string) *model.LocalUser {
	if auth.runtime.LocalUsers == nil {
		return nil
	}
	for _, user := range auth.runtime.LocalUsers {
		if user.Username == username {
			return &user
		}
	}
	return nil
}

func (auth *AuthService) GetLDAPUser(userDN string) (*model.LDAPUser, error) {
	if auth.ldap == nil {
		return nil, errors.New("ldap service not configured")
	}

	auth.ldapGroupsMutex.RLock()
	entry, exists := auth.ldapGroupsCache[userDN]
	auth.ldapGroupsMutex.RUnlock()

	if exists && time.Now().Before(entry.Expires) {
		return &model.LDAPUser{
			DN:     userDN,
			Groups: entry.Groups,
		}, nil
	}

	groups, err := auth.ldap.GetUserGroups(userDN)

	if err != nil {
		return nil, fmt.Errorf("failed to get ldap groups: %w", err)
	}

	auth.ldapGroupsMutex.Lock()
	auth.ldapGroupsCache[userDN] = &LdapGroupsCache{
		Groups:  groups,
		Expires: time.Now().Add(time.Duration(auth.config.LDAP.GroupCacheTTL) * time.Second),
	}
	auth.ldapGroupsMutex.Unlock()

	return &model.LDAPUser{
		DN:     userDN,
		Groups: groups,
	}, nil
}

func (auth *AuthService) IsAccountLocked(identifier string) (bool, int) {
	auth.loginMutex.RLock()
	defer auth.loginMutex.RUnlock()

	if auth.lockdown != nil && auth.lockdown.Active {
		remaining := int(time.Until(auth.lockdown.ActiveUntil).Seconds())
		return true, remaining
	}

	if auth.config.Auth.LoginMaxRetries <= 0 || auth.config.Auth.LoginTimeout <= 0 {
		return false, 0
	}

	attempt, exists := auth.loginAttempts[identifier]
	if !exists {
		return false, 0
	}

	if attempt.LockedUntil.After(time.Now()) {
		remaining := int(time.Until(attempt.LockedUntil).Seconds())
		return true, remaining
	}

	return false, 0
}

func (auth *AuthService) RecordLoginAttempt(identifier string, success bool) {
	if auth.config.Auth.LoginMaxRetries <= 0 || auth.config.Auth.LoginTimeout <= 0 {
		return
	}

	auth.loginMutex.Lock()
	defer auth.loginMutex.Unlock()

	if len(auth.loginAttempts) >= MaxLoginAttemptRecords {
		if auth.lockdown != nil && auth.lockdown.Active {
			return
		}
		go auth.lockdownMode()
		return
	}

	attempt, exists := auth.loginAttempts[identifier]
	if !exists {
		attempt = &LoginAttempt{}
		auth.loginAttempts[identifier] = attempt
	}

	attempt.LastAttempt = time.Now()

	if success {
		attempt.FailedAttempts = 0
		attempt.LockedUntil = time.Time{} // Reset lock time
		return
	}

	attempt.FailedAttempts++

	if attempt.FailedAttempts >= auth.config.Auth.LoginMaxRetries {
		attempt.LockedUntil = time.Now().Add(time.Duration(auth.config.Auth.LoginTimeout) * time.Second)
		auth.log.App.Warn().Str("identifier", identifier).Int("failedAttempts", attempt.FailedAttempts).Msg("Account locked due to too many failed login attempts")
	}
}

func (auth *AuthService) IsEmailWhitelisted(provider string, email string) bool {
	whitelist := auth.runtime.OAuthWhitelist
	if providerConfig, ok := auth.runtime.OAuthProviders[provider]; ok && len(providerConfig.Whitelist) > 0 {
		whitelist = providerConfig.Whitelist
	}

	match, err := utils.CheckFilter(strings.Join(whitelist, ","), email)
	if err != nil {
		auth.log.App.Warn().Err(err).Str("provider", provider).Str("email", email).Msg("Invalid email filter pattern")
		return false
	}
	return match
}

func (auth *AuthService) GetUsernameOverride(email string) (string, bool) {
	username, exists := auth.runtime.OAuthUsernameOverrides[email]
	return username, exists
}

func (auth *AuthService) CreateSession(ctx context.Context, data repository.Session) (*http.Cookie, error) {
	if data.Provider == "tailscale" && auth.tailscale == nil {
		return nil, fmt.Errorf("tailscale service not configured, cannot create session for tailscale user")
	}

	uuid, err := uuid.NewRandom()

	if err != nil {
		return nil, fmt.Errorf("failed to generate session uuid: %w", err)
	}

	var expiry int

	if data.TotpPending {
		expiry = 3600
	} else {
		expiry = auth.config.Auth.SessionExpiry
	}

	expiresAt := time.Now().Add(time.Duration(expiry) * time.Second)

	session := repository.CreateSessionParams{
		UUID:        uuid.String(),
		Username:    data.Username,
		Email:       data.Email,
		Name:        data.Name,
		Provider:    data.Provider,
		TotpPending: data.TotpPending,
		OAuthGroups: data.OAuthGroups,
		Expiry:      expiresAt.Unix(),
		CreatedAt:   time.Now().Unix(),
		OAuthName:   data.OAuthName,
		OAuthSub:    data.OAuthSub,
	}

	_, err = auth.queries.CreateSession(ctx, session)

	if err != nil {
		return nil, fmt.Errorf("failed to create session entry: %w", err)
	}

	if data.Provider == "tailscale" {
		auth.log.App.Trace().Str("url", fmt.Sprintf("https://%s", auth.tailscale.GetHostname())).Msg("Extracting root domain from Tailscale hostname")

		tsCookieDomain, err := utils.GetCookieDomain(fmt.Sprintf("https://%s", auth.tailscale.GetHostname()))

		if err != nil {
			return nil, fmt.Errorf("failed to get cookie domain for tailscale user: %w", err)
		}

		return &http.Cookie{
			Name:     auth.runtime.SessionCookieName,
			Value:    session.UUID,
			Path:     "/",
			Domain:   fmt.Sprintf(".%s", tsCookieDomain),
			Expires:  expiresAt,
			MaxAge:   int(time.Until(expiresAt).Seconds()),
			Secure:   auth.config.Auth.SecureCookie,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}, nil
	}

	return &http.Cookie{
		Name:     auth.runtime.SessionCookieName,
		Value:    session.UUID,
		Path:     "/",
		Domain:   fmt.Sprintf(".%s", auth.runtime.CookieDomain),
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		Secure:   auth.config.Auth.SecureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

func (auth *AuthService) RefreshSession(ctx context.Context, uuid string) (*http.Cookie, error) {
	session, err := auth.queries.GetSession(ctx, uuid)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve session: %w", err)
	}

	currentTime := time.Now().Unix()

	var refreshThreshold int64

	if auth.config.Auth.SessionExpiry <= int(time.Hour.Seconds()) {
		refreshThreshold = int64(auth.config.Auth.SessionExpiry / 2)
	} else {
		refreshThreshold = int64(time.Hour.Seconds())
	}

	if session.Expiry-currentTime > refreshThreshold {
		return nil, nil
	}

	newExpiry := session.Expiry + refreshThreshold

	_, err = auth.queries.UpdateSession(ctx, repository.UpdateSessionParams{
		Username:    session.Username,
		Email:       session.Email,
		Name:        session.Name,
		Provider:    session.Provider,
		TotpPending: session.TotpPending,
		OAuthGroups: session.OAuthGroups,
		Expiry:      newExpiry,
		OAuthName:   session.OAuthName,
		OAuthSub:    session.OAuthSub,
		UUID:        session.UUID,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to update session expiry: %w", err)
	}

	return &http.Cookie{
		Name:     auth.runtime.SessionCookieName,
		Value:    session.UUID,
		Path:     "/",
		Domain:   fmt.Sprintf(".%s", auth.runtime.CookieDomain),
		Expires:  time.Now().Add(time.Duration(newExpiry-currentTime) * time.Second),
		MaxAge:   int(newExpiry - currentTime),
		Secure:   auth.config.Auth.SecureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil

}

func (auth *AuthService) DeleteSession(ctx context.Context, uuid string) (*http.Cookie, error) {
	err := auth.queries.DeleteSession(ctx, uuid)

	if err != nil {
		auth.log.App.Error().Err(err).Str("uuid", uuid).Msg("Failed to delete session from database")
	}

	return &http.Cookie{
		Name:     auth.runtime.SessionCookieName,
		Value:    "",
		Path:     "/",
		Domain:   fmt.Sprintf(".%s", auth.runtime.CookieDomain),
		Expires:  time.Now(),
		MaxAge:   -1,
		Secure:   auth.config.Auth.SecureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

func (auth *AuthService) GetSession(ctx context.Context, uuid string) (*repository.Session, error) {
	session, err := auth.queries.GetSession(ctx, uuid)

	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, errors.New("session not found")
		}
		return nil, err
	}

	currentTime := time.Now().Unix()

	if auth.config.Auth.SessionMaxLifetime != 0 && session.CreatedAt != 0 {
		if currentTime-session.CreatedAt > int64(auth.config.Auth.SessionMaxLifetime) {
			err = auth.queries.DeleteSession(ctx, uuid)
			if err != nil {
				return nil, fmt.Errorf("failed to delete expired session: %w", err)
			}
			return nil, fmt.Errorf("session max lifetime exceeded")
		}
	}

	if currentTime > session.Expiry {
		err = auth.queries.DeleteSession(ctx, uuid)
		if err != nil {
			return nil, fmt.Errorf("failed to delete expired session: %w", err)
		}
		return nil, fmt.Errorf("session expired")
	}

	return &session, nil
}

func (auth *AuthService) LocalAuthConfigured() bool {
	return len(auth.runtime.LocalUsers) > 0
}

func (auth *AuthService) LDAPAuthConfigured() bool {
	return auth.ldap != nil
}

func (auth *AuthService) NewOAuthSession(serviceName string, params OAuthURLParams) (string, OAuthPendingSession, error) {
	auth.ensureOAuthSessionLimit()

	service, ok := auth.oauthBroker.GetService(serviceName)

	if !ok {
		return "", OAuthPendingSession{}, fmt.Errorf("oauth service not found: %s", serviceName)
	}

	sessionId, err := uuid.NewRandom()

	if err != nil {
		return "", OAuthPendingSession{}, fmt.Errorf("failed to generate session ID: %w", err)
	}

	state := service.NewRandom()
	verifier := service.NewRandom()

	session := OAuthPendingSession{
		State:          state,
		Verifier:       verifier,
		Service:        &service,
		ExpiresAt:      time.Now().Add(1 * time.Hour),
		CallbackParams: params,
	}

	auth.oauthMutex.Lock()
	auth.oauthPendingSessions[sessionId.String()] = &session
	auth.oauthMutex.Unlock()

	return sessionId.String(), session, nil
}

func (auth *AuthService) GetOAuthURL(sessionId string) (string, error) {
	session, err := auth.GetOAuthPendingSession(sessionId)

	if err != nil {
		return "", err
	}

	return (*session.Service).GetAuthURL(session.State, session.Verifier), nil
}

func (auth *AuthService) GetOAuthToken(sessionId string, code string) (*oauth2.Token, error) {
	session, err := auth.GetOAuthPendingSession(sessionId)

	if err != nil {
		return nil, err
	}

	token, err := (*session.Service).GetToken(code, session.Verifier)

	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	auth.oauthMutex.Lock()
	session.Token = token
	auth.oauthMutex.Unlock()

	return token, nil
}

func (auth *AuthService) GetOAuthUserinfo(sessionId string) (*model.Claims, error) {
	session, err := auth.GetOAuthPendingSession(sessionId)

	if err != nil {
		return nil, err
	}

	if session.Token == nil {
		return nil, fmt.Errorf("oauth token not found for session: %s", sessionId)
	}

	userinfo, err := (*session.Service).GetUserinfo(session.Token)

	if err != nil {
		return nil, fmt.Errorf("failed to get userinfo: %w", err)
	}

	return userinfo, nil
}

func (auth *AuthService) GetOAuthService(sessionId string) (OAuthServiceImpl, error) {
	session, err := auth.GetOAuthPendingSession(sessionId)

	if err != nil {
		return nil, err
	}

	return *session.Service, nil
}

func (auth *AuthService) EndOAuthSession(sessionId string) {
	auth.oauthMutex.Lock()
	delete(auth.oauthPendingSessions, sessionId)
	auth.oauthMutex.Unlock()
}

func (auth *AuthService) CleanupOAuthSessionsRoutine() {
	auth.log.App.Debug().Msg("Starting OAuth session cleanup routine")

	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			auth.log.App.Debug().Msg("Running OAuth session cleanup")

			auth.oauthMutex.Lock()

			now := time.Now()

			for sessionId, session := range auth.oauthPendingSessions {
				if now.After(session.ExpiresAt) {
					delete(auth.oauthPendingSessions, sessionId)
				}
			}

			auth.oauthMutex.Unlock()
			auth.log.App.Debug().Msg("OAuth session cleanup completed")
		case <-auth.context.Done():
			auth.log.App.Debug().Msg("Stopping OAuth session cleanup routine")
			return
		}
	}
}

func (auth *AuthService) GetOAuthPendingSession(sessionId string) (*OAuthPendingSession, error) {
	auth.ensureOAuthSessionLimit()

	auth.oauthMutex.RLock()
	session, exists := auth.oauthPendingSessions[sessionId]
	auth.oauthMutex.RUnlock()

	if !exists {
		return &OAuthPendingSession{}, fmt.Errorf("oauth session not found: %s", sessionId)
	}

	if time.Now().After(session.ExpiresAt) {
		auth.oauthMutex.Lock()
		delete(auth.oauthPendingSessions, sessionId)
		auth.oauthMutex.Unlock()
		return &OAuthPendingSession{}, fmt.Errorf("oauth session expired: %s", sessionId)
	}

	return session, nil
}

func (auth *AuthService) ensureOAuthSessionLimit() {
	auth.oauthMutex.Lock()
	defer auth.oauthMutex.Unlock()

	if len(auth.oauthPendingSessions) <= MaxOAuthPendingSessions {
		return
	}

	type entry struct {
		id        string
		expiresAt int64
	}

	entries := make([]entry, 0, len(auth.oauthPendingSessions))
	for id, session := range auth.oauthPendingSessions {
		entries = append(entries, entry{id, session.ExpiresAt.Unix()})
	}

	slices.SortFunc(entries, func(a, b entry) int {
		if a.expiresAt < b.expiresAt {
			return -1
		}
		if a.expiresAt > b.expiresAt {
			return 1
		}
		return 0
	})

	for _, e := range entries[:OAuthCleanupCount] {
		delete(auth.oauthPendingSessions, e.id)
	}
}

func (auth *AuthService) lockdownMode() {
	ctx, cancel := context.WithCancel(context.Background())

	auth.loginMutex.Lock()

	if auth.lockdown != nil && auth.lockdown.Active {
		auth.loginMutex.Unlock()
		cancel()
		return
	}

	auth.lockdownCtx = ctx
	auth.lockdownCancelFunc = cancel

	auth.log.App.Warn().Msg("Too many failed login attempts, entering lockdown mode")

	auth.lockdown = &Lockdown{
		Active:      true,
		ActiveUntil: time.Now().Add(time.Duration(auth.config.Auth.LoginTimeout) * time.Second),
	}

	// At this point all login attemps will also expire so,
	// we might as well clear them to free up memory
	auth.loginAttempts = make(map[string]*LoginAttempt)

	timer := time.NewTimer(time.Until(auth.lockdown.ActiveUntil))

	auth.loginMutex.Unlock()

	defer cancel()
	defer timer.Stop()

	select {
	case <-timer.C:
		// Timer expired, end lockdown
	case <-ctx.Done():
		// Context cancelled, end lockdown
	case <-auth.context.Done():
		// Service is shutting down, end lockdown
	}

	auth.loginMutex.Lock()

	auth.log.App.Info().Msg("Exiting lockdown mode")

	auth.lockdown = nil
	auth.loginMutex.Unlock()
}

// Function only used for testing - do not use in prod!
func (auth *AuthService) ClearRateLimitsTestingOnly() {
	auth.loginMutex.Lock()
	auth.loginAttempts = make(map[string]*LoginAttempt)
	if auth.lockdown != nil {
		auth.lockdownCancelFunc()
	}
	auth.loginMutex.Unlock()
}
