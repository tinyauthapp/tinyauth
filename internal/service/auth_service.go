package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"go.uber.org/dig"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

// hard-defaults, may make configurable in the future if needed,
// but for now these are just safety limits to prevent unbounded memory usage
const MaxOAuthPendingSessions = 256
const OAuthCleanupCount = 16

var (
	ErrUserNotFound = errors.New("user not found")
)

// We either store params for redirecting to an app after OAuth login,
// or for redirecting back to the authorize screen to continue OIDC
type OAuthCallbackParams struct {
	LoginFor    string `form:"login_for" url:"login_for"`
	OIDCTicket  string `form:"oidc_ticket" url:"oidc_ticket"`
	OIDCScope   string `form:"oidc_scope" url:"oidc_scope"`
	OIDCName    string `form:"oidc_name" url:"oidc_name"`
	RedirectURI string `form:"redirect_uri" url:"redirect_uri"`
}

type OAuthPendingSession struct {
	State          string
	Verifier       string
	Token          *oauth2.Token
	Service        *OAuthServiceImpl
	ExpiresAt      time.Time
	CallbackParams OAuthCallbackParams
}

type LoginAttempt struct {
	FailedAttempts int
	LastAttempt    time.Time
	LockedUntil    time.Time
}

type AuthService struct {
	log     *logger.Logger
	config  *model.Config
	runtime *model.RuntimeConfig
	ctx     context.Context

	ldap         *LdapService
	queries      repository.Store
	oauthBroker  *OAuthBrokerService
	tailscale    *TailscaleService
	policyEngine *PolicyEngine

	lockdown struct {
		active     bool
		until      time.Time
		ctx        context.Context
		cancelFunc context.CancelFunc
		mu         sync.RWMutex
	}

	caches struct {
		login *CacheStore[LoginAttempt]
		oauth *CacheStore[OAuthPendingSession]
		ldap  *CacheStore[[]string]
	}

	maxLoginLimits int
}

type AuthServiceInput struct {
	dig.In

	Log          *logger.Logger
	Config       *model.Config
	Runtime      *model.RuntimeConfig
	Ctx          context.Context
	Ding         *ding.Ding
	LDAP         *LdapService `optional:"true"`
	Queries      repository.Store
	OAuthBroker  *OAuthBrokerService
	Tailscale    *TailscaleService `optional:"true"`
	PolicyEngine *PolicyEngine
}

func NewAuthService(i AuthServiceInput) *AuthService {
	service := &AuthService{
		log:          i.Log,
		runtime:      i.Runtime,
		ctx:          i.Ctx,
		config:       i.Config,
		ldap:         i.LDAP,
		queries:      i.Queries,
		oauthBroker:  i.OAuthBroker,
		tailscale:    i.Tailscale,
		policyEngine: i.PolicyEngine,
	}

	// get the max login limits based on the number of users and the configured max retries
	service.maxLoginLimits = service.calculateLockdownLimit()

	loginCacheSize := 0

	if !service.config.Auth.LockdownEnabled {
		loginCacheSize = service.maxLoginLimits
	}

	// caches setup
	oauthCache := NewCacheStore[OAuthPendingSession](256)
	loginCache := NewCacheStore[LoginAttempt](loginCacheSize)
	ldapCache := NewCacheStore[[]string](1024)

	service.caches.oauth = oauthCache
	service.caches.login = loginCache
	service.caches.ldap = ldapCache

	i.Ding.Go(func(ctx context.Context) {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				service.caches.oauth.Sweep()
				service.caches.login.Sweep()
				service.caches.ldap.Sweep()
			case <-ctx.Done():
				return
			}
		}
	}, ding.RingMinor)

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

	entry, exists := auth.caches.ldap.Get(userDN)

	if exists {
		return &model.LDAPUser{
			DN:     userDN,
			Groups: entry,
		}, nil
	}

	groups, err := auth.ldap.GetUserGroups(userDN)

	if err != nil {
		return nil, fmt.Errorf("failed to get ldap groups: %w", err)
	}

	auth.caches.ldap.Set(userDN, groups, time.Duration(auth.config.LDAP.GroupCacheTTL)*time.Second)

	return &model.LDAPUser{
		DN:     userDN,
		Groups: groups,
	}, nil
}

func (auth *AuthService) IsAccountLocked(identifier string) (bool, int) {
	if locked, remaining := auth.IsInLockdown(); locked {
		return true, remaining
	}

	if auth.config.Auth.LoginMaxRetries <= 0 || auth.config.Auth.LoginTimeout <= 0 {
		return false, 0
	}

	attempt, exists := auth.caches.login.Get(identifier)
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

	if !success && auth.config.Auth.LockdownEnabled && auth.caches.login.Size() >= auth.maxLoginLimits {
		if locked, _ := auth.IsInLockdown(); locked {
			return
		}
		go auth.lockdownMode()
		return
	}

	auth.caches.login.WithLock(func(actions CacheStoreActions[LoginAttempt]) {
		entry, ok := actions.Get(identifier)

		if !ok {
			attempt := LoginAttempt{
				LastAttempt: time.Now(),
			}
			if !success {
				attempt.FailedAttempts = 1
				if attempt.FailedAttempts >= auth.config.Auth.LoginMaxRetries {
					attempt.LockedUntil = time.Now().Add(time.Duration(auth.config.Auth.LoginTimeout) * time.Second)
					auth.log.App.Warn().Str("identifier", identifier).Int("failedAttempts", attempt.FailedAttempts).Msg("Account locked due to too many failed login attempts")
				}
			}
			// match current tinyauth behavior which doesn't expire rate limits
			actions.Set(identifier, attempt, 0)
			return
		}

		entry.LastAttempt = time.Now()

		if success {
			entry.FailedAttempts = 0
			entry.LockedUntil = time.Time{}
		} else {
			entry.FailedAttempts++

			if entry.FailedAttempts >= auth.config.Auth.LoginMaxRetries {
				entry.LockedUntil = time.Now().Add(time.Duration(auth.config.Auth.LoginTimeout) * time.Second)
				auth.log.App.Warn().Str("identifier", identifier).Int("failedAttempts", entry.FailedAttempts).Msg("Account locked due to too many failed login attempts")
			}
		}

		actions.Set(identifier, entry, 0)
	})
}

// We could also directly access the policyEngine.effectToAccess but
// I believe it's better to use the exported functions instead
func (auth *AuthService) IsEmailWhitelisted(provider string, email string) bool {
	return auth.policyEngine.EvaluateFunc(func() Effect {
		whitelist := auth.runtime.OAuthWhitelist
		if providerConfig, ok := auth.runtime.OAuthProviders[provider]; ok && len(providerConfig.Whitelist) > 0 {
			whitelist = providerConfig.Whitelist
		}
		match, err := utils.CheckFilter(strings.Join(whitelist, ","), email)
		if err != nil {
			if err == utils.ErrFilterEmpty {
				return EffectAbstain
			}
			auth.log.App.Error().Err(err).Str("email", email).Msg("Failed to evaluate email whitelist filter, defaulting to deny")
			return EffectDeny
		}
		if match {
			return EffectAllow
		}
		return EffectDeny
	})
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

func (auth *AuthService) NewOAuthSession(serviceName string, params OAuthCallbackParams) (string, error) {
	service, ok := auth.oauthBroker.GetService(serviceName)

	if !ok {
		return "", fmt.Errorf("oauth service not found: %s", serviceName)
	}

	sessionId, err := uuid.NewRandom()

	if err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
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

	auth.caches.oauth.Set(sessionId.String(), session, time.Minute*10)

	return sessionId.String(), nil
}

func (auth *AuthService) GetOAuthURL(sessionId string) (string, error) {
	session, err := auth.GetOAuthPendingSession(sessionId)

	if err != nil {
		return "", err
	}

	return (*session.Service).GetAuthURL(session.State, session.Verifier), nil
}

func (auth *AuthService) GetOAuthToken(sessionId string, code string) (*oauth2.Token, error) {
	session, ok := auth.caches.oauth.Get(sessionId)

	if !ok {
		return nil, fmt.Errorf("oauth session not found: %s", sessionId)
	}

	token, err := (*session.Service).GetToken(code, session.Verifier)

	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	session.Token = token

	// ttl 0 means keep current expiration
	ok = auth.caches.oauth.Update(sessionId, session, 0)

	if !ok {
		return nil, fmt.Errorf("failed to update oauth session with token: %s", sessionId)
	}

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
	auth.caches.oauth.Delete(sessionId)
}

func (auth *AuthService) GetOAuthPendingSession(sessionId string) (*OAuthPendingSession, error) {
	session, exists := auth.caches.oauth.Get(sessionId)

	if !exists {
		return &OAuthPendingSession{}, fmt.Errorf("oauth session not found: %s", sessionId)
	}

	return &session, nil
}

func (auth *AuthService) lockdownMode() {
	defer func() {
		if r := recover(); r != nil {
			auth.log.App.Error().Interface("panic", r).Msg("Recovered from panic in lockdownMode")
		}
	}()

	auth.lockdown.mu.Lock()

	if auth.lockdown.active {
		auth.lockdown.mu.Unlock()
		return
	}

	ctx, cancel := context.WithCancel(auth.ctx)

	auth.log.App.Warn().Msg("Too many failed login attempts, entering lockdown mode")

	auth.lockdown.active = true
	auth.lockdown.ctx = ctx
	auth.lockdown.cancelFunc = cancel

	d := time.Duration(auth.config.Auth.LoginTimeout) * time.Second
	auth.lockdown.until = time.Now().Add(d)
	timer := time.NewTimer(d)

	auth.lockdown.mu.Unlock()

	defer cancel()
	defer timer.Stop()

	select {
	case <-timer.C:
		// Timer expired, end lockdown
	case <-ctx.Done():
		// Context cancelled, end lockdown
	}

	auth.lockdown.mu.Lock()

	auth.log.App.Info().Msg("Exiting lockdown mode")

	auth.caches.login.Clear()
	auth.lockdown.active = false
	auth.lockdown.until = time.Time{}
	auth.lockdown.ctx = nil
	auth.lockdown.cancelFunc = nil

	auth.lockdown.mu.Unlock()
}

func (auth *AuthService) IsInLockdown() (bool, int) {
	auth.lockdown.mu.RLock()
	defer auth.lockdown.mu.RUnlock()
	if auth.lockdown.active {
		remaining := int(time.Until(auth.lockdown.until).Seconds())
		return true, remaining
	}
	return false, 0
}

// mostly a testing function, not useful for anything else
func (auth *AuthService) ClearLoginAttempts() {
	auth.caches.login.Clear()
}

func (auth *AuthService) calculateLockdownLimit() int {
	userCount := len(auth.runtime.LocalUsers)

	if auth.ldap != nil {
		ldapUsers, err := auth.ldap.GetUserCount()
		if err != nil {
			auth.log.App.Warn().Err(err).Msg("Failed to get LDAP user count")
		} else {
			userCount += ldapUsers
		}
	}

	limit := userCount * auth.config.Auth.LoginMaxRetries

	jitter, err := rand.Int(rand.Reader, big.NewInt(64))

	if err != nil {
		auth.log.App.Warn().Err(err).Msg("Failed to generate jitter for lockdown limit")
	} else {
		limit += int(jitter.Int64())
	}

	if limit < 256 {
		limit = 256
	}

	return limit
}
