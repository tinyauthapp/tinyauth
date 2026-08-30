package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/cache"
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
	Service        IOAuthService
	ExpiresAt      time.Time
	CallbackParams OAuthCallbackParams
}

type LoginAttempt struct {
	FailedAttempts int
	LastAttempt    time.Time
	LockedUntil    time.Time
}

// LogoutRequest contains the session and redirect information needed to end a
// local session and optionally cascade logout to its OAuth provider.
type LogoutRequest struct {
	SessionID           string
	UserContext         *model.UserContext
	ClientIP            string
	RedirectURI         string
	ProviderCallbackURL string
	ProviderState       string
}

// LogoutResponse contains the local session cookie and the next browser
// location selected by the logout flow.
type LogoutResponse struct {
	Cookie         *http.Cookie
	RedirectURL    string
	ProviderLogout bool
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

	dummyHash string

	caches struct {
		login          *cache.CacheStore[LoginAttempt]
		oauth          *cache.CacheStore[OAuthPendingSession]
		ldap           *cache.CacheStore[[]string]
		logoutCallback *cache.CacheStore[string]
	}
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

func NewAuthService(i AuthServiceInput) (*AuthService, error) {
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

	// dummy hash
	dummyHash, err := bcrypt.GenerateFromPassword([]byte(utils.GenerateString(8)), bcrypt.DefaultCost)

	if err != nil {
		return nil, fmt.Errorf("failed to generate dummy hash: %w", err)
	}

	service.dummyHash = string(dummyHash)

	// caches setup
	oauthCache := cache.NewCacheStore[OAuthPendingSession](256)
	loginCache := cache.NewCacheStore[LoginAttempt](service.calculateLockdownLimit())
	ldapCache := cache.NewCacheStore[[]string](1024)
	logoutCallbackCache := cache.NewCacheStore[string](256)

	service.caches.oauth = oauthCache
	service.caches.login = loginCache
	service.caches.ldap = ldapCache
	service.caches.logoutCallback = logoutCallbackCache

	i.Ding.Go(func(ctx context.Context) {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				service.caches.oauth.Sweep()
				service.caches.login.Sweep()
				service.caches.ldap.Sweep()
				service.caches.logoutCallback.Sweep()
			case <-ctx.Done():
				return
			}
		}
	}, ding.RingMinor)

	i.Ding.Go(func(ctx context.Context) {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				service.log.App.Debug().Msg("Updating login cache limits")
				service.caches.login.SetMaxSize(service.calculateLockdownLimit())
				service.log.App.Debug().Msg("Login cache limits updated")
			case <-ctx.Done():
				return
			}
		}

	}, ding.RingMinor)

	return service, nil
}

func (auth *AuthService) DummyPasswordCheck(password string) {
	bcrypt.CompareHashAndPassword([]byte(auth.dummyHash), []byte(password))
}

func (auth *AuthService) SearchUser(username string) (*model.UserSearch, error) {
	if auth.GetLocalUser(username) != nil {
		return &model.UserSearch{
			Username: username,
			Type:     model.UserLocal,
		}, nil
	}

	if auth.ldap != nil {
		userDN, email, cn, err := auth.ldap.GetUserInfo(username)

		if err != nil {
			return nil, fmt.Errorf("failed to get ldap user: %w", err)
		}

		return &model.UserSearch{
			Username: userDN,
			Email:    email,
			Name:     cn,
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

	auth.caches.login.WithLock(func(actions cache.CacheStoreActions[LoginAttempt]) {
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

	u, err := uuid.NewRandom()

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
		UUID:         u.String(),
		Username:     data.Username,
		Email:        data.Email,
		Name:         data.Name,
		Provider:     data.Provider,
		TotpPending:  data.TotpPending,
		OAuthGroups:  data.OAuthGroups,
		Expiry:       expiresAt.Unix(),
		CreatedAt:    time.Now().Unix(),
		OAuthName:    data.OAuthName,
		OAuthSub:     data.OAuthSub,
		OAuthIDToken: data.OAuthIDToken,
	}

	_, err = auth.queries.CreateSession(ctx, session)

	if err != nil {
		return nil, fmt.Errorf("failed to create session entry: %w", err)
	}

	return &http.Cookie{
		Name:     auth.runtime.SessionCookieName,
		Value:    session.UUID,
		Path:     "/",
		Domain:   auth.getCookieDomain(),
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
		Username:     session.Username,
		Email:        session.Email,
		Name:         session.Name,
		Provider:     session.Provider,
		TotpPending:  session.TotpPending,
		OAuthGroups:  session.OAuthGroups,
		Expiry:       newExpiry,
		OAuthName:    session.OAuthName,
		OAuthSub:     session.OAuthSub,
		OAuthIDToken: session.OAuthIDToken,
		UUID:         session.UUID,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to update session expiry: %w", err)
	}

	return &http.Cookie{
		Name:     auth.runtime.SessionCookieName,
		Value:    session.UUID,
		Path:     "/",
		Domain:   auth.getCookieDomain(),
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
		Domain:   auth.getCookieDomain(),
		Expires:  time.Now(),
		MaxAge:   -1,
		Secure:   auth.config.Auth.SecureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// Logout deletes the local session and compiles an upstream provider logout
// request when the session originated from a configured OAuth provider.
func (auth *AuthService) Logout(ctx context.Context, req LogoutRequest) (*LogoutResponse, error) {
	providerID := ""
	idToken := ""
	if req.UserContext != nil && req.UserContext.IsOAuth() {
		providerID = req.UserContext.OAuth.ID
		idToken = req.UserContext.OAuth.IDToken
	}

	response := &LogoutResponse{
		RedirectURL: req.RedirectURI,
	}
	if req.SessionID != "" {
		cookie, err := auth.DeleteSession(ctx, req.SessionID)
		if err != nil {
			return nil, err
		}
		response.Cookie = cookie

		if req.UserContext != nil {
			auth.log.AuditLogout(req.UserContext.GetUsername(), req.UserContext.GetProviderID(), req.ClientIP)
		} else {
			auth.log.App.Warn().Msg("Failed to get user context during logout, logging audit with unknown user")
			auth.log.AuditLogout("unknown", "unknown", req.ClientIP)
		}
	} else {
		auth.log.App.Warn().Msg("Logout attempt without session cookie, treating as successful logout")
	}

	provider, ok := auth.runtime.OAuthProviders[providerID]
	if !ok || provider.LogoutURL == "" {
		return response, nil
	}

	logoutURL, err := buildOAuthLogoutURL(
		provider,
		req.ProviderCallbackURL,
		idToken,
		req.ProviderState,
	)
	if err != nil {
		auth.log.App.Warn().Err(err).Str("provider", providerID).Msg("Invalid OAuth logout URL, skipping provider logout")
		return response, nil
	}

	response.RedirectURL = logoutURL
	response.ProviderLogout = true
	return response, nil
}

// CreateLogoutCallbackTicket stores a previously validated redirect URI under
// an opaque, short-lived identifier for the upstream provider callback.
func (auth *AuthService) CreateLogoutCallbackTicket(redirectURI string) string {
	ticket := utils.GenerateString(32)
	auth.caches.logoutCallback.Set(ticket, redirectURI, 10*time.Minute)
	return ticket
}

// ConsumeLogoutCallbackTicket returns and removes a redirect URI associated
// with an opaque callback ticket.
func (auth *AuthService) ConsumeLogoutCallbackTicket(ticket string) (string, bool) {
	redirectURI := ""
	found := false
	auth.caches.logoutCallback.WithLock(func(actions cache.CacheStoreActions[string]) {
		redirectURI, found = actions.Get(ticket)
		if found {
			actions.Delete(ticket)
		}
	})
	return redirectURI, found
}

func buildOAuthLogoutURL(provider model.OAuthServiceConfig, callbackURL, idToken, state string) (string, error) {
	logoutURL, err := url.Parse(provider.LogoutURL)
	if err != nil || logoutURL.Host == "" {
		return "", fmt.Errorf("invalid logout URL")
	}
	if logoutURL.Scheme != "https" {
		return "", fmt.Errorf("unsupported logout URL scheme")
	}

	query := logoutURL.Query()
	if provider.ClientID != "" {
		query.Set("client_id", provider.ClientID)
	}
	if idToken != "" {
		query.Set("id_token_hint", idToken)
	}
	query.Set("post_logout_redirect_uri", callbackURL)
	if state != "" {
		query.Set("state", state)
	}
	logoutURL.RawQuery = query.Encode()

	return logoutURL.String(), nil
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
		Service:        service,
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

	return session.Service.GetAuthURL(session.State, session.Verifier), nil
}

func (auth *AuthService) GetOAuthToken(sessionId string, code string) (*oauth2.Token, error) {
	session, ok := auth.caches.oauth.Get(sessionId)

	if !ok {
		return nil, fmt.Errorf("oauth session not found: %s", sessionId)
	}

	token, err := session.Service.GetToken(code, session.Verifier)

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

	userinfo, err := session.Service.GetUserinfo(session.Token)

	if err != nil {
		return nil, fmt.Errorf("failed to get userinfo: %w", err)
	}

	return userinfo, nil
}

func (auth *AuthService) GetOAuthService(sessionId string) (IOAuthService, error) {
	session, err := auth.GetOAuthPendingSession(sessionId)

	if err != nil {
		return nil, err
	}

	return session.Service, nil
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

// ClearLoginAttempts is a testing function, not useful for anything else
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

func (auth *AuthService) getCookieDomain() string {
	if !auth.config.Auth.SubdomainsEnabled {
		return ""
	}
	return auth.runtime.CookieDomain
}
