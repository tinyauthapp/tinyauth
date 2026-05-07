package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"

	"slices"

	"github.com/gin-gonic/gin"
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

type AuthServiceConfig struct {
	LocalUsers         *[]model.LocalUser
	OauthWhitelist     []string
	SessionExpiry      int
	SessionMaxLifetime int
	SecureCookie       bool
	CookieDomain       string
	LoginTimeout       int
	LoginMaxRetries    int
	SessionCookieName  string
	IP                 model.IPConfig
	LDAPGroupsCacheTTL int
	SubdomainsEnabled  bool
}

type AuthService struct {
	config               AuthServiceConfig
	loginAttempts        map[string]*LoginAttempt
	ldapGroupsCache      map[string]*LdapGroupsCache
	oauthPendingSessions map[string]*OAuthPendingSession
	oauthMutex           sync.RWMutex
	loginMutex           sync.RWMutex
	ldapGroupsMutex      sync.RWMutex
	ldap                 *LdapService
	queries              *repository.Queries
	oauthBroker          *OAuthBrokerService
	lockdown             *Lockdown
	lockdownCtx          context.Context
	lockdownCancelFunc   context.CancelFunc
}

func NewAuthService(config AuthServiceConfig, ldap *LdapService, queries *repository.Queries, oauthBroker *OAuthBrokerService) *AuthService {
	return &AuthService{
		config:               config,
		loginAttempts:        make(map[string]*LoginAttempt),
		ldapGroupsCache:      make(map[string]*LdapGroupsCache),
		oauthPendingSessions: make(map[string]*OAuthPendingSession),
		ldap:                 ldap,
		queries:              queries,
		oauthBroker:          oauthBroker,
	}
}

func (auth *AuthService) Init() error {
	go auth.CleanupOAuthSessionsRoutine()
	return nil
}

func (auth *AuthService) SearchUser(username string) (*model.UserSearch, error) {
	if auth.GetLocalUser(username) != nil {
		return &model.UserSearch{
			Username: username,
			Type:     model.UserLocal,
		}, nil
	}

	if auth.ldap.IsConfigured() {
		userDN, err := auth.ldap.GetUserDN(username)

		if err != nil {
			return nil, fmt.Errorf("failed to get ldap user: %w", err)
		}

		return &model.UserSearch{
			Username: userDN,
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
		if auth.ldap.IsConfigured() {
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
	if auth.config.LocalUsers == nil {
		return nil
	}
	for _, user := range *auth.config.LocalUsers {
		if user.Username == username {
			return &user
		}
	}
	return nil
}

func (auth *AuthService) GetLDAPUser(userDN string) (*model.LDAPUser, error) {
	if !auth.ldap.IsConfigured() {
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
		Expires: time.Now().Add(time.Duration(auth.config.LDAPGroupsCacheTTL) * time.Second),
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

	if auth.config.LoginMaxRetries <= 0 || auth.config.LoginTimeout <= 0 {
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
	if auth.config.LoginMaxRetries <= 0 || auth.config.LoginTimeout <= 0 {
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

	if attempt.FailedAttempts >= auth.config.LoginMaxRetries {
		attempt.LockedUntil = time.Now().Add(time.Duration(auth.config.LoginTimeout) * time.Second)
		tlog.App.Warn().Str("identifier", identifier).Int("timeout", auth.config.LoginTimeout).Msg("Account locked due to too many failed login attempts")
	}
}

func (auth *AuthService) IsEmailWhitelisted(email string) bool {
	return utils.CheckFilter(strings.Join(auth.config.OauthWhitelist, ","), email)
}

func (auth *AuthService) CreateSession(ctx context.Context, data repository.Session) (*http.Cookie, error) {
	uuid, err := uuid.NewRandom()

	if err != nil {
		return nil, fmt.Errorf("failed to generate session uuid: %w", err)
	}

	var expiry int

	if data.TotpPending {
		expiry = 3600
	} else {
		expiry = auth.config.SessionExpiry
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

	return &http.Cookie{
		Name:     auth.config.SessionCookieName,
		Value:    session.UUID,
		Path:     "/",
		Domain:   fmt.Sprintf(".%s", auth.config.CookieDomain),
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		Secure:   auth.config.SecureCookie,
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

	if auth.config.SessionExpiry <= int(time.Hour.Seconds()) {
		refreshThreshold = int64(auth.config.SessionExpiry / 2)
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
		Name:     auth.config.SessionCookieName,
		Value:    session.UUID,
		Path:     "/",
		Domain:   fmt.Sprintf(".%s", auth.config.CookieDomain),
		Expires:  time.Now().Add(time.Duration(newExpiry-currentTime) * time.Second),
		MaxAge:   int(newExpiry - currentTime),
		Secure:   auth.config.SecureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil

}

func (auth *AuthService) DeleteSession(ctx context.Context, uuid string) (*http.Cookie, error) {
	err := auth.queries.DeleteSession(ctx, uuid)

	if err != nil {
		tlog.App.Warn().Err(err).Msg("Failed to delete session from database, proceeding to clear cookie anyway")
	}

	err = auth.queries.DeleteSession(ctx, uuid)

	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:     auth.config.SessionCookieName,
		Value:    "",
		Path:     "/",
		Domain:   fmt.Sprintf(".%s", auth.config.CookieDomain),
		Expires:  time.Now(),
		MaxAge:   -1,
		Secure:   auth.config.SecureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

func (auth *AuthService) GetSession(ctx context.Context, uuid string) (*repository.Session, error) {
	session, err := auth.queries.GetSession(ctx, uuid)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("session not found")
		}
		return nil, err
	}

	currentTime := time.Now().Unix()

	if auth.config.SessionMaxLifetime != 0 && session.CreatedAt != 0 {
		if currentTime-session.CreatedAt > int64(auth.config.SessionMaxLifetime) {
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
	return auth.config.LocalUsers != nil && len(*auth.config.LocalUsers) > 0
}

func (auth *AuthService) LDAPAuthConfigured() bool {
	return auth.ldap.IsConfigured()
}

func (auth *AuthService) IsUserAllowed(c *gin.Context, context model.UserContext, acls *model.App) bool {
	if acls == nil {
		return true
	}

	if context.Provider == model.ProviderOAuth {
		tlog.App.Debug().Msg("Checking OAuth whitelist")
		return utils.CheckFilter(acls.OAuth.Whitelist, context.OAuth.Email)
	}

	if acls.Users.Block != "" {
		tlog.App.Debug().Msg("Checking blocked users")
		if utils.CheckFilter(acls.Users.Block, context.GetUsername()) {
			return false
		}
	}

	tlog.App.Debug().Msg("Checking users")
	return utils.CheckFilter(acls.Users.Allow, context.GetUsername())
}

func (auth *AuthService) IsInOAuthGroup(c *gin.Context, context model.UserContext, acls *model.App) bool {
	if acls == nil {
		return true
	}

	if !context.IsOAuth() {
		tlog.App.Debug().Msg("User is not an OAuth user, skipping OAuth group check")
		return false
	}

	if _, ok := model.OverrideProviders[context.OAuth.ID]; ok {
		tlog.App.Debug().Msg("Provider override for OAuth groups enabled, skipping group check")
		return true
	}

	for _, userGroup := range context.OAuth.Groups {
		if utils.CheckFilter(acls.OAuth.Groups, strings.TrimSpace(userGroup)) {
			tlog.App.Trace().Str("group", userGroup).Str("required", acls.OAuth.Groups).Msg("User group matched")
			return true
		}
	}

	tlog.App.Debug().Msg("No groups matched")
	return false
}

func (auth *AuthService) IsInLDAPGroup(c *gin.Context, context model.UserContext, acls *model.App) bool {
	if acls == nil {
		return true
	}

	if !context.IsLDAP() {
		tlog.App.Debug().Msg("User is not an LDAP user, skipping LDAP group check")
		return false
	}

	for _, userGroup := range context.LDAP.Groups {
		if utils.CheckFilter(acls.LDAP.Groups, strings.TrimSpace(userGroup)) {
			tlog.App.Trace().Str("group", userGroup).Str("required", acls.LDAP.Groups).Msg("User group matched")
			return true
		}
	}

	tlog.App.Debug().Msg("No groups matched")
	return false
}

func (auth *AuthService) IsAuthEnabled(uri string, acls *model.App) (bool, error) {
	if acls == nil {
		return true, nil
	}

	// Check for block list
	if acls.Path.Block != "" {
		regex, err := regexp.Compile(acls.Path.Block)

		if err != nil {
			return true, err
		}

		if !regex.MatchString(uri) {
			return false, nil
		}
	}

	// Check for allow list
	if acls.Path.Allow != "" {
		regex, err := regexp.Compile(acls.Path.Allow)

		if err != nil {
			return true, err
		}

		if regex.MatchString(uri) {
			return false, nil
		}
	}

	return true, nil
}

func (auth *AuthService) CheckIP(ip string, acls *model.App) bool {
	if acls == nil {
		return true
	}

	// Merge the global and app IP filter
	blockedIps := append(auth.config.IP.Block, acls.IP.Block...)
	allowedIPs := append(auth.config.IP.Allow, acls.IP.Allow...)

	for _, blocked := range blockedIps {
		res, err := utils.FilterIP(blocked, ip)
		if err != nil {
			tlog.App.Warn().Err(err).Str("item", blocked).Msg("Invalid IP/CIDR in block list")
			continue
		}
		if res {
			tlog.App.Debug().Str("ip", ip).Str("item", blocked).Msg("IP is in blocked list, denying access")
			return false
		}
	}

	for _, allowed := range allowedIPs {
		res, err := utils.FilterIP(allowed, ip)
		if err != nil {
			tlog.App.Warn().Err(err).Str("item", allowed).Msg("Invalid IP/CIDR in allow list")
			continue
		}
		if res {
			tlog.App.Debug().Str("ip", ip).Str("item", allowed).Msg("IP is in allowed list, allowing access")
			return true
		}
	}

	if len(allowedIPs) > 0 {
		tlog.App.Debug().Str("ip", ip).Msg("IP not in allow list, denying access")
		return false
	}

	tlog.App.Debug().Str("ip", ip).Msg("IP not in allow or block list, allowing by default")
	return true
}

func (auth *AuthService) IsBypassedIP(ip string, acls *model.App) bool {
	if acls == nil {
		return false
	}

	for _, bypassed := range acls.IP.Bypass {
		res, err := utils.FilterIP(bypassed, ip)
		if err != nil {
			tlog.App.Warn().Err(err).Str("item", bypassed).Msg("Invalid IP/CIDR in bypass list")
			continue
		}
		if res {
			tlog.App.Debug().Str("ip", ip).Str("item", bypassed).Msg("IP is in bypass list, allowing access")
			return true
		}
	}

	tlog.App.Debug().Str("ip", ip).Msg("IP not in bypass list, continuing with authentication")
	return false
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
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		auth.oauthMutex.Lock()

		now := time.Now()

		for sessionId, session := range auth.oauthPendingSessions {
			if now.After(session.ExpiresAt) {
				delete(auth.oauthPendingSessions, sessionId)
			}
		}

		auth.oauthMutex.Unlock()
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

	if len(auth.oauthPendingSessions) >= MaxOAuthPendingSessions {

		cleanupIds := make([]string, 0, OAuthCleanupCount)

		for range OAuthCleanupCount {
			oldestId := ""
			oldestTime := int64(0)

			for id, session := range auth.oauthPendingSessions {
				if oldestTime == 0 {
					oldestId = id
					oldestTime = session.ExpiresAt.Unix()
					continue
				}
				if slices.Contains(cleanupIds, id) {
					continue
				}
				if session.ExpiresAt.Unix() < oldestTime {
					oldestId = id
					oldestTime = session.ExpiresAt.Unix()
				}
			}

			cleanupIds = append(cleanupIds, oldestId)
		}

		for _, id := range cleanupIds {
			delete(auth.oauthPendingSessions, id)
		}
	}
}

func (auth *AuthService) lockdownMode() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth.lockdownCtx = ctx
	auth.lockdownCancelFunc = cancel

	auth.loginMutex.Lock()

	tlog.App.Warn().Msg("Multiple login attempts detected, possibly DDOS attack. Activating temporary lockdown.")

	auth.lockdown = &Lockdown{
		Active:      true,
		ActiveUntil: time.Now().Add(time.Duration(auth.config.LoginTimeout) * time.Second),
	}

	// At this point all login attemps will also expire so,
	// we might as well clear them to free up memory
	auth.loginAttempts = make(map[string]*LoginAttempt)

	timer := time.NewTimer(time.Until(auth.lockdown.ActiveUntil))
	defer timer.Stop()

	auth.loginMutex.Unlock()

	select {
	case <-timer.C:
		// Timer expired, end lockdown
	case <-ctx.Done():
		// Context cancelled, end lockdown
	}

	auth.loginMutex.Lock()

	tlog.App.Info().Msg("Lockdown period ended, resuming normal operation")
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

func (auth *AuthService) getCookieDomain() string {
	if auth.config.SubdomainsEnabled {
		return "." + auth.config.CookieDomain
	}
	return auth.config.CookieDomain
}
