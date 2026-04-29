package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/repository"
	"github.com/steveiliop56/tinyauth/internal/utils"
	"github.com/steveiliop56/tinyauth/internal/utils/tlog"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
)

// hard-defaults, may make configurable in the future if needed,
// but for now these are just safety limits to prevent unbounded memory usage
const MaxOAuthPendingSessions = 256
const OAuthCleanupCount = 16
const MaxLoginAttemptRecords = 256

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
	Users              []config.User
	OauthWhitelist     []string
	SessionExpiry      int
	SessionMaxLifetime int
	SecureCookie       bool
	CookieDomain       string
	LoginTimeout       int
	LoginMaxRetries    int
	SessionCookieName  string
	IP                 config.IPConfig
	LDAPGroupsCacheTTL int
	SubdomainsEnabled  bool
}

type AuthService struct {
	config               AuthServiceConfig
	docker               *DockerService
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

func NewAuthService(config AuthServiceConfig, docker *DockerService, ldap *LdapService, queries *repository.Queries, oauthBroker *OAuthBrokerService) *AuthService {
	return &AuthService{
		config:               config,
		docker:               docker,
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

func (auth *AuthService) SearchUser(username string) config.UserSearch {
	if auth.GetLocalUser(username).Username != "" {
		return config.UserSearch{
			Username: username,
			Type:     "local",
		}
	}

	if auth.ldap.IsConfigured() {
		userDN, err := auth.ldap.GetUserDN(username)

		if err != nil {
			tlog.App.Warn().Err(err).Str("username", username).Msg("Failed to search for user in LDAP")
			return config.UserSearch{
				Type: "unknown",
			}
		}

		return config.UserSearch{
			Username: userDN,
			Type:     "ldap",
		}
	}

	return config.UserSearch{
		Type: "unknown",
	}
}

func (auth *AuthService) VerifyUser(search config.UserSearch, password string) bool {
	switch search.Type {
	case "local":
		user := auth.GetLocalUser(search.Username)
		return auth.CheckPassword(user, password)
	case "ldap":
		if auth.ldap.IsConfigured() {
			err := auth.ldap.Bind(search.Username, password)
			if err != nil {
				tlog.App.Warn().Err(err).Str("username", search.Username).Msg("Failed to bind to LDAP")
				return false
			}

			err = auth.ldap.BindService(true)
			if err != nil {
				tlog.App.Error().Err(err).Msg("Failed to rebind with service account after user authentication")
				return false
			}

			return true
		}
	default:
		tlog.App.Debug().Str("type", search.Type).Msg("Unknown user type for authentication")
		return false
	}

	tlog.App.Warn().Str("username", search.Username).Msg("User authentication failed")
	return false
}

func (auth *AuthService) GetLocalUser(username string) config.User {
	for _, user := range auth.config.Users {
		if user.Username == username {
			return user
		}
	}

	tlog.App.Warn().Str("username", username).Msg("Local user not found")
	return config.User{}
}

func (auth *AuthService) GetLdapUser(userDN string) (config.LdapUser, error) {
	if !auth.ldap.IsConfigured() {
		return config.LdapUser{}, errors.New("LDAP service not initialized")
	}

	auth.ldapGroupsMutex.RLock()
	entry, exists := auth.ldapGroupsCache[userDN]
	auth.ldapGroupsMutex.RUnlock()

	if exists && time.Now().Before(entry.Expires) {
		return config.LdapUser{
			DN:     userDN,
			Groups: entry.Groups,
		}, nil
	}

	groups, err := auth.ldap.GetUserGroups(userDN)

	if err != nil {
		return config.LdapUser{}, err
	}

	auth.ldapGroupsMutex.Lock()
	auth.ldapGroupsCache[userDN] = &LdapGroupsCache{
		Groups:  groups,
		Expires: time.Now().Add(time.Duration(auth.config.LDAPGroupsCacheTTL) * time.Second),
	}
	auth.ldapGroupsMutex.Unlock()

	return config.LdapUser{
		DN:     userDN,
		Groups: groups,
	}, nil
}

func (auth *AuthService) CheckPassword(user config.User, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) == nil
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

func (auth *AuthService) CreateSessionCookie(c *gin.Context, data *repository.Session) error {
	uuid, err := uuid.NewRandom()

	if err != nil {
		return err
	}

	var expiry int

	if data.TotpPending {
		expiry = 3600
	} else {
		expiry = auth.config.SessionExpiry
	}

	session := repository.CreateSessionParams{
		UUID:        uuid.String(),
		Username:    data.Username,
		Email:       data.Email,
		Name:        data.Name,
		Provider:    data.Provider,
		TotpPending: data.TotpPending,
		OAuthGroups: data.OAuthGroups,
		Expiry:      time.Now().Add(time.Duration(expiry) * time.Second).Unix(),
		CreatedAt:   time.Now().Unix(),
		OAuthName:   data.OAuthName,
		OAuthSub:    data.OAuthSub,
	}

	_, err = auth.queries.CreateSession(c, session)

	if err != nil {
		return err
	}

	c.SetCookie(auth.config.SessionCookieName, session.UUID, expiry, "/", auth.getCookieDomain(), auth.config.SecureCookie, true)

	return nil
}

func (auth *AuthService) RefreshSessionCookie(c *gin.Context) error {
	cookie, err := c.Cookie(auth.config.SessionCookieName)

	if err != nil {
		return err
	}

	session, err := auth.queries.GetSession(c, cookie)

	if err != nil {
		return err
	}

	currentTime := time.Now().Unix()

	var refreshThreshold int64

	if auth.config.SessionExpiry <= int(time.Hour.Seconds()) {
		refreshThreshold = int64(auth.config.SessionExpiry / 2)
	} else {
		refreshThreshold = int64(time.Hour.Seconds())
	}

	if session.Expiry-currentTime > refreshThreshold {
		return nil
	}

	newExpiry := session.Expiry + refreshThreshold

	_, err = auth.queries.UpdateSession(c, repository.UpdateSessionParams{
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
		return err
	}

	c.SetCookie(auth.config.SessionCookieName, cookie, int(newExpiry-currentTime), "/", auth.getCookieDomain(), auth.config.SecureCookie, true)
	tlog.App.Trace().Str("username", session.Username).Msg("Session cookie refreshed")

	return nil
}

func (auth *AuthService) DeleteSessionCookie(c *gin.Context) error {
	cookie, err := c.Cookie(auth.config.SessionCookieName)

	if err != nil {
		return err
	}

	err = auth.queries.DeleteSession(c, cookie)

	if err != nil {
		return err
	}

	c.SetCookie(auth.config.SessionCookieName, "", -1, "/", auth.getCookieDomain(), auth.config.SecureCookie, true)

	return nil
}

func (auth *AuthService) GetSessionCookie(c *gin.Context) (repository.Session, error) {
	cookie, err := c.Cookie(auth.config.SessionCookieName)

	if err != nil {
		return repository.Session{}, err
	}

	session, err := auth.queries.GetSession(c, cookie)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return repository.Session{}, fmt.Errorf("session not found")
		}
		return repository.Session{}, err
	}

	currentTime := time.Now().Unix()

	if auth.config.SessionMaxLifetime != 0 && session.CreatedAt != 0 {
		if currentTime-session.CreatedAt > int64(auth.config.SessionMaxLifetime) {
			err = auth.queries.DeleteSession(c, cookie)
			if err != nil {
				tlog.App.Error().Err(err).Msg("Failed to delete session exceeding max lifetime")
			}
			return repository.Session{}, fmt.Errorf("session expired due to max lifetime exceeded")
		}
	}

	if currentTime > session.Expiry {
		err = auth.queries.DeleteSession(c, cookie)
		if err != nil {
			tlog.App.Error().Err(err).Msg("Failed to delete expired session")
		}
		return repository.Session{}, fmt.Errorf("session expired")
	}

	return repository.Session{
		UUID:        session.UUID,
		Username:    session.Username,
		Email:       session.Email,
		Name:        session.Name,
		Provider:    session.Provider,
		TotpPending: session.TotpPending,
		OAuthGroups: session.OAuthGroups,
		OAuthName:   session.OAuthName,
		OAuthSub:    session.OAuthSub,
	}, nil
}

func (auth *AuthService) LocalAuthConfigured() bool {
	return len(auth.config.Users) > 0
}

func (auth *AuthService) LdapAuthConfigured() bool {
	return auth.ldap.IsConfigured()
}

func (auth *AuthService) IsUserAllowed(c *gin.Context, context config.UserContext, acls config.App) bool {
	if context.OAuth {
		tlog.App.Debug().Msg("Checking OAuth whitelist")
		return utils.CheckFilter(acls.OAuth.Whitelist, context.Email)
	}

	if acls.Users.Block != "" {
		tlog.App.Debug().Msg("Checking blocked users")
		if utils.CheckFilter(acls.Users.Block, context.Username) {
			return false
		}
	}

	tlog.App.Debug().Msg("Checking users")
	return utils.CheckFilter(acls.Users.Allow, context.Username)
}

func (auth *AuthService) IsInOAuthGroup(c *gin.Context, context config.UserContext, requiredGroups string) bool {
	if requiredGroups == "" {
		return true
	}

	for id := range config.OverrideProviders {
		if context.Provider == id {
			tlog.App.Info().Str("provider", id).Msg("OAuth groups not supported for this provider")
			return true
		}
	}

	for userGroup := range strings.SplitSeq(context.OAuthGroups, ",") {
		if utils.CheckFilter(requiredGroups, strings.TrimSpace(userGroup)) {
			tlog.App.Trace().Str("group", userGroup).Str("required", requiredGroups).Msg("User group matched")
			return true
		}
	}

	tlog.App.Debug().Msg("No groups matched")
	return false
}

func (auth *AuthService) IsInLdapGroup(c *gin.Context, context config.UserContext, requiredGroups string) bool {
	if requiredGroups == "" {
		return true
	}

	for userGroup := range strings.SplitSeq(context.LdapGroups, ",") {
		if utils.CheckFilter(requiredGroups, strings.TrimSpace(userGroup)) {
			tlog.App.Trace().Str("group", userGroup).Str("required", requiredGroups).Msg("User group matched")
			return true
		}
	}

	tlog.App.Debug().Msg("No groups matched")
	return false
}

func (auth *AuthService) IsAuthEnabled(uri string, path config.AppPath) (bool, error) {
	// Check for block list
	if path.Block != "" {
		regex, err := regexp.Compile(path.Block)

		if err != nil {
			return true, err
		}

		if !regex.MatchString(uri) {
			return false, nil
		}
	}

	// Check for allow list
	if path.Allow != "" {
		regex, err := regexp.Compile(path.Allow)

		if err != nil {
			return true, err
		}

		if regex.MatchString(uri) {
			return false, nil
		}
	}

	return true, nil
}

func (auth *AuthService) GetBasicAuth(c *gin.Context) *config.User {
	username, password, ok := c.Request.BasicAuth()
	if !ok {
		tlog.App.Debug().Msg("No basic auth provided")
		return nil
	}
	return &config.User{
		Username: username,
		Password: password,
	}
}

func (auth *AuthService) CheckIP(acls config.AppIP, ip string) bool {
	// Merge the global and app IP filter
	blockedIps := append(auth.config.IP.Block, acls.Block...)
	allowedIPs := append(auth.config.IP.Allow, acls.Allow...)

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

func (auth *AuthService) IsBypassedIP(acls config.AppIP, ip string) bool {
	for _, bypassed := range acls.Bypass {
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

func (auth *AuthService) GetOAuthUserinfo(sessionId string) (config.Claims, error) {
	session, err := auth.GetOAuthPendingSession(sessionId)

	if err != nil {
		return config.Claims{}, err
	}

	if session.Token == nil {
		return config.Claims{}, fmt.Errorf("oauth token not found for session: %s", sessionId)
	}

	userinfo, err := (*session.Service).GetUserinfo(session.Token)

	if err != nil {
		return config.Claims{}, fmt.Errorf("failed to get userinfo: %w", err)
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
