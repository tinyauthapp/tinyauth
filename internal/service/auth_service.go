package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/cache"
	"go.uber.org/dig"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound = errors.New("user not found")
)

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

	dummyHash string

	caches struct {
		login *cache.CacheStore[LoginAttempt]
		ldap  *cache.CacheStore[[]string]
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
	dummyHash, err := bcrypt.GenerateFromPassword([]byte(utils.GenerateSecureString(8)), bcrypt.DefaultCost)

	if err != nil {
		return nil, fmt.Errorf("failed to generate dummy hash: %w", err)
	}

	service.dummyHash = string(dummyHash)

	// caches setup
	loginCache := cache.NewCacheStore[LoginAttempt](service.calculateLockdownLimit())
	ldapCache := cache.NewCacheStore[[]string](1024)

	service.caches.login = loginCache
	service.caches.ldap = ldapCache

	i.Ding.Go(func(ctx context.Context) {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				service.caches.login.Sweep()
				service.caches.ldap.Sweep()
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

// User management functions

func (auth *AuthService) SearchUser(username string) (*model.UserSearch, error) {
	if auth.GetLocalUser(username) != nil {
		return &model.UserSearch{
			Username: username,
			Type:     model.UserLocal,
		}, nil
	}

	if auth.ldap != nil {
		res, err := auth.ldap.GetUserInfo(username)

		if err != nil {
			if errors.Is(err, ErrLDAPMultipleUsers) || errors.Is(err, ErrLDAPNoUsers) {
				return nil, ErrUserNotFound
			}
			return nil, fmt.Errorf("failed to get ldap user: %w", err)
		}

		return &model.UserSearch{
			Username: res.DN,
			Email:    res.Email,
			Name:     res.CN,
			Type:     model.UserLDAP,
		}, nil
	}

	return nil, ErrUserNotFound
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

func (auth *AuthService) CheckUserPassword(search model.UserSearch, password string) (err error) {
	switch search.Type {
	case model.UserLocal:
		user := auth.GetLocalUser(search.Username)
		if user == nil {
			return ErrUserNotFound
		}
		return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	case model.UserLDAP:
		if auth.ldap != nil {
			defer func() {
				bindErr := auth.ldap.BindService()
				if bindErr != nil {
					if err != nil {
						err = fmt.Errorf("failed to rebind to ldap service account: %w, original error: %w", bindErr, err)
						return
					}
					err = fmt.Errorf("failed to rebind to ldap service account: %w", bindErr)
				}
			}()

			err = auth.ldap.Bind(search.Username, password)
			if err != nil {
				return fmt.Errorf("failed to bind to ldap user: %w", err)
			}

			return nil
		}
	default:
		return errors.New("unknown user search type")
	}
	return errors.New("user authentication failed")
}

func (auth *AuthService) DummyPasswordCheck(password string) {
	bcrypt.CompareHashAndPassword([]byte(auth.dummyHash), []byte(password))
}

// Account rate limiting

func (auth *AuthService) IsAccountLocked(identifier string, actions cache.CacheStoreActions[LoginAttempt]) (bool, int) {
	if !auth.rateLimitEnabled() {
		return false, 0
	}

	attempt, exists := actions.Get(identifier)
	if !exists {
		return false, 0
	}

	if attempt.LockedUntil.After(time.Now()) {
		remaining := int(time.Until(attempt.LockedUntil).Seconds())
		return true, remaining
	}

	return false, 0
}

func (auth *AuthService) RecordLoginAttempt(identifier string, success bool, actions cache.CacheStoreActions[LoginAttempt]) {
	if !auth.rateLimitEnabled() {
		return
	}

	entry, ok := actions.Get(identifier)

	if !ok {
		attempt := LoginAttempt{
			LastAttempt: time.Now(),
		}
		if !success {
			attempt.FailedAttempts = 1
			if attempt.FailedAttempts >= auth.config.Auth.LoginMaxRetries {
				attempt.LockedUntil = time.Now().Add(time.Duration(auth.config.Auth.LoginTimeout) * time.Second)
				auth.log.App.Warn().Str("identifier", identifier).Int("failed_attempts", attempt.FailedAttempts).Msg("Account locked due to too many failed login attempts")
			}
		}
		actions.Set(identifier, attempt, time.Duration(auth.config.Auth.LoginTimeout)*time.Second)
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
			auth.log.App.Warn().Str("identifier", identifier).Int("failed_attempts", entry.FailedAttempts).Msg("Account locked due to too many failed login attempts")
		}
	}

	actions.Set(identifier, entry, time.Duration(auth.config.Auth.LoginTimeout)*time.Second)
}

func (auth *AuthService) WithLoginAttempt(identifier string, f func(actions cache.CacheStoreActions[LoginAttempt]) error) error {
	var err error
	auth.caches.login.WithKeyedLock(identifier, func(actions cache.CacheStoreActions[LoginAttempt]) {
		err = f(actions)
	})
	return err
}

func (auth *AuthService) rateLimitEnabled() bool {
	return auth.config.Auth.LoginMaxRetries > 0 && auth.config.Auth.LoginTimeout > 0
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

// Cookie management

type CreateCookieParams struct {
	Name      string
	Value     string
	ExpiresAt time.Time
}

func (auth *AuthService) CreateCookie(args CreateCookieParams) *http.Cookie {
	domain := auth.runtime.CookieDomain

	if !auth.config.Auth.SubdomainsEnabled {
		domain = ""
	}

	return &http.Cookie{
		Name:     args.Name,
		Value:    args.Value,
		Path:     "/",
		Domain:   domain,
		Expires:  args.ExpiresAt,
		MaxAge:   int(time.Until(args.ExpiresAt).Seconds()),
		Secure:   auth.config.Auth.SecureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// Configured providers

func (auth *AuthService) LocalAuthConfigured() bool {
	return len(auth.runtime.LocalUsers) > 0
}

func (auth *AuthService) LDAPAuthConfigured() bool {
	return auth.ldap != nil
}

func (auth *AuthService) TailscaleAuthConfigured() bool {
	return auth.tailscale != nil
}

// OAuth management

func (auth *AuthService) IsEmailWhitelisted(provider string, email string) bool {
	return auth.policyEngine.EvaluateFunc(func() Effect {
		whitelist := auth.runtime.OAuthWhitelist

		if providerConfig, ok := auth.runtime.OAuthProviders[provider]; ok && len(providerConfig.Whitelist) > 0 {
			whitelist = providerConfig.Whitelist
		}

		match, err := utils.CheckFilter(strings.Join(whitelist, ","), email)

		if err != nil {
			if errors.Is(err, utils.ErrFilterEmpty) {
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

// Testing functions, not useful for anything else

func (auth *AuthService) ClearLoginAttempts() {
	auth.caches.login.Clear()
}
