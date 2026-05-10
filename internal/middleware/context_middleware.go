package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"

	"github.com/gin-gonic/gin"
)

// Gin won't let us set a middleware on a specific route (at least it doesn't work,
// see https://github.com/gin-gonic/gin/issues/531) so we have to do some hackery
var (
	contextSkipPathsPrefix = []string{
		"GET /api/context/app",
		"GET /api/healthz",
		"HEAD /api/healthz",
		"GET /api/oauth/url",
		"GET /api/oauth/callback",
		"GET /api/oidc/clients",
		"POST /api/oidc/token",
		"GET /api/oidc/userinfo",
		"POST /api/oidc/userinfo",
		"GET /resources",
		"POST /api/user/login",
		"GET /.well-known/openid-configuration",
		"GET /.well-known/jwks.json",
	}
)

type ContextMiddleware struct {
	log     *logger.Logger
	runtime model.RuntimeConfig
	auth    *service.AuthService
	broker  *service.OAuthBrokerService
}

func NewContextMiddleware(
	log *logger.Logger,
	runtime model.RuntimeConfig,
	auth *service.AuthService,
	broker *service.OAuthBrokerService,
) *ContextMiddleware {
	return &ContextMiddleware{
		log:     log,
		runtime: runtime,
		auth:    auth,
		broker:  broker,
	}
}

func (m *ContextMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.isIgnorePath(c.Request.Method + " " + c.Request.URL.Path) {
			c.Next()
			return
		}

		uuid, err := c.Cookie(m.runtime.SessionCookieName)

		if err == nil {
			userContext, cookie, err := m.cookieAuth(c.Request.Context(), uuid)

			if err == nil {
				if cookie != nil {
					http.SetCookie(c.Writer, cookie)
				}

				m.log.App.Debug().Msgf("Authenticated user %s via session cookie", userContext.GetUsername())
				c.Set("context", userContext)
				c.Next()
				return
			} else {
				m.log.App.Debug().Msgf("Error authenticating session cookie: %v", err)
			}
		}

		username, password, ok := c.Request.BasicAuth()

		if ok {
			userContext, headers, err := m.basicAuth(username, password)

			if err != nil {
				m.log.App.Error().Msgf("Error authenticating basic auth: %v", err)
				c.Next()
				return
			}

			for k, v := range headers {
				c.Header(k, v)
			}

			c.Set("context", userContext)
			c.Next()
			return
		}

		c.Next()
	}
}

func (m *ContextMiddleware) cookieAuth(ctx context.Context, uuid string) (*model.UserContext, *http.Cookie, error) {
	session, err := m.auth.GetSession(ctx, uuid)

	if err != nil {
		return nil, nil, fmt.Errorf("error retrieving session: %w", err)
	}

	userContext, err := new(model.UserContext).NewFromSession(session)

	if err != nil {
		return nil, nil, fmt.Errorf("error creating user context from session: %w", err)
	}

	if userContext.Provider == model.ProviderLocal &&
		userContext.Local.TOTPPending {
		return userContext, nil, nil
	}

	switch userContext.Provider {
	case model.ProviderLocal:
		user := m.auth.GetLocalUser(userContext.Local.Username)

		if user == nil {
			return nil, nil, fmt.Errorf("local user not found")
		}

		userContext.Local.Attributes = user.Attributes

		if userContext.Local.Attributes.Name == "" {
			userContext.Local.Attributes.Name = utils.Capitalize(user.Username)
		}

		if userContext.Local.Attributes.Email == "" {
			userContext.Local.Attributes.Email = utils.CompileUserEmail(user.Username, m.runtime.CookieDomain)
		}
	case model.ProviderLDAP:
		search, err := m.auth.SearchUser(userContext.LDAP.Username)

		if err != nil {
			return nil, nil, fmt.Errorf("error searching for ldap user: %w", err)
		}

		if search.Type != model.UserLDAP {
			return nil, nil, fmt.Errorf("user from session cookie is not ldap")
		}

		user, err := m.auth.GetLDAPUser(search.Username)

		if err != nil {
			return nil, nil, fmt.Errorf("error retrieving ldap user details: %w", err)
		}

		userContext.LDAP.Groups = user.Groups
		userContext.LDAP.Name = utils.Capitalize(userContext.LDAP.Username)

		userContext.LDAP.Email = utils.CompileUserEmail(userContext.LDAP.Username, m.runtime.CookieDomain)
		if search.Email != "" {
			userContext.LDAP.Email = search.Email
		}

	case model.ProviderOAuth:
		_, exists := m.broker.GetService(userContext.OAuth.ID)

		if !exists {
			return nil, nil, fmt.Errorf("oauth provider from session cookie not found: %s", userContext.OAuth.ID)
		}

		if !m.auth.IsEmailWhitelisted(userContext.OAuth.Email) {
			m.auth.DeleteSession(ctx, uuid)
			return nil, nil, fmt.Errorf("email from session cookie not whitelisted: %s", userContext.OAuth.Email)
		}
	}

	cookie, err := m.auth.RefreshSession(ctx, uuid)

	if err != nil {
		return nil, nil, fmt.Errorf("error refreshing session: %w", err)
	}

	return userContext, cookie, nil
}

func (m *ContextMiddleware) basicAuth(username string, password string) (*model.UserContext, map[string]string, error) {
	headers := make(map[string]string)
	userContext := new(model.UserContext)
	locked, remaining := m.auth.IsAccountLocked(username)

	if locked {
		m.log.App.Debug().Msgf("Account for user %s is locked for %d seconds, denying auth", username, remaining)
		headers["x-tinyauth-lock-locked"] = "true"
		headers["x-tinyauth-lock-reset"] = time.Now().Add(time.Duration(remaining) * time.Second).Format(time.RFC3339)
		return nil, headers, nil
	}

	search, err := m.auth.SearchUser(username)

	if err != nil {
		return nil, nil, fmt.Errorf("error searching for user: %w", err)
	}

	err = m.auth.CheckUserPassword(*search, password)

	if err != nil {
		m.auth.RecordLoginAttempt(username, false)
		return nil, nil, fmt.Errorf("invalid password for basic auth user: %w", err)
	}

	m.auth.RecordLoginAttempt(username, true)

	switch search.Type {
	case model.UserLocal:
		user := m.auth.GetLocalUser(username)

		if user.TOTPSecret != "" {
			return nil, nil, fmt.Errorf("user with totp not allowed to login via basic auth: %s", username)
		}

		userContext.Local = &model.LocalContext{
			BaseContext: model.BaseContext{
				Username: user.Username,
				Name:     utils.Capitalize(user.Username),
				Email:    utils.CompileUserEmail(user.Username, m.runtime.CookieDomain),
			},
			Attributes: user.Attributes,
		}
		userContext.Provider = model.ProviderLocal
	case model.UserLDAP:
		user, err := m.auth.GetLDAPUser(username)

		if err != nil {
			return nil, nil, fmt.Errorf("error retrieving ldap user details: %w", err)
		}

		userContext.LDAP = &model.LDAPContext{
			BaseContext: model.BaseContext{
				Username: username,
				Name:     utils.Capitalize(username),
			},
			Groups: user.Groups,
		}
		userContext.Provider = model.ProviderLDAP

		userContext.LDAP.Email = utils.CompileUserEmail(username, m.runtime.CookieDomain)
		if search.Email != "" {
			userContext.LDAP.Email = search.Email
		}
	}

	userContext.Authenticated = true
	return userContext, nil, nil
}

func (m *ContextMiddleware) isIgnorePath(path string) bool {
	for _, prefix := range contextSkipPathsPrefix {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
