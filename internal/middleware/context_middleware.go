package middleware

import (
	"strings"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/config"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"

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

type ContextMiddlewareConfig struct {
	CookieDomain string
}

type ContextMiddleware struct {
	config ContextMiddlewareConfig
	auth   *service.AuthService
	broker *service.OAuthBrokerService
}

func NewContextMiddleware(config ContextMiddlewareConfig, auth *service.AuthService, broker *service.OAuthBrokerService) *ContextMiddleware {
	return &ContextMiddleware{
		config: config,
		auth:   auth,
		broker: broker,
	}
}

func (m *ContextMiddleware) Init() error {
	return nil
}

func (m *ContextMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.isIgnorePath(c.Request.Method + " " + c.Request.URL.Path) {
			c.Next()
			return
		}

		cookie, err := m.auth.GetSessionCookie(c)

		if err != nil {
			tlog.App.Debug().Err(err).Msg("No valid session cookie found")
			goto basic
		}

		if cookie.TotpPending {
			c.Set("context", &config.UserContext{
				Username:    cookie.Username,
				Name:        cookie.Name,
				Email:       cookie.Email,
				Provider:    "local",
				TotpPending: true,
				TotpEnabled: true,
			})
			c.Next()
			return
		}

		switch cookie.Provider {
		case "local", "ldap":
			userSearch := m.auth.SearchUser(cookie.Username)

			if userSearch.Type == "unknown" {
				tlog.App.Debug().Msg("User from session cookie not found")
				m.auth.DeleteSessionCookie(c)
				goto basic
			}

			if userSearch.Type != cookie.Provider {
				tlog.App.Warn().Msg("User type from session cookie does not match user search type")
				m.auth.DeleteSessionCookie(c)
				c.Next()
				return
			}

			var ldapGroups []string
			var localAttributes config.UserAttributes

			if cookie.Provider == "ldap" {
				ldapUser, err := m.auth.GetLdapUser(userSearch.Username)

				if err != nil {
					tlog.App.Error().Err(err).Msg("Error retrieving LDAP user details")
					c.Next()
					return
				}

				ldapGroups = ldapUser.Groups
			}

			if cookie.Provider == "local" {
				localUser := m.auth.GetLocalUser(cookie.Username)
				localAttributes = localUser.Attributes
			}

			m.auth.RefreshSessionCookie(c)
			c.Set("context", &config.UserContext{
				Username:   cookie.Username,
				Name:       cookie.Name,
				Email:      cookie.Email,
				Provider:   cookie.Provider,
				IsLoggedIn: true,
				LdapGroups: strings.Join(ldapGroups, ","),
				Attributes: localAttributes,
			})
			c.Next()
			return
		default:
			_, exists := m.broker.GetService(cookie.Provider)

			if !exists {
				tlog.App.Debug().Msg("OAuth provider from session cookie not found")
				m.auth.DeleteSessionCookie(c)
				goto basic
			}

			if !m.auth.IsEmailWhitelisted(cookie.Email) {
				tlog.App.Debug().Msg("Email from session cookie not whitelisted")
				m.auth.DeleteSessionCookie(c)
				goto basic
			}

			m.auth.RefreshSessionCookie(c)
			c.Set("context", &config.UserContext{
				Username:    cookie.Username,
				Name:        cookie.Name,
				Email:       cookie.Email,
				Provider:    cookie.Provider,
				OAuthGroups: cookie.OAuthGroups,
				OAuthName:   cookie.OAuthName,
				OAuthSub:    cookie.OAuthSub,
				IsLoggedIn:  true,
				OAuth:       true,
			})
			c.Next()
			return
		}

	basic:
		basic := m.auth.GetBasicAuth(c)

		if basic == nil {
			tlog.App.Debug().Msg("No basic auth provided")
			c.Next()
			return
		}

		locked, remaining := m.auth.IsAccountLocked(basic.Username)

		if locked {
			tlog.App.Debug().Msgf("Account for user %s is locked for %d seconds, denying auth", basic.Username, remaining)
			c.Writer.Header().Add("x-tinyauth-lock-locked", "true")
			c.Writer.Header().Add("x-tinyauth-lock-reset", time.Now().Add(time.Duration(remaining)*time.Second).Format(time.RFC3339))
			c.Next()
			return
		}

		userSearch := m.auth.SearchUser(basic.Username)

		if userSearch.Type == "unknown" || userSearch.Type == "error" {
			m.auth.RecordLoginAttempt(basic.Username, false)
			tlog.App.Debug().Msg("User from basic auth not found")
			c.Next()
			return
		}

		if !m.auth.VerifyUser(userSearch, basic.Password) {
			m.auth.RecordLoginAttempt(basic.Username, false)
			tlog.App.Debug().Msg("Invalid password for basic auth user")
			c.Next()
			return
		}

		m.auth.RecordLoginAttempt(basic.Username, true)

		switch userSearch.Type {
		case "local":
			tlog.App.Debug().Msg("Basic auth user is local")

			user := m.auth.GetLocalUser(basic.Username)

			if user.TotpSecret != "" {
				tlog.App.Debug().Msg("User with TOTP not allowed to login via basic auth")
				return
			}

			name := utils.Capitalize(user.Username)
			if user.Attributes.Name != "" {
				name = user.Attributes.Name
			}
			email := utils.CompileUserEmail(user.Username, m.config.CookieDomain)
			if user.Attributes.Email != "" {
				email = user.Attributes.Email
			}

			c.Set("context", &config.UserContext{
				Username:    user.Username,
				Name:        name,
				Email:       email,
				Provider:    "local",
				IsLoggedIn:  true,
				IsBasicAuth: true,
				Attributes:  user.Attributes,
			})
			c.Next()
			return
		case "ldap":
			tlog.App.Debug().Msg("Basic auth user is LDAP")

			ldapUser, err := m.auth.GetLdapUser(basic.Username)

			if err != nil {
				tlog.App.Debug().Err(err).Msg("Error retrieving LDAP user details")
				c.Next()
				return
			}

			c.Set("context", &config.UserContext{
				Username:    basic.Username,
				Name:        utils.Capitalize(basic.Username),
				Email:       utils.CompileUserEmail(basic.Username, m.config.CookieDomain),
				Provider:    "ldap",
				IsLoggedIn:  true,
				LdapGroups:  strings.Join(ldapUser.Groups, ","),
				IsBasicAuth: true,
			})
			c.Next()
			return
		}

		c.Next()
	}
}

func (m *ContextMiddleware) isIgnorePath(path string) bool {
	for _, prefix := range contextSkipPathsPrefix {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
