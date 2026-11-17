package controller

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/cache"
	"go.uber.org/dig"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TotpRequest struct {
	Code string `json:"code"`
}

type UserController struct {
	log      *logger.Logger
	runtime  *model.RuntimeConfig
	auth     *service.AuthService
	identity *service.IdentityService
	sessions *service.SessionsService
}

type UserControllerInput struct {
	dig.In

	Log           *logger.Logger
	RuntimeConfig *model.RuntimeConfig
	RouterGroup   *gin.RouterGroup `name:"apiRouterGroup"`
	AuthService   *service.AuthService
	Identity      *service.IdentityService
	Sessions      *service.SessionsService
}

func NewUserController(i UserControllerInput) *UserController {
	controller := &UserController{
		log:      i.Log,
		runtime:  i.RuntimeConfig,
		auth:     i.AuthService,
		identity: i.Identity,
		sessions: i.Sessions,
	}

	userGroup := i.RouterGroup.Group("/user")
	userGroup.POST("/login", controller.loginHandler)
	userGroup.POST("/logout", controller.logoutHandler)
	userGroup.POST("/totp", controller.totpHandler)
	userGroup.POST("/tailscale", controller.tailscaleHandler)

	return controller
}

func (controller *UserController) loginHandler(c *gin.Context) {
	var req LoginRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to bind JSON")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	controller.log.App.Debug().Str("username", req.Username).Msg("Login attempt")

	var search *model.UserSearch

	err = controller.auth.WithLoginAttempt(req.Username, func(actions cache.CacheStoreActions[service.LoginAttempt]) error {
		search, err = controller.auth.SearchUser(req.Username)

		if err != nil {
			if errors.Is(err, service.ErrUserNotFound) {
				controller.auth.DummyPasswordCheck(req.Password)
				controller.log.App.Warn().Str("username", req.Username).Msg("User not found during login attempt")
				controller.log.AuditLoginFailure(req.Username, "unknown", c.ClientIP(), "user not found")
				c.JSON(401, gin.H{
					"status":  401,
					"message": "Unauthorized",
				})
				return fmt.Errorf("user not found")
			}
			controller.log.App.Error().Err(err).Str("username", req.Username).Msg("Error searching for user during login attempt")
			c.JSON(500, gin.H{
				"status":  500,
				"message": "Internal Server Error",
			})
			return fmt.Errorf("error searching for user")
		}

		isLocked, remaining := controller.auth.IsAccountLocked(req.Username, actions)

		if isLocked {
			controller.log.App.Warn().Str("username", req.Username).Msg("Account is locked due to too many failed login attempts")
			controller.log.AuditLoginFailure(req.Username, search.Type.String(), c.ClientIP(), "account locked")
			c.Writer.Header().Add("x-tinyauth-lock-locked", "true")
			c.Writer.Header().Add("x-tinyauth-lock-reset", time.Now().Add(time.Duration(remaining)*time.Second).Format(time.RFC3339))
			c.JSON(429, gin.H{
				"status":  429,
				"message": fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", remaining),
			})
			return fmt.Errorf("account locked")
		}

		if err = controller.auth.CheckUserPassword(*search, req.Password); err != nil {
			controller.log.App.Warn().Str("username", req.Username).Msg("Invalid password during login attempt")
			controller.auth.RecordLoginAttempt(req.Username, false, actions)
			controller.log.AuditLoginFailure(req.Username, search.Type.String(), c.ClientIP(), "invalid password")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return fmt.Errorf("invalid password")
		}

		return nil
	})

	if err != nil {
		return
	}

	var identityParams service.StoreIdentityParams
	var sessionContext model.SessionContext

	switch search.Type {
	case model.UserLocal:
		user := controller.auth.GetLocalUser(search.Username)

		if user == nil {
			controller.log.App.Error().Str("username", search.Username).Msg("Local user not found after successful password verification")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		if user.TOTPSecret != "" {
			sessionContext.Local.TOTPPending = true
		}

		name := utils.Capitalize(user.Username)
		if user.Attributes.Name != "" {
			name = user.Attributes.Name
		}

		email := utils.CompileUserEmail(user.Username, controller.runtime.CookieDomain)
		if user.Attributes.Email != "" {
			email = user.Attributes.Email
		}

		identityParams = service.StoreIdentityParams{
			Username:       user.Username,
			Email:          email,
			Name:           name,
			ProviderID:     "local",
			ProviderType:   model.ProviderLocal,
			ProviderUserID: "local:" + user.Username,
			IdentityContext: model.IdentityContext{
				Local: model.IdentityLocalContext{
					Attributes: user.Attributes,
				},
			},
		}
	case model.UserLDAP:
		user, err := controller.auth.GetLDAPUser(search.Username)

		if err != nil {
			controller.log.App.Error().Err(err).Str("username", search.Username).Msg("Error retrieving LDAP user after successful password verification")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		if user == nil {
			controller.log.App.Error().Str("username", search.Username).Msg("LDAP user not found after successful password verification")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		identityParams = service.StoreIdentityParams{
			Username:       req.Username,
			Email:          search.Email,
			Name:           search.Name,
			ProviderID:     "ldap",
			ProviderType:   model.ProviderLDAP,
			ProviderUserID: user.DN,
			IdentityContext: model.IdentityContext{
				LDAP: model.IdentityLDAPContext{
					Groups: user.Groups,
				},
			},
		}
	}

	identity, err := controller.identity.Store(c, identityParams)

	if err != nil {
		controller.log.App.Error().Err(err).Str("username", req.Username).Msg("Error storing identity after successful login")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	session, err := controller.sessions.Create(c, identity.UUID, sessionContext)

	if err != nil {
		controller.log.App.Error().Err(err).Str("username", req.Username).Msg("Error creating session after successful login")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	cookie := controller.auth.CreateCookie(service.CreateCookieParams{
		Name:      controller.runtime.SessionCookieName,
		Value:     session.UUID,
		ExpiresAt: time.Unix(session.ExpiresAt, 0),
	})

	http.SetCookie(c.Writer, cookie)

	if sessionContext.Local.TOTPPending {
		controller.log.App.Info().Str("username", req.Username).Msg("Pending TOTP session created, awaiting verification")
		c.JSON(200, gin.H{
			"status":      202,
			"message":     "Pending TOTP session created, awaiting verification",
			"totpPending": true,
		})
		return
	}

	controller.log.App.Info().Str("username", req.Username).Msg("Login successful")

	controller.log.AuditLoginSuccess(req.Username, search.Type.String(), c.ClientIP())

	controller.auth.WithLoginAttempt(req.Username, func(actions cache.CacheStoreActions[service.LoginAttempt]) error {
		controller.auth.RecordLoginAttempt(req.Username, true, actions)
		return nil
	})

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}

func (controller *UserController) logoutHandler(c *gin.Context) {
	controller.log.App.Debug().Msg("Logout attempt")

	uuid, err := c.Cookie(controller.runtime.SessionCookieName)

	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			controller.log.App.Warn().Msg("Logout attempt without session cookie, treating as successful logout")
			c.JSON(200, gin.H{
				"status":  200,
				"message": "Logout successful",
			})
			return
		}
		controller.log.App.Error().Err(err).Msg("Error retrieving session cookie on logout")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	err = controller.sessions.Delete(c, uuid)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Error deleting session on logout")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	context, err := new(model.UserContext).NewFromGin(c)

	if err == nil {
		controller.log.AuditLogout(context.GetUsername(), context.GetProviderID(), c.ClientIP())
	} else {
		controller.log.App.Warn().Err(err).Msg("Failed to get user context during logout, logging audit with unknown user")
		controller.log.AuditLogout("unknown", "unknown", c.ClientIP())
	}

	cookie := controller.auth.CreateCookie(service.CreateCookieParams{
		Name:      controller.runtime.SessionCookieName,
		Value:     "",
		ExpiresAt: time.Now().Add(-time.Hour),
	})

	http.SetCookie(c.Writer, cookie)

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Logout successful",
	})
}

func (controller *UserController) totpHandler(c *gin.Context) {
	var req TotpRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to bind JSON for TOTP verification")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	uuid, err := c.Cookie(controller.runtime.SessionCookieName)

	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			controller.log.App.Warn().Msg("TOTP verification attempt without session cookie")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}
		controller.log.App.Error().Err(err).Msg("Failed to retrieve session cookie for pending TOTP session")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	context, err := new(model.UserContext).NewFromGin(c)

	if err != nil {
		if errors.Is(err, model.ErrUserContextNotFound) {
			controller.log.App.Warn().Msg("TOTP verification attempt without user context")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}
		controller.log.App.Error().Err(err).Msg("Failed to create user context from request for TOTP verification")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	if !context.TOTPPending() {
		controller.log.App.Warn().Str("username", context.GetUsername()).Msg("TOTP verification attempt without pending TOTP session")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	controller.log.App.Debug().Str("username", context.GetUsername()).Msg("TOTP verification attempt")

	var user *model.LocalUser

	err = controller.auth.WithLoginAttempt(context.GetUsername(), func(actions cache.CacheStoreActions[service.LoginAttempt]) error {
		isLocked, remaining := controller.auth.IsAccountLocked(context.GetUsername(), actions)

		if isLocked {
			controller.log.App.Warn().Str("username", context.GetUsername()).Msg("Account is locked due to too many failed TOTP attempts")
			controller.log.AuditLoginFailure(context.GetUsername(), "local", c.ClientIP(), "account locked")
			c.Writer.Header().Add("x-tinyauth-lock-locked", "true")
			c.Writer.Header().Add("x-tinyauth-lock-reset", time.Now().Add(time.Duration(remaining)*time.Second).Format(time.RFC3339))
			c.JSON(429, gin.H{
				"status":  429,
				"message": fmt.Sprintf("Too many failed TOTP attempts. Try again in %d seconds", remaining),
			})
			return fmt.Errorf("account locked")
		}

		user = controller.auth.GetLocalUser(context.GetUsername())

		if user == nil {
			controller.log.App.Error().Str("username", context.GetUsername()).Msg("Local user not found during TOTP verification")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return fmt.Errorf("local user not found")
		}

		ok := totp.Validate(req.Code, user.TOTPSecret)

		if !ok {
			controller.log.App.Warn().Str("username", context.GetUsername()).Msg("Invalid TOTP code during verification attempt")
			controller.auth.RecordLoginAttempt(context.GetUsername(), false, actions)
			controller.log.AuditLoginFailure(context.GetUsername(), "local", c.ClientIP(), "invalid TOTP code")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return fmt.Errorf("invalid TOTP code")
		}

		controller.auth.RecordLoginAttempt(context.GetUsername(), true, actions)

		return nil
	})

	if err != nil {
		return
	}

	session, err := controller.sessions.Update(c, uuid, model.SessionContext{
		Local: model.SessionLocalContext{
			TOTPPending: false,
		},
	})

	if err != nil {
		controller.log.App.Error().Err(err).Str("username", context.GetUsername()).Msg("Failed to update pending TOTP session after successful verification")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	cookie := controller.auth.CreateCookie(service.CreateCookieParams{
		Name:      controller.runtime.SessionCookieName,
		Value:     session.UUID,
		ExpiresAt: time.Unix(session.ExpiresAt, 0),
	})

	http.SetCookie(c.Writer, cookie)

	controller.log.App.Info().Str("username", context.GetUsername()).Msg("TOTP verification successful, login complete")
	controller.log.AuditLoginSuccess(context.GetUsername(), "local", c.ClientIP())

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}

func (controller *UserController) tailscaleHandler(c *gin.Context) {
	context, err := new(model.UserContext).NewFromGin(c)

	if err != nil {
		if errors.Is(err, model.ErrUserContextNotFound) {
			controller.log.App.Warn().Msg("Tailscale login attempt without user context")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}
		controller.log.App.Error().Err(err).Msg("Failed to create user context from request")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	if context.Tailscale == nil {
		controller.log.App.Warn().Msg("Tailscale login attempt without Tailscale context")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	identity, err := controller.identity.Store(c, service.StoreIdentityParams{
		Username:       context.Tailscale.Username,
		Email:          context.Tailscale.Email,
		Name:           context.Tailscale.Name,
		ProviderID:     "tailscale",
		ProviderType:   model.ProviderTailscale,
		ProviderUserID: context.GetDistinctUserID(),
		IdentityContext: model.IdentityContext{
			Tailscale: model.IdentityTailscaleContext{
				NodeName: context.Tailscale.NodeName,
			},
		},
	})

	if err != nil {
		controller.log.App.Error().Err(err).Str("username", context.GetUsername()).Msg("Failed to store Tailscale identity after successful login")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	session, err := controller.sessions.Create(c, identity.UUID, model.SessionContext{})

	if err != nil {
		controller.log.App.Error().Err(err).Str("username", context.GetUsername()).Msg("Failed to create Tailscale session after successful login")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	cookie := controller.auth.CreateCookie(service.CreateCookieParams{
		Name:      controller.runtime.SessionCookieName,
		Value:     session.UUID,
		ExpiresAt: time.Unix(session.ExpiresAt, 0),
	})

	http.SetCookie(c.Writer, cookie)

	controller.log.App.Info().Str("username", context.GetUsername()).Msg("Tailscale login successful, login complete")
	controller.log.AuditLoginSuccess(context.GetUsername(), "tailscale", c.ClientIP())

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}
