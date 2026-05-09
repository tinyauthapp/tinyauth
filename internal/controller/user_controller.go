package controller

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"

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
	log     *logger.Logger
	runtime model.RuntimeConfig
	auth    *service.AuthService
}

func NewUserController(
	log *logger.Logger,
	runtimeConfig model.RuntimeConfig,
	router *gin.RouterGroup,
	auth *service.AuthService,
) *UserController {
	controller := &UserController{
		log:     log,
		runtime: runtimeConfig,
		auth:    auth,
	}

	userGroup := router.Group("/user")
	userGroup.POST("/login", controller.loginHandler)
	userGroup.POST("/logout", controller.logoutHandler)
	userGroup.POST("/totp", controller.totpHandler)

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

	isLocked, remaining := controller.auth.IsAccountLocked(req.Username)

	if isLocked {
		controller.log.App.Warn().Str("username", req.Username).Msg("Account is locked due to too many failed login attempts")
		controller.log.AuditLoginFailure(req.Username, "local", c.ClientIP(), "account locked")
		c.Writer.Header().Add("x-tinyauth-lock-locked", "true")
		c.Writer.Header().Add("x-tinyauth-lock-reset", time.Now().Add(time.Duration(remaining)*time.Second).Format(time.RFC3339))
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", remaining),
		})
		return
	}

	search, err := controller.auth.SearchUser(req.Username)

	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			controller.log.App.Warn().Str("username", req.Username).Msg("User not found during login attempt")
			controller.auth.RecordLoginAttempt(req.Username, false)
			controller.log.AuditLoginFailure(req.Username, "unknown", c.ClientIP(), "user not found")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}
		controller.log.App.Error().Err(err).Str("username", req.Username).Msg("Error searching for user during login attempt")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	if err := controller.auth.CheckUserPassword(*search, req.Password); err != nil {
		controller.log.App.Warn().Str("username", req.Username).Msg("Invalid password during login attempt")
		controller.auth.RecordLoginAttempt(req.Username, false)
		if search.Type == model.UserLocal {
			controller.log.AuditLoginFailure(req.Username, "local", c.ClientIP(), "invalid password")
		} else {
			controller.log.AuditLoginFailure(req.Username, "ldap", c.ClientIP(), "invalid password")
		}
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	var localUser *model.LocalUser

	if search.Type == model.UserLocal {
		localUser = controller.auth.GetLocalUser(req.Username)

		if localUser == nil {
			controller.log.App.Error().Str("username", req.Username).Msg("Local user not found after successful password verification")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		if localUser.TOTPSecret != "" {
			controller.log.App.Debug().Str("username", req.Username).Msg("TOTP required for user, creating pending TOTP session")

			name := localUser.Attributes.Name
			if name == "" {
				name = utils.Capitalize(localUser.Username)
			}

			email := localUser.Attributes.Email
			if email == "" {
				email = utils.CompileUserEmail(localUser.Username, controller.runtime.CookieDomain)
			}

			cookie, err := controller.auth.CreateSession(c, repository.Session{
				Username:    localUser.Username,
				Name:        name,
				Email:       email,
				Provider:    "local",
				TotpPending: true,
			})

			if err != nil {
				controller.log.App.Error().Err(err).Str("username", req.Username).Msg("Failed to create pending TOTP session")
				c.JSON(500, gin.H{
					"status":  500,
					"message": "Internal Server Error",
				})
				return
			}

			http.SetCookie(c.Writer, cookie)

			c.JSON(200, gin.H{
				"status":      200,
				"message":     "TOTP required",
				"totpPending": true,
			})
			return
		}
	}

	sessionCookie := repository.Session{
		Username: req.Username,
		Name:     utils.Capitalize(req.Username),
		Email:    utils.CompileUserEmail(req.Username, controller.runtime.CookieDomain),
		Provider: "local",
	}

	if search.Type == model.UserLocal {
		if localUser.Attributes.Name != "" {
			sessionCookie.Name = localUser.Attributes.Name
		}
		if localUser.Attributes.Email != "" {
			sessionCookie.Email = localUser.Attributes.Email
		}
	}

	if search.Type == model.UserLDAP {
		sessionCookie.Provider = "ldap"
	}

	cookie, err := controller.auth.CreateSession(c, sessionCookie)

	if err != nil {
		controller.log.App.Error().Err(err).Str("username", req.Username).Msg("Failed to create session cookie after successful login")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	http.SetCookie(c.Writer, cookie)

	controller.log.App.Info().Str("username", req.Username).Msg("Login successful")

	if search.Type == model.UserLocal {
		controller.log.AuditLoginSuccess(req.Username, "local", c.ClientIP())
	} else {
		controller.log.AuditLoginSuccess(req.Username, "ldap", c.ClientIP())
	}

	controller.auth.RecordLoginAttempt(req.Username, true)

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

	cookie, err := controller.auth.DeleteSession(c, uuid)

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

	context, err := new(model.UserContext).NewFromGin(c)

	if err != nil {
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

	isLocked, remaining := controller.auth.IsAccountLocked(context.GetUsername())

	if isLocked {
		controller.log.App.Warn().Str("username", context.GetUsername()).Msg("Account is locked due to too many failed TOTP attempts")
		controller.log.AuditLoginFailure(context.GetUsername(), "local", c.ClientIP(), "account locked")
		c.Writer.Header().Add("x-tinyauth-lock-locked", "true")
		c.Writer.Header().Add("x-tinyauth-lock-reset", time.Now().Add(time.Duration(remaining)*time.Second).Format(time.RFC3339))
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed TOTP attempts. Try again in %d seconds", remaining),
		})
		return
	}

	user := controller.auth.GetLocalUser(context.GetUsername())

	if user == nil {
		controller.log.App.Error().Str("username", context.GetUsername()).Msg("Local user not found during TOTP verification")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	ok := totp.Validate(req.Code, user.TOTPSecret)

	if !ok {
		controller.log.App.Warn().Str("username", context.GetUsername()).Msg("Invalid TOTP code during verification attempt")
		controller.auth.RecordLoginAttempt(context.GetUsername(), false)
		controller.log.AuditLoginFailure(context.GetUsername(), "local", c.ClientIP(), "invalid TOTP code")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	uuid, err := c.Cookie(controller.runtime.SessionCookieName)

	if err == nil {
		_, err = controller.auth.DeleteSession(c, uuid)
		if err != nil {
			controller.log.App.Error().Err(err).Msg("Failed to delete pending TOTP session after successful verification")
		}
	} else {
		controller.log.App.Warn().Err(err).Msg("Failed to retrieve session cookie for pending TOTP session, cannot delete it")
	}

	controller.auth.RecordLoginAttempt(context.GetUsername(), true)

	sessionCookie := repository.Session{
		Username: user.Username,
		Name:     utils.Capitalize(user.Username),
		Email:    utils.CompileUserEmail(user.Username, controller.runtime.CookieDomain),
		Provider: "local",
	}

	if user.Attributes.Name != "" {
		sessionCookie.Name = user.Attributes.Name
	}
	if user.Attributes.Email != "" {
		sessionCookie.Email = user.Attributes.Email
	}

	cookie, err := controller.auth.CreateSession(c, sessionCookie)

	if err != nil {
		controller.log.App.Error().Err(err).Str("username", context.GetUsername()).Msg("Failed to create session cookie after successful TOTP verification")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	http.SetCookie(c.Writer, cookie)

	controller.log.App.Info().Str("username", context.GetUsername()).Msg("TOTP verification successful, login complete")
	controller.log.AuditLoginSuccess(context.GetUsername(), "local", c.ClientIP())

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}
