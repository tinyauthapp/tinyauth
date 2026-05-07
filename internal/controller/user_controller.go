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
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"

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

type UserControllerConfig struct {
	CookieDomain      string
	SessionCookieName string
}

type UserController struct {
	config UserControllerConfig
	router *gin.RouterGroup
	auth   *service.AuthService
}

func NewUserController(config UserControllerConfig, router *gin.RouterGroup, auth *service.AuthService) *UserController {
	return &UserController{
		config: config,
		router: router,
		auth:   auth,
	}
}

func (controller *UserController) SetupRoutes() {
	userGroup := controller.router.Group("/user")
	userGroup.POST("/login", controller.loginHandler)
	userGroup.POST("/logout", controller.logoutHandler)
	userGroup.POST("/totp", controller.totpHandler)
}

func (controller *UserController) loginHandler(c *gin.Context) {
	var req LoginRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to bind JSON")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	tlog.App.Debug().Str("username", req.Username).Msg("Login attempt")

	isLocked, remaining := controller.auth.IsAccountLocked(req.Username)

	if isLocked {
		tlog.App.Warn().Str("username", req.Username).Msg("Account is locked due to too many failed login attempts")
		tlog.AuditLoginFailure(c, req.Username, "username", "account locked")
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
			tlog.App.Warn().Str("username", req.Username).Msg("User not found")
			controller.auth.RecordLoginAttempt(req.Username, false)
			tlog.AuditLoginFailure(c, req.Username, "username", "user not found")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}
		tlog.App.Error().Err(err).Str("username", req.Username).Msg("Error searching for user")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	if err := controller.auth.CheckUserPassword(*search, req.Password); err != nil {
		tlog.App.Warn().Err(err).Str("username", req.Username).Msg("Failed to verify password")
		controller.auth.RecordLoginAttempt(req.Username, false)
		tlog.AuditLoginFailure(c, req.Username, "username", "invalid password")
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
			tlog.App.Warn().Str("username", req.Username).Msg("User disappeared during login")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		if localUser.TOTPSecret != "" {
			tlog.App.Debug().Str("username", req.Username).Msg("User has TOTP enabled, requiring TOTP verification")

			name := localUser.Attributes.Name
			if name == "" {
				name = utils.Capitalize(localUser.Username)
			}

			email := localUser.Attributes.Email
			if email == "" {
				email = utils.CompileUserEmail(localUser.Username, controller.config.CookieDomain)
			}

			cookie, err := controller.auth.CreateSession(c, repository.Session{
				Username:    localUser.Username,
				Name:        name,
				Email:       email,
				Provider:    "local",
				TotpPending: true,
			})

			if err != nil {
				tlog.App.Error().Err(err).Msg("Failed to create session cookie")
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
		Email:    utils.CompileUserEmail(req.Username, controller.config.CookieDomain),
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

	tlog.App.Trace().Interface("session_cookie", sessionCookie).Msg("Creating session cookie")

	cookie, err := controller.auth.CreateSession(c, sessionCookie)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to create session cookie")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	http.SetCookie(c.Writer, cookie)

	tlog.App.Info().Str("username", req.Username).Msg("Login successful")
	tlog.AuditLoginSuccess(c, req.Username, "username")

	controller.auth.RecordLoginAttempt(req.Username, true)

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}

func (controller *UserController) logoutHandler(c *gin.Context) {
	tlog.App.Debug().Msg("Logout request received")

	uuid, err := c.Cookie(controller.config.SessionCookieName)

	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			tlog.App.Warn().Msg("No session cookie found on logout request")
			c.JSON(200, gin.H{
				"status":  200,
				"message": "Logout successful",
			})
			return
		}
		tlog.App.Error().Err(err).Msg("Error retrieving session cookie on logout")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	cookie, err := controller.auth.DeleteSession(c, uuid)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Error deleting session on logout")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	context, err := new(model.UserContext).NewFromGin(c)

	if err == nil {
		tlog.AuditLogout(c, context.GetUsername(), context.GetProviderID())
	} else {
		tlog.App.Warn().Err(err).Msg("Failed to get user context for logout audit, proceeding without username")
		tlog.AuditLogout(c, "unknown", "unknown")
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
		tlog.App.Error().Err(err).Msg("Failed to bind JSON")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	context, err := new(model.UserContext).NewFromGin(c)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to get user context")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	if !context.TOTPPending() {
		tlog.App.Warn().Msg("TOTP attempt without a pending TOTP session")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	tlog.App.Debug().Str("username", context.GetUsername()).Msg("TOTP verification attempt")

	isLocked, remaining := controller.auth.IsAccountLocked(context.GetUsername())

	if isLocked {
		tlog.App.Warn().Str("username", context.GetUsername()).Msg("Account is locked due to too many failed TOTP attempts")
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
		tlog.App.Error().Str("username", context.GetUsername()).Msg("User not found in TOTP handler")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	ok := totp.Validate(req.Code, user.TOTPSecret)

	if !ok {
		tlog.App.Warn().Str("username", context.GetUsername()).Msg("Invalid TOTP code")
		controller.auth.RecordLoginAttempt(context.GetUsername(), false)
		tlog.AuditLoginFailure(c, context.GetUsername(), "totp", "invalid totp code")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	uuid, err := c.Cookie(controller.config.SessionCookieName)

	if err == nil {
		_, err = controller.auth.DeleteSession(c, uuid)
		if err != nil {
			tlog.App.Warn().Err(err).Msg("Failed to delete pending TOTP session")
		}
	} else {
		tlog.App.Warn().Err(err).Msg("Failed to retrieve session cookie for pending TOTP session, proceeding without deleting it")
	}

	controller.auth.RecordLoginAttempt(context.GetUsername(), true)

	sessionCookie := repository.Session{
		Username: user.Username,
		Name:     utils.Capitalize(user.Username),
		Email:    utils.CompileUserEmail(user.Username, controller.config.CookieDomain),
		Provider: "local",
	}

	if user.Attributes.Name != "" {
		sessionCookie.Name = user.Attributes.Name
	}
	if user.Attributes.Email != "" {
		sessionCookie.Email = user.Attributes.Email
	}

	tlog.App.Trace().Interface("session_cookie", sessionCookie).Msg("Creating session cookie")

	cookie, err := controller.auth.CreateSession(c, sessionCookie)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to create session cookie")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	http.SetCookie(c.Writer, cookie)

	tlog.App.Info().Str("username", context.GetUsername()).Msg("TOTP verification successful")
	tlog.AuditLoginSuccess(c, context.GetUsername(), "totp")

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}
