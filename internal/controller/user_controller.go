package controller

import (
	"fmt"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/config"
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
	CookieDomain string
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

	userSearch := controller.auth.SearchUser(req.Username)

	if userSearch.Type == "unknown" {
		tlog.App.Warn().Str("username", req.Username).Msg("User not found")
		controller.auth.RecordLoginAttempt(req.Username, false)
		tlog.AuditLoginFailure(c, req.Username, "username", "user not found")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	if !controller.auth.VerifyUser(userSearch, req.Password) {
		tlog.App.Warn().Str("username", req.Username).Msg("Invalid password")
		controller.auth.RecordLoginAttempt(req.Username, false)
		tlog.AuditLoginFailure(c, req.Username, "username", "invalid password")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	tlog.App.Info().Str("username", req.Username).Msg("Login successful")
	tlog.AuditLoginSuccess(c, req.Username, "username")

	controller.auth.RecordLoginAttempt(req.Username, true)

	var localUser *config.User
	if userSearch.Type == "local" {
		user := controller.auth.GetLocalUser(userSearch.Username)
		localUser = &user
	}

	if userSearch.Type == "local" && localUser != nil {
		user := *localUser

		if user.TotpSecret != "" {
			tlog.App.Debug().Str("username", req.Username).Msg("User has TOTP enabled, requiring TOTP verification")

			name := user.Attributes.Name
			if name == "" {
				name = utils.Capitalize(user.Username)
			}

			email := user.Attributes.Email
			if email == "" {
				email = utils.CompileUserEmail(user.Username, controller.config.CookieDomain)
			}

			err := controller.auth.CreateSessionCookie(c, &repository.Session{
				Username:    user.Username,
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

	if userSearch.Type == "local" && localUser != nil {
		if localUser.Attributes.Name != "" {
			sessionCookie.Name = localUser.Attributes.Name
		}
		if localUser.Attributes.Email != "" {
			sessionCookie.Email = localUser.Attributes.Email
		}
	}

	if userSearch.Type == "ldap" {
		sessionCookie.Provider = "ldap"
	}

	tlog.App.Trace().Interface("session_cookie", sessionCookie).Msg("Creating session cookie")

	err = controller.auth.CreateSessionCookie(c, &sessionCookie)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to create session cookie")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}

func (controller *UserController) logoutHandler(c *gin.Context) {
	tlog.App.Debug().Msg("Logout request received")

	controller.auth.DeleteSessionCookie(c)

	context, err := utils.GetContext(c)
	if err == nil && context.IsLoggedIn {
		tlog.AuditLogout(c, context.Username, context.Provider)
	}

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

	context, err := utils.GetContext(c)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to get user context")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	if !context.TotpPending {
		tlog.App.Warn().Msg("TOTP attempt without a pending TOTP session")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	tlog.App.Debug().Str("username", context.Username).Msg("TOTP verification attempt")

	isLocked, remaining := controller.auth.IsAccountLocked(context.Username)

	if isLocked {
		tlog.App.Warn().Str("username", context.Username).Msg("Account is locked due to too many failed TOTP attempts")
		c.Writer.Header().Add("x-tinyauth-lock-locked", "true")
		c.Writer.Header().Add("x-tinyauth-lock-reset", time.Now().Add(time.Duration(remaining)*time.Second).Format(time.RFC3339))
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed TOTP attempts. Try again in %d seconds", remaining),
		})
		return
	}

	user := controller.auth.GetLocalUser(context.Username)

	ok := totp.Validate(req.Code, user.TotpSecret)

	if !ok {
		tlog.App.Warn().Str("username", context.Username).Msg("Invalid TOTP code")
		controller.auth.RecordLoginAttempt(context.Username, false)
		tlog.AuditLoginFailure(c, context.Username, "totp", "invalid totp code")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	tlog.App.Info().Str("username", context.Username).Msg("TOTP verification successful")
	tlog.AuditLoginSuccess(c, context.Username, "totp")

	controller.auth.RecordLoginAttempt(context.Username, true)

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

	err = controller.auth.CreateSessionCookie(c, &sessionCookie)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to create session cookie")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}
