package controller

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/validators"
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
	log     *logger.Logger
	config  *model.Config
	runtime *model.RuntimeConfig
	auth    *service.AuthService
}

type UserControllerInput struct {
	dig.In

	Log           *logger.Logger
	StaticConfig  *model.Config
	RuntimeConfig *model.RuntimeConfig
	RouterGroup   *gin.RouterGroup `name:"apiRouterGroup"`
	AuthService   *service.AuthService
}

func NewUserController(i UserControllerInput) *UserController {
	controller := &UserController{
		log:     i.Log,
		config:  i.StaticConfig,
		runtime: i.RuntimeConfig,
		auth:    i.AuthService,
	}

	userGroup := i.RouterGroup.Group("/user")
	userGroup.POST("/login", controller.loginHandler)
	userGroup.POST("/logout", controller.logoutHandler)
	userGroup.GET("/logout/callback", controller.ssoLogoutCallbackHandler)
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

	search, err := controller.auth.SearchUser(req.Username)

	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			controller.auth.DummyPasswordCheck(req.Password)
			controller.log.App.Warn().Str("username", req.Username).Msg("User not found during login attempt")
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

	isLocked, remaining := controller.auth.IsAccountLocked(req.Username)

	if isLocked {
		controller.log.App.Warn().Str("username", req.Username).Msg("Account is locked due to too many failed login attempts")
		controller.log.AuditLoginFailure(req.Username, search.Type.String(), c.ClientIP(), "account locked")
		c.Writer.Header().Add("x-tinyauth-lock-locked", "true")
		c.Writer.Header().Add("x-tinyauth-lock-reset", time.Now().Add(time.Duration(remaining)*time.Second).Format(time.RFC3339))
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", remaining),
		})
		return
	}

	if err := controller.auth.CheckUserPassword(*search, req.Password); err != nil {
		controller.log.App.Warn().Str("username", req.Username).Msg("Invalid password during login attempt")
		controller.auth.RecordLoginAttempt(req.Username, false)
		controller.log.AuditLoginFailure(req.Username, search.Type.String(), c.ClientIP(), "invalid password")
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
		if search.Email != "" {
			sessionCookie.Email = search.Email
		}
		if search.Name != "" {
			sessionCookie.Name = search.Name
		}
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

	controller.log.AuditLoginSuccess(req.Username, search.Type.String(), c.ClientIP())

	controller.auth.RecordLoginAttempt(req.Username, true)

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}

func (controller *UserController) logoutHandler(c *gin.Context) {
	controller.log.App.Debug().Msg("Logout attempt")

	// redirect_uri is a Tinyauth UI/navigation parameter. It is not an
	// OpenID Connect RP-Initiated Logout parameter. The standardized OP-facing
	// parameters are added later by buildOAuthLogoutURL.
	requestedRedirectURI := ""
	if c.Query("login_for") == "app" {
		requestedRedirectURI = c.Query("redirect_uri")
	}
	redirectURI := controller.safeLogoutRedirect(requestedRedirectURI)

	userContext, err := new(model.UserContext).NewFromGin(c)
	if err != nil {
		userContext = nil
	}

	providerID := ""
	idToken := ""
	if userContext != nil && userContext.IsOAuth() {
		providerID = userContext.OAuth.ID
		idToken = userContext.OAuth.IDToken
	}

	uuid, err := c.Cookie(controller.runtime.SessionCookieName)
	if err == nil {
		cookie, err := controller.auth.DeleteSession(c, uuid)
		if err != nil {
			controller.log.App.Error().Err(err).Msg("Error deleting session on logout")
			c.JSON(http.StatusInternalServerError, gin.H{
				"status":  http.StatusInternalServerError,
				"message": "Internal Server Error",
			})
			return
		}

		http.SetCookie(c.Writer, cookie)

		if userContext != nil {
			controller.log.AuditLogout(userContext.GetUsername(), userContext.GetProviderID(), c.ClientIP())
		} else {
			controller.log.App.Warn().Msg("Failed to get user context during logout, logging audit with unknown user")
			controller.log.AuditLogout("unknown", "unknown", c.ClientIP())
		}
	} else if errors.Is(err, http.ErrNoCookie) {
		controller.log.App.Warn().Msg("Logout attempt without session cookie, treating as successful logout")
	} else {
		controller.log.App.Error().Err(err).Msg("Error retrieving session cookie on logout")
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  http.StatusInternalServerError,
			"message": "Internal Server Error",
		})
		return
	}

	response := gin.H{
		"status":  http.StatusOK,
		"message": "Logout successful",
	}

	provider, ok := controller.runtime.OAuthProviders[providerID]
	if ok && provider.LogoutURL != "" {
		// OpenID Connect RP-Initiated Logout 1.0:
		// https://openid.net/specs/openid-connect-rpinitiated-1_0-final.html#RPLogout
		//
		// OP-facing standardized parameters:
		//   id_token_hint
		//   post_logout_redirect_uri
		//   state
		callbackURL := controller.runtime.AppURL + "/api/user/logout/callback"
		logoutURL, err := buildOAuthLogoutURL(provider, callbackURL, idToken, redirectURI)
		if err != nil {
			controller.log.App.Warn().Err(err).Str("provider", providerID).Msg("Invalid OAuth logout URL, skipping provider logout")
			if requestedRedirectURI != "" {
				response["redirectUrl"] = redirectURI
			}
		} else {
			response["redirectUrl"] = logoutURL
		}
	} else if requestedRedirectURI != "" {
		// Non-OIDC/local logout can still return to the validated application.
		response["redirectUrl"] = redirectURI
	}

	c.JSON(http.StatusOK, response)
}

func (controller *UserController) ssoLogoutCallbackHandler(c *gin.Context) {
	// state is defined by OpenID Connect RP-Initiated Logout 1.0 as an opaque
	// RP value that the OP returns unchanged after logout. We use it to carry
	// the already-validated Tinyauth application return URI across the OP hop.
	redirectURI := controller.safeLogoutRedirect(c.Query("state"))
	c.Redirect(http.StatusFound, redirectURI)
}

func (controller *UserController) safeLogoutRedirect(raw string) string {
	fallback := controller.runtime.AppURL
	if raw == "" {
		return fallback
	}

	appURL, err := url.Parse(controller.runtime.AppURL)
	if err != nil {
		return fallback
	}

	allowedSchemes := []string{"http", "https"}
	if appURL.Scheme == "https" {
		allowedSchemes = []string{"https"}
	}

	schemeValidator := validators.NewDomainValidator(validators.DomainValidatorOptions{
		WithScheme:     true,
		AllowedSchemes: allowedSchemes,
	})
	hostname, err := schemeValidator.SafeHostname(raw)
	if err != nil {
		return fallback
	}

	domainValidator := validators.NewDomainValidator(validators.DomainValidatorOptions{
		WithPort: true,
	})
	err = domainValidator.Validate(raw, controller.runtime.AppURL)
	if err == nil {
		return raw
	}

	if !errors.Is(err, validators.ErrHostnameMismatch) ||
		controller.config == nil ||
		!controller.config.Auth.SubdomainsEnabled {
		return fallback
	}

	cookieDomain := strings.ToLower(controller.runtime.CookieDomain)
	if hostname == cookieDomain || strings.HasSuffix(hostname, "."+cookieDomain) {
		return raw
	}

	return fallback
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

	sessionCookie := repository.Session{
		Username: context.Tailscale.Username,
		Name:     context.Tailscale.Name,
		Email:    context.Tailscale.Email,
		Provider: "tailscale",
	}

	cookie, err := controller.auth.CreateSession(c, sessionCookie)

	if err != nil {
		controller.log.App.Error().Err(err).Str("username", context.GetUsername()).Msg("Failed to create session cookie after successful Tailscale login")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	http.SetCookie(c.Writer, cookie)

	controller.log.App.Info().Str("username", context.GetUsername()).Msg("Tailscale login successful, login complete")
	controller.log.AuditLoginSuccess(context.GetUsername(), "tailscale", c.ClientIP())

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}
