package controller

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/config"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
)

type OAuthRequest struct {
	Provider string `uri:"provider" binding:"required"`
}

type OAuthControllerConfig struct {
	CSRFCookieName         string
	OAuthSessionCookieName string
	RedirectCookieName     string
	SecureCookie           bool
	AppURL                 string
	CookieDomain           string
}

type OAuthController struct {
	config OAuthControllerConfig
	router *gin.RouterGroup
	auth   *service.AuthService
}

func NewOAuthController(config OAuthControllerConfig, router *gin.RouterGroup, auth *service.AuthService) *OAuthController {
	return &OAuthController{
		config: config,
		router: router,
		auth:   auth,
	}
}

func (controller *OAuthController) SetupRoutes() {
	oauthGroup := controller.router.Group("/oauth")
	oauthGroup.GET("/url/:provider", controller.oauthURLHandler)
	oauthGroup.GET("/callback/:provider", controller.oauthCallbackHandler)
}

func (controller *OAuthController) oauthURLHandler(c *gin.Context) {
	var req OAuthRequest

	err := c.BindUri(&req)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	var reqParams service.OAuthURLParams

	err = c.BindQuery(&reqParams)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to bind query parameters")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	if !controller.isOidcRequest(reqParams) {
		isRedirectSafe := utils.IsRedirectSafe(reqParams.RedirectURI, controller.config.CookieDomain)

		if !isRedirectSafe {
			tlog.App.Warn().Str("redirect_uri", reqParams.RedirectURI).Msg("Unsafe redirect URI detected, ignoring")
			reqParams.RedirectURI = ""
		}
	}

	sessionId, _, err := controller.auth.NewOAuthSession(req.Provider, reqParams)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to create OAuth session")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	authUrl, err := controller.auth.GetOAuthURL(sessionId)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to get OAuth URL")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	c.SetCookie(controller.config.OAuthSessionCookieName, sessionId, int(time.Hour.Seconds()), "/", fmt.Sprintf(".%s", controller.config.CookieDomain), controller.config.SecureCookie, true)

	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
		"url":     authUrl,
	})
}

func (controller *OAuthController) oauthCallbackHandler(c *gin.Context) {
	var req OAuthRequest

	err := c.BindUri(&req)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	sessionIdCookie, err := c.Cookie(controller.config.OAuthSessionCookieName)

	if err != nil {
		tlog.App.Warn().Err(err).Msg("OAuth session cookie missing")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	c.SetCookie(controller.config.OAuthSessionCookieName, "", -1, "/", fmt.Sprintf(".%s", controller.config.CookieDomain), controller.config.SecureCookie, true)

	oauthPendingSession, err := controller.auth.GetOAuthPendingSession(sessionIdCookie)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to get OAuth pending session")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	defer controller.auth.EndOAuthSession(sessionIdCookie)

	state := c.Query("state")
	if state != oauthPendingSession.State {
		tlog.App.Warn().Err(err).Msg("CSRF token mismatch")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	code := c.Query("code")
	_, err = controller.auth.GetOAuthToken(sessionIdCookie, code)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to exchange code for token")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	user, err := controller.auth.GetOAuthUserinfo(sessionIdCookie)

	if user.Email == "" {
		tlog.App.Error().Msg("OAuth provider did not return an email")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	if !controller.auth.IsEmailWhitelisted(user.Email) {
		tlog.App.Warn().Str("email", user.Email).Msg("Email not whitelisted")
		tlog.AuditLoginFailure(c, user.Email, req.Provider, "email not whitelisted")

		queries, err := query.Values(config.UnauthorizedQuery{
			Username: user.Email,
		})

		if err != nil {
			tlog.App.Error().Err(err).Msg("Failed to encode unauthorized query")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.config.AppURL, queries.Encode()))
		return
	}

	var name string

	if strings.TrimSpace(user.Name) != "" {
		tlog.App.Debug().Msg("Using name from OAuth provider")
		name = user.Name
	} else {
		tlog.App.Debug().Msg("No name from OAuth provider, using pseudo name")
		name = fmt.Sprintf("%s (%s)", utils.Capitalize(strings.Split(user.Email, "@")[0]), strings.Split(user.Email, "@")[1])
	}

	var username string

	if strings.TrimSpace(user.PreferredUsername) != "" {
		tlog.App.Debug().Msg("Using preferred username from OAuth provider")
		username = user.PreferredUsername
	} else {
		tlog.App.Debug().Msg("No preferred username from OAuth provider, using pseudo username")
		username = strings.Replace(user.Email, "@", "_", 1)
	}

	svc, err := controller.auth.GetOAuthService(sessionIdCookie)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to get OAuth service for session")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	if svc.ID() != req.Provider {
		tlog.App.Error().Msgf("OAuth service ID mismatch: expected %s, got %s", svc.ID(), req.Provider)
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	sessionCookie := repository.Session{
		Username:    username,
		Name:        name,
		Email:       user.Email,
		Provider:    svc.ID(),
		OAuthGroups: utils.CoalesceToString(user.Groups),
		OAuthName:   svc.Name(),
		OAuthSub:    user.Sub,
	}

	tlog.App.Trace().Interface("session_cookie", sessionCookie).Msg("Creating session cookie")

	err = controller.auth.CreateSessionCookie(c, &sessionCookie)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to create session cookie")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	tlog.AuditLoginSuccess(c, sessionCookie.Username, sessionCookie.Provider)

	if controller.isOidcRequest(oauthPendingSession.CallbackParams) {
		tlog.App.Debug().Msg("OIDC request, redirecting to authorize page")
		queries, err := query.Values(oauthPendingSession.CallbackParams)
		if err != nil {
			tlog.App.Error().Err(err).Msg("Failed to encode OIDC callback query")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
			return
		}
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/authorize?%s", controller.config.AppURL, queries.Encode()))
		return
	}

	if oauthPendingSession.CallbackParams.RedirectURI != "" {
		queries, err := query.Values(config.RedirectQuery{
			RedirectURI: oauthPendingSession.CallbackParams.RedirectURI,
		})

		if err != nil {
			tlog.App.Error().Err(err).Msg("Failed to encode redirect URI query")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/continue?%s", controller.config.AppURL, queries.Encode()))
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, controller.config.AppURL)
}

func (controller *OAuthController) isOidcRequest(params service.OAuthURLParams) bool {
	return params.Scope != "" &&
		params.ResponseType != "" &&
		params.ClientID != "" &&
		params.RedirectURI != ""
}
