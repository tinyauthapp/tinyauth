package controller

import (
	"errors"
	"fmt"
	"net/http"
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
	"github.com/google/go-querystring/query"
)

type OAuthRequest struct {
	Provider string `uri:"provider" binding:"required"`
}

type OAuthController struct {
	log     *logger.Logger
	config  *model.Config
	runtime *model.RuntimeConfig
	auth    *service.AuthService
}

type OAuthControllerInput struct {
	dig.In

	Log           *logger.Logger
	Config        *model.Config
	RuntimeConfig *model.RuntimeConfig
	RouterGroup   *gin.RouterGroup `name:"apiRouterGroup"`
	AuthService   *service.AuthService
}

func NewOAuthController(i OAuthControllerInput) *OAuthController {
	controller := &OAuthController{
		log:     i.Log,
		config:  i.Config,
		runtime: i.RuntimeConfig,
		auth:    i.AuthService,
	}

	oauthGroup := i.RouterGroup.Group("/oauth")
	oauthGroup.GET("/url/:provider", controller.oauthURLHandler)
	oauthGroup.GET("/callback/:provider", controller.oauthCallbackHandler)

	return controller
}

func (controller *OAuthController) oauthURLHandler(c *gin.Context) {
	var req OAuthRequest

	err := c.BindUri(&req)
	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	var reqParams service.OAuthCallbackParams

	err = c.BindQuery(&reqParams)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to bind query parameters")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	if !controller.isOidcRequest(reqParams) {
		if !controller.isRedirectSafe(reqParams.RedirectURI) {
			controller.log.App.Warn().Str("redirectUri", reqParams.RedirectURI).Msg("Unsafe redirect URI, ignoring")
			reqParams.RedirectURI = ""
		}
	}

	sessionId, err := controller.auth.NewOAuthSession(req.Provider, reqParams)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to create new OAuth session")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	authUrl, err := controller.auth.GetOAuthURL(sessionId)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get OAuth URL for session")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	c.SetCookie(controller.runtime.OAuthSessionCookieName, sessionId, int(time.Hour.Seconds()), "/", controller.getCookieDomain(), controller.config.Auth.SecureCookie, true)

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
		controller.log.App.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	sessionIdCookie, err := c.Cookie(controller.runtime.OAuthSessionCookieName)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get OAuth session cookie")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	c.SetCookie(controller.runtime.OAuthSessionCookieName, "", -1, "/", controller.getCookieDomain(), controller.config.Auth.SecureCookie, true)

	oauthPendingSession, err := controller.auth.GetOAuthPendingSession(sessionIdCookie)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get pending OAuth session")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	defer controller.auth.EndOAuthSession(sessionIdCookie)

	state := c.Query("state")
	if state != oauthPendingSession.State {
		controller.log.App.Warn().Msg("OAuth state mismatch")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	code := c.Query("code")
	_, err = controller.auth.GetOAuthToken(sessionIdCookie, code)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to exchange code for token")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	user, err := controller.auth.GetOAuthUserinfo(sessionIdCookie)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get user info from OAuth provider")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	if user == nil {
		controller.log.App.Warn().Msg("OAuth provider did not return user info")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	if user.Email == "" {
		controller.log.App.Warn().Msg("OAuth provider did not return an email")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	svc, err := controller.auth.GetOAuthService(sessionIdCookie)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get OAuth service for session")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	if svc.ID() != req.Provider {
		controller.log.App.Warn().Msgf("OAuth provider mismatch: expected %s, got %s", req.Provider, svc.ID())
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	if !controller.auth.IsEmailWhitelisted(svc.ID(), user.Email) {
		controller.log.App.Warn().Str("email", user.Email).Msg("Email not whitelisted, denying access")
		controller.log.AuditLoginFailure(user.Email, svc.ID(), c.ClientIP(), "email not whitelisted")

		queries, err := query.Values(UnauthorizedQuery{
			Username: user.Email,
		})

		if err != nil {
			controller.log.App.Error().Err(err).Msg("Failed to encode unauthorized query")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.runtime.AppURL, queries.Encode()))
		return
	}

	oauthUserInfo := controller.createOAuthUserInfo(oauthUserInfo{
		Username: user.PreferredUsername,
		Email:    user.Email,
		Name:     user.Name,
	})

	sessionCookie := repository.Session{
		Username:    oauthUserInfo.Username,
		Name:        oauthUserInfo.Name,
		Email:       oauthUserInfo.Email,
		Provider:    svc.ID(),
		OAuthGroups: utils.CoalesceToString(user.Groups),
		OAuthName:   svc.Name(),
		OAuthSub:    user.Sub,
	}

	controller.log.App.Debug().Msg("Creating session cookie for user")

	cookie, err := controller.auth.CreateSession(c, sessionCookie)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to create session cookie")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	http.SetCookie(c.Writer, cookie)

	controller.log.AuditLoginSuccess(sessionCookie.Username, sessionCookie.Provider, c.ClientIP())

	if controller.isOidcRequest(oauthPendingSession.CallbackParams) {
		controller.log.App.Debug().Msg("OIDC request detected, redirecting to authorization endpoint with callback params")
		queries, err := query.Values(oauthPendingSession.CallbackParams)
		if err != nil {
			controller.log.App.Error().Err(err).Msg("Failed to encode OIDC callback query")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
			return
		}
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/oidc/authorize?%s", controller.runtime.AppURL, queries.Encode()))
		return
	}

	if oauthPendingSession.CallbackParams.RedirectURI != "" {
		queries, err := query.Values(RedirectQuery{
			RedirectURI: oauthPendingSession.CallbackParams.RedirectURI,
			LoginFor:    FrontendLoginForApp,
		})

		if err != nil {
			controller.log.App.Error().Err(err).Msg("Failed to encode redirect query")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/continue?%s", controller.runtime.AppURL, queries.Encode()))
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, controller.runtime.AppURL)
}

func (controller *OAuthController) isOidcRequest(params service.OAuthCallbackParams) bool {
	return params.LoginFor == string(FrontendLoginForOIDC)
}

func (controller *OAuthController) getCookieDomain() string {
	if !controller.config.Auth.SubdomainsEnabled {
		return ""
	}
	return controller.runtime.CookieDomain
}

func (controller *OAuthController) isRedirectSafe(redirectURI string) bool {
	v := validators.NewDomainValidator(validators.DomainValidatorOptions{
		WithPort: true,
	})

	_, err := v.SafeHostname(controller.runtime.AppURL)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("App URL is invalid, cannot validate redirect URI")
		return false
	}

	err = v.Validate(redirectURI, controller.runtime.AppURL)

	if err == nil {
		return true
	}

	controller.log.App.Debug().Err(err).Msg("Failed to validate redirect URI")

	if !errors.Is(err, validators.ErrHostnameMismatch) {
		return false
	}

	if !controller.config.Auth.SubdomainsEnabled {
		return false
	}

	v = validators.NewDomainValidator(validators.DomainValidatorOptions{})

	hostname, err := v.SafeHostname(redirectURI)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get safe hostname from redirect URI")
		return false
	}

	if strings.HasSuffix(hostname, "."+strings.ToLower(controller.runtime.CookieDomain)) ||
		hostname == controller.runtime.CookieDomain {
		return true
	}

	return false
}

type oauthUserInfo struct {
	Email    string
	Username string
	Name     string
}

func (controller *OAuthController) createOAuthUserInfo(input oauthUserInfo) oauthUserInfo {
	info := oauthUserInfo{
		Email: input.Email,
	}

	if controller.config.Experimental.OAuthBridgeEnabled {
		if input.Username != "" {
			info.Username = input.Username
		} else {
			info.Username = strings.SplitN(input.Email, "@", 2)[0]
		}

		if input.Name != "" {
			info.Name = input.Name
		} else {
			info.Name = utils.Capitalize(info.Username)
		}

		return info
	}

	if input.Name == "" {
		controller.log.App.Debug().Msg("Using name from OAuth provider")
		info.Name = input.Name
	} else {
		controller.log.App.Debug().Msg("No name from OAuth provider, generating from email")
		parts := strings.SplitN(input.Email, "@", 2)
		info.Name = fmt.Sprintf("%s (%s)", utils.Capitalize(parts[0]), parts[1])
	}

	if input.Username != "" {
		controller.log.App.Debug().Msg("Using preferred username from OAuth provider")
		info.Username = input.Username
	} else {
		controller.log.App.Debug().Msg("No preferred username from OAuth provider, generating from email")
		info.Username = strings.Replace(info.Email, "@", "_", 1)
	}

	return info
}
