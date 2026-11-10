package controller

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
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
	log      *logger.Logger
	config   *model.Config
	runtime  *model.RuntimeConfig
	auth     *service.AuthService
	broker   *service.OAuthBrokerService
	identity *service.IdentityService
	sessions *service.SessionsService
}

type OAuthControllerInput struct {
	dig.In

	Log             *logger.Logger
	Config          *model.Config
	RuntimeConfig   *model.RuntimeConfig
	RouterGroup     *gin.RouterGroup `name:"apiRouterGroup"`
	AuthService     *service.AuthService
	OAuthBroker     *service.OAuthBrokerService
	IdentityService *service.IdentityService
	SessionsService *service.SessionsService
}

func NewOAuthController(i OAuthControllerInput) *OAuthController {
	controller := &OAuthController{
		log:      i.Log,
		config:   i.Config,
		runtime:  i.RuntimeConfig,
		auth:     i.AuthService,
		broker:   i.OAuthBroker,
		identity: i.IdentityService,
		sessions: i.SessionsService,
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

	flowId, ok := controller.broker.BeginOAuthFlow(req.Provider, reqParams)

	if !ok {
		controller.log.App.Error().Err(err).Msg("Failed to initiate OAuth flow")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	authUrl, ok := controller.broker.FlowAuthURL(flowId)

	if !ok {
		controller.log.App.Error().Err(err).Msg("Failed to get OAuth URL for flow")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	cookie := controller.auth.CreateCookie(service.CreateCookieParams{
		Name:      controller.runtime.OAuthFlowCookieName,
		Value:     flowId,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	http.SetCookie(c.Writer, cookie)

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

	flowId, err := c.Cookie(controller.runtime.OAuthFlowCookieName)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get OAuth flow cookie")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	cookie := controller.auth.CreateCookie(service.CreateCookieParams{
		Name:      controller.runtime.OAuthFlowCookieName,
		Value:     "",
		ExpiresAt: time.Now().Add(-time.Hour),
	})

	http.SetCookie(c.Writer, cookie)

	flow, ok := controller.broker.GetFlow(flowId)

	if !ok {
		controller.log.App.Error().Err(err).Msg("Failed to get OAuth flow")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	defer controller.broker.EndFlow(flowId)

	state := c.Query("state")
	if state != flow.State {
		controller.log.App.Warn().Msg("OAuth state mismatch")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	code := c.Query("code")
	_, err = controller.broker.FlowOAuthToken(flowId, code)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to exchange code for token")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	user, err := controller.broker.FlowOAuthUserinfo(flowId)

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

	if flow.Service.ID() != req.Provider {
		controller.log.App.Warn().Msgf("OAuth provider mismatch: expected %s, got %s", req.Provider, flow.Service.ID())
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	if !controller.auth.IsEmailWhitelisted(flow.Service.ID(), user.Email) {
		controller.log.App.Warn().Str("email", user.Email).Msg("Email not whitelisted, denying access")
		controller.log.AuditLoginFailure(user.Email, flow.Service.ID(), c.ClientIP(), "email not whitelisted")

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

	userinfo := controller.createOAuthUserInfo(oauthUserInfo{
		Username: user.PreferredUsername,
		Email:    user.Email,
		Name:     user.Name,
	})

	identityContext := model.IdentityContext{
		OAuth: model.IdentityOAuthContext{
			Groups:      utils.CoalesceToString(user.Groups),
			DisplayName: flow.Service.Name(),
		},
	}

	identity, err := controller.identity.Store(c, service.StoreIdentityParams{
		Username:        userinfo.Username,
		Email:           userinfo.Email,
		Name:            userinfo.Name,
		ProviderID:      flow.Service.ID(),
		ProviderType:    model.ProviderOAuth,
		ProviderUserID:  user.Sub,
		IdentityContext: identityContext,
	})

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to store identity")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	controller.log.App.Debug().Str("username", userinfo.Username).Str("email", userinfo.Email).Msg("Identity created")

	session, err := controller.sessions.Create(c, identity.UUID, model.SessionContext{})

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to create session")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	controller.log.App.Debug().Str("username", userinfo.Username).Str("email", userinfo.Email).Msg("Session created")

	sessionCookie := controller.auth.CreateCookie(service.CreateCookieParams{
		Name:      controller.runtime.SessionCookieName,
		Value:     session.UUID,
		ExpiresAt: time.Unix(session.ExpiresAt, 0),
	})

	http.SetCookie(c.Writer, sessionCookie)

	controller.log.AuditLoginSuccess(userinfo.Username, flow.Service.ID(), c.ClientIP())

	if controller.isOidcRequest(flow.CallbackParams) {
		controller.log.App.Debug().Msg("OIDC request detected, redirecting to authorization endpoint with callback params")
		queries, err := query.Values(flow.CallbackParams)
		if err != nil {
			controller.log.App.Error().Err(err).Msg("Failed to encode OIDC callback query")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
			return
		}
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/oidc/authorize?%s", controller.runtime.AppURL, queries.Encode()))
		return
	}

	if flow.CallbackParams.RedirectURI != "" {
		queries, err := query.Values(RedirectQuery{
			RedirectURI: flow.CallbackParams.RedirectURI,
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

func (controller *OAuthController) isRedirectSafe(redirectURI string) bool {
	v := validators.NewDomainValidator(validators.DomainValidatorOptions{
		WithPort:       true,
		WithScheme:     true,
		AllowedSchemes: []string{"https", "http"},
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

	if controller.config.Experimental.NoOAuthUserinfoGen {
		if input.Username != "" {
			info.Username = input.Username
		} else {
			parts := strings.SplitN(input.Email, "@", 2)
			if len(parts) != 2 {
				controller.log.App.Error().Str("email", input.Email).Msg("Invalid email address")
			} else {
				info.Username = parts[0]
			}
		}

		if input.Name != "" {
			info.Name = input.Name
		} else {
			info.Name = utils.Capitalize(info.Username)
		}

		return info
	}

	if input.Name != "" {
		controller.log.App.Debug().Msg("Using name from OAuth provider")
		info.Name = input.Name
	} else {
		controller.log.App.Debug().Msg("No name from OAuth provider, generating from email")
		parts := strings.SplitN(input.Email, "@", 2)
		if len(parts) != 2 {
			controller.log.App.Error().Str("email", input.Email).Msg("Invalid email address")
		} else {
			info.Name = fmt.Sprintf("%s (%s)", utils.Capitalize(parts[0]), parts[1])
		}
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
