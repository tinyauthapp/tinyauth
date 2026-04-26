package controller

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"

	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
)

type OIDCControllerConfig struct{}

type OIDCController struct {
	config OIDCControllerConfig
	router *gin.RouterGroup
	oidc   *service.OIDCService
}

type AuthorizeCallback struct {
	Code  string `url:"code"`
	State string `url:"state,omitempty"`
}

type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required" url:"grant_type"`
	Code         string `form:"code" url:"code"`
	RedirectURI  string `form:"redirect_uri" url:"redirect_uri"`
	RefreshToken string `form:"refresh_token" url:"refresh_token"`
	ClientSecret string `form:"client_secret" url:"client_secret"`
	ClientID     string `form:"client_id" url:"client_id"`
	CodeVerifier string `form:"code_verifier" url:"code_verifier"`
}

type CallbackError struct {
	Error            string `url:"error"`
	ErrorDescription string `url:"error_description"`
	State            string `url:"state"`
}

type ErrorScreen struct {
	Error string `url:"error"`
}

type ClientRequest struct {
	ClientID string `uri:"id" binding:"required"`
}

type ClientCredentials struct {
	ClientID     string
	ClientSecret string
}

func NewOIDCController(config OIDCControllerConfig, oidcService *service.OIDCService, router *gin.RouterGroup) *OIDCController {
	return &OIDCController{
		config: config,
		oidc:   oidcService,
		router: router,
	}
}

func (controller *OIDCController) SetupRoutes() {
	oidcGroup := controller.router.Group("/oidc")
	oidcGroup.GET("/clients/:id", controller.GetClientInfo)
	oidcGroup.POST("/authorize", controller.Authorize)
	oidcGroup.POST("/token", controller.Token)
	oidcGroup.GET("/userinfo", controller.Userinfo)
	oidcGroup.POST("/userinfo", controller.Userinfo)
}

func (controller *OIDCController) GetClientInfo(c *gin.Context) {
	var req ClientRequest

	err := c.BindUri(&req)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	client, ok := controller.oidc.GetClient(req.ClientID)

	if !ok {
		tlog.App.Warn().Str("client_id", req.ClientID).Msg("Client not found")
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Client not found",
		})
		return
	}

	c.JSON(200, gin.H{
		"status": 200,
		"client": client.ClientID,
		"name":   client.Name,
	})
}

func (controller *OIDCController) Authorize(c *gin.Context) {
	if !controller.oidc.IsConfigured() {
		controller.authorizeError(c, errors.New("err_oidc_not_configured"), "OIDC not configured", "This instance is not configured for OIDC", "", "", "")
		return
	}

	userContext, err := utils.GetContext(c)

	if err != nil {
		controller.authorizeError(c, err, "Failed to get user context", "User is not logged in or the session is invalid", "", "", "")
		return
	}

	if !userContext.IsLoggedIn {
		controller.authorizeError(c, errors.New("err user not logged in"), "User not logged in", "The user is not logged in", "", "", "")
		return
	}

	var req service.AuthorizeRequest

	err = c.BindJSON(&req)
	if err != nil {
		controller.authorizeError(c, err, "Failed to bind JSON", "The client provided an invalid authorization request", "", "", "")
		return
	}

	client, ok := controller.oidc.GetClient(req.ClientID)

	if !ok {
		controller.authorizeError(c, err, "Client not found", "The client ID is invalid", "", "", "")
		return
	}

	err = controller.oidc.ValidateAuthorizeParams(req)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to validate authorize params")
		if err.Error() != "invalid_request_uri" {
			controller.authorizeError(c, err, "Failed validate authorize params", "Invalid request parameters", req.RedirectURI, err.Error(), req.State)
			return
		}
		controller.authorizeError(c, err, "Redirect URI not trusted", "The provided redirect URI is not trusted", "", "", "")
		return
	}

	// WARNING: Since Tinyauth is stateless, we cannot have a sub that never changes. We will just create a uuid out of the username and client name which remains stable, but if username or client name changes then sub changes too.
	sub := utils.GenerateUUID(fmt.Sprintf("%s:%s", userContext.Username, client.ID))
	code := utils.GenerateString(32)

	// Before storing the code, delete old session
	err = controller.oidc.DeleteOldSession(c, sub)
	if err != nil {
		controller.authorizeError(c, err, "Failed to delete old sessions", "Failed to delete old sessions", req.RedirectURI, "server_error", req.State)
		return
	}

	err = controller.oidc.StoreCode(c, sub, code, req)

	if err != nil {
		controller.authorizeError(c, err, "Failed to store code", "Failed to store code", req.RedirectURI, "server_error", req.State)
		return
	}

	// We also need a snapshot of the user that authorized this (skip if no openid scope)
	if slices.Contains(strings.Fields(req.Scope), "openid") {
		err = controller.oidc.StoreUserinfo(c, sub, userContext, req)

		if err != nil {
			tlog.App.Error().Err(err).Msg("Failed to insert user info into database")
			controller.authorizeError(c, err, "Failed to store user info", "Failed to store user info", req.RedirectURI, "server_error", req.State)
			return
		}
	}

	queries, err := query.Values(AuthorizeCallback{
		Code:  code,
		State: req.State,
	})

	if err != nil {
		controller.authorizeError(c, err, "Failed to build query", "Failed to build query", req.RedirectURI, "server_error", req.State)
		return
	}

	c.JSON(200, gin.H{
		"status":       200,
		"redirect_uri": fmt.Sprintf("%s?%s", req.RedirectURI, queries.Encode()),
	})
}

func (controller *OIDCController) Token(c *gin.Context) {
	if !controller.oidc.IsConfigured() {
		tlog.App.Warn().Msg("OIDC not configured")
		c.JSON(404, gin.H{
			"error": "not_found",
		})
		return
	}

	var req TokenRequest

	err := c.Bind(&req)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to bind token request")
		c.JSON(400, gin.H{
			"error": "invalid_request",
		})
		return
	}

	err = controller.oidc.ValidateGrantType(req.GrantType)
	if err != nil {
		tlog.App.Warn().Str("grant_type", req.GrantType).Msg("Unsupported grant type")
		c.JSON(400, gin.H{
			"error": err.Error(),
		})
		return
	}

	// First we try form values
	creds := ClientCredentials{
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
	}

	// If it fails, we try basic auth
	if creds.ClientID == "" || creds.ClientSecret == "" {
		tlog.App.Debug().Msg("Tried form values and they are empty, trying basic auth")

		clientId, clientSecret, ok := c.Request.BasicAuth()

		if !ok {
			tlog.App.Error().Msg("Missing authorization header")
			c.Header("www-authenticate", `Basic realm="Tinyauth OIDC Token Endpoint"`)
			c.JSON(400, gin.H{
				"error": "invalid_client",
			})
			return
		}

		creds.ClientID = clientId
		creds.ClientSecret = clientSecret
	}

	// END - we don't support other authentication methods

	client, ok := controller.oidc.GetClient(creds.ClientID)

	if !ok {
		tlog.App.Warn().Str("client_id", creds.ClientID).Msg("Client not found")
		c.JSON(400, gin.H{
			"error": "invalid_client",
		})
		return
	}

	if client.ClientSecret != creds.ClientSecret {
		tlog.App.Warn().Str("client_id", creds.ClientID).Msg("Invalid client secret")
		c.JSON(400, gin.H{
			"error": "invalid_client",
		})
		return
	}

	var tokenResponse service.TokenResponse

	switch req.GrantType {
	case "authorization_code":
		entry, err := controller.oidc.GetCodeEntry(c, controller.oidc.Hash(req.Code), client.ClientID)
		if err != nil {
			if err := controller.oidc.DeleteTokenByCodeHash(c, controller.oidc.Hash(req.Code)); err != nil {
				tlog.App.Error().Err(err).Msg("Failed to delete access token by code hash")
			}
			if errors.Is(err, service.ErrCodeNotFound) {
				tlog.App.Warn().Msg("Code not found")
				c.JSON(400, gin.H{
					"error": "invalid_grant",
				})
				return
			}
			if errors.Is(err, service.ErrCodeExpired) {
				tlog.App.Warn().Msg("Code expired")
				c.JSON(400, gin.H{
					"error": "invalid_grant",
				})
				return
			}
			if errors.Is(err, service.ErrInvalidClient) {
				tlog.App.Warn().Msg("Invalid client ID")
				c.JSON(400, gin.H{
					"error": "invalid_client",
				})
				return
			}
			tlog.App.Warn().Err(err).Msg("Failed to get OIDC code entry")
			c.JSON(400, gin.H{
				"error": "server_error",
			})
			return
		}

		if entry.RedirectURI != req.RedirectURI {
			tlog.App.Warn().Str("redirect_uri", req.RedirectURI).Msg("Redirect URI mismatch")
			c.JSON(400, gin.H{
				"error": "invalid_grant",
			})
			return
		}

		ok := controller.oidc.ValidatePKCE(entry.CodeChallenge, req.CodeVerifier)

		if !ok {
			tlog.App.Warn().Msg("PKCE validation failed")
			c.JSON(400, gin.H{
				"error": "invalid_grant",
			})
			return
		}

		tokenRes, err := controller.oidc.GenerateAccessToken(c, client, entry)

		if err != nil {
			tlog.App.Error().Err(err).Msg("Failed to generate access token")
			c.JSON(400, gin.H{
				"error": "server_error",
			})
			return
		}

		tokenResponse = tokenRes
	case "refresh_token":
		tokenRes, err := controller.oidc.RefreshAccessToken(c, req.RefreshToken, creds.ClientID)

		if err != nil {
			if errors.Is(err, service.ErrTokenExpired) {
				tlog.App.Error().Err(err).Msg("Refresh token expired")
				c.JSON(400, gin.H{
					"error": "invalid_grant",
				})
				return
			}

			if errors.Is(err, service.ErrInvalidClient) {
				tlog.App.Error().Err(err).Msg("Invalid client")
				c.JSON(400, gin.H{
					"error": "invalid_grant",
				})
				return
			}

			tlog.App.Error().Err(err).Msg("Failed to refresh access token")
			c.JSON(400, gin.H{
				"error": "server_error",
			})
			return
		}

		tokenResponse = tokenRes
	}

	c.Header("cache-control", "no-store")
	c.Header("pragma", "no-cache")

	c.JSON(200, tokenResponse)
}

func (controller *OIDCController) Userinfo(c *gin.Context) {
	if !controller.oidc.IsConfigured() {
		tlog.App.Warn().Msg("OIDC not configured")
		c.JSON(404, gin.H{
			"error": "not_found",
		})
		return
	}

	var token string

	authorization := c.GetHeader("Authorization")
	if authorization != "" {
		tokenType, bearerToken, ok := strings.Cut(authorization, " ")
		if !ok {
			tlog.App.Warn().Msg("OIDC userinfo accessed with malformed authorization header")
			c.JSON(401, gin.H{
				"error": "invalid_request",
			})
			return
		}

		if strings.ToLower(tokenType) != "bearer" {
			tlog.App.Warn().Msg("OIDC userinfo accessed with invalid token type")
			c.JSON(401, gin.H{
				"error": "invalid_request",
			})
			return
		}

		token = bearerToken
	} else if c.Request.Method == http.MethodPost {
		if c.ContentType() != "application/x-www-form-urlencoded" {
			tlog.App.Warn().Msg("OIDC userinfo POST accessed with invalid content type")
			c.JSON(400, gin.H{
				"error": "invalid_request",
			})
			return
		}
		token = c.PostForm("access_token")
		if token == "" {
			tlog.App.Warn().Msg("OIDC userinfo POST accessed without access_token in body")
			c.JSON(401, gin.H{
				"error": "invalid_request",
			})
			return
		}
	} else {
		tlog.App.Warn().Msg("OIDC userinfo accessed without authorization header")
		c.JSON(401, gin.H{
			"error": "invalid_request",
		})
		return
	}

	entry, err := controller.oidc.GetAccessToken(c, controller.oidc.Hash(token))

	if err != nil {
		if err == service.ErrTokenNotFound {
			tlog.App.Warn().Msg("OIDC userinfo accessed with invalid token")
			c.JSON(401, gin.H{
				"error": "invalid_grant",
			})
			return
		}

		tlog.App.Err(err).Msg("Failed to get token entry")
		c.JSON(401, gin.H{
			"error": "server_error",
		})
		return
	}

	// If we don't have the openid scope, return an error
	if !slices.Contains(strings.Split(entry.Scope, ","), "openid") {
		tlog.App.Warn().Msg("OIDC userinfo accessed without openid scope")
		c.JSON(401, gin.H{
			"error": "invalid_scope",
		})
		return
	}

	user, err := controller.oidc.GetUserinfo(c, entry.Sub)

	if err != nil {
		tlog.App.Err(err).Msg("Failed to get user entry")
		c.JSON(401, gin.H{
			"error": "server_error",
		})
		return
	}

	c.JSON(200, controller.oidc.CompileUserinfo(user, entry.Scope))
}

func (controller *OIDCController) authorizeError(c *gin.Context, err error, reason string, reasonUser string, callback string, callbackError string, state string) {
	tlog.App.Error().Err(err).Msg(reason)

	if callback != "" {
		errorQueries := CallbackError{
			Error: callbackError,
		}

		if reasonUser != "" {
			errorQueries.ErrorDescription = reasonUser
		}

		if state != "" {
			errorQueries.State = state
		}

		queries, err := query.Values(errorQueries)

		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.JSON(200, gin.H{
			"status":       200,
			"redirect_uri": fmt.Sprintf("%s?%s", callback, queries.Encode()),
		})
		return
	}

	errorQueries := ErrorScreen{
		Error: reasonUser,
	}

	queries, err := query.Values(errorQueries)

	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(200, gin.H{
		"status":       200,
		"redirect_uri": fmt.Sprintf("%s/error?%s", controller.oidc.GetIssuer(), queries.Encode()),
	})
}
