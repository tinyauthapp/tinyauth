package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/google/go-querystring/query"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

type authorizeErrorParams struct {
	err           error
	reason        string
	reasonPublic  string
	callback      string
	callbackError string
	state         string
	json          bool
}

type OIDCController struct {
	log     *logger.Logger
	oidc    *service.OIDCService
	runtime model.RuntimeConfig
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

type AuthorizeScreenParams struct {
	LoginFor   FrontendLoginFor `url:"login_for"`
	OIDCTicket string           `url:"oidc_ticket"`
	OIDCScope  string           `url:"oidc_scope"`
	OIDCName   string           `url:"oidc_name"`
}

type AuthorizeCompleteRequest struct {
	Ticket string `json:"ticket" binding:"required"`
}

func NewOIDCController(
	log *logger.Logger,
	oidcService *service.OIDCService,
	runtimeConfig model.RuntimeConfig,
	router *gin.RouterGroup,
	mainRouter *gin.RouterGroup) *OIDCController {
	controller := &OIDCController{
		log:     log,
		oidc:    oidcService,
		runtime: runtimeConfig,
	}

	mainRouter.POST("/authorize", controller.authorize)
	mainRouter.GET("/authorize", controller.authorize)

	oidcGroup := router.Group("/oidc")
	oidcGroup.POST("/authorize-complete", controller.authorizeComplete)
	oidcGroup.POST("/token", controller.Token)
	oidcGroup.GET("/userinfo", controller.Userinfo)
	oidcGroup.POST("/userinfo", controller.Userinfo)

	return controller
}

// This endpoint does **not** return a code, it handles param validation, ticket creation
// and then redirects to the frontend to handle the consent screen. It performs no destructive
// actions (like logging out an existing session)
func (controller *OIDCController) authorize(c *gin.Context) {
	if controller.oidc == nil {
		controller.authorizeError(c, authorizeErrorParams{
			err:          errors.New("err_oidc_not_configured"),
			reason:       "OIDC not configured",
			reasonPublic: "This instance is not configured for OIDC",
		})
		return
	}

	var req service.AuthorizeRequest

	reqQueries := c.Request.URL.Query()

	if reqQueries.Get("request") != "" {
		requestObject, err := controller.oidc.DecodeAuthorizeJWT(reqQueries.Get("request"))

		if err != nil {
			controller.authorizeError(c, authorizeErrorParams{
				err:          err,
				reason:       "Failed to decode request object",
				reasonPublic: "The client provided an invalid request object",
			})
			return
		}

		req = *requestObject
	} else {
		var queryReq service.AuthorizeRequest

		err := c.ShouldBindWith(&queryReq, binding.Query)

		if err != nil {
			controller.authorizeError(c, authorizeErrorParams{
				err:          err,
				reason:       "Failed to bind query parameters",
				reasonPublic: "The client provided invalid query parameters",
			})
			return
		}

		req = queryReq
	}

	client, ok := controller.oidc.GetClient(req.ClientID)

	if !ok {
		controller.authorizeError(c, authorizeErrorParams{
			err:          fmt.Errorf("client not found: %s", req.ClientID),
			reason:       "Client not found",
			reasonPublic: "The client ID is invalid",
		})
		return
	}

	err := controller.oidc.ValidateAuthorizeParams(req)

	if err != nil {
		controller.log.App.Warn().Err(err).Msg("Failed to validate authorize params")
		if err.Error() != "invalid_request_uri" {
			controller.authorizeError(c, authorizeErrorParams{
				err:           err,
				reason:        "Failed validate authorize params",
				reasonPublic:  "Invalid request parameters",
				callback:      req.RedirectURI,
				callbackError: err.Error(),
				state:         req.State,
			})
			return
		}
		controller.authorizeError(c, authorizeErrorParams{
			err:          err,
			reason:       "Redirect URI not trusted",
			reasonPublic: "The provided redirect URI is not trusted",
		})
		return
	}

	ticket := controller.oidc.CreateAuthorizeRequestTicket(req)

	queries, err := query.Values(AuthorizeScreenParams{
		LoginFor:   FrontendLoginForOIDC,
		OIDCTicket: ticket,
		OIDCScope:  req.Scope,
		OIDCName:   client.Name,
	})

	if err != nil {
		controller.authorizeError(c, authorizeErrorParams{
			err:          err,
			reason:       "Failed to compile authorize queries",
			reasonPublic: "An internal error occured while processing your request",
		})
		return
	}

	redirectUrl := fmt.Sprintf("%s/oidc/authorize?%s", controller.oidc.GetIssuer(), queries.Encode())
	c.Redirect(http.StatusFound, redirectUrl)
}

// The actual **internal** endpoint that actually creates the code and session.
// It is called by the frontend after the user has logged in and given consent.
func (controller *OIDCController) authorizeComplete(c *gin.Context) {
	if controller.oidc == nil {
		// For this endpoint we return JSON errors since it's called
		// by the frontend and not an external client, so there's
		// no redirect_uri to send the user to in case of error
		controller.authorizeError(c, authorizeErrorParams{
			err:          errors.New("err_oidc_not_configured"),
			reason:       "OIDC not configured",
			reasonPublic: "This instance is not configured for OIDC",
			json:         true,
		})
		return
	}

	userContext, err := new(model.UserContext).NewFromGin(c)

	if err != nil {
		controller.authorizeError(c, authorizeErrorParams{
			err:          err,
			reason:       "Failed to get user context",
			reasonPublic: "User is not logged in or the session is invalid",
			json:         true,
		})
		return
	}

	if !userContext.Authenticated {
		controller.authorizeError(c, authorizeErrorParams{
			err:          errors.New("err user not logged in"),
			reason:       "User not logged in",
			reasonPublic: "The user is not logged in",
			json:         true,
		})
		return
	}

	var req AuthorizeCompleteRequest

	err = c.BindJSON(&req)

	if err != nil {
		controller.authorizeError(c, authorizeErrorParams{
			err:          err,
			reason:       "Failed to bind JSON",
			reasonPublic: "The client provided an invalid authorization request",
			json:         true,
		})
		return
	}

	authorizeReq, ok := controller.oidc.GetAuthorizeRequestByTicket(req.Ticket)

	if !ok {
		controller.authorizeError(c, authorizeErrorParams{
			err:          errors.New("authorize request not found for ticket"),
			reason:       "Invalid or expired ticket",
			reasonPublic: "The authorization request has expired or is invalid",
			json:         true,
		})
		return
	}

	// We no longer need the ticket
	controller.oidc.DeleteAuthorizeRequestTicket(req.Ticket)

	// Create the sub to find and delete old sessions
	sub := controller.oidc.CreateSub(*userContext, authorizeReq.ClientID)

	// Before storing the code, delete old session
	err = controller.oidc.DeleteOldSession(c, sub)
	if err != nil {
		controller.authorizeError(c, authorizeErrorParams{
			err:           err,
			reason:        "Failed to delete old sessions",
			reasonPublic:  "Failed to delete old sessions",
			callback:      authorizeReq.RedirectURI,
			callbackError: "server_error",
			state:         authorizeReq.State,
		})
		return
	}

	// Create the authorization code
	code := controller.oidc.CreateCode(*authorizeReq, *userContext)

	queries, err := query.Values(AuthorizeCallback{
		Code:  code,
		State: authorizeReq.State,
	})

	if err != nil {
		controller.authorizeError(c, authorizeErrorParams{
			err:           err,
			reason:        "Failed to build query",
			reasonPublic:  "Failed to build query",
			callback:      authorizeReq.RedirectURI,
			callbackError: "server_error",
			state:         authorizeReq.State,
		})
		return
	}

	c.JSON(200, gin.H{
		"status":       200,
		"redirect_uri": fmt.Sprintf("%s?%s", authorizeReq.RedirectURI, queries.Encode()),
	})
}

func (controller *OIDCController) Token(c *gin.Context) {
	if controller.oidc == nil {
		controller.log.App.Warn().Msg("Received OIDC request but OIDC server is not configured")
		c.JSON(500, gin.H{
			"error": "server_error",
		})
		return
	}

	var req TokenRequest

	err := c.Bind(&req)
	if err != nil {
		controller.log.App.Warn().Err(err).Msg("Failed to bind token request")
		c.JSON(400, gin.H{
			"error": "invalid_request",
		})
		return
	}

	err = controller.oidc.ValidateGrantType(req.GrantType)
	if err != nil {
		controller.log.App.Warn().Err(err).Msg("Invalid grant type")
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
		controller.log.App.Debug().Msg("Client credentials not found in form, trying basic auth")

		clientId, clientSecret, ok := c.Request.BasicAuth()

		if !ok {
			controller.log.App.Warn().Msg("Client credentials not found in basic auth")
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
		controller.log.App.Warn().Str("clientId", creds.ClientID).Msg("Client not found")
		c.JSON(400, gin.H{
			"error": "invalid_client",
		})
		return
	}

	if client.ClientSecret != creds.ClientSecret {
		controller.log.App.Warn().Str("clientId", creds.ClientID).Msg("Invalid client secret")
		c.JSON(400, gin.H{
			"error": "invalid_client",
		})
		return
	}

	var tokenResponse service.TokenResponse

	switch req.GrantType {
	case "authorization_code":
		entry, ok := controller.oidc.GetCodeEntry(controller.oidc.Hash(req.Code), client.ClientID)

		if !ok {
			// ensure no code reuse
			usedCodeSub, ok := controller.oidc.IsCodeUsed(controller.oidc.Hash(req.Code))

			if ok {
				controller.log.App.Warn().Msg("Code reuse detected")
				err := controller.oidc.DeleteSessionBySub(c, usedCodeSub)
				if err != nil {
					controller.log.App.Error().Err(err).Msg("Failed to delete session for reused code")
				}
				c.JSON(400, gin.H{
					"error": "invalid_grant",
				})
				return
			}

			controller.log.App.Warn().Msg("Code not found")
			c.JSON(400, gin.H{
				"error": "invalid_grant",
			})
			return
		}

		// mark code as used to prevent reuse
		controller.oidc.MarkCodeAsUsed(controller.oidc.Hash(req.Code), entry.Userinfo.Sub)

		if entry.RedirectURI != req.RedirectURI {
			controller.log.App.Warn().Msg("Redirect URI does not match")
			c.JSON(400, gin.H{
				"error": "invalid_grant",
			})
			return
		}

		ok = controller.oidc.ValidatePKCE(entry.CodeChallenge, req.CodeVerifier)

		if !ok {
			controller.log.App.Warn().Msg("PKCE validation failed")
			c.JSON(400, gin.H{
				"error": "invalid_grant",
			})
			return
		}

		tokenRes, err := controller.oidc.GenerateAccessToken(c, client, *entry)

		if err != nil {
			controller.log.App.Error().Err(err).Msg("Failed to generate access token")
			c.JSON(400, gin.H{
				"error": "server_error",
			})
			return
		}

		tokenResponse = *tokenRes
	case "refresh_token":
		tokenRes, err := controller.oidc.RefreshAccessToken(c, req.RefreshToken, creds.ClientID)

		if err != nil {
			if errors.Is(err, service.ErrTokenExpired) {
				controller.log.App.Warn().Msg("Refresh token expired")
				c.JSON(400, gin.H{
					"error": "invalid_grant",
				})
				return
			}

			if errors.Is(err, service.ErrInvalidClient) {
				controller.log.App.Warn().Msg("Refresh token does not belong to client")
				c.JSON(400, gin.H{
					"error": "invalid_grant",
				})
				return
			}

			controller.log.App.Error().Err(err).Msg("Failed to refresh access token")
			c.JSON(400, gin.H{
				"error": "server_error",
			})
			return
		}

		tokenResponse = *tokenRes
	}

	c.Header("cache-control", "no-store")
	c.Header("pragma", "no-cache")

	c.JSON(200, tokenResponse)
}

func (controller *OIDCController) Userinfo(c *gin.Context) {
	if controller.oidc == nil {
		controller.log.App.Warn().Msg("Received OIDC userinfo request but OIDC server is not configured")
		c.JSON(500, gin.H{
			"error": "server_error",
		})
		return
	}

	var token string

	authorization := c.GetHeader("Authorization")
	if authorization != "" {
		tokenType, bearerToken, ok := strings.Cut(authorization, " ")
		if !ok {
			controller.log.App.Warn().Msg("OIDC userinfo accessed with invalid authorization header")
			c.JSON(401, gin.H{
				"error": "invalid_request",
			})
			return
		}

		if strings.ToLower(tokenType) != "bearer" {
			controller.log.App.Warn().Msg("OIDC userinfo accessed with non-bearer token")
			c.JSON(401, gin.H{
				"error": "invalid_request",
			})
			return
		}

		token = bearerToken
	} else if c.Request.Method == http.MethodPost {
		if c.ContentType() != "application/x-www-form-urlencoded" {
			controller.log.App.Warn().Msg("OIDC userinfo POST accessed with invalid content type")
			c.JSON(400, gin.H{
				"error": "invalid_request",
			})
			return
		}
		token = c.PostForm("access_token")
		if token == "" {
			controller.log.App.Warn().Msg("OIDC userinfo POST accessed without access_token")
			c.JSON(401, gin.H{
				"error": "invalid_request",
			})
			return
		}
	} else {
		controller.log.App.Warn().Msg("OIDC userinfo accessed without authorization header or POST body")
		c.JSON(401, gin.H{
			"error": "invalid_request",
		})
		return
	}

	entry, err := controller.oidc.GetSessionByToken(c, controller.oidc.Hash(token))

	if err != nil {
		if errors.Is(err, service.ErrTokenNotFound) {
			controller.log.App.Warn().Msg("OIDC userinfo accessed with invalid token")
			c.JSON(401, gin.H{
				"error": "invalid_grant",
			})
			return
		}

		controller.log.App.Error().Err(err).Msg("Failed to get access token")
		c.JSON(401, gin.H{
			"error": "server_error",
		})
		return
	}

	// If we don't have the openid scope, return an error
	if !slices.Contains(strings.Split(entry.Scope, " "), "openid") {
		controller.log.App.Warn().Msg("OIDC userinfo accessed with missing openid scope")
		c.JSON(401, gin.H{
			"error": "invalid_scope",
		})
		return
	}

	var userinfo service.UserinfoResponse

	err = json.Unmarshal([]byte(entry.UserinfoJson), &userinfo)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get user info")
		c.JSON(401, gin.H{
			"error": "server_error",
		})
		return
	}

	c.JSON(200, controller.oidc.CompileUserinfo(userinfo, entry.Scope))
}

func (controller *OIDCController) authorizeError(c *gin.Context, params authorizeErrorParams) {
	controller.log.App.Error().Err(params.err).Str("reason", params.reason).Msg("Authorization error")

	if params.callback != "" {
		errorQueries := CallbackError{
			Error: params.callbackError,
		}

		if params.reasonPublic != "" {
			errorQueries.ErrorDescription = params.reasonPublic
		}

		if params.state != "" {
			errorQueries.State = params.state
		}

		queries, err := query.Values(errorQueries)

		if err != nil {
			controller.log.App.Error().Err(err).Msg("Failed to build callback error query")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		redirectUrl := fmt.Sprintf("%s?%s", params.callback, queries.Encode())

		if params.json {
			c.JSON(200, gin.H{
				"status":       200,
				"redirect_uri": redirectUrl,
			})
			return
		}

		c.Redirect(http.StatusFound, redirectUrl)
		return
	}

	errorQueries := ErrorScreen{
		Error: params.reasonPublic,
	}

	queries, err := query.Values(errorQueries)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to build error query")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	redirectUrl := ""

	if controller.oidc != nil {
		redirectUrl = fmt.Sprintf("%s/error?%s", controller.oidc.GetIssuer(), queries.Encode())
	} else {
		redirectUrl = fmt.Sprintf("%s/error?%s", controller.runtime.AppURL, queries.Encode())
	}

	if params.json {
		c.JSON(200, gin.H{
			"status":       200,
			"redirect_uri": redirectUrl,
		})
		return
	}

	c.Redirect(http.StatusFound, redirectUrl)
}
