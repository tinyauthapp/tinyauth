package controller

import (
	"fmt"
	"net/url"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"

	"github.com/gin-gonic/gin"
)

type UserContextResponse struct {
	Status      int    `json:"status"`
	Message     string `json:"message"`
	IsLoggedIn  bool   `json:"isLoggedIn"`
	Username    string `json:"username"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	Provider    string `json:"provider"`
	OAuth       bool   `json:"oauth"`
	TOTPPending bool   `json:"totpPending"`
	OAuthName   string `json:"oauthName"`
}

type AppContextResponse struct {
	Status                int              `json:"status"`
	Message               string           `json:"message"`
	Providers             []model.Provider `json:"providers"`
	Title                 string           `json:"title"`
	AppURL                string           `json:"appUrl"`
	CookieDomain          string           `json:"cookieDomain"`
	ForgotPasswordMessage string           `json:"forgotPasswordMessage"`
	BackgroundImage       string           `json:"backgroundImage"`
	OAuthAutoRedirect     string           `json:"oauthAutoRedirect"`
	WarningsEnabled       bool             `json:"warningsEnabled"`
}

type ContextController struct {
	log     *logger.Logger
	config  model.Config
	runtime model.RuntimeConfig
}

func NewContextController(
	log *logger.Logger,
	config model.Config,
	runtimeConfig model.RuntimeConfig,
	router *gin.RouterGroup,
) *ContextController {
	controller := &ContextController{
		log:     log,
		config:  config,
		runtime: runtimeConfig,
	}

	if !config.UI.WarningsEnabled {
		log.App.Warn().Msg("UI warnings are disabled. This may lead to security issues if you are not careful. Make sure to enable warnings in production environments.")
	}

	contextGroup := router.Group("/context")
	contextGroup.GET("/user", controller.userContextHandler)
	contextGroup.GET("/app", controller.appContextHandler)

	return controller
}

func (controller *ContextController) userContextHandler(c *gin.Context) {
	context, err := new(model.UserContext).NewFromGin(c)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to create user context from request")
		c.JSON(200, UserContextResponse{
			Status:     401,
			Message:    "Unauthorized",
			IsLoggedIn: false,
		})
		return
	}

	userContext := UserContextResponse{
		Status:      200,
		Message:     "Success",
		IsLoggedIn:  context.Authenticated,
		Username:    context.GetUsername(),
		Name:        context.GetName(),
		Email:       context.GetEmail(),
		Provider:    context.GetProviderID(),
		OAuth:       context.IsOAuth(),
		TOTPPending: context.TOTPPending(),
		OAuthName:   context.OAuthName(),
	}

	c.JSON(200, userContext)
}

func (controller *ContextController) appContextHandler(c *gin.Context) {
	appUrl, err := url.Parse(controller.runtime.AppURL)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to parse app URL")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	c.JSON(200, AppContextResponse{
		Status:                200,
		Message:               "Success",
		Providers:             controller.runtime.ConfiguredProviders,
		Title:                 controller.config.UI.Title,
		AppURL:                fmt.Sprintf("%s://%s", appUrl.Scheme, appUrl.Host),
		CookieDomain:          controller.runtime.CookieDomain,
		ForgotPasswordMessage: controller.config.UI.ForgotPasswordMessage,
		BackgroundImage:       controller.config.UI.BackgroundImage,
		OAuthAutoRedirect:     controller.config.OAuth.AutoRedirect,
		WarningsEnabled:       controller.config.UI.WarningsEnabled,
	})
}
