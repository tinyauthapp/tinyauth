package controller

import (
	"fmt"
	"net/url"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"

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
	Status                int        `json:"status"`
	Message               string     `json:"message"`
	Providers             []Provider `json:"providers"`
	Title                 string     `json:"title"`
	AppURL                string     `json:"appUrl"`
	CookieDomain          string     `json:"cookieDomain"`
	ForgotPasswordMessage string     `json:"forgotPasswordMessage"`
	BackgroundImage       string     `json:"backgroundImage"`
	OAuthAutoRedirect     string     `json:"oauthAutoRedirect"`
	WarningsEnabled       bool       `json:"warningsEnabled"`
}

type Provider struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	OAuth bool   `json:"oauth"`
}

type ContextControllerConfig struct {
	Providers             []Provider
	Title                 string
	AppURL                string
	CookieDomain          string
	ForgotPasswordMessage string
	BackgroundImage       string
	OAuthAutoRedirect     string
	WarningsEnabled       bool
}

type ContextController struct {
	config ContextControllerConfig
	router *gin.RouterGroup
}

func NewContextController(config ContextControllerConfig, router *gin.RouterGroup) *ContextController {
	if !config.WarningsEnabled {
		tlog.App.Warn().Msg("UI warnings are disabled. This may expose users to security risks. Proceed with caution.")
	}

	return &ContextController{
		config: config,
		router: router,
	}
}

func (controller *ContextController) SetupRoutes() {
	contextGroup := controller.router.Group("/context")
	contextGroup.GET("/user", controller.userContextHandler)
	contextGroup.GET("/app", controller.appContextHandler)
}

func (controller *ContextController) userContextHandler(c *gin.Context) {
	context, err := new(model.UserContext).NewFromGin(c)

	if err != nil {
		tlog.App.Debug().Err(err).Msg("No user context found in request")
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
	appUrl, err := url.Parse(controller.config.AppURL)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to parse app URL")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	c.JSON(200, AppContextResponse{
		Status:                200,
		Message:               "Success",
		Providers:             controller.config.Providers,
		Title:                 controller.config.Title,
		AppURL:                fmt.Sprintf("%s://%s", appUrl.Scheme, appUrl.Host),
		CookieDomain:          controller.config.CookieDomain,
		ForgotPasswordMessage: controller.config.ForgotPasswordMessage,
		BackgroundImage:       controller.config.BackgroundImage,
		OAuthAutoRedirect:     controller.config.OAuthAutoRedirect,
		WarningsEnabled:       controller.config.WarningsEnabled,
	})
}
