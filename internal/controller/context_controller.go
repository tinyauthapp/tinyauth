package controller

import (
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"go.uber.org/dig"

	"github.com/gin-gonic/gin"
)

// UCR -> User Context Response

type UCRAuth struct {
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	ProviderID    string `json:"providerId"`
}

type UCROAuth struct {
	Active      bool   `json:"active"`
	DisplayName string `json:"displayName"`
}

type UCRTOTP struct {
	Pending bool `json:"pending"`
}

type UCRTailscale struct {
	NodeName string `json:"nodeName,omitempty"`
}

type UserContextResponse struct {
	Status    int          `json:"status"`
	Message   string       `json:"message"`
	Auth      UCRAuth      `json:"auth"`
	OAuth     UCROAuth     `json:"oauth"`
	TOTP      UCRTOTP      `json:"totp"`
	Tailscale UCRTailscale `json:"tailscale"`
}

// ACR -> App Context Response

type ACRAuth struct {
	Providers []model.Provider `json:"providers"`
}

type ACROAuth struct {
	AutoRedirect string `json:"autoRedirect"`
}

type ACRUI struct {
	Title                 string `json:"title"`
	ForgotPasswordMessage string `json:"forgotPasswordMessage"`
	BackgroundImage       string `json:"backgroundImage"`
	WarningsEnabled       bool   `json:"warningsEnabled"`
}

type ACRApp struct {
	AppURL            string `json:"appUrl"`
	CookieDomain      string `json:"cookieDomain"`
	SubdomainsEnabled bool   `json:"subdomainsEnabled"`
}

type AppContextResponse struct {
	Status  int      `json:"status"`
	Message string   `json:"message"`
	Auth    ACRAuth  `json:"auth"`
	OAuth   ACROAuth `json:"oauth"`
	UI      ACRUI    `json:"ui"`
	App     ACRApp   `json:"app"`
}

type ContextControllerInput struct {
	dig.In

	Log         *logger.Logger
	Config      *model.Config
	Runtime     *model.RuntimeConfig
	RouterGroup *gin.RouterGroup `name:"apiRouterGroup"`
}

type ContextController struct {
	log     *logger.Logger
	config  *model.Config
	runtime *model.RuntimeConfig
}

func NewContextController(i ContextControllerInput) *ContextController {
	controller := &ContextController{
		log:     i.Log,
		config:  i.Config,
		runtime: i.Runtime,
	}

	if !i.Config.UI.WarningsEnabled {
		i.Log.App.Warn().Msg("UI warnings are disabled. This may lead to security issues if you are not careful. Make sure to enable warnings in production environments.")
	}

	contextGroup := i.RouterGroup.Group("/context")
	contextGroup.GET("/user", controller.userContextHandler)
	contextGroup.GET("/app", controller.appContextHandler)

	return controller
}

func (controller *ContextController) userContextHandler(c *gin.Context) {
	context, err := new(model.UserContext).NewFromGin(c)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to create user context from request")
		c.JSON(200, UserContextResponse{
			Status:  401,
			Message: "Unauthorized",
			Auth:    UCRAuth{Authenticated: false},
		})
		return
	}

	userContext := UserContextResponse{
		Status:  200,
		Message: "Success",
		Auth: UCRAuth{
			Authenticated: context.Authenticated,
			Username:      context.GetUsername(),
			Name:          context.GetName(),
			Email:         context.GetEmail(),
			ProviderID:    context.GetProviderID(),
		},
		OAuth: UCROAuth{
			Active:      context.IsOAuth(),
			DisplayName: context.OAuthName(),
		},
		TOTP: UCRTOTP{
			Pending: context.TOTPPending(),
		},
		Tailscale: UCRTailscale{
			NodeName: context.TailscaleNodeName(),
		},
	}

	c.JSON(200, userContext)
}

func (controller *ContextController) appContextHandler(c *gin.Context) {
	c.JSON(200, AppContextResponse{
		Status:  200,
		Message: "Success",
		Auth: ACRAuth{
			Providers: controller.runtime.ConfiguredProviders,
		},
		OAuth: ACROAuth{
			AutoRedirect: controller.config.OAuth.AutoRedirect,
		},
		UI: ACRUI{
			Title:                 controller.config.UI.Title,
			ForgotPasswordMessage: controller.config.UI.ForgotPasswordMessage,
			BackgroundImage:       controller.config.UI.BackgroundImage,
			WarningsEnabled:       controller.config.UI.WarningsEnabled,
		},
		App: ACRApp{
			AppURL:            controller.runtime.AppURL,
			CookieDomain:      controller.runtime.CookieDomain,
			SubdomainsEnabled: controller.config.Auth.SubdomainsEnabled,
		},
	})
}
