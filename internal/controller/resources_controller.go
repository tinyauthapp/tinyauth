package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"go.uber.org/dig"
)

type ResourcesController struct {
	config     *model.Config
	fileServer http.Handler
}

type ResourcesControllerInput struct {
	dig.In

	RouterGroup *gin.RouterGroup `name:"mainRouterGroup"`
	Config      *model.Config
}

func NewResourcesController(i ResourcesControllerInput) *ResourcesController {
	fileServer := http.StripPrefix("/resources", http.FileServer(http.Dir(i.Config.Resources.Path)))

	controller := &ResourcesController{
		config:     i.Config,
		fileServer: fileServer,
	}

	i.RouterGroup.GET("/resources/*resource", controller.resourcesHandler)

	return controller
}

func (controller *ResourcesController) resourcesHandler(c *gin.Context) {
	if controller.config.Resources.Path == "" {
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Resource not found",
		})
		return
	}
	if !controller.config.Resources.Enabled {
		c.JSON(403, gin.H{
			"status":  403,
			"message": "Resources are disabled",
		})
		return
	}
	controller.fileServer.ServeHTTP(c.Writer, c.Request)
}
