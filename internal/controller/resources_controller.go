package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tinyauthapp/tinyauth/internal/model"
)

type ResourcesController struct {
	config     model.Config
	fileServer http.Handler
}

func NewResourcesController(
	config model.Config,
	router *gin.RouterGroup,
) *ResourcesController {
	fileServer := http.StripPrefix("/resources", http.FileServer(http.Dir(config.Resources.Path)))

	controller := &ResourcesController{
		config:     config,
		fileServer: fileServer,
	}

	router.GET("/resources/*resource", controller.resourcesHandler)

	return controller
}

func (controller *ResourcesController) resourcesHandler(c *gin.Context) {
	if controller.config.Resources.Path == "" {
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Resources not found",
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
