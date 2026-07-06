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

// Resources godoc
//
//	@Summary		Resources Endpoint
//	@Description	Get a resource by file name
//	@Tags			resources
//	@Param			resource	path	string	true	"Resource Name"
//	@Success		200
//	@Failure		404	{object}	SimpleResponse
//	@Failure		403	{object}	SimpleResponse
//	@Router			/resources/{resource} [get]
func (controller *ResourcesController) resourcesHandler(c *gin.Context) {
	if controller.config.Resources.Path == "" {
		c.JSON(404, SimpleResponse{
			Status:  404,
			Message: "Resource not found",
		})
		return
	}
	if !controller.config.Resources.Enabled {
		c.JSON(403, SimpleResponse{
			Status:  403,
			Message: "Resources are disabled",
		})
		return
	}
	controller.fileServer.ServeHTTP(c.Writer, c.Request)
}
