package controller

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/dig"
)

type HealthController struct {
}

type HealthControllerInput struct {
	dig.In

	RouterGroup *gin.RouterGroup `name:"apiRouterGroup"`
}

func NewHealthController(i HealthControllerInput) *HealthController {
	controller := &HealthController{}

	i.RouterGroup.GET("/healthz", controller.healthHandler)
	i.RouterGroup.HEAD("/healthz", controller.healthHandler)

	return controller
}

// HealthCheck godoc
//
//	@Summary		Healthcheck
//	@Description	Check if the server is up and running
//	@Tags			health
//	@Produce		json
//	@Success		200	{object}	SimpleResponse
//	@Router			/api/healthz [get]
//	@Router			/api/healthz [head]
func (controller *HealthController) healthHandler(c *gin.Context) {
	c.JSON(200, SimpleResponse{
		Status:  200,
		Message: "OK",
	})
}
