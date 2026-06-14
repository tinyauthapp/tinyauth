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

func (controller *HealthController) healthHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  200,
		"message": "Healthy",
	})
}
