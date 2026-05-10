package controller

import "github.com/gin-gonic/gin"

type HealthController struct {
}

func NewHealthController(router *gin.RouterGroup) *HealthController {
	controller := &HealthController{}

	router.GET("/healthz", controller.healthHandler)
	router.HEAD("/healthz", controller.healthHandler)

	return controller
}

func (controller *HealthController) healthHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  200,
		"message": "Healthy",
	})
}
