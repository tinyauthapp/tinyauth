package bootstrap

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestConfigureRouterEngineTrustedPlatform(t *testing.T) {
	engine := gin.New()
	engine.TrustedPlatform = gin.PlatformGoogleAppEngine

	configureRouterEngine(engine)

	assert.Empty(t, engine.TrustedPlatform)
}
