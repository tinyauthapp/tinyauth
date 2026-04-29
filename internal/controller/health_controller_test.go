package controller_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
	"github.com/stretchr/testify/assert"
)

func TestHealthController(t *testing.T) {
	tlog.NewTestLogger().Init()
	tests := []struct {
		description string
		path        string
		method      string
		expected    string
	}{
		{
			description: "Ensure health endpoint returns 200 OK",
			path:        "/api/healthz",
			method:      "GET",
			expected: func() string {
				expectedHealthResponse := map[string]any{
					"status":  200,
					"message": "Healthy",
				}
				bytes, err := json.Marshal(expectedHealthResponse)
				assert.NoError(t, err)
				return string(bytes)
			}(),
		},
		{
			description: "Ensure health endpoint returns 200 OK for HEAD request",
			path:        "/api/healthz",
			method:      "HEAD",
			expected: func() string {
				expectedHealthResponse := map[string]any{
					"status":  200,
					"message": "Healthy",
				}
				bytes, err := json.Marshal(expectedHealthResponse)
				assert.NoError(t, err)
				return string(bytes)
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()
			group := router.Group("/api")
			gin.SetMode(gin.TestMode)

			healthController := controller.NewHealthController(group)
			healthController.SetupRoutes()

			recorder := httptest.NewRecorder()

			request, err := http.NewRequest(test.method, test.path, nil)
			assert.NoError(t, err)

			router.ServeHTTP(recorder, request)

			assert.Equal(t, http.StatusOK, recorder.Code)
			assert.Equal(t, test.expected, recorder.Body.String())
		})
	}
}
