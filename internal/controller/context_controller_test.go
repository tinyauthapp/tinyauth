package controller_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tinyauthapp/tinyauth/internal/config"
	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
	"github.com/stretchr/testify/assert"
)

func TestContextController(t *testing.T) {
	tlog.NewTestLogger().Init()
	controllerConfig := controller.ContextControllerConfig{
		Providers: []controller.Provider{
			{
				Name:  "Local",
				ID:    "local",
				OAuth: false,
			},
		},
		Title:                 "Tinyauth",
		AppURL:                "https://tinyauth.example.com",
		CookieDomain:          "example.com",
		ForgotPasswordMessage: "foo",
		BackgroundImage:       "/background.jpg",
		OAuthAutoRedirect:     "none",
		WarningsEnabled:       true,
	}

	tests := []struct {
		description string
		middlewares []gin.HandlerFunc
		expected    string
		path        string
	}{
		{
			description: "Ensure context controller returns app context",
			middlewares: []gin.HandlerFunc{},
			path:        "/api/context/app",
			expected: func() string {
				expectedAppContextResponse := controller.AppContextResponse{
					Status:                200,
					Message:               "Success",
					Providers:             controllerConfig.Providers,
					Title:                 controllerConfig.Title,
					AppURL:                controllerConfig.AppURL,
					CookieDomain:          controllerConfig.CookieDomain,
					ForgotPasswordMessage: controllerConfig.ForgotPasswordMessage,
					BackgroundImage:       controllerConfig.BackgroundImage,
					OAuthAutoRedirect:     controllerConfig.OAuthAutoRedirect,
					WarningsEnabled:       controllerConfig.WarningsEnabled,
				}
				bytes, err := json.Marshal(expectedAppContextResponse)
				assert.NoError(t, err)
				return string(bytes)
			}(),
		},
		{
			description: "Ensure user context returns 401 when unauthorized",
			middlewares: []gin.HandlerFunc{},
			path:        "/api/context/user",
			expected: func() string {
				expectedUserContextResponse := controller.UserContextResponse{
					Status:  401,
					Message: "Unauthorized",
				}
				bytes, err := json.Marshal(expectedUserContextResponse)
				assert.NoError(t, err)
				return string(bytes)
			}(),
		},
		{
			description: "Ensure user context returns when authorized",
			middlewares: []gin.HandlerFunc{
				func(c *gin.Context) {
					c.Set("context", &config.UserContext{
						Username:   "johndoe",
						Name:       "John Doe",
						Email:      utils.CompileUserEmail("johndoe", controllerConfig.CookieDomain),
						Provider:   "local",
						IsLoggedIn: true,
					})
				},
			},
			path: "/api/context/user",
			expected: func() string {
				expectedUserContextResponse := controller.UserContextResponse{
					Status:     200,
					Message:    "Success",
					IsLoggedIn: true,
					Username:   "johndoe",
					Name:       "John Doe",
					Email:      utils.CompileUserEmail("johndoe", controllerConfig.CookieDomain),
					Provider:   "local",
				}
				bytes, err := json.Marshal(expectedUserContextResponse)
				assert.NoError(t, err)
				return string(bytes)
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()

			for _, middleware := range test.middlewares {
				router.Use(middleware)
			}

			group := router.Group("/api")
			gin.SetMode(gin.TestMode)

			contextController := controller.NewContextController(controllerConfig, group)
			contextController.SetupRoutes()

			recorder := httptest.NewRecorder()

			request, err := http.NewRequest("GET", test.path, nil)
			assert.NoError(t, err)

			router.ServeHTTP(recorder, request)

			assert.Equal(t, http.StatusOK, recorder.Code)
			assert.Equal(t, test.expected, recorder.Body.String())
		})
	}
}
