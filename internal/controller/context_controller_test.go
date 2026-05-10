package controller_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestContextController(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)

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
					Status:  200,
					Message: "Success",
					Auth: controller.ACRAuth{
						Providers: runtime.ConfiguredProviders,
					},
					OAuth: controller.ACROAuth{
						AutoRedirect: cfg.OAuth.AutoRedirect,
					},
					UI: controller.ACRUI{
						Title:                 cfg.UI.Title,
						ForgotPasswordMessage: cfg.UI.ForgotPasswordMessage,
						BackgroundImage:       cfg.UI.BackgroundImage,
						WarningsEnabled:       cfg.UI.WarningsEnabled,
					},
					App: controller.ACRApp{
						AppURL:         runtime.AppURL,
						CookieDomain:   runtime.CookieDomain,
						TrustedDomains: runtime.TrustedDomains,
					},
				}
				bytes, err := json.Marshal(expectedAppContextResponse)
				require.NoError(t, err)
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
				require.NoError(t, err)
				return string(bytes)
			}(),
		},
		{
			description: "Ensure user context returns when authorized",
			middlewares: []gin.HandlerFunc{
				func(c *gin.Context) {
					c.Set("context", &model.UserContext{
						Authenticated: true,
						Provider:      model.ProviderLocal,
						Local: &model.LocalContext{
							BaseContext: model.BaseContext{
								Username: "johndoe",
								Name:     "John Doe",
								Email:    utils.CompileUserEmail("johndoe", runtime.CookieDomain),
							},
						},
					})
				},
			},
			path: "/api/context/user",
			expected: func() string {
				expectedUserContextResponse := controller.UserContextResponse{
					Status:  200,
					Message: "Success",
					Auth: controller.UCRAuth{
						Authenticated: true,
						Username:      "johndoe",
						Name:          "John Doe",
						Email:         utils.CompileUserEmail("johndoe", runtime.CookieDomain),
						ProviderID:    "local",
					},
				}
				bytes, err := json.Marshal(expectedUserContextResponse)
				require.NoError(t, err)
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

			controller.NewContextController(log, cfg, runtime, group)

			recorder := httptest.NewRecorder()

			request, err := http.NewRequest("GET", test.path, nil)
			require.NoError(t, err)

			router.ServeHTTP(recorder, request)

			assert.Equal(t, http.StatusOK, recorder.Code)
			assert.Equal(t, test.expected, recorder.Body.String())
		})
	}
}
