package controller_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/bootstrap"
	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestWellKnownController(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)

	type testCase struct {
		description string
		run         func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder)
	}

	tests := []testCase{
		{
			description: "Ensure well-known endpoint returns correct OIDC configuration",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)

				res := controller.OpenIDConnectConfiguration{}
				err := json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)

				expected := controller.OpenIDConnectConfiguration{
					Issuer:                                 runtime.AppURL,
					AuthorizationEndpoint:                  fmt.Sprintf("%s/authorize", runtime.AppURL),
					TokenEndpoint:                          fmt.Sprintf("%s/api/oidc/token", runtime.AppURL),
					UserinfoEndpoint:                       fmt.Sprintf("%s/api/oidc/userinfo", runtime.AppURL),
					JwksUri:                                fmt.Sprintf("%s/.well-known/jwks.json", runtime.AppURL),
					ScopesSupported:                        service.SupportedScopes,
					ResponseTypesSupported:                 service.SupportedResponseTypes,
					GrantTypesSupported:                    service.SupportedGrantTypes,
					SubjectTypesSupported:                  []string{"pairwise"},
					IDTokenSigningAlgValuesSupported:       []string{"RS256"},
					TokenEndpointAuthMethodsSupported:      []string{"client_secret_basic", "client_secret_post"},
					ClaimsSupported:                        []string{"sub", "updated_at", "name", "preferred_username", "email", "email_verified", "groups", "phone_number", "phone_number_verified", "address", "given_name", "family_name", "middle_name", "nickname", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale"},
					ServiceDocumentation:                   "https://tinyauth.app/docs/guides/oidc",
					RequestParameterSupported:              true,
					RequestObjectSigningAlgValuesSupported: []string{"none"},
				}

				assert.Equal(t, expected, res)
			},
		},
		{
			description: "Ensure well-known endpoint returns correct JWKS",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)

				decodedBody := make(map[string]any)
				err := json.Unmarshal(recorder.Body.Bytes(), &decodedBody)
				assert.NoError(t, err)

				keys, ok := decodedBody["keys"].([]any)
				assert.True(t, ok)
				assert.Len(t, keys, 1)

				keyData, ok := keys[0].(map[string]any)
				assert.True(t, ok)
				assert.Equal(t, "RSA", keyData["kty"])
				assert.Equal(t, "sig", keyData["use"])
				assert.Equal(t, "RS256", keyData["alg"])
			},
		},
	}

	ctx := context.TODO()
	wg := &sync.WaitGroup{}

	app := bootstrap.NewBootstrapApp(cfg)

	err := app.SetupDatabase()
	require.NoError(t, err)

	queries := repository.New(app.GetDB())

	oidcService, err := service.NewOIDCService(log, cfg, runtime, queries, ctx, wg)
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()
			gin.SetMode(gin.TestMode)

			recorder := httptest.NewRecorder()

			controller.NewWellKnownController(oidcService, &router.RouterGroup)

			test.run(t, router, recorder)
		})
	}

	t.Cleanup(func() {
		app.GetDB().Close()
	})
}
