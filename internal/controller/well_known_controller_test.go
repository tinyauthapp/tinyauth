package controller_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/bootstrap"
	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
)

func TestWellKnownController(t *testing.T) {
	tlog.NewTestLogger().Init()
	tempDir := t.TempDir()

	oidcServiceCfg := service.OIDCServiceConfig{
		Clients: map[string]model.OIDCClientConfig{
			"test": {
				ClientID:            "some-client-id",
				ClientSecret:        "some-client-secret",
				TrustedRedirectURIs: []string{"https://test.example.com/callback"},
				Name:                "Test Client",
			},
		},
		PrivateKeyPath: path.Join(tempDir, "key.pem"),
		PublicKeyPath:  path.Join(tempDir, "key.pub"),
		Issuer:         "https://tinyauth.example.com",
		SessionExpiry:  500,
	}

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
					Issuer:                                 oidcServiceCfg.Issuer,
					AuthorizationEndpoint:                  fmt.Sprintf("%s/authorize", oidcServiceCfg.Issuer),
					TokenEndpoint:                          fmt.Sprintf("%s/api/oidc/token", oidcServiceCfg.Issuer),
					UserinfoEndpoint:                       fmt.Sprintf("%s/api/oidc/userinfo", oidcServiceCfg.Issuer),
					JwksUri:                                fmt.Sprintf("%s/.well-known/jwks.json", oidcServiceCfg.Issuer),
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

	app := bootstrap.NewBootstrapApp(model.Config{})

	db, err := app.SetupDatabase(path.Join(tempDir, "tinyauth.db"))
	require.NoError(t, err)

	queries := repository.New(db)

	oidcService := service.NewOIDCService(oidcServiceCfg, queries)
	err = oidcService.Init()
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()
			gin.SetMode(gin.TestMode)

			recorder := httptest.NewRecorder()

			wellKnownController := controller.NewWellKnownController(controller.WellKnownControllerConfig{}, oidcService, router)
			wellKnownController.SetupRoutes()

			test.run(t, router, recorder)
		})
	}

	t.Cleanup(func() {
		err = db.Close()
		require.NoError(t, err)
	})
}
