package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/ding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/repository/memory"
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
		oidcEnabled bool
		run         func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder)
	}

	tests := []testCase{
		{
			description: "Ensure well-known endpoint returns correct OIDC configuration",
			oidcEnabled: true,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)

				res := OpenIDConnectConfiguration{}
				err := json.Unmarshal(recorder.Body.Bytes(), &res)
				require.NoError(t, err)

				expected := OpenIDConnectConfiguration{
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
					RequestObjectSigningAlgValuesSupported: []string{"none"},
					RequestParameterSupported:              true,
				}

				assert.Equal(t, expected, res)
			},
		},
		{
			description: "Ensure well-known endpoint returns correct JWKS",
			oidcEnabled: true,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)

				decodedBody := make(map[string]any)
				err := json.Unmarshal(recorder.Body.Bytes(), &decodedBody)
				require.NoError(t, err)

				keys, ok := decodedBody["keys"].([]any)
				require.True(t, ok)
				assert.Len(t, keys, 1)

				keyData, ok := keys[0].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, "RSA", keyData["kty"])
				assert.Equal(t, "sig", keyData["use"])
				assert.Equal(t, "RS256", keyData["alg"])
			},
		},
		{
			description: "Ensure openid configuration returns 500 on nil oidc service",
			oidcEnabled: false,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 500, recorder.Code)

				decodedBody := make(map[string]any)
				err := json.Unmarshal(recorder.Body.Bytes(), &decodedBody)
				require.NoError(t, err)

				assert.Equal(t, "OIDC service not configured", decodedBody["message"])
			},
		},
		{
			description: "Ensure jwks endpoint returns 500 on nil oidc service",
			oidcEnabled: false,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 500, recorder.Code)

				decodedBody := make(map[string]any)
				err := json.Unmarshal(recorder.Body.Bytes(), &decodedBody)
				require.NoError(t, err)

				assert.Equal(t, "OIDC service not configured", decodedBody["message"])
			},
		},
		{
			description: "Ensure webfinger returns 400 on invalid resource",
			oidcEnabled: true,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/.well-known/webfinger?resource=invalid-resource", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 400, recorder.Code)
				assert.Equal(t, "application/jrd+json", recorder.Header().Get("content-type"))
				assert.Equal(t, "*", recorder.Header().Get("access-control-allow-origin"))

				decodedBody := make(map[string]any)
				err := json.Unmarshal(recorder.Body.Bytes(), &decodedBody)
				require.NoError(t, err)

				assert.Equal(t, "invalid resource", decodedBody["message"])
			},
		},
		{
			description: "Ensure webfinger resource validator allows acct",
			oidcEnabled: true,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				resource := "acct:testuser@example.com"
				req := httptest.NewRequest("GET", fmt.Sprintf("/.well-known/webfinger?resource=%s", url.QueryEscape(resource)), nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Equal(t, "application/jrd+json", recorder.Header().Get("content-type"))
				assert.Equal(t, "*", recorder.Header().Get("access-control-allow-origin"))
			},
		},
		{
			description: "Ensure webfinger resource validator allows https",
			oidcEnabled: true,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				resource := "https://example.com/testuser"
				req := httptest.NewRequest("GET", fmt.Sprintf("/.well-known/webfinger?resource=%s", url.QueryEscape(resource)), nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Equal(t, "application/jrd+json", recorder.Header().Get("content-type"))
				assert.Equal(t, "*", recorder.Header().Get("access-control-allow-origin"))
			},
		},
		{
			description: "Ensure webfinger resource validator allows http",
			oidcEnabled: true,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				resource := "http://example.com/testuser"
				req := httptest.NewRequest("GET", fmt.Sprintf("/.well-known/webfinger?resource=%s", url.QueryEscape(resource)), nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Equal(t, "application/jrd+json", recorder.Header().Get("content-type"))
				assert.Equal(t, "*", recorder.Header().Get("access-control-allow-origin"))
			},
		},
		{
			description: "Webfinger should return no links when oidc is nil",
			oidcEnabled: false,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				resource := "acct:testuser@example.com"
				req := httptest.NewRequest("GET", fmt.Sprintf("/.well-known/webfinger?resource=%s", url.QueryEscape(resource)), nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Equal(t, "application/jrd+json", recorder.Header().Get("content-type"))
				assert.Equal(t, "*", recorder.Header().Get("access-control-allow-origin"))

				decodedBody := make(map[string]any)
				err := json.Unmarshal(recorder.Body.Bytes(), &decodedBody)
				require.NoError(t, err)

				links, ok := decodedBody["links"].([]any)
				require.True(t, ok)
				assert.Len(t, links, 0)
			},
		},
		{
			description: "Webfinger should return links when oidc is configured and no rel is provided",
			oidcEnabled: true,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				resource := "acct:testuser@example.com"
				req := httptest.NewRequest("GET", fmt.Sprintf("/.well-known/webfinger?resource=%s", url.QueryEscape(resource)), nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Equal(t, "application/jrd+json", recorder.Header().Get("content-type"))
				assert.Equal(t, "*", recorder.Header().Get("access-control-allow-origin"))

				decodedBody := make(map[string]any)
				err := json.Unmarshal(recorder.Body.Bytes(), &decodedBody)
				require.NoError(t, err)

				links, ok := decodedBody["links"].([]any)
				require.True(t, ok)
				assert.Len(t, links, 1)

				linkData, ok := links[0].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, "http://openid.net/specs/connect/1.0/issuer", linkData["rel"])
				assert.Equal(t, runtime.AppURL, linkData["href"])
			},
		},
		{
			description: "Webfinger should return links when oidc is configured and rel is provided",
			oidcEnabled: true,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				resource := fmt.Sprintf("acct:%s@%s", "testuser", runtime.AppURL)
				rel := "http://openid.net/specs/connect/1.0/issuer"
				req := httptest.NewRequest("GET", fmt.Sprintf("/.well-known/webfinger?resource=%s&rel=%s", url.QueryEscape(resource), url.QueryEscape(rel)), nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Equal(t, "application/jrd+json", recorder.Header().Get("content-type"))
				assert.Equal(t, "*", recorder.Header().Get("access-control-allow-origin"))

				decodedBody := make(map[string]any)
				err := json.Unmarshal(recorder.Body.Bytes(), &decodedBody)
				require.NoError(t, err)

				links, ok := decodedBody["links"].([]any)
				require.True(t, ok)
				assert.Len(t, links, 1)

				linkData, ok := links[0].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, rel, linkData["rel"])
				assert.Equal(t, runtime.AppURL, linkData["href"])
			},
		},
		{
			description: "Webfinger should return no links when oidc is configured and rel is provided but does not match",
			oidcEnabled: true,
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				resource := "acct:testuser@example.com"
				rel := "http://example.com/does-not-exist"
				req := httptest.NewRequest("GET", fmt.Sprintf("/.well-known/webfinger?resource=%s&rel=%s", url.QueryEscape(resource), url.QueryEscape(rel)), nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Equal(t, "application/jrd+json", recorder.Header().Get("content-type"))
				assert.Equal(t, "*", recorder.Header().Get("access-control-allow-origin"))

				decodedBody := make(map[string]any)
				err := json.Unmarshal(recorder.Body.Bytes(), &decodedBody)
				require.NoError(t, err)

				links, ok := decodedBody["links"].([]any)
				require.True(t, ok)
				assert.Len(t, links, 0)
			},
		},
	}

	ctx := context.TODO()
	dg := ding.New(ctx)

	store := memory.New()

	oidcService, err := service.NewOIDCService(service.OIDCServiceInput{
		Log:     log,
		Config:  &cfg,
		Runtime: &runtime,
		Queries: store,
		Ding:    dg,
	})
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()
			gin.SetMode(gin.TestMode)

			recorder := httptest.NewRecorder()

			wellKnownControllerInput := WellKnownControllerInput{
				RouterGroup: &router.RouterGroup,
			}

			if test.oidcEnabled {
				wellKnownControllerInput.OIDCService = oidcService
			}

			NewWellKnownController(wellKnownControllerInput)

			test.run(t, router, recorder)
		})
	}
}
