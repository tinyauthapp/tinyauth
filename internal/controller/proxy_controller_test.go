package controller_test

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/bootstrap"
	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestProxyController(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)

	acls := map[string]model.App{
		"app_path_allow": {
			Config: model.AppConfig{
				Domain: "path-allow.example.com",
			},
			Path: model.AppPath{
				Allow: "/allowed",
			},
		},
		"app_user_allow": {
			Config: model.AppConfig{
				Domain: "user-allow.example.com",
			},
			Users: model.AppUsers{
				Allow: "testuser",
			},
		},
		"ip_bypass": {
			Config: model.AppConfig{
				Domain: "ip-bypass.example.com",
			},
			IP: model.AppIP{
				Bypass: []string{"10.10.10.10"},
			},
		},
	}

	const browserUserAgent = `
	Mozilla/5.0 (Linux; Android 8.0.0; SM-G955U Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36`

	simpleCtx := func(c *gin.Context) {
		c.Set("context", &model.UserContext{
			Authenticated: true,
			Provider:      model.ProviderLocal,
			Local: &model.LocalContext{
				BaseContext: model.BaseContext{
					Username: "testuser",
					Name:     "Testuser",
					Email:    "testuser@example.com",
				},
			},
		})
		c.Next()
	}

	simpleCtxTotp := func(c *gin.Context) {
		c.Set("context", &model.UserContext{
			Authenticated: true,
			Provider:      model.ProviderLocal,
			Local: &model.LocalContext{
				BaseContext: model.BaseContext{
					Username: "totpuser",
					Name:     "Totpuser",
					Email:    "totpuser@example.com",
				},
			},
		})
		c.Next()
	}

	type testCase struct {
		description string
		middlewares []gin.HandlerFunc
		run         func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder)
	}

	tests := []testCase{
		{
			description: "Default forward auth should be detected and used for traefik",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 307, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Equal(t, "https://tinyauth.example.com/login?redirect_uri=https%3A%2F%2Ftest.example.com%2F", location)
			},
		},
		{
			description: "Auth request (nginx) should be detected and used",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/nginx", nil)
				req.Header.Set("x-original-url", "https://test.example.com/")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 401, recorder.Code)
				location := recorder.Header().Get("x-tinyauth-location")
				assert.Equal(t, "https://tinyauth.example.com/login?redirect_uri=https%3A%2F%2Ftest.example.com%2F", location)
			},
		},
		{
			description: "Ext authz (envoy) should be detected and used",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("HEAD", "/api/auth/envoy?path=/hello", nil) // test a different method for envoy
				req.Host = "test.example.com"
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 307, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Equal(t, "https://tinyauth.example.com/login?redirect_uri=https%3A%2F%2Ftest.example.com%2Fhello", location)
			},
		},
		{
			description: "Forward auth with caddy should be detected and used",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/caddy", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 307, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Equal(t, "https://tinyauth.example.com/login?redirect_uri=https%3A%2F%2Ftest.example.com%2F", location)
			},
		},
		{
			description: "Ensure forward auth fallback for nginx",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/nginx", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 401, recorder.Code)
				location := recorder.Header().Get("x-tinyauth-location")
				assert.Equal(t, "https://tinyauth.example.com/login?redirect_uri=https%3A%2F%2Ftest.example.com%2F", location)
			},
		},
		{
			description: "Ensure forward auth fallback for envoy",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("HEAD", "/api/auth/envoy?path=/hello", nil)
				req.Host = ""
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/hello")
				req.Header.Set("user-agent", browserUserAgent)
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 307, recorder.Code)
				location := recorder.Header().Get("Location")
				assert.Equal(t, "https://tinyauth.example.com/login?redirect_uri=https%3A%2F%2Ftest.example.com%2Fhello", location)
			},
		},
		{
			description: "Ensure forward auth with non browser returns json for traefik",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 401, recorder.Code)
				assert.Contains(t, recorder.Body.String(), `"status":401`)
				assert.Contains(t, recorder.Body.String(), `"message":"Unauthorized"`)
			},
		},
		{
			description: "Ensure forward auth with non browser returns json for caddy",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/caddy", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 401, recorder.Code)
				assert.Contains(t, recorder.Body.String(), `"status":401`)
				assert.Contains(t, recorder.Body.String(), `"message":"Unauthorized"`)
			},
		},
		{
			description: "Ensure extauthz with envoy non browser returns json",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("HEAD", "/api/auth/envoy?path=/hello", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/hello")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 401, recorder.Code)
				assert.Contains(t, recorder.Body.String(), `"status":401`)
				assert.Contains(t, recorder.Body.String(), `"message":"Unauthorized"`)
			},
		},
		{
			description: "Ensure normal authentication flow for forward auth",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "test.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Equal(t, "testuser", recorder.Header().Get("remote-user"))
				assert.Equal(t, "Testuser", recorder.Header().Get("remote-name"))
				assert.Equal(t, "testuser@example.com", recorder.Header().Get("remote-email"))
			},
		},
		{
			description: "Ensure normal authentication flow for nginx auth request",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/nginx", nil)
				req.Header.Set("x-original-url", "https://test.example.com/")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Equal(t, "testuser", recorder.Header().Get("remote-user"))
				assert.Equal(t, "Testuser", recorder.Header().Get("remote-name"))
				assert.Equal(t, "testuser@example.com", recorder.Header().Get("remote-email"))
			},
		},
		{
			description: "Ensure normal authentication flow for envoy ext authz",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("HEAD", "/api/auth/envoy?path=/hello", nil)
				req.Host = "test.example.com"
				req.Header.Set("x-forwarded-proto", "https")
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Equal(t, "testuser", recorder.Header().Get("remote-user"))
				assert.Equal(t, "Testuser", recorder.Header().Get("remote-name"))
				assert.Equal(t, "testuser@example.com", recorder.Header().Get("remote-email"))
			},
		},
		{
			description: "Ensure path allow ACL works on forward auth",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "path-allow.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/allowed")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)
			},
		},
		{
			description: "Ensure path allow ACL works on nginx auth request",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/nginx", nil)
				req.Header.Set("x-original-url", "https://path-allow.example.com/allowed")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)
			},
		},
		{
			description: "Ensure path allow ACL works on envoy ext authz",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("HEAD", "/api/auth/envoy?path=/allowed", nil)
				req.Host = "path-allow.example.com"
				req.Header.Set("x-forwarded-proto", "https")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)
			},
		},
		{
			description: "Ensure ip bypass ACL works on forward auth",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "ip-bypass.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				req.Header.Set("x-forwarded-for", "10.10.10.10")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)
			},
		},
		{
			description: "Ensure ip bypass ACL works on nginx auth request",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/nginx", nil)
				req.Header.Set("x-original-url", "https://ip-bypass.example.com/")
				req.Header.Set("x-forwarded-for", "10.10.10.10")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)
			},
		},
		{
			description: "Ensure ip bypass ACL works on envoy ext authz",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("HEAD", "/api/auth/envoy?path=/hello", nil)
				req.Host = "ip-bypass.example.com"
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-for", "10.10.10.10")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)
			},
		},
		{
			description: "Ensure user allow ACL allows correct user (should allow testuser)",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "user-allow.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 200, recorder.Code)
			},
		},
		{
			description: "Ensure user allow ACL blocks incorrect user (should block totpuser)",
			middlewares: []gin.HandlerFunc{
				simpleCtxTotp,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/api/auth/traefik", nil)
				req.Header.Set("x-forwarded-host", "user-allow.example.com")
				req.Header.Set("x-forwarded-proto", "https")
				req.Header.Set("x-forwarded-uri", "/")
				router.ServeHTTP(recorder, req)
				assert.Equal(t, 403, recorder.Code)
				assert.Equal(t, "", recorder.Header().Get("remote-user"))
				assert.Equal(t, "", recorder.Header().Get("remote-name"))
				assert.Equal(t, "", recorder.Header().Get("remote-email"))
			},
		},
	}

	app := bootstrap.NewBootstrapApp(cfg)

	err := app.SetupDatabase()
	require.NoError(t, err)

	queries := repository.New(app.GetDB())

	wg := &sync.WaitGroup{}
	ctx := context.TODO()

	broker := service.NewOAuthBrokerService(log, map[string]model.OAuthServiceConfig{}, ctx)
	authService := service.NewAuthService(log, cfg, runtime, ctx, wg, nil, queries, broker)
	aclsService := service.NewAccessControlsService(log, nil, acls)

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()

			for _, m := range test.middlewares {
				router.Use(m)
			}

			group := router.Group("/api")
			gin.SetMode(gin.TestMode)

			recorder := httptest.NewRecorder()

			controller.NewProxyController(log, runtime, group, aclsService, authService)

			test.run(t, router, recorder)
		})
	}

	t.Cleanup(func() {
		app.GetDB().Close()
	})
}
