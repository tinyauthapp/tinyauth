package controller_test

import (
	"net/http/httptest"
	"path"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tinyauthapp/tinyauth/internal/bootstrap"
	"github.com/tinyauthapp/tinyauth/internal/config"
	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyController(t *testing.T) {
	tlog.NewTestLogger().Init()
	tempDir := t.TempDir()

	authServiceCfg := service.AuthServiceConfig{
		Users: []config.User{
			{
				Username: "testuser",
				Password: "$2a$10$ZwVYQH07JX2zq7Fjkt3gU.BjwvvwPeli4OqOno04RQIv0P7usBrXa", // password
			},
			{
				Username:   "totpuser",
				Password:   "$2a$10$ZwVYQH07JX2zq7Fjkt3gU.BjwvvwPeli4OqOno04RQIv0P7usBrXa", // password
				TotpSecret: "JPIEBDKJH6UGWJMX66RR3S55UFP2SGKK",
			},
		},
		SessionExpiry:     10, // 10 seconds, useful for testing
		CookieDomain:      "example.com",
		LoginTimeout:      10, // 10 seconds, useful for testing
		LoginMaxRetries:   3,
		SessionCookieName: "tinyauth-session",
	}

	controllerCfg := controller.ProxyControllerConfig{
		AppURL: "https://tinyauth.example.com",
	}

	acls := map[string]config.App{
		"app_path_allow": {
			Config: config.AppConfig{
				Domain: "path-allow.example.com",
			},
			Path: config.AppPath{
				Allow: "/allowed",
			},
		},
		"app_user_allow": {
			Config: config.AppConfig{
				Domain: "user-allow.example.com",
			},
			Users: config.AppUsers{
				Allow: "testuser",
			},
		},
		"ip_bypass": {
			Config: config.AppConfig{
				Domain: "ip-bypass.example.com",
			},
			IP: config.AppIP{
				Bypass: []string{"10.10.10.10"},
			},
		},
	}

	const browserUserAgent = `
	Mozilla/5.0 (Linux; Android 8.0.0; SM-G955U Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36`

	simpleCtx := func(c *gin.Context) {
		c.Set("context", &config.UserContext{
			Username:   "testuser",
			Name:       "Testuser",
			Email:      "testuser@example.com",
			IsLoggedIn: true,
			Provider:   "local",
		})
		c.Next()
	}

	simpleCtxTotp := func(c *gin.Context) {
		c.Set("context", &config.UserContext{
			Username:    "totpuser",
			Name:        "Totpuser",
			Email:       "totpuser@example.com",
			IsLoggedIn:  true,
			Provider:    "local",
			TotpEnabled: true,
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

	oauthBrokerCfgs := make(map[string]config.OAuthServiceConfig)

	app := bootstrap.NewBootstrapApp(config.Config{})

	db, err := app.SetupDatabase(path.Join(tempDir, "tinyauth.db"))
	require.NoError(t, err)

	queries := repository.New(db)

	docker := service.NewDockerService()
	err = docker.Init()
	require.NoError(t, err)

	ldap := service.NewLdapService(service.LdapServiceConfig{})
	err = ldap.Init()
	require.NoError(t, err)

	broker := service.NewOAuthBrokerService(oauthBrokerCfgs)
	err = broker.Init()
	require.NoError(t, err)

	authService := service.NewAuthService(authServiceCfg, ldap, queries, broker)
	err = authService.Init()
	require.NoError(t, err)

	aclsService := service.NewAccessControlsService(docker, acls)

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()

			for _, m := range test.middlewares {
				router.Use(m)
			}

			group := router.Group("/api")
			gin.SetMode(gin.TestMode)

			recorder := httptest.NewRecorder()

			proxyController := controller.NewProxyController(controllerCfg, group, aclsService, authService)
			proxyController.SetupRoutes()

			test.run(t, router, recorder)
		})
	}

	t.Cleanup(func() {
		err = db.Close()
		require.NoError(t, err)
	})
}
