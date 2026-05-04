package controller_test

import (
	"encoding/json"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"github.com/tinyauthapp/tinyauth/internal/bootstrap"
	"github.com/tinyauthapp/tinyauth/internal/config"
	"github.com/tinyauthapp/tinyauth/internal/controller"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserController(t *testing.T) {
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
			{
				Username: "attruser",
				Password: "$2a$10$ZwVYQH07JX2zq7Fjkt3gU.BjwvvwPeli4OqOno04RQIv0P7usBrXa", // password
				Attributes: config.UserAttributes{
					Name:  "Alice Smith",
					Email: "alice@example.com",
				},
			},
			{
				Username:   "attrtotpuser",
				Password:   "$2a$10$ZwVYQH07JX2zq7Fjkt3gU.BjwvvwPeli4OqOno04RQIv0P7usBrXa", // password
				TotpSecret: "JPIEBDKJH6UGWJMX66RR3S55UFP2SGKK",
				Attributes: config.UserAttributes{
					Name:  "Bob Jones",
					Email: "bob@example.com",
				},
			},
		},
		SessionExpiry:     10, // 10 seconds, useful for testing
		CookieDomain:      "example.com",
		LoginTimeout:      10, // 10 seconds, useful for testing
		LoginMaxRetries:   3,
		SessionCookieName: "tinyauth-session",
	}

	userControllerCfg := controller.UserControllerConfig{
		CookieDomain: "example.com",
	}

	type testCase struct {
		description string
		middlewares []gin.HandlerFunc
		run         func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder)
	}

	tests := []testCase{
		{
			description: "Should be able to login with valid credentials",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				loginReq := controller.LoginRequest{
					Username: "testuser",
					Password: "password",
				}
				loginReqBody, err := json.Marshal(loginReq)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
				req.Header.Set("Content-Type", "application/json")

				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Len(t, recorder.Result().Cookies(), 1)

				cookie := recorder.Result().Cookies()[0]
				assert.Equal(t, "tinyauth-session", cookie.Name)
				assert.True(t, cookie.HttpOnly)
				assert.Equal(t, "example.com", cookie.Domain)
				assert.Equal(t, 10, cookie.MaxAge)
			},
		},
		{
			description: "Should reject login with invalid credentials",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				loginReq := controller.LoginRequest{
					Username: "testuser",
					Password: "wrongpassword",
				}
				loginReqBody, err := json.Marshal(loginReq)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
				req.Header.Set("Content-Type", "application/json")

				router.ServeHTTP(recorder, req)

				assert.Equal(t, 401, recorder.Code)
				assert.Len(t, recorder.Result().Cookies(), 0)
				assert.Contains(t, recorder.Body.String(), "Unauthorized")
			},
		},
		{
			description: "Should rate limit on 3 invalid attempts",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				loginReq := controller.LoginRequest{
					Username: "testuser",
					Password: "wrongpassword",
				}
				loginReqBody, err := json.Marshal(loginReq)
				assert.NoError(t, err)

				for range 3 {
					recorder := httptest.NewRecorder()

					req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
					req.Header.Set("Content-Type", "application/json")

					router.ServeHTTP(recorder, req)

					assert.Equal(t, 401, recorder.Code)
					assert.Len(t, recorder.Result().Cookies(), 0)
					assert.Contains(t, recorder.Body.String(), "Unauthorized")
				}

				// 4th attempt should be rate limited
				recorder = httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
				req.Header.Set("Content-Type", "application/json")

				router.ServeHTTP(recorder, req)

				assert.Equal(t, 429, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "Too many failed login attempts.")
			},
		},
		{
			description: "Should not allow full login with totp",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				loginReq := controller.LoginRequest{
					Username: "totpuser",
					Password: "password",
				}
				loginReqBody, err := json.Marshal(loginReq)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
				req.Header.Set("Content-Type", "application/json")

				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)

				decodedBody := make(map[string]any)
				err = json.Unmarshal(recorder.Body.Bytes(), &decodedBody)
				assert.NoError(t, err)

				assert.Equal(t, decodedBody["totpPending"], true)

				// should set the session cookie
				assert.Len(t, recorder.Result().Cookies(), 1)
				cookie := recorder.Result().Cookies()[0]
				assert.Equal(t, "tinyauth-session", cookie.Name)
				assert.True(t, cookie.HttpOnly)
				assert.Equal(t, "example.com", cookie.Domain)
				assert.Equal(t, 3600, cookie.MaxAge) // 1 hour, default for totp pending sessions
			},
		},
		{
			description: "Should be able to logout",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				// First login to get a session cookie
				loginReq := controller.LoginRequest{
					Username: "testuser",
					Password: "password",
				}
				loginReqBody, err := json.Marshal(loginReq)
				assert.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
				req.Header.Set("Content-Type", "application/json")

				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Len(t, recorder.Result().Cookies(), 1)

				cookie := recorder.Result().Cookies()[0]
				assert.Equal(t, "tinyauth-session", cookie.Name)

				// Now logout using the session cookie
				recorder = httptest.NewRecorder()
				req = httptest.NewRequest("POST", "/api/user/logout", nil)
				req.AddCookie(cookie)

				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Len(t, recorder.Result().Cookies(), 1)

				logoutCookie := recorder.Result().Cookies()[0]
				assert.Equal(t, "tinyauth-session", logoutCookie.Name)
				assert.Equal(t, "", logoutCookie.Value)
				assert.Equal(t, -1, logoutCookie.MaxAge) // MaxAge -1 means delete cookie
			},
		},
		{
			description: "Should be able to login with totp",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				code, err := totp.GenerateCode("JPIEBDKJH6UGWJMX66RR3S55UFP2SGKK", time.Now())
				assert.NoError(t, err)

				totpReq := controller.TotpRequest{
					Code: code,
				}

				totpReqBody, err := json.Marshal(totpReq)
				assert.NoError(t, err)

				recorder = httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/api/user/totp", strings.NewReader(string(totpReqBody)))
				req.Header.Set("Content-Type", "application/json")

				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Len(t, recorder.Result().Cookies(), 1)

				// should set a new session cookie with totp pending removed
				totpCookie := recorder.Result().Cookies()[0]
				assert.Equal(t, "tinyauth-session", totpCookie.Name)
				assert.True(t, totpCookie.HttpOnly)
				assert.Equal(t, "example.com", totpCookie.Domain)
				assert.Equal(t, 10, totpCookie.MaxAge) // should use the regular session expiry time
			},
		},
		{
			description: "Totp should rate limit on multiple invalid attempts",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				for range 3 {
					totpReq := controller.TotpRequest{
						Code: "000000", // invalid code
					}

					totpReqBody, err := json.Marshal(totpReq)
					assert.NoError(t, err)

					recorder = httptest.NewRecorder()
					req := httptest.NewRequest("POST", "/api/user/totp", strings.NewReader(string(totpReqBody)))
					req.Header.Set("Content-Type", "application/json")

					router.ServeHTTP(recorder, req)

					assert.Equal(t, 401, recorder.Code)
					assert.Contains(t, recorder.Body.String(), "Unauthorized")
				}

				// 4th attempt should be rate limited
				recorder = httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/api/user/totp", strings.NewReader(string(`{"code":"000000"}`)))
				req.Header.Set("Content-Type", "application/json")

				router.ServeHTTP(recorder, req)

				assert.Equal(t, 429, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "Too many failed TOTP attempts.")
			},
		},
		{
			description: "Login uses name and email from user attributes",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				loginReq := controller.LoginRequest{Username: "attruser", Password: "password"}
				body, err := json.Marshal(loginReq)
				require.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)

				require.Equal(t, 200, recorder.Code)
				cookies := recorder.Result().Cookies()
				require.Len(t, cookies, 1)
				assert.Equal(t, "tinyauth-session", cookies[0].Name)
			},
		},
		{
			description: "Login with TOTP uses name and email from user attributes in pending session",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				loginReq := controller.LoginRequest{Username: "attrtotpuser", Password: "password"}
				body, err := json.Marshal(loginReq)
				require.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)

				require.Equal(t, 200, recorder.Code)
				var res map[string]any
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))
				assert.Equal(t, true, res["totpPending"])
				require.Len(t, recorder.Result().Cookies(), 1)
			},
		},
		{
			description: "TOTP completion uses name and email from user attributes",
			middlewares: []gin.HandlerFunc{},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				code, err := totp.GenerateCode("JPIEBDKJH6UGWJMX66RR3S55UFP2SGKK", time.Now())
				require.NoError(t, err)

				totpReq := controller.TotpRequest{Code: code}
				body, err := json.Marshal(totpReq)
				require.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/user/totp", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(recorder, req)

				require.Equal(t, 200, recorder.Code)
				cookies := recorder.Result().Cookies()
				require.Len(t, cookies, 1)
				assert.Equal(t, "tinyauth-session", cookies[0].Name)
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

	beforeEach := func() {
		// Clear failed login attempts before each test
		authService.ClearRateLimitsTestingOnly()
	}

	setTotpMiddlewareOverrides := map[string]config.UserContext{
		"Should be able to login with totp": {
			Username:    "totpuser",
			Name:        "Totpuser",
			Email:       "totpuser@example.com",
			Provider:    "local",
			TotpPending: true,
			TotpEnabled: true,
		},
		"Totp should rate limit on multiple invalid attempts": {
			Username:    "totpuser",
			Name:        "Totpuser",
			Email:       "totpuser@example.com",
			Provider:    "local",
			TotpPending: true,
			TotpEnabled: true,
		},
		"TOTP completion uses name and email from user attributes": {
			Username:    "attrtotpuser",
			Name:        "Bob Jones",
			Email:       "bob@example.com",
			Provider:    "local",
			TotpPending: true,
			TotpEnabled: true,
		},
	}

	for _, test := range tests {
		beforeEach()
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()

			for _, middleware := range test.middlewares {
				router.Use(middleware)
			}

			// Gin is stupid and doesn't allow setting a middleware after the groups
			// so we need to do some stupid overrides here
			if ctx, ok := setTotpMiddlewareOverrides[test.description]; ok {
				ctx := ctx
				router.Use(func(c *gin.Context) {
					c.Set("context", &ctx)
				})
			}

			group := router.Group("/api")
			gin.SetMode(gin.TestMode)

			userController := controller.NewUserController(userControllerCfg, group, authService)
			userController.SetupRoutes()

			recorder := httptest.NewRecorder()

			test.run(t, router, recorder)
		})
	}

	t.Cleanup(func() {
		err = db.Close()
		require.NoError(t, err)
	})
}
