package controller_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
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

func TestUserController(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	cfg, runtime := test.CreateTestConfigs(t)

	totpCtx := func(c *gin.Context) {
		c.Set("context", &model.UserContext{
			Authenticated: false,
			Provider:      model.ProviderLocal,
			Local: &model.LocalContext{
				BaseContext: model.BaseContext{
					Username: "totpuser",
					Name:     "Totpuser",
					Email:    "totpuser@example.com",
				},
				TOTPPending: true,
			},
		})
	}

	totpAttrCtx := func(c *gin.Context) {
		c.Set("context", &model.UserContext{
			Authenticated: false,
			Provider:      model.ProviderLocal,
			Local: &model.LocalContext{
				BaseContext: model.BaseContext{
					Username: "attrtotpuser",
					Name:     "Bob Jones",
					Email:    "bob@example.com",
				},
				TOTPPending: true,
			},
		})
	}

	simpleCtx := func(c *gin.Context) {
		c.Set("context", &model.UserContext{
			Authenticated: true,
			Provider:      model.ProviderLocal,
			Local: &model.LocalContext{
				BaseContext: model.BaseContext{
					Username: "testuser",
					Name:     "Test User",
					Email:    "testuser@example.com",
				},
			},
		})
	}

	app := bootstrap.NewBootstrapApp(cfg)

	err := app.SetupDatabase()
	require.NoError(t, err)

	queries := repository.New(app.GetDB())

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
				require.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
				req.Header.Set("Content-Type", "application/json")

				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				require.Len(t, recorder.Result().Cookies(), 1)

				cookie := recorder.Result().Cookies()[0]
				assert.Equal(t, "tinyauth-session", cookie.Name)
				assert.True(t, cookie.HttpOnly)
				assert.Equal(t, "example.com", cookie.Domain)
				// 3 seconds should be more than enough for even slow test environments
				assert.GreaterOrEqual(t, cookie.MaxAge, 7)
				assert.LessOrEqual(t, cookie.MaxAge, 10)
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
				require.NoError(t, err)

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
				require.NoError(t, err)

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
				require.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
				req.Header.Set("Content-Type", "application/json")

				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)

				decodedBody := make(map[string]any)
				err = json.Unmarshal(recorder.Body.Bytes(), &decodedBody)
				require.NoError(t, err)

				assert.Equal(t, decodedBody["totpPending"], true)

				// should set the session cookie
				require.Len(t, recorder.Result().Cookies(), 1)
				cookie := recorder.Result().Cookies()[0]
				assert.Equal(t, "tinyauth-session", cookie.Name)
				assert.True(t, cookie.HttpOnly)
				assert.Equal(t, "example.com", cookie.Domain)
				assert.GreaterOrEqual(t, cookie.MaxAge, 3597)
				assert.LessOrEqual(t, cookie.MaxAge, 3600)
			},
		},
		{
			description: "Should be able to logout",
			middlewares: []gin.HandlerFunc{
				simpleCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				// First login to get a session cookie
				loginReq := controller.LoginRequest{
					Username: "testuser",
					Password: "password",
				}
				loginReqBody, err := json.Marshal(loginReq)
				require.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(string(loginReqBody)))
				req.Header.Set("Content-Type", "application/json")

				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				cookies := recorder.Result().Cookies()
				require.Len(t, cookies, 1)

				cookie := cookies[0]
				assert.Equal(t, "tinyauth-session", cookie.Name)

				// Now logout using the session cookie
				recorder = httptest.NewRecorder()
				req = httptest.NewRequest("POST", "/api/user/logout", nil)
				req.AddCookie(cookie)

				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				cookies = recorder.Result().Cookies()
				require.Len(t, cookies, 1)

				cookie = cookies[0]
				assert.Equal(t, "tinyauth-session", cookie.Name)
				assert.Equal(t, "", cookie.Value)
				assert.Equal(t, -1, cookie.MaxAge) // MaxAge -1 means delete cookie
			},
		},
		{
			description: "Should be able to login with totp",
			middlewares: []gin.HandlerFunc{
				totpCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				_, err := queries.CreateSession(context.TODO(), repository.CreateSessionParams{
					UUID:        "test-totp-login-uuid",
					Username:    "test",
					Email:       "test@example.com",
					Name:        "Test",
					Provider:    "local",
					TotpPending: true,
					Expiry:      time.Now().Add(1 * time.Hour).Unix(),
					CreatedAt:   time.Now().Unix(),
				})
				require.NoError(t, err)

				code, err := totp.GenerateCode("JPIEBDKJH6UGWJMX66RR3S55UFP2SGKK", time.Now())
				require.NoError(t, err)

				totpReq := controller.TotpRequest{
					Code: code,
				}

				totpReqBody, err := json.Marshal(totpReq)
				require.NoError(t, err)

				recorder = httptest.NewRecorder()
				req := httptest.NewRequest("POST", "/api/user/totp", strings.NewReader(string(totpReqBody)))
				req.Header.Set("Content-Type", "application/json")
				req.AddCookie(&http.Cookie{
					Name:     "tinyauth-session",
					Value:    "test-totp-login-uuid",
					HttpOnly: true,
					MaxAge:   3600,
					Expires:  time.Now().Add(1 * time.Hour),
				})
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				require.Len(t, recorder.Result().Cookies(), 1)

				// should set a new session cookie with totp pending removed
				totpCookie := recorder.Result().Cookies()[0]
				assert.Equal(t, "tinyauth-session", totpCookie.Name)
				assert.True(t, totpCookie.HttpOnly)
				assert.Equal(t, "example.com", totpCookie.Domain)
				assert.GreaterOrEqual(t, totpCookie.MaxAge, 7)
				assert.LessOrEqual(t, totpCookie.MaxAge, 10)
			},
		},
		{
			description: "Totp should rate limit on multiple invalid attempts",
			middlewares: []gin.HandlerFunc{
				totpCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				for range 3 {
					totpReq := controller.TotpRequest{
						Code: "000000", // invalid code
					}

					totpReqBody, err := json.Marshal(totpReq)
					require.NoError(t, err)

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
			middlewares: []gin.HandlerFunc{
				totpAttrCtx,
			},
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				_, err := queries.CreateSession(context.TODO(), repository.CreateSessionParams{
					UUID:        "test-totp-login-attributes-uuid",
					Username:    "test",
					Email:       "test@example.com",
					Name:        "Test",
					Provider:    "local",
					TotpPending: true,
					Expiry:      time.Now().Add(1 * time.Hour).Unix(),
					CreatedAt:   time.Now().Unix(),
				})
				require.NoError(t, err)

				code, err := totp.GenerateCode("JPIEBDKJH6UGWJMX66RR3S55UFP2SGKK", time.Now())
				require.NoError(t, err)

				totpReq := controller.TotpRequest{Code: code}
				body, err := json.Marshal(totpReq)
				require.NoError(t, err)

				req := httptest.NewRequest("POST", "/api/user/totp", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				req.AddCookie(&http.Cookie{
					Name:     "tinyauth-session",
					Value:    "test-totp-login-attributes-uuid",
					HttpOnly: true,
					MaxAge:   3600,
					Expires:  time.Now().Add(1 * time.Hour),
				})
				router.ServeHTTP(recorder, req)

				require.Equal(t, 200, recorder.Code)
				cookies := recorder.Result().Cookies()
				require.Len(t, cookies, 1)
				assert.Equal(t, "tinyauth-session", cookies[0].Name)
			},
		},
	}

	ctx := context.TODO()
	wg := &sync.WaitGroup{}

	broker := service.NewOAuthBrokerService(log, map[string]model.OAuthServiceConfig{}, ctx)
	authService := service.NewAuthService(log, cfg, runtime, ctx, wg, nil, queries, broker)

	beforeEach := func() {
		// Clear failed login attempts before each test
		authService.ClearRateLimitsTestingOnly()
	}

	for _, test := range tests {
		beforeEach()
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()

			for _, middleware := range test.middlewares {
				router.Use(middleware)
			}

			group := router.Group("/api")
			gin.SetMode(gin.TestMode)

			controller.NewUserController(log, runtime, group, authService)

			recorder := httptest.NewRecorder()

			test.run(t, router, recorder)
		})
	}

	t.Cleanup(func() {
		app.GetDB().Close()
	})
}
